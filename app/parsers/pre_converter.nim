# app/parsers/pre_converter.nim
# Pre-conversion layer: classify, shard, and entropy-filter all file types
# before nim_parser.nim processes them.
# Pipeline: raw file → ShardMap → nim_parser.parseShardMap

import std/[os, strutils, tables, math, strformat]
import zippy
import zippy/ziparchives

# ─── Constants ────────────────────────────────────────────────────────────────

const
  ENTROPY_BINARY*   = 7.0    # skip — image/raw binary
  ENTROPY_MIXED*    = 5.0    # decompress + classify
  SHARD_BYTE_MAX*   = 8_000  # max bytes per text shard
  CSV_ROW_SHARD*    = 10_000 # row threshold for CSV sharding
  CONFIG_BYTE_MAX*  = 51_200 # 50KB — configs above this get sharded

# ─── Types ────────────────────────────────────────────────────────────────────

type
  ContentType* = enum
    ctText    = "text"
    ctTable   = "table"
    ctVisual  = "visual"
    ctCode    = "code"
    ctConfig  = "config"
    ctUnknown = "unknown"

  Shard* = object
    index*:       int
    contentType*: ContentType
    rawBytes*:    string
    pageNum*:     int                  # -1 if not page-based
    byteOffset*:  int
    byteLen*:     int
    entropy*:     float
    hints*:       Table[string, string]

  ShardMap* = object
    filePaths*:   seq[string]
    fileFormat*:  string
    totalShards*: int
    shards*:      seq[Shard]
    skipped*:     int

# ─── Entropy ──────────────────────────────────────────────────────────────────

proc calcEntropy*(data: string): float =
  if data.len == 0: return 0.0
  var freq: array[256, int]
  for c in data: freq[c.ord].inc
  let n = data.len.float
  for count in freq:
    if count > 0:
      let p = count.float / n
      result -= p * log2(p)

# ─── Content Weight Sniffer ───────────────────────────────────────────────────

proc calcContentWeights*(text: string): tuple[alpha, digit, symbol, space: float] =
  if text.len == 0: return (0.0, 0.0, 0.0, 0.0)
  var a, d, s, sp: int
  for c in text:
    if c.isAlphaAscii:   inc a
    elif c.isDigit:      inc d
    elif c == ' ' or c == '\n' or c == '\t': inc sp
    else:                inc s
  let n = text.len.float
  (a.float/n, d.float/n, s.float/n, sp.float/n)

proc sniffContentType*(data: string): ContentType =
  let e = calcEntropy(data)
  if e > ENTROPY_BINARY: return ctVisual   # garbage / binary
  let (alpha, digit, symbol, _) = calcContentWeights(data)
  if alpha < 0.2 and symbol > 0.3:         return ctVisual
  if digit > 0.25 and symbol > 0.15:       return ctTable
  # table smell: pipe-delimited or tab-aligned
  let lineCount  = data.count('\n') + 1
  let pipeCount  = data.count('|')
  let tabCount   = data.count('\t')
  if lineCount > 2:
    if pipeCount.float / lineCount.float > 1.5: return ctTable
    if tabCount.float  / lineCount.float > 1.5: return ctTable
  # TOC/index smell: short lines ending in numbers
  var shortNumLines = 0
  for line in data.splitLines():
    let s = line.strip()
    if s.len > 0 and s.len < 60 and s[^1].isDigit: inc shortNumLines
  if shortNumLines.float / lineCount.float > 0.5: return ctTable
  if alpha > 0.5: return ctText
  return ctUnknown

# ─── Shard Builder Helper ─────────────────────────────────────────────────────

proc makeShard(index: int, ct: ContentType, raw: string,
               page: int = -1, offset: int = 0,
               hints: Table[string, string] = initTable[string, string]()): Shard =
  Shard(
    index:       index,
    contentType: ct,
    rawBytes:    raw,
    pageNum:     page,
    byteOffset:  offset,
    byteLen:     raw.len,
    entropy:     calcEntropy(raw),
    hints:       hints
  )

# ─── PDF Sharder ──────────────────────────────────────────────────────────────

proc tryDecompress(data: string): string =
  let s = data.strip(leading = false, chars = {'\r', '\n', ' '})
  try: result = uncompress(s, dfZlib)
  except:
    try: result = uncompress(s, dfDeflate)
    except: result = data

proc extractPdfPageStreams*(raw: string): seq[tuple[page: int, data: string]] =
  ## Walk PDF for /Type /Page objects, extract each page's content stream.
  ## Falls back to sequential stream extraction if page objects not found.
  var pageStreams: seq[tuple[page: int, data: string]]
  var pageNum = 0
  var i = 0
  while i < raw.len:
    let si = raw.find("stream", i)
    if si < 0: break
    let header = raw[max(0, si - 512) ..< si]
    # skip image, font, and metadata streams
    if "/Subtype /Image" in header or
       "/Type /Font"     in header or
       "/Type /FontDescriptor" in header or
       "/Type /Metadata" in header:
      i = si + 6
      continue
    let flate = "FlateDecode" in header or "/Fl " in header
    var ds = si + 6
    if ds < raw.len and raw[ds] == '\r': inc ds
    if ds < raw.len and raw[ds] == '\n': inc ds
    let ei = raw.find("endstream", ds)
    if ei < 0: break
    let content = if flate: tryDecompress(raw[ds ..< ei]) else: raw[ds ..< ei]
    # check entropy — skip binary/image streams
    let e = calcEntropy(content)
    if e <= ENTROPY_BINARY:
      # check if it contains BT...ET text blocks
      if "BT" in content and "ET" in content:
        inc pageNum
        pageStreams.add((pageNum, content))
    i = ei + 9
  result = pageStreams

proc extractTextFromPdfStream(content: string): string =
  ## Extract printable text from BT...ET blocks in a PDF stream.
  var parts: seq[string]
  var j = 0
  while j < content.len - 1:
    if content[j] == 'B' and content[j+1] == 'T':
      var k = j + 2
      while k < content.len - 1:
        if content[k] == 'E' and content[k+1] == 'T': break
        if content[k] == ')':
          var m = k - 1
          while m > j and content[m] != '(': dec m
          if content[m] == '(':
            var text = ""
            for c in content[m+1 ..< k]:
              if c >= ' ' and c <= '~': text.add(c)
            let cleaned = text.strip()
            if cleaned.len > 2: parts.add(cleaned)
        inc k
      j = k + 2
      continue
    inc j
  result = parts.join(" ").strip()

proc shardPdf*(filePath: string): seq[Shard] =
  let raw = readFile(filePath)
  let pageStreams = extractPdfPageStreams(raw)
  var idx = 0
  var skipped = 0
  for (pageNum, streamData) in pageStreams:
    let text = extractTextFromPdfStream(streamData)
    if text.len == 0:
      inc skipped
      continue
    let ct = sniffContentType(text)
    if ct == ctVisual:
      inc skipped
      continue
    var hints = initTable[string, string]()
    hints["page"] = $pageNum
    result.add(makeShard(idx, ct, text, page = pageNum, hints = hints))
    inc idx
  # fallback: if no page streams found, treat whole file as one shard
  if result.len == 0:
    var hints = initTable[string, string]()
    hints["fallback"] = "true"
    result.add(makeShard(0, ctText, raw, hints = hints))

# ─── DOCX Sharder ─────────────────────────────────────────────────────────────

proc shardDocx*(filePath: string): seq[Shard] =
  try:
    let z = openZipArchive(filePath)
    defer: z.close()
    let xmlStr = z.extractFile("word/document.xml")
    # split on section break marker w:sectPr or accumulate by size
    var chunks: seq[string]
    var current = ""
    for line in xmlStr.splitLines():
      current.add(line & "\n")
      if "w:sectPr" in line or current.len > SHARD_BYTE_MAX:
        if current.strip().len > 0: chunks.add(current)
        current = ""
    if current.strip().len > 0: chunks.add(current)
    for i, chunk in chunks:
      let ct = sniffContentType(chunk)
      result.add(makeShard(i, ct, chunk))
  except:
    var hints = initTable[string, string]()
    hints["error"] = "docx_read_failed"
    result.add(makeShard(0, ctUnknown, "", hints = hints))

# ─── Markdown Sharder ─────────────────────────────────────────────────────────

proc shardMarkdown*(raw: string): seq[Shard] =
  var chunks: seq[string]
  var current = ""
  for line in raw.splitLines():
    # split on h1/h2
    if (line.startsWith("# ") or line.startsWith("## ")) and current.strip().len > 0:
      chunks.add(current)
      current = ""
    current.add(line & "\n")
    if current.len > SHARD_BYTE_MAX:
      chunks.add(current)
      current = ""
  if current.strip().len > 0: chunks.add(current)
  if chunks.len == 0: chunks.add(raw)
  for i, chunk in chunks:
    result.add(makeShard(i, ctText, chunk))

# ─── Plain Text Sharder ───────────────────────────────────────────────────────

proc shardPlainText*(raw: string): seq[Shard] =
  var chunks: seq[string]
  var current = ""
  for para in raw.split("\n\n"):
    current.add(para & "\n\n")
    if current.len > SHARD_BYTE_MAX:
      chunks.add(current)
      current = ""
  if current.strip().len > 0: chunks.add(current)
  if chunks.len == 0: chunks.add(raw)
  for i, chunk in chunks:
    let ct = sniffContentType(chunk)
    result.add(makeShard(i, ct, chunk))

# ─── HTML Sharder ─────────────────────────────────────────────────────────────

proc shardHtml*(raw: string): seq[Shard] =
  var chunks: seq[string]
  var current = ""
  for line in raw.splitLines():
    let l = line.toLowerAscii()
    let isBlockStart = l.contains("<h1") or l.contains("<h2") or
                       l.contains("<article") or l.contains("<section")
    if isBlockStart and current.strip().len > 0:
      chunks.add(current)
      current = ""
    current.add(line & "\n")
    if current.len > SHARD_BYTE_MAX:
      chunks.add(current)
      current = ""
  if current.strip().len > 0: chunks.add(current)
  if chunks.len == 0: chunks.add(raw)
  for i, chunk in chunks:
    result.add(makeShard(i, ctText, chunk))

# ─── CSV Sharder ──────────────────────────────────────────────────────────────

proc shardCsv*(filePath: string): seq[Shard] =
  let raw = readFile(filePath)
  let lines = raw.splitLines()
  if lines.len == 0: return
  let header = if lines.len > 0: lines[0] else: ""
  if lines.len <= CSV_ROW_SHARD + 1:
    var hints = initTable[string, string]()
    hints["row_start"] = "0"
    hints["row_end"]   = $lines.len
    result.add(makeShard(0, ctTable, raw, hints = hints))
    return
  # shard by row range
  var idx = 0
  var rowStart = 1  # skip header
  while rowStart < lines.len:
    let rowEnd = min(rowStart + CSV_ROW_SHARD, lines.len)
    let chunk  = header & "\n" & lines[rowStart ..< rowEnd].join("\n")
    var hints = initTable[string, string]()
    hints["row_start"] = $rowStart
    hints["row_end"]   = $rowEnd
    result.add(makeShard(idx, ctTable, chunk, hints = hints))
    inc idx
    rowStart = rowEnd

# ─── Config Sharder ───────────────────────────────────────────────────────────

proc shardConfig*(raw: string, fmt: string): seq[Shard] =
  if raw.len <= CONFIG_BYTE_MAX:
    var hints = initTable[string, string]()
    hints["format"] = fmt
    result.add(makeShard(0, ctConfig, raw, hints = hints))
    return
  # large config: split on top-level keys by blank line separation
  var chunks: seq[string]
  var current = ""
  for line in raw.splitLines():
    current.add(line & "\n")
    if current.len > CONFIG_BYTE_MAX:
      chunks.add(current)
      current = ""
  if current.strip().len > 0: chunks.add(current)
  for i, chunk in chunks:
    var hints = initTable[string, string]()
    hints["format"] = fmt
    result.add(makeShard(i, ctConfig, chunk, hints = hints))

# ─── Main Entry Point ─────────────────────────────────────────────────────────

proc buildShardMap*(filePaths: seq[string]): ShardMap =
  result.filePaths = filePaths
  let ext = filePaths[0].splitFile().ext.toLowerAscii()
  result.fileFormat = ext

  case ext
  of ".pdf":
    result.shards = shardPdf(filePaths[0])
  of ".docx":
    result.shards = shardDocx(filePaths[0])
  of ".md", ".markdown", ".mdx":
    result.shards = shardMarkdown(readFile(filePaths[0]))
  of ".html", ".htm":
    result.shards = shardHtml(readFile(filePaths[0]))
  of ".csv", ".tsv":
    result.shards = shardCsv(filePaths[0])
  of ".json", ".jsonl", ".ndjson":
    result.shards = shardConfig(readFile(filePaths[0]), ext[1..^1])
  of ".yaml", ".yml":
    result.shards = shardConfig(readFile(filePaths[0]), "yaml")
  of ".toml":
    result.shards = shardConfig(readFile(filePaths[0]), "toml")
  of ".xml":
    result.shards = shardConfig(readFile(filePaths[0]), "xml")
  else:
    result.shards = shardPlainText(readFile(filePaths[0]))

  result.totalShards = result.shards.len
