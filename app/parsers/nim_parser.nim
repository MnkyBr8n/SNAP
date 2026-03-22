# app/parsers/nim_parser.nim
# Replaces text_extractor.py and csv_parser.py
# Formats: MD, HTML, plain text, DOCX, PDF (text only), CSV
# Output: text snapshots (DocGraph) + csv snapshots
# DocGraph: hash-linked structural nodes, no raw content stored

import std/[os, strutils, sequtils, tables, sets, json, streams,
            xmlparser, xmltree, parsecsv, hashes, strtabs]
import checksums/sha1
import zippy/ziparchives
import zippy
import pre_converter 


# ─── Types ────────────────────────────────────────────────────────────────────

type
  NodeType* = enum
    ntRoot       = "root"
    ntSection    = "section"
    ntParagraph  = "paragraph"
    ntList       = "list"
    ntListItem   = "list_item"
    ntTable      = "table"
    ntReference  = "reference"
    ntCodeBlock  = "code_block"

  DocNode* = object
    nodeType*:       NodeType
    contentHash*:    string   # SHA-1 hex of node content (unique per node)
    connectingHash*: string   # parent node hash or cross-doc root hash
    level*:          int      # section depth 1-6, 0 otherwise
    text*:           string   # dehydrated content (no raw text stored)
    children*:       seq[string]  # child contentHash list

  DocGraph* = object
    rootHash*:  string
    nodes*:     Table[string, DocNode]
    filePath*:  string
    title*:     string
    author*:    string
    date*:      string
    source*:    string
    topics*:    seq[string]
    entities*:  seq[string]

  CsvSchema* = object
    headers*:      seq[string]
    types*:        seq[string]
    rowCount*:     int
    columnCount*:  int
    sample*:       seq[seq[string]]
    nullCounts*:   Table[string, int]
    uniqueCounts*: Table[string, int]

  ParseResult* = object
    snapType*: string
    graph*: DocGraph
    csv*:      CsvSchema
    config*:   ConfigSchema

  FileFormat* = enum
    fmMarkdown, fmHtml, fmDocx, fmPdf, fmCsv, fmPlainText,
    fmJson, fmJsonl, fmXml, fmYaml, fmToml

  ConfigSchema* = object
    filePath*:     string
    format*:       string
    topLevelKeys*: seq[string]
    paramNames*:   seq[string]
    envVars*:      seq[string]
    dbStrings*:    seq[string]
    nestedPaths*:  seq[string]
    apiEndpoints*: seq[string]
    apiHosts*:     seq[string]

# ─── Hashing ──────────────────────────────────────────────────────────────────

proc nodeHash*(nodeType: NodeType, text, parentHash: string): string =
  ## Deterministic SHA-1 hex hash for a node
  let ctx = secureHash($nodeType & "|" & text & "|" & parentHash)
  result = $ctx

# ─── Format Detection ─────────────────────────────────────────────────────────

proc detectFormat*(filePath: string): FileFormat =
  let ext = filePath.splitFile().ext.toLowerAscii()
  case ext
  of ".md", ".markdown", ".mdx": fmMarkdown
  of ".html", ".htm":            fmHtml
  of ".docx":                    fmDocx
  of ".pdf":                     fmPdf
  of ".csv":                     fmCsv
  of ".tsv":                     fmCsv
  of ".json":                    fmJson
  of ".jsonl", ".ndjson":        fmJsonl
  of ".xml":                     fmXml
  of ".yaml", ".yml":            fmYaml
  of ".toml":                    fmToml
  else:                          fmPlainText

# ─── DocGraph Helpers ─────────────────────────────────────────────────────────

proc newDocGraph*(filePath: string): DocGraph =
  result.filePath = filePath
  result.nodes    = initTable[string, DocNode]()

proc makeNode*(t: NodeType, rawText, connectingHash: string,
               level: int = 0): DocNode =
  let h = nodeHash(t, rawText, connectingHash)
  DocNode(nodeType: t, contentHash: h, connectingHash: connectingHash,
          level: level, text: rawText, children: @[])

proc addChild*(graph: var DocGraph, parentHash, childHash: string) =
  if parentHash in graph.nodes:
    graph.nodes[parentHash].children.add(childHash)

proc put*(graph: var DocGraph, node: DocNode) =
  graph.nodes[node.contentHash] = node

# ─── Markdown Parser ──────────────────────────────────────────────────────────

proc headingLevel(line: string): tuple[level: int, text: string] =
  var n = 0
  for ch in line:
    if ch == '#': inc n else: break
  if n in 1..6: (n, line[n..^1].strip())
  else:          (0, "")

proc parseMarkdown*(content, filePath: string): DocGraph =
  result = newDocGraph(filePath)
  let lines = content.splitLines()

  var title = filePath.splitFile().name
  for ln in lines:
    let (lvl, txt) = headingLevel(ln)
    if lvl == 1: title = txt; break

  let root = makeNode(ntRoot, title, "")
  result.rootHash = root.contentHash
  result.title    = title
  result.put(root)

  var sectionStack = @[root.contentHash]
  var currentListHash = ""
  var inList    = false
  var inCode    = false
  var paraLines: seq[string]

  proc flushPara(graph: var DocGraph, pLines: var seq[string], secStack: seq[string]) =
    if pLines.len == 0: return
    let txt = pLines.join(" ").strip()
    if txt.len > 0:
      let parent = if secStack.len > 0: secStack[^1] else: graph.rootHash
      let node = makeNode(ntParagraph, txt, parent)
      graph.put(node)
      graph.addChild(parent, node.contentHash)
    pLines = @[]

  for ln in lines:
    if ln.strip().startsWith("```"):
      inCode = not inCode
      continue
    if inCode: continue

    let (lvl, htxt) = headingLevel(ln)
    if lvl > 0:
      flushPara(result, paraLines, sectionStack)
      inList = false
      while sectionStack.len > 1:
        let topLevel = result.nodes[sectionStack[^1]].level
        if topLevel >= lvl: discard sectionStack.pop()
        else: break
      let parent = sectionStack[^1]
      let sec = makeNode(ntSection, htxt, parent, lvl)
      result.put(sec)
      result.addChild(parent, sec.contentHash)
      sectionStack.add(sec.contentHash)
      continue

    let stripped = ln.strip()
    let isBullet  = stripped.startsWith("- ") or stripped.startsWith("* ") or
                    stripped.startsWith("+ ")
    let isNumeric = stripped.len > 2 and stripped[0].isDigit() and
                    (stripped[1] == '.' or stripped[1] == ')')
    if isBullet or isNumeric:
      flushPara(result, paraLines, sectionStack)
      if not inList:
        inList = true
        let parent = if sectionStack.len > 0: sectionStack[^1] else: result.rootHash
        let lst = makeNode(ntList, "", parent)
        result.put(lst)
        result.addChild(parent, lst.contentHash)
        currentListHash = lst.contentHash
      let itemTxt =
        if isBullet: stripped[2..^1]
        else: stripped[stripped.find({'.', ')'}) + 1 .. ^1].strip()
      var item = makeNode(ntListItem, itemTxt, currentListHash)
      if itemTxt.contains("]("):
        let ls = itemTxt.find("](") + 2
        let le = itemTxt.find(")", ls)
        if le > ls:
          let target = itemTxt[ls ..< le]
          let refNode = makeNode(ntReference, target, item.contentHash)
          result.put(refNode)
          item.children.add(refNode.contentHash)
      result.put(item)
      result.addChild(currentListHash, item.contentHash)
      continue

    if stripped.len == 0:
      flushPara(result, paraLines, sectionStack)
      inList = false
      continue

    paraLines.add(ln)

  flushPara(result, paraLines, sectionStack)

proc parsePlainText*(content, filePath: string): DocGraph

# ─── HTML Parser ──────────────────────────────────────────────────────────────

proc xmlInnerText(node: XmlNode): string =
  if node == nil: return ""
  if node.kind == xnText: return node.text
  for child in node: result.add(xmlInnerText(child))

proc htmlFindTitle(n: XmlNode, title: var string) =
  if n == nil: return
  if n.tag in ["title", "h1"]:
    title = xmlInnerText(n).strip(); return
  for ch in n: htmlFindTitle(ch, title)

proc htmlWalk(n: XmlNode, parentHash: string, graph: var DocGraph, curSec: var string) =
  if n == nil: return
  case n.tag
  of "h1", "h2", "h3", "h4", "h5", "h6":
    let lvl = parseInt($n.tag[1])
    let sec = makeNode(ntSection, xmlInnerText(n).strip(), parentHash, lvl)
    graph.put(sec); graph.addChild(parentHash, sec.contentHash)
    curSec = sec.contentHash
  of "p":
    let txt = xmlInnerText(n).strip()
    if txt.len > 0:
      let para = makeNode(ntParagraph, txt, curSec)
      graph.put(para); graph.addChild(curSec, para.contentHash)
  of "ul", "ol":
    let lst = makeNode(ntList, "", curSec)
    graph.put(lst); graph.addChild(curSec, lst.contentHash)
    for ch in n:
      if ch.tag == "li":
        let item = makeNode(ntListItem, xmlInnerText(ch).strip(), lst.contentHash)
        graph.put(item); graph.addChild(lst.contentHash, item.contentHash)
  of "table":
    let tbl = makeNode(ntTable, xmlInnerText(n).strip(), curSec)
    graph.put(tbl); graph.addChild(curSec, tbl.contentHash)
  of "a":
    let href = n.attr("href")
    if href.len > 0:
      let refNode = makeNode(ntReference, href, curSec)
      graph.put(refNode); graph.addChild(curSec, refNode.contentHash)
  else:
    for ch in n: htmlWalk(ch, parentHash, graph, curSec)

proc parseHtmlDoc*(content, filePath: string): DocGraph =
  result = newDocGraph(filePath)
  var xml: XmlNode
  try:
    xml = parseXml(newStringStream(content))
  except:
    return parsePlainText(content, filePath)
  var title = filePath.splitFile().name
  htmlFindTitle(xml, title)
  let root = makeNode(ntRoot, title, "")
  result.rootHash = root.contentHash
  result.title    = title
  result.put(root)
  var curSection = root.contentHash
  htmlWalk(xml, root.contentHash, result, curSection)

# ─── Plain Text Parser ────────────────────────────────────────────────────────

proc parsePlainText*(content, filePath: string): DocGraph =
  result = newDocGraph(filePath)
  let title = filePath.splitFile().name
  let root  = makeNode(ntRoot, title, "")
  result.rootHash = root.contentHash
  result.title    = title
  result.put(root)

  var curSection = root.contentHash
  for para in content.split("\n\n"):
    let txt = para.strip()
    if txt.len == 0: continue
    let lines = txt.splitLines()
    let isHeading = lines.len == 1 and txt.len <= 80 and
                    not txt.endsWith('.') and not txt.endsWith(',') and
                    txt[0].isUpperAscii()
    if isHeading:
      let sec = makeNode(ntSection, txt, root.contentHash, 1)
      result.put(sec)
      result.addChild(root.contentHash, sec.contentHash)
      curSection = sec.contentHash
    else:
      let node = makeNode(ntParagraph, txt, curSection)
      result.put(node)
      result.addChild(curSection, node.contentHash)

# ─── DOCX Parser ──────────────────────────────────────────────────────────────

proc extractDocxText*(filePath: string): string =
  ## DOCX = zip(word/document.xml). Extract w:t text runs.
  try:
    let z = openZipArchive(filePath)
    defer: z.close()
    let xmlStr = z.extractFile("word/document.xml")
    let doc = parseXml(xmlStr)
    var parts: seq[string]
    proc collectRuns(x: XmlNode, paraText: var string) =
      if x == nil: return
      if x.tag == "w:t":
        for ch in x:
          if ch.kind == xnText: paraText.add(ch.text)
      for ch in x: collectRuns(ch, paraText)
    proc walkDoc(n: XmlNode, parts: var seq[string]) =
      if n == nil: return
      if n.tag == "w:p":
        var paraText = ""
        collectRuns(n, paraText)
        if paraText.strip().len > 0: parts.add(paraText)
        return
      for ch in n: walkDoc(ch, parts)
    walkDoc(doc, parts)
    result = parts.join("\n\n")
  except:
    result = ""

proc parseDocx*(filePath: string): DocGraph =
  let content = extractDocxText(filePath)
  if content.len > 0: parsePlainText(content, filePath)
  else: newDocGraph(filePath)

# ─── PDF Parser (text only) ───────────────────────────────────────────────────

proc tryDecompress(data: string): string =
  let s = data.strip(leading = false, chars = {'\r', '\n', ' '})
  try: uncompress(s, dfZlib)
  except:
    try: uncompress(s, dfDeflate)
    except: data

proc extractPdfText*(filePath: string): string =
  try:
    let raw = readFile(filePath)
    var parts: seq[string]
    var i = 0
    while i < raw.len:
      let si = raw.find("stream", i)
      if si < 0: break
      let header = raw[max(0, si - 512) ..< si]
      let flate = "FlateDecode" in header or "/Fl " in header
      var ds = si + 6
      if ds < raw.len and raw[ds] == '\r': inc ds
      if ds < raw.len and raw[ds] == '\n': inc ds
      let ei = raw.find("endstream", ds)
      if ei < 0: break
      let content = if flate: tryDecompress(raw[ds ..< ei]) else: raw[ds ..< ei]
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
      i = ei + 9
    result = parts.join(" ").strip()
  except:
    result = ""


proc parsePdf*(filePath: string): DocGraph =
  let content = extractPdfText(filePath)
  if content.len > 0: parsePlainText(content, filePath)
  else: newDocGraph(filePath)

# ─── CSV Parser ───────────────────────────────────────────────────────────────


proc inferType(vals: seq[string]): string =
  var isInt = true; var isFloat = true; var nonNull = 0
  for v in vals:
    if v.strip().len == 0: continue
    inc nonNull
    try: discard parseInt(v.strip())   except: isInt = false
    try: discard parseFloat(v.strip()) except: isFloat = false
  if nonNull == 0: return "null"
  if isInt:        return "integer"
  if isFloat:      return "float"
  return "string"

proc parseCsv*(filePath: string): CsvSchema =
  result.nullCounts = initTable[string, int]()
  var p: CsvParser
  try:
    let isTsv = filePath.splitFile().ext.toLowerAscii() == ".tsv"
    let sep   = if isTsv: '\t' else: ','
    p.open(filePath, separator = sep)
    p.readHeaderRow()
    result.headers     = p.headers
    result.columnCount = result.headers.len
    for h in result.headers: result.nullCounts[h] = 0
    var colVals = newSeq[seq[string]](result.headers.len)
    while p.readRow():
      inc result.rowCount
      var row: seq[string]
      for i, h in result.headers:
        let v = p.rowEntry(h)
        row.add(v)
        colVals[i].add(v)
        if v.strip().len == 0:
          result.nullCounts[h] = result.nullCounts.getOrDefault(h) + 1
      if result.rowCount <= 5: result.sample.add(row)
    result.types = colVals.mapIt(inferType(it))
    # unique counts per column
    result.uniqueCounts = initTable[string, int]()
    for i, h in result.headers:
      var seen: HashSet[string]
      for v in colVals[i]: seen.incl(v)
      result.uniqueCounts[h] = seen.len
    p.close()
  except: discard

# ─── Topic / Entity Extraction ────────────────────────────────────────────────

proc extractTopics*(graph: DocGraph): seq[string] =
  for _, node in graph.nodes:
    if node.nodeType == ntSection and node.level <= 2 and node.text.len > 0:
      result.add(node.text)
  result = result.deduplicate()

proc extractEntities*(graph: DocGraph): seq[string] =
  for _, node in graph.nodes:
    if node.nodeType in {ntParagraph, ntListItem}:
      for word in node.text.splitWhitespace():
        if word.len > 2 and word[0].isUpperAscii():
          result.add(word)
  result = result.deduplicate()
  if result.len > 20: result.setLen(20)


# ─── Config Parsers (JSON, JSONL, XML, YAML, TOML) ───────────────────────────

proc collectJsonPaths(node: JsonNode, prefix: string,
                      paths: var seq[string], keys: var seq[string],
                      envVars: var seq[string]) =
  case node.kind
  of JObject:
    for k, v in node:
      let p = if prefix.len > 0: prefix & "." & k else: k
      keys.add(k)
      paths.add(p)
      if v.kind == JString:
        let s = v.getStr()
        var i = 0
        while i < s.len - 1:
          if s[i] == '$' and s[i+1] == '{':
            let e = s.find('}', i+2)
            if e > 0: envVars.add(s[i+2 ..< e])
            i = e + 1
          else: inc i
      collectJsonPaths(v, p, paths, keys, envVars)
  of JArray:
    for i, v in node:
      collectJsonPaths(v, prefix & "[" & $i & "]", paths, keys, envVars)
  else: discard

proc extractConfigUrls(content: string,
                       endpoints: var seq[string], hosts: var seq[string]) =
  var i = 0
  while i < content.len - 7:
    if content[i..min(i+6, content.len-1)] in ["http://", "https:/"]:
      var j = i
      while j < content.len and content[j] notin {'"', '\'', '\n', ' '}: inc j
      let url = content[i ..< j]
      endpoints.add(url)
      # extract host
      let afterScheme = url.find("//")
      if afterScheme >= 0:
        var h = afterScheme + 2
        var hend = h
        while hend < url.len and url[hend] notin {'/', '?', '#'}: inc hend
        hosts.add(url[h ..< hend])
    inc i

proc extractDbStrings(content: string): seq[string] =
  for scheme in ["postgresql://", "postgres://", "mysql://", "mongodb://",
                 "redis://", "sqlite://", "mssql://"]:
    var i = 0
    while i < content.len - scheme.len:
      if content[i ..< i + scheme.len] == scheme:
        var j = i
        while j < content.len and content[j] notin {'"', '\'', '\n', ' '}: inc j
        var s = content[i ..< j]
        # redact password: scheme://user:PASS@host
        let atPos = s.find('@')
        let colonPos = s.find(':', scheme.len)
        if atPos > 0 and colonPos > 0 and colonPos < atPos:
          s = s[0 ..< colonPos + 1] & "***" & s[atPos .. ^1]
        result.add(s)
      inc i

proc parseJsonConfig*(content, filePath, fmt: string): ConfigSchema =
  result.filePath = filePath
  result.format   = fmt
  try:
    let node = parseJson(content)
    if node.kind == JObject:
      for k in node.keys: result.topLevelKeys.add(k)
    var paths, keys, envs: seq[string]
    collectJsonPaths(node, "", paths, keys, envs)
    result.nestedPaths = paths
    result.paramNames  = keys.deduplicate()
    result.envVars     = envs.deduplicate()
  except: discard
  result.dbStrings = extractDbStrings(content)
  extractConfigUrls(content, result.apiEndpoints, result.apiHosts)
  result.apiEndpoints = result.apiEndpoints.deduplicate()
  result.apiHosts     = result.apiHosts.deduplicate()

proc parseJsonlConfig*(content, filePath: string): ConfigSchema =
  ## JSONL: parse first non-empty line as representative object
  result.filePath = filePath
  result.format   = "jsonl"
  for line in content.splitLines():
    let s = line.strip()
    if s.len == 0: continue
    try:
      let node = parseJson(s)
      if node.kind == JObject:
        for k in node.keys: result.topLevelKeys.add(k)
        result.paramNames = result.topLevelKeys
      break
    except: continue
  result.dbStrings = extractDbStrings(content)
  extractConfigUrls(content, result.apiEndpoints, result.apiHosts)
  result.apiEndpoints = result.apiEndpoints.deduplicate()
  result.apiHosts     = result.apiHosts.deduplicate()

proc collectXmlPaths(node: XmlNode, prefix: string,
                     paths: var seq[string], keys: var seq[string]) =
  if node == nil: return
  let p = if prefix.len > 0: prefix & "." & node.tag else: node.tag
  keys.add(node.tag)
  paths.add(p)
  for attr in node.attrs.pairs:
    keys.add(attr[0])
    paths.add(p & "[@" & attr[0] & "]")
  for child in node:
    if child.kind == xnElement:
      collectXmlPaths(child, p, paths, keys)

proc classifyXml(root: XmlNode): string =
  ## Sniff XML type from root element structure
  if root == nil: return "config"
  let tag = root.tag.toLowerAscii()
  # doc indicators
  if tag in ["html", "body", "article", "section", "document", "book",
             "chapter", "para", "text", "div"]:
    return "doc"
  for ch in root:
    if ch.kind == xnElement and ch.tag.toLowerAscii() in
        ["p", "h1", "h2", "h3", "body", "section", "article"]:
      return "doc"
  # data indicators: many children sharing the same tag (record rows)
  if root.len >= 2:
    var tagCounts = initTable[string, int]()
    for ch in root:
      if ch.kind == xnElement:
        tagCounts[ch.tag] = tagCounts.getOrDefault(ch.tag) + 1
    for _, count in tagCounts:
      if count >= 2: return "data"
  return "config"

proc xmlFindTitle(n: XmlNode, title: var string) =
  if n == nil: return
  if n.tag.toLowerAscii() in ["title", "h1"]:
    title = xmlInnerText(n).strip(); return
  for ch in n: xmlFindTitle(ch, title)

proc xmlDocWalk(n: XmlNode, parentHash: string, graph: var DocGraph, curSec: var string) =
  if n == nil: return
  let t = n.tag.toLowerAscii()
  if t in ["h1","h2","h3","h4","h5","h6"]:
    let lvl = parseInt($t[1])
    let sec = makeNode(ntSection, xmlInnerText(n).strip(), parentHash, lvl)
    graph.put(sec); graph.addChild(parentHash, sec.contentHash)
    curSec = sec.contentHash
  elif t in ["p", "para", "paragraph"]:
    let txt = xmlInnerText(n).strip()
    if txt.len > 0:
      let para = makeNode(ntParagraph, txt, curSec)
      graph.put(para); graph.addChild(curSec, para.contentHash)
  elif t in ["ul","ol","list","itemizedlist","orderedlist"]:
    let lst = makeNode(ntList, "", curSec)
    graph.put(lst); graph.addChild(curSec, lst.contentHash)
    for ch in n:
      if ch.kind == xnElement and ch.tag.toLowerAscii() in ["li","listitem"]:
        let item = makeNode(ntListItem, xmlInnerText(ch).strip(), lst.contentHash)
        graph.put(item); graph.addChild(lst.contentHash, item.contentHash)
  elif t == "a":
    let href = n.attr("href")
    if href.len > 0:
      let refNode = makeNode(ntReference, href, curSec)
      graph.put(refNode); graph.addChild(curSec, refNode.contentHash)
  else:
    for ch in n: xmlDocWalk(ch, parentHash, graph, curSec)

proc parseXmlDoc*(content, filePath: string): DocGraph =
  ## XML documents (XHTML, DocBook, DITA, etc.) → DocGraph
  result = newDocGraph(filePath)
  var xml: XmlNode
  try: xml = parseXml(newStringStream(content))
  except: return parsePlainText(content, filePath)
  var title = filePath.splitFile().name
  xmlFindTitle(xml, title)
  let root = makeNode(ntRoot, title, "")
  result.rootHash = root.contentHash
  result.title    = title
  result.put(root)
  var curSection = root.contentHash
  xmlDocWalk(xml, root.contentHash, result, curSection)

proc parseXmlData*(content, filePath: string): CsvSchema =
  ## XML data (repeated record rows) → CsvSchema
  try:
    let root = parseXml(newStringStream(content))
    if root == nil: return
    # first child element = first record, its children = columns
    var firstRecord: XmlNode
    for ch in root:
      if ch.kind == xnElement: firstRecord = ch; break
    if firstRecord == nil: return
    for ch in firstRecord:
      if ch.kind == xnElement: result.headers.add(ch.tag)
    result.columnCount = result.headers.len
    result.nullCounts  = initTable[string, int]()
    result.uniqueCounts = initTable[string, int]()
    for h in result.headers:
      result.nullCounts[h] = 0
      result.uniqueCounts[h] = 0
    var colVals = newSeq[seq[string]](result.headers.len)
    for rec in root:
      if rec.kind != xnElement: continue
      inc result.rowCount
      var row: seq[string]
      for i, h in result.headers:
        var val = ""
        for ch in rec:
          if ch.kind == xnElement and ch.tag == h:
            val = xmlInnerText(ch).strip(); break
        row.add(val)
        colVals[i].add(val)
        if val.len == 0: result.nullCounts[h] += 1
      if result.rowCount <= 5: result.sample.add(row)
    result.types = colVals.mapIt(inferType(it))
    for i, h in result.headers:
      var seen: HashSet[string]
      for v in colVals[i]: seen.incl(v)
      result.uniqueCounts[h] = seen.len
  except: discard

proc parseXmlConfig*(content, filePath: string): ConfigSchema =
  result.filePath = filePath
  result.format   = "xml"
  try:
    let root = parseXml(newStringStream(content))
    if root != nil:
      result.topLevelKeys.add(root.tag)
      var paths, keys: seq[string]
      collectXmlPaths(root, "", paths, keys)
      result.nestedPaths = paths
      result.paramNames  = keys.deduplicate()
  except: discard
  result.dbStrings = extractDbStrings(content)
  extractConfigUrls(content, result.apiEndpoints, result.apiHosts)
  result.apiEndpoints = result.apiEndpoints.deduplicate()
  result.apiHosts     = result.apiHosts.deduplicate()

proc parseYamlConfig*(content, filePath: string): ConfigSchema =
  ## YAML: extract keys via simple line scanning (no full YAML parser needed)
  result.filePath = filePath
  result.format   = "yaml"
  var envVars: seq[string]
  for line in content.splitLines():
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"): continue
    let colonPos = s.find(':')
    if colonPos > 0:
      let key = s[0 ..< colonPos].strip()
      if key.len > 0 and not key.startsWith("-"):
        result.paramNames.add(key)
        let indent = line.len - line.strip(leading=true, trailing=false).len
        if indent == 0: result.topLevelKeys.add(key)
    # env vars: ${VAR} or $VAR
    var i = 0
    while i < s.len:
      if s[i] == '$':
        if i + 1 < s.len and s[i+1] == '{':
          let e = s.find('}', i+2)
          if e > 0: envVars.add(s[i+2 ..< e])
          i = e + 1
        else:
          var j = i + 1
          while j < s.len and (s[j].isAlphaAscii() or s[j] == '_' or s[j].isDigit()): inc j
          if j > i + 1: envVars.add(s[i+1 ..< j])
          i = j
      else: inc i
  result.paramNames  = result.paramNames.deduplicate()
  result.topLevelKeys = result.topLevelKeys.deduplicate()
  result.envVars     = envVars.deduplicate()
  result.dbStrings   = extractDbStrings(content)
  extractConfigUrls(content, result.apiEndpoints, result.apiHosts)
  result.apiEndpoints = result.apiEndpoints.deduplicate()
  result.apiHosts     = result.apiHosts.deduplicate()

proc parseTomlConfig*(content, filePath: string): ConfigSchema =
  ## TOML: extract keys and sections via line scanning
  result.filePath = filePath
  result.format   = "toml"
  for line in content.splitLines():
    let s = line.strip()
    if s.len == 0 or s.startsWith("#"): continue
    if s.startsWith("["):
      let e = s.find(']')
      if e > 0: result.topLevelKeys.add(s[1 ..< e].split('.')[0])
    else:
      let eq = s.find('=')
      if eq > 0:
        result.paramNames.add(s[0 ..< eq].strip())
  result.topLevelKeys = result.topLevelKeys.deduplicate()
  result.paramNames   = result.paramNames.deduplicate()
  result.dbStrings    = extractDbStrings(content)
  extractConfigUrls(content, result.apiEndpoints, result.apiHosts)
  result.apiEndpoints = result.apiEndpoints.deduplicate()
  result.apiHosts     = result.apiHosts.deduplicate()


# ─── Snapshot JSON Builders ───────────────────────────────────────────────────

proc graphToJson*(graph: DocGraph, filePath: string): JsonNode =
  var sections, codeSnippets, urls, relatedFiles, apiEndpoints: seq[string]
  var questions, risks, decisions, assumptions, constraints: seq[string]
  for _, node in graph.nodes:
    case node.nodeType
    of ntSection:
      sections.add(node.text)
      for line in node.text.splitLines():
        let l = line.strip()
        if l.len == 0: continue
        if l.endsWith("?"):                       questions.add(l)
        elif l.toLowerAscii.contains("risk"):     risks.add(l)
        elif l.toLowerAscii.contains("decision"): decisions.add(l)
        elif l.toLowerAscii.contains("assum"):    assumptions.add(l)
        elif l.toLowerAscii.contains("constraint"): constraints.add(l)
    of ntCodeBlock: codeSnippets.add(node.text)
    of ntReference:
      let t = node.text.strip()
      if t.startsWith("http"):
        if "/api/" in t or "/v1/" in t or "/v2/" in t: apiEndpoints.add(t)
        else: urls.add(t)
      elif t.contains(".") and not t.contains(" "): relatedFiles.add(t)
      else: urls.add(t)
    else: discard
  result = newJObject()
  if graph.title.len > 0:      result["doc.title"]            = %graph.title
  if graph.author.len > 0:     result["doc.author"]           = %graph.author
  if graph.date.len > 0:       result["doc.date"]             = %graph.date
  if sections.len > 0:         result["doc.sections"]         = %sections
  if codeSnippets.len > 0:     result["doc.code_snippets"]    = %codeSnippets
  if urls.len > 0:             result["doc.urls"]             = %urls
  if relatedFiles.len > 0:     result["doc.related_files"]    = %relatedFiles
  if apiEndpoints.len > 0:     result["doc.api_endpoints"]    = %apiEndpoints
  if graph.topics.len > 0:     result["doc.key_requirements"] = %graph.topics
  if graph.entities.len > 0:   result["doc.entities"]         = %graph.entities
  if graph.source.len > 0:     result["doc.references"]       = %(@[graph.source])
  if questions.len > 0:        result["doc.questions"]        = %questions
  if risks.len > 0:            result["doc.risks"]            = %risks
  if decisions.len > 0:        result["doc.decisions"]        = %decisions
  if assumptions.len > 0:      result["doc.assumptions"]      = %assumptions
  if constraints.len > 0:      result["doc.constraints"]      = %constraints

proc csvToJson*(schema: CsvSchema, filePath: string): JsonNode =
  result = newJObject()
  var nullsNode = newJObject()
  for k, v in schema.nullCounts: nullsNode[k] = %v
  var uniquesNode = newJObject()
  for k, v in schema.uniqueCounts: uniquesNode[k] = %v
  var sampleNode = newJArray()
  for row in schema.sample:
    var rowNode = newJArray()
    for cell in row: rowNode.add(%cell)
    sampleNode.add(rowNode)
  if schema.headers.len > 0: result["csv.schema.column_names"]  = %schema.headers
  if schema.types.len > 0:   result["csv.schema.column_types"]  = %schema.types
  result["csv.schema.column_count"]  = %schema.columnCount
  result["csv.stats.row_count"]      = %schema.rowCount
  result["csv.stats.null_counts"]    = nullsNode
  result["csv.stats.unique_counts"]  = uniquesNode
  result["csv.sample.first_rows"]    = sampleNode

proc configToJson*(config: ConfigSchema): JsonNode =
  result = newJObject()
  if config.filePath.len > 0:      result["config.file.path"]                  = %config.filePath
  if config.format.len > 0:        result["config.file.format"]                = %config.format
  if config.topLevelKeys.len > 0:  result["config.structure.toplevel_keys"]    = %config.topLevelKeys
  if config.paramNames.len > 0:    result["config.settings.parameter_names"]   = %config.paramNames
  if config.envVars.len > 0:       result["config.settings.env_vars"]          = %config.envVars
  if config.dbStrings.len > 0:     result["config.database.connection_strings"] = %config.dbStrings
  if config.nestedPaths.len > 0:   result["config.structure.nested_paths"]     = %config.nestedPaths
  if config.apiEndpoints.len > 0:  result["config.api.endpoints"]              = %config.apiEndpoints
  if config.apiHosts.len > 0:      result["config.api.hosts"]                  = %config.apiHosts


# ─── Main Entry Point ─────────────────────────────────────────────────────────


proc parseShardMap*(sm: ShardMap): seq[ParseResult] =
  var results: seq[ParseResult]
  for filePath in sm.filePaths:
    var r: ParseResult
    let fmt = detectFormat(filePath)
    case fmt
    of fmMarkdown:
      r.snapType = "text"
      r.graph    = parseMarkdown(readFile(filePath), filePath)
    of fmHtml:
      r.snapType = "text"
      r.graph    = parseHtmlDoc(readFile(filePath), filePath)
    of fmDocx:
      r.snapType = "text"
      r.graph    = parseDocx(filePath)
    of fmPdf:
      r.snapType = "text"
      r.graph    = parsePdf(filePath)
    of fmCsv:
      r.snapType = "csv"
      r.csv      = parseCsv(filePath)
    of fmJson:
      r.snapType = "config"
      r.config   = parseJsonConfig(readFile(filePath), filePath, "json")
    of fmJsonl:
      r.snapType = "config"
      r.config   = parseJsonlConfig(readFile(filePath), filePath)
    of fmXml:
      let xmlContent = readFile(filePath)
      try:
        let xmlRoot = parseXml(newStringStream(xmlContent))
        case classifyXml(xmlRoot)
        of "doc":
          r.snapType = "text"
          r.graph    = parseXmlDoc(xmlContent, filePath)
        of "data":
          r.snapType = "csv"
          r.csv      = parseXmlData(xmlContent, filePath)
        else:
          r.snapType = "config"
          r.config   = parseXmlConfig(xmlContent, filePath)
      except:
        r.snapType = "config"
        r.config   = parseXmlConfig(xmlContent, filePath)
    of fmYaml:
      r.snapType = "config"
      r.config   = parseYamlConfig(readFile(filePath), filePath)
    of fmToml:
      r.snapType = "config"
      r.config   = parseTomlConfig(readFile(filePath), filePath)
    of fmPlainText:
      r.snapType = "text"
      r.graph    = parsePlainText(readFile(filePath), filePath)

    if r.snapType == "text":
      r.graph.topics   = extractTopics(r.graph)
      r.graph.entities = extractEntities(r.graph)

      results.add(r)
    return results
