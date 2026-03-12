# nim_parser.nim
# High-performance document parser outputting SNAP binary format

import std/[os, strutils, json, tables, sequtils, unicode]

const
  FILE_MAGIC = "SNAPFILE"
  FILE_VERSION: uint16 = 1
  SNAP_MAGIC = "SNAP"
  SNAP_VERSION: uint16 = 1
  HEADER_SIZE = 559

  TYPE_STRING: uint8 = 0
  TYPE_INT: uint8 = 1
  TYPE_BINARY: uint8 = 2
  TYPE_ARRAY: uint8 = 3

type
  SnapshotType = enum
    DocMetadata = 0
    DocContent = 1
    DocAnalysis = 2

proc extractMarkdown(content: string): Table[string, JsonNode] =
  result = initTable[string, JsonNode]()

  # Extract title (first # heading)
  var title = ""
  for line in content.splitLines():
    if line.startsWith("# "):
      title = line[2..^1].strip()
      break

  # Extract key concepts (words in **bold** or __italic__)
  var concepts: seq[string] = @[]
  var i = 0
  while i < content.len:
    if i + 1 < content.len and content[i..i+1] == "**":
      var j = i + 2
      while j + 1 < content.len and content[j..j+1] != "**":
        j += 1
      if j + 1 < content.len:
        concepts.add(content[i+2..j-1])
        i = j + 2
    else:
      i += 1

  # Extract URLs
  var urls: seq[string] = @[]
  for match in content.findAll(re"https?://[^\s\)]+"):
    urls.add(match)

  result["doc.title"] = %title
  result["doc.content"] = %content
  result["doc.key_concepts"] = %concepts
  result["doc.urls"] = %urls
  result["doc.word_count"] = %(content.split().len)

proc extractText(content: string): Table[string, JsonNode] =
  result = initTable[string, JsonNode]()
  let lines = content.splitLines()

  result["doc.content"] = %content
  result["doc.line_count"] = %(lines.len)
  result["doc.word_count"] = %(content.split().len)
  result["doc.char_count"] = %(content.len)

proc extractCSV(content: string): Table[string, JsonNode] =
  result = initTable[string, JsonNode]()
  let lines = content.splitLines()

  if lines.len > 0:
    let headers = lines[0].split(',')
    result["csv.headers"] = %headers
    result["csv.row_count"] = %(lines.len - 1)
    result["csv.column_count"] = %(headers.len)

  result["doc.content"] = %content

proc encodeValue(val: JsonNode): (uint8, seq[byte]) =
  case val.kind
  of JString:
    let s = val.getStr()
    result = (TYPE_STRING, cast[seq[byte]](s))
  of JInt:
    let i = val.getInt()
    var bytes: seq[byte] = @[]
    for j in 0..7:
      bytes.add(byte((i shr (j * 8)) and 0xFF))
    result = (TYPE_INT, bytes)
  of JArray:
    var parts: seq[byte] = @[]
    let count = uint32(val.len)
    # Add count (4 bytes)
    for j in 0..3:
      parts.add(byte((count shr (j * 8)) and 0xFF))
    # Add each item
    for item in val:
      let s = item.getStr()
      let itemBytes = cast[seq[byte]](s)
      let itemLen = uint32(itemBytes.len)
      # Add length (4 bytes)
      for j in 0..3:
        parts.add(byte((itemLen shr (j * 8)) and 0xFF))
      # Add data
      parts.add(itemBytes)
    result = (TYPE_ARRAY, parts)
  else:
    result = (TYPE_STRING, cast[seq[byte]]($val))

proc packSnapshot(
  projectId: string,
  snapshotType: SnapshotType,
  fields: Table[string, JsonNode],
  fieldIdMap: Table[string, uint16]
): seq[byte] =
  var output: seq[byte] = @[]

  # File header
  output.add(cast[seq[byte]](FILE_MAGIC))
  # Version (2 bytes)
  output.add(byte(FILE_VERSION and 0xFF))
  output.add(byte((FILE_VERSION shr 8) and 0xFF))
  # Project ID length (2 bytes)
  let pidLen = uint16(projectId.len)
  output.add(byte(pidLen and 0xFF))
  output.add(byte((pidLen shr 8) and 0xFF))
  # Snapshot count (4 bytes) = 1
  output.add([byte(1), byte(0), byte(0), byte(0)])
  # Project ID
  output.add(cast[seq[byte]](projectId))

  # Snapshot header
  output.add(cast[seq[byte]](SNAP_MAGIC))
  # Version
  output.add(byte(SNAP_VERSION and 0xFF))
  output.add(byte((SNAP_VERSION shr 8) and 0xFF))
  # Snapshot type
  output.add(byte(snapshotType))
  # Field count
  let fieldCount = uint16(fields.len)
  output.add(byte(fieldCount and 0xFF))
  output.add(byte((fieldCount shr 8) and 0xFF))
  # Content hash (32 bytes of zeros for now)
  for i in 0..31:
    output.add(byte(0))
  # SimHash (8 bytes of zeros)
  for i in 0..7:
    output.add(byte(0))
  # MinHash (128 * 4 = 512 bytes of zeros)
  for i in 0..511:
    output.add(byte(0))

  # Build field descriptors and data
  var descriptors: seq[byte] = @[]
  var dataBlock: seq[byte] = @[]
  var offset: uint32 = 0

  for fieldName, value in fields:
    let fieldId = fieldIdMap.getOrDefault(fieldName, uint16(0))
    if fieldId == 0:
      continue

    let (dataType, dataBytes) = encodeValue(value)
    let length = uint32(dataBytes.len)

    # Field descriptor (11 bytes)
    # Field ID (2 bytes)
    descriptors.add(byte(fieldId and 0xFF))
    descriptors.add(byte((fieldId shr 8) and 0xFF))
    # Data type (1 byte)
    descriptors.add(dataType)
    # Offset (4 bytes)
    for j in 0..3:
      descriptors.add(byte((offset shr (j * 8)) and 0xFF))
    # Length (4 bytes)
    for j in 0..3:
      descriptors.add(byte((length shr (j * 8)) and 0xFF))

    # Add to data block
    dataBlock.add(dataBytes)
    offset += length

  output.add(descriptors)
  output.add(dataBlock)

  result = output

proc parseFile(filePath: string, projectId: string, outputPath: string) =
  if not fileExists(filePath):
    quit("File not found: " & filePath, 1)

  let content = readFile(filePath)
  let ext = splitFile(filePath).ext.toLowerAscii()

  # Determine parser and extract fields
  var fields: Table[string, JsonNode]
  var snapshotType: SnapshotType

  case ext
  of ".md", ".markdown":
    fields = extractMarkdown(content)
    snapshotType = DocContent
  of ".csv":
    fields = extractCSV(content)
    snapshotType = DocContent
  else:
    fields = extractText(content)
    snapshotType = DocContent

  # Simple field ID mapping (in production, load from YAML)
  var fieldIdMap = initTable[string, uint16]()
  fieldIdMap["doc.title"] = 1
  fieldIdMap["doc.content"] = 2
  fieldIdMap["doc.key_concepts"] = 3
  fieldIdMap["doc.urls"] = 4
  fieldIdMap["doc.word_count"] = 5
  fieldIdMap["doc.line_count"] = 6
  fieldIdMap["doc.char_count"] = 7
  fieldIdMap["csv.headers"] = 8
  fieldIdMap["csv.row_count"] = 9
  fieldIdMap["csv.column_count"] = 10

  # Pack to binary
  let binaryData = packSnapshot(projectId, snapshotType, fields, fieldIdMap)

  # Write output
  writeFile(outputPath, cast[string](binaryData))
  echo "Parsed ", filePath, " -> ", outputPath, " (", binaryData.len, " bytes)"

when isMainModule:
  if paramCount() < 3:
    echo "Usage: nim_parser <input_file> <project_id> <output_file>"
    quit(1)

  let inputFile = paramStr(1)
  let projectId = paramStr(2)
  let outputFile = paramStr(3)

  parseFile(inputFile, projectId, outputFile)
