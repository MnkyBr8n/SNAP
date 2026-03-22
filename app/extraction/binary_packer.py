"""
Binary packer/unpacker matching Nim storage format.

SnapshotHeader (561 bytes):
  - magic: array[4, char] = "SNAP"
  - version: uint16
  - snapshot_type: uint8   <- fnv1a(type_name) % 255 + 1  (stable across processes)
  - field_count: uint16
  - content_hash: array[32, uint8] (SHA-256)
  - simhash: uint64
  - minhash: array[128, uint32]

FieldDescriptor (11 bytes each):
  - field_id: uint16       <- fnv1a(field_name) % 65535 + 1  (stable across processes)
  - data_type: uint8 (0=string, 1=int, 2=bainary, 3=array)
  - offset: uint32
  - length: uint32

Data Block: variable
"""

from typing import Dict, Any, List, Tuple, Optional, Set
import struct
import re

VOWELS = frozenset('aeiouAEIOU')

# Filler words → stable token IDs. Stored as \x00<byte> inline in text.
FILLER_WORDS: Dict[str, int] = {
    # articles / determiners
    'a': 1, 'an': 2, 'the': 3, 'thee': 4,
    # conjunctions
    'and': 5, 'or': 6, 'but': 7, 'nor': 8, 'so': 9, 'yet': 10,
    # prepositions
    'of': 11, 'in': 12, 'to': 13, 'for': 14, 'on': 15, 'at': 16,
    'by': 17, 'from': 18, 'with': 19, 'as': 20, 'into': 21, 'onto': 22,
    'upon': 23, 'about': 24, 'above': 25, 'below': 26, 'between': 27,
    'through': 28, 'during': 29, 'before': 30, 'after': 31, 'over': 32,
    'under': 33, 'within': 34, 'without': 35, 'along': 36, 'across': 37,
    # pronouns
    'it': 38, 'its': 39, 'this': 40, 'that': 41, 'these': 42, 'those': 43,
    'they': 44, 'them': 45, 'their': 46, 'we': 47, 'our': 48, 'us': 49,
    'he': 50, 'she': 51, 'his': 52, 'her': 53, 'him': 54,
    'i': 55, 'me': 56, 'my': 57, 'you': 58, 'your': 59,
    # aux verbs / modal
    'is': 60, 'are': 61, 'was': 62, 'were': 63, 'be': 64, 'been': 65,
    'being': 66, 'have': 67, 'has': 68, 'had': 69, 'do': 70, 'does': 71,
    'did': 72, 'will': 73, 'would': 74, 'shall': 75, 'should': 76,
    'may': 77, 'might': 78, 'must': 79, 'can': 80, 'could': 81,
    # wh-words
    'what': 82, 'when': 83, 'where': 84, 'which': 85, 'who': 86,
    'whom': 87, 'whose': 88, 'why': 89, 'how': 90,
    # common fillers
    'not': 91, 'no': 92, 'if': 93, 'then': 94, 'than': 95, 'also': 96,
    'just': 97, 'each': 98, 'all': 99, 'any': 100, 'both': 101,
    'few': 102, 'more': 103, 'most': 104, 'some': 105, 'such': 106,
    'too': 107, 'very': 108, 'same': 109, 'other': 110, 'only': 111,
    'own': 112, 'up': 113, 'out': 114, 'off': 115, 'down': 116,
    'again': 117, 'further': 118, 'once': 119, 'here': 120, 'there': 121,
    'am': 122, 'get': 123, 'got': 124, 'let': 125,
}
_FILLER_ID_TO_WORD: Dict[int, str] = {v: k for k, v in FILLER_WORDS.items()}

# Path-like token — skip dehydration entirely
_PATH_RE = re.compile(r'[/\\]|\.[\w]{1,6}$')

# Names/Titles/Places set — populated externally via set_names()
_NAMES: Dict[str, frozenset] = {'val': frozenset()}


def set_names(names: Set[str]) -> None:
    """Inject names/titles/places dictionary (case-insensitive)."""
    _NAMES['val'] = frozenset(n.lower() for n in names)


def _dehydrate_word(word: str) -> str:
    if not word:
        return word
    if word.lower() in _NAMES['val']:
        return word                                           # Name/Title/Place — keep whole
    if _PATH_RE.search(word):
        return word                                           # file path token — keep whole
    if word[0].lower() in VOWELS:
        return word[0] + re.sub(r'[aeiouAEIOU]', '', word[1:])  # keep leading vowel only
    return re.sub(r'[aeiouAEIOU]', '', word)                 # consonant-start — strip ALL vowels


def dehydrate(text: str) -> str:
    """Dehydrate a string: remove fillers, strip vowels per rules, normalize whitespace."""
    parts = re.split(r'(\w+)', text)
    result = []
    for part in parts:
        if not part:
            continue
        lower = part.lower()
        if lower in FILLER_WORDS:
            result.append('\x00' + chr(FILLER_WORDS[lower]))  # inline filler token
        elif re.match(r'\w', part):
            result.append(_dehydrate_word(part))
        else:
            # symbols/whitespace — collapse runs of whitespace to single space
            collapsed = re.sub(r'\s+', ' ', part)
            result.append(collapsed)
    return ''.join(result)


def rehydrate(text: str) -> str:
    """Rehydrate a string: restore filler tokens. Vowel/name restoration is lossless by design."""
    def _restore(m: re.Match) -> str:
        fid = ord(m.group(1))
        word = _FILLER_ID_TO_WORD.get(fid)
        return (' ' + word + ' ') if word else m.group(0)
    return re.sub(r'\x00(.)', _restore, text)

FILE_MAGIC = b'SNAPFILE'
FILE_VERSION = 1

MAGIC = b'SNAP'
VERSION = 1
HEADER_SIZE = 561
DESCRIPTOR_SIZE = 11

TYPE_STRING = 0
TYPE_INT = 1
TYPE_BINARY = 2
TYPE_ARRAY = 3


def fnv1a(s: str) -> int:
    """FNV-1a 32-bit hash — deterministic across all Python processes."""
    h = 2166136261
    for b in s.encode():
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def type_id(snapshot_type: str) -> int:
    """Stable uint8 ID for a snapshot type name. Never 0."""
    return fnv1a(snapshot_type) % 255 + 1


def field_id(field_name: str) -> int:
    """Stable uint16 ID for a field name. Never 0."""
    return fnv1a(field_name) % 65535 + 1


def build_field_reverse_map(field_names) -> Dict[int, str]:
    """Build {field_id: field_name} reverse map for unpacking."""
    return {field_id(name): name for name in field_names}


def read_project_id_from_file(file_path: str) -> Optional[str]:
    """Read project_id from binary file header."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(8)
            if magic != FILE_MAGIC:
                return None
            version, project_id_len, _ = struct.unpack('<HHI', f.read(8))
            if version != FILE_VERSION:
                return None
            return f.read(project_id_len).decode('utf-8')
    except (OSError, struct.error, UnicodeDecodeError):
        return None


def write_file_header(file_path: str, project_id: str, content: bytes) -> None:
    """Write file with binary header containing project_id."""
    project_id_bytes = project_id.encode('utf-8')
    header = struct.pack(
        '<8sHHI',
        FILE_MAGIC,
        FILE_VERSION,
        len(project_id_bytes),
        1
    ) + project_id_bytes
    with open(file_path, 'wb') as f:
        f.write(header + content)


class BinaryPacker:
    """Pack snapshots to Nim binary format using fnv1a field IDs."""

    def pack(
        self,
        snapshot_type: int,
        field_values: Dict[str, Any],
        content_hash: bytes,
        simhash: int,
        minhash: List[int]
    ) -> bytes:
        fields = []
        data_blocks = []
        current_offset = 0

        for field_name, value in field_values.items():
            fid = field_id(field_name)
            data_type, data_bytes = self._encode_value(value)
            fields.append({'id': fid, 'type': data_type, 'offset': current_offset, 'length': len(data_bytes)})
            data_blocks.append(data_bytes)
            current_offset += len(data_bytes)

        return self._build_binary(snapshot_type, fields, b''.join(data_blocks), content_hash, simhash, minhash)

    def _encode_value(self, value: Any) -> Tuple[int, bytes]:
        if isinstance(value, str):
            return (TYPE_STRING, dehydrate(value).encode('utf-8'))
        if isinstance(value, int):
            return (TYPE_INT, struct.pack('<q', value))
        if isinstance(value, (list, tuple)):
            return self._encode_array(value)
        if isinstance(value, bytes):
            return (TYPE_BINARY, value)
        return (TYPE_STRING, str(value).encode('utf-8'))

    def _encode_array(self, arr: List[Any]) -> Tuple[int, bytes]:
        parts = [struct.pack('<I', len(arr))]
        for item in arr:
            _, item_bytes = self._encode_value(item)
            parts.append(struct.pack('<I', len(item_bytes)))
            parts.append(item_bytes)
        return (TYPE_ARRAY, b''.join(parts))

    def _build_binary(
        self,
        snapshot_type: int,
        fields: List[Dict],
        data_block: bytes,
        content_hash: bytes,
        simhash: int,
        minhash: List[int]
    ) -> bytes:
        if len(content_hash) != 32:
            content_hash = content_hash[:32].ljust(32, b'\x00')
        if len(minhash) < 128:
            minhash = minhash + [0] * (128 - len(minhash))
        minhash = minhash[:128]

        header = struct.pack(
            '<4sHBH32sQ',
            MAGIC, VERSION, snapshot_type, len(fields), content_hash, simhash
        )
        header += struct.pack('<128I', *minhash)

        descriptors = b''.join(
            struct.pack('<HBII', f['id'], f['type'], f['offset'], f['length'])
            for f in fields
        )
        return header + descriptors + data_block


class BinaryUnpacker:
    """Unpack Nim binary format to Python dict."""

    def __init__(self):
        self.field_name_map: Dict[int, str] = {}

    def set_field_map(self, field_map: Dict[int, str]):
        self.field_name_map = field_map

    def unpack(self, binary_data: bytes) -> Dict[str, Any]:
        if len(binary_data) < HEADER_SIZE:
            raise ValueError(f"Invalid binary data: expected >= {HEADER_SIZE} bytes, got {len(binary_data)}")

        magic, version, snapshot_type, field_count, content_hash, simhash = struct.unpack(
            '<4sHBH32sQ', binary_data[:49]
        )
        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        minhash = list(struct.unpack('<128I', binary_data[49:561]))

        offset = HEADER_SIZE
        fields = []
        for _ in range(field_count):
            fid, data_type, data_offset, length = struct.unpack('<HBII', binary_data[offset:offset + DESCRIPTOR_SIZE])
            fields.append({'id': fid, 'type': data_type, 'offset': data_offset, 'length': length})
            offset += DESCRIPTOR_SIZE

        data_block_start = HEADER_SIZE + (field_count * DESCRIPTOR_SIZE)
        field_values = {}
        for f in fields:
            field_name = self.field_name_map.get(f['id'])
            if field_name is None:
                continue
            data_start = data_block_start + f['offset']
            data_bytes = binary_data[data_start:data_start + f['length']]
            field_values[field_name] = self._decode_value(f['type'], data_bytes)

        return {
            'snapshot_type': snapshot_type,
            'field_values': field_values,
            'content_hash': content_hash,
            'simhash': simhash,
            'minhash': minhash,
        }

    def _decode_value(self, data_type: int, data_bytes: bytes) -> Any:
        if data_type == TYPE_STRING:
            return rehydrate(data_bytes.decode('utf-8', errors='replace'))
        if data_type == TYPE_INT:
            return struct.unpack('<q', data_bytes)[0]
        if data_type == TYPE_ARRAY:
            return self._decode_array(data_bytes)
        if data_type == TYPE_BINARY:
            return data_bytes
        return data_bytes.decode('utf-8', errors='replace')

    def _decode_array(self, data_bytes: bytes) -> List[Any]:
        if len(data_bytes) < 4:
            return []
        count = struct.unpack('<I', data_bytes[:4])[0]
        items = []
        offset = 4
        for _ in range(count):
            if offset + 4 > len(data_bytes):
                break
            item_len = struct.unpack('<I', data_bytes[offset:offset + 4])[0]
            offset += 4
            if offset + item_len > len(data_bytes):
                break
            items.append(data_bytes[offset:offset + item_len].decode('utf-8', errors='replace'))
            offset += item_len
        return items
