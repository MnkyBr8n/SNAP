"""
Binary packer/unpacker matching Nim storage format.

SnapshotHeader (559 bytes):
  - magic: array[4, char] = "SNAP"
  - version: uint16
  - snapshot_type: uint8
  - field_count: uint16
  - content_hash: array[32, uint8] (SHA-256)
  - simhash: uint64
  - minhash: array[128, uint32]

FieldDescriptor (11 bytes each):
  - field_id: uint16
  - data_type: uint8 (0=string, 1=int, 2=binary, 3=array)
  - offset: uint32
  - length: uint32

Data Block: variable
"""

from typing import Dict, Any, List, Tuple, Optional
import struct
import hashlib

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


def read_project_id_from_file(file_path: str) -> Optional[str]:
    """Read project_id from binary file header."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(8)
            if magic != FILE_MAGIC:
                return None

            version, project_id_len, snapshot_count = struct.unpack('<HHI', f.read(8))
            if version != FILE_VERSION:
                return None

            project_id_bytes = f.read(project_id_len)
            return project_id_bytes.decode('utf-8')
    except Exception:
        return None


def write_file_header(file_path: str, project_id: str, content: bytes) -> None:
    """Write file with binary header containing project_id."""
    project_id_bytes = project_id.encode('utf-8')
    project_id_len = len(project_id_bytes)

    header = struct.pack(
        '<8sHHI',
        FILE_MAGIC,           # magic: 8 bytes
        FILE_VERSION,         # version: uint16
        project_id_len,       # project_id_len: uint16
        1                     # snapshot_count: uint32
    )
    header += project_id_bytes

    with open(file_path, 'wb') as f:
        f.write(header + content)


class BinaryPacker:
    """Pack snapshots to Nim binary format."""

    def __init__(self):
        self.field_id_map: Dict[str, int] = {}

    def set_field_map(self, field_map: Dict[str, int]):
        self.field_id_map = field_map

    def pack(
        self,
        snapshot_type: int,
        field_values: Dict[str, Any],
        content_hash: bytes,
        simhash: int,
        minhash: List[int]
    ) -> bytes:
        """
        Pack snapshot to Nim binary format.

        Args:
            snapshot_type: Snapshot type code (uint8)
            field_values: Field name -> value dict
            content_hash: 32-byte SHA-256 hash
            simhash: 64-bit similarity hash
            minhash: List of 128 x 32-bit MinHash values

        Returns:
            Binary packed data
        """
        fields = []
        data_blocks = []
        current_offset = 0

        for field_name, value in field_values.items():
            field_id = self.field_id_map.get(field_name)
            if field_id is None:
                continue

            data_type, data_bytes = self._encode_value(value)

            fields.append({
                'id': field_id,
                'type': data_type,
                'offset': current_offset,
                'length': len(data_bytes)
            })

            data_blocks.append(data_bytes)
            current_offset += len(data_bytes)

        return self._build_binary(
            snapshot_type,
            fields,
            b''.join(data_blocks),
            content_hash,
            simhash,
            minhash
        )

    def _encode_value(self, value: Any) -> Tuple[int, bytes]:
        """Encode value to (type_code, bytes)."""
        if isinstance(value, str):
            return (TYPE_STRING, value.encode('utf-8'))
        elif isinstance(value, int):
            return (TYPE_INT, struct.pack('<q', value))
        elif isinstance(value, (list, tuple)):
            return self._encode_array(value)
        elif isinstance(value, bytes):
            return (TYPE_BINARY, value)
        else:
            return (TYPE_STRING, str(value).encode('utf-8'))

    def _encode_array(self, arr: List[Any]) -> Tuple[int, bytes]:
        """Encode array: [count:4][len1:4][data1][len2:4][data2]..."""
        parts = [struct.pack('<I', len(arr))]

        for item in arr:
            item_type, item_bytes = self._encode_value(item)
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
        """Build Nim binary format."""
        field_count = len(fields)

        # Ensure content_hash is 32 bytes
        if len(content_hash) != 32:
            content_hash = content_hash[:32].ljust(32, b'\x00')

        # Ensure minhash is 128 values
        if len(minhash) < 128:
            minhash = minhash + [0] * (128 - len(minhash))
        minhash = minhash[:128]

        # SnapshotHeader (559 bytes)
        header = struct.pack(
            '<4sHBH32sQ',
            MAGIC,           # magic: 4 bytes
            VERSION,         # version: uint16
            snapshot_type,   # snapshot_type: uint8
            field_count,     # field_count: uint16
            content_hash,    # content_hash: 32 bytes
            simhash          # simhash: uint64
        )
        # minhash: 128 x uint32 = 512 bytes
        minhash_bytes = struct.pack('<128I', *minhash)
        header += minhash_bytes

        # Field descriptors (11 bytes each)
        descriptors = []
        for field in fields:
            desc = struct.pack(
                '<HBI I',
                field['id'],      # field_id: uint16
                field['type'],    # data_type: uint8
                field['offset'],  # offset: uint32
                field['length']   # length: uint32
            )
            descriptors.append(desc)

        return header + b''.join(descriptors) + data_block


class BinaryUnpacker:
    """Unpack Nim binary format to Python dict."""

    def __init__(self):
        self.field_name_map: Dict[int, str] = {}

    def set_field_map(self, field_map: Dict[int, str]):
        self.field_name_map = field_map

    def unpack(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Unpack Nim binary to snapshot dict.

        Returns:
            {
                'snapshot_type': int,
                'field_values': {field_name: value},
                'content_hash': bytes,
                'simhash': int,
                'minhash': List[int]
            }
        """
        if len(binary_data) < HEADER_SIZE:
            raise ValueError(f"Invalid binary data: expected >= {HEADER_SIZE} bytes, got {len(binary_data)}")

        # Parse SnapshotHeader
        magic, version, snapshot_type, field_count, content_hash, simhash = struct.unpack(
            '<4sHBH32sQ',
            binary_data[:49]
        )

        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        # Parse minhash (128 x uint32)
        minhash = list(struct.unpack('<128I', binary_data[49:561]))

        # Parse field descriptors
        offset = HEADER_SIZE
        fields = []
        for _ in range(field_count):
            field_id, data_type, data_offset, length = struct.unpack(
                '<HBII',
                binary_data[offset:offset + DESCRIPTOR_SIZE]
            )
            fields.append({
                'id': field_id,
                'type': data_type,
                'offset': data_offset,
                'length': length
            })
            offset += DESCRIPTOR_SIZE

        # Data block starts after descriptors
        data_block_start = HEADER_SIZE + (field_count * DESCRIPTOR_SIZE)

        # Decode fields
        field_values = {}
        for field in fields:
            field_name = self.field_name_map.get(field['id'])
            if field_name is None:
                continue

            data_start = data_block_start + field['offset']
            data_end = data_start + field['length']
            data_bytes = binary_data[data_start:data_end]

            value = self._decode_value(field['type'], data_bytes)
            field_values[field_name] = value

        return {
            'snapshot_type': snapshot_type,
            'field_values': field_values,
            'content_hash': content_hash,
            'simhash': simhash,
            'minhash': minhash
        }

    def _decode_value(self, data_type: int, data_bytes: bytes) -> Any:
        """Decode value from bytes."""
        if data_type == TYPE_STRING:
            return data_bytes.decode('utf-8', errors='replace')
        elif data_type == TYPE_INT:
            return struct.unpack('<q', data_bytes)[0]
        elif data_type == TYPE_ARRAY:
            return self._decode_array(data_bytes)
        elif data_type == TYPE_BINARY:
            return data_bytes
        else:
            return data_bytes.decode('utf-8', errors='replace')

    def _decode_array(self, data_bytes: bytes) -> List[Any]:
        """Decode array from bytes."""
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

            item_bytes = data_bytes[offset:offset + item_len]
            offset += item_len

            items.append(item_bytes.decode('utf-8', errors='replace'))

        return items
