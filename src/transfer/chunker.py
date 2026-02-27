import hashlib
import os
from dataclasses import dataclass

CHUNK_SIZE = 512 * 1024  # 512 KB per chunk


@dataclass
class ChunkInfo:
    index: int
    hash: str  # SHA-256 of chunk
    size: int


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def split_file(filepath: str) -> tuple:
    """
    Split a file into CHUNK_SIZE pieces.
    Returns (manifest_dict, {index: bytes}).
    """
    chunks_data = {}
    chunks_info = []
    file_hash = hashlib.sha256()

    with open(filepath, 'rb') as f:
        idx = 0
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            file_hash.update(data)
            chunk_hash = hash_bytes(data)
            chunks_data[idx] = data
            chunks_info.append(ChunkInfo(idx, chunk_hash, len(data)))
            idx += 1

    manifest = {
        'file_id': file_hash.hexdigest(),
        'filename': os.path.basename(filepath),
        'size': os.path.getsize(filepath),
        'chunk_size': CHUNK_SIZE,
        'nb_chunks': len(chunks_info),
        'chunks': [{'index': c.index, 'hash': c.hash, 'size': c.size} for c in chunks_info],
    }
    return manifest, chunks_data


def reassemble(chunks_data: dict, nb_chunks: int, output_path: str):
    """Reassemble chunks in order and write final file, then return SHA-256."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        for i in range(nb_chunks):
            f.write(chunks_data[i])

    with open(output_path, 'rb') as f:
        return hash_bytes(f.read())


def verify_chunk(data: bytes, expected_hash: str) -> bool:
    """Return False if chunk integrity check fails."""
    return hash_bytes(data) == expected_hash
