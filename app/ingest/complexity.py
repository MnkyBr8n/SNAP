"""
Language-agnostic complexity estimation using entropy and byte-level analysis.
Routes complex files to single-file processing, simple files to batch processing.
"""

import math
import zlib
from pathlib import Path
from typing import Dict, Any
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0-8, higher = more random/complex)."""
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def estimate_complexity(file_path: Path) -> Dict[str, Any]:
    """
    Entropy-based complexity estimation (language-agnostic).

    Detects:
    - High entropy (complex logic, obfuscated code)
    - Low compression ratio (hard to compress = complex)
    - Minified code (long lines, no whitespace)
    - Generated code patterns

    Returns:
        Dict with complexity metrics and routing decision
    """
    try:
        content_bytes = file_path.read_bytes()
        file_size = len(content_bytes)

        if file_size == 0:
            return {'score': 0, 'is_complex': False, 'route': 'batch', 'metrics': {}}

        # Shannon entropy (0-8)
        entropy = calculate_entropy(content_bytes)

        # Compression ratio (low = hard to compress = complex)
        compressed_size = len(zlib.compress(content_bytes, level=1))
        compression_ratio = compressed_size / file_size

        # Line analysis
        newline_count = content_bytes.count(b'\n')
        avg_line_length = file_size / max(newline_count, 1)

        # Whitespace ratio (low = minified/dense code)
        whitespace_count = (
            content_bytes.count(b' ') +
            content_bytes.count(b'\t') +
            content_bytes.count(b'\n')
        )
        whitespace_ratio = whitespace_count / file_size

        # Complexity score (0-100+)
        score = (
            (entropy * 10) +
            (compression_ratio * 50) +
            (avg_line_length / 10) +
            ((1 - whitespace_ratio) * 30)
        )

        # Thresholds
        HIGH_ENTROPY = 6.0
        HIGH_COMPRESSION = 0.7
        LONG_LINES = 150
        LOW_WHITESPACE = 0.20

        is_complex = (
            entropy > HIGH_ENTROPY or
            compression_ratio > HIGH_COMPRESSION or
            avg_line_length > LONG_LINES or
            whitespace_ratio < LOW_WHITESPACE
        )

        return {
            'score': score,
            'is_complex': is_complex,
            'metrics': {
                'entropy': round(entropy, 2),
                'compression_ratio': round(compression_ratio, 3),
                'avg_line_length': round(avg_line_length, 1),
                'whitespace_ratio': round(whitespace_ratio, 3),
                'file_size': file_size
            },
            'route': 'single' if is_complex else 'batch'
        }

    except Exception as e:
        return {
            'score': 0,
            'is_complex': False,
            'metrics': {},
            'route': 'batch',
            'error': str(e)
        }
