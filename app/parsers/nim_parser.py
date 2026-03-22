"""Python wrapper for Nim parser."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from app.logging.logger import get_logger

logger = get_logger("parsers.nim_parser")

_BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
NIM_PARSER_BIN = _BASE / "nim_parser.exe"


def parse_with_nim(file_path: Path) -> Dict[str, Any]:
    """
    Parse file using Nim parser.

    Calls nim_parser <file_path>, reads JSON from stdout.
    Returns parsed dict with doc.*, csv.*, or config.* fields.
    """
    if not NIM_PARSER_BIN.exists():
        raise FileNotFoundError(
            f"Nim parser binary not found: {NIM_PARSER_BIN}. "
            "Compile with: nim c -d:release --opt:speed -o:app/parsers/nim_parser app/parsers/nim_parser.nim"
        )

    try:
        result = subprocess.run(
            [str(NIM_PARSER_BIN), str(file_path)],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Nim parser timed out for {file_path}") from exc

    if result.returncode != 0:
        raise RuntimeError(f"Nim parser failed for {file_path}: {result.stderr.strip()}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Nim parser returned invalid JSON for {file_path}: {exc}") from exc


def is_nim_parser_available() -> bool:
    """Check if Nim parser binary is compiled and available."""
    return NIM_PARSER_BIN.exists()
