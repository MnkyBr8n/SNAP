"""Python wrapper for Nim parser."""

import subprocess
from pathlib import Path
from typing import Optional

from app.logging.logger import get_logger

logger = get_logger("parsers.nim_parser")

NIM_PARSER_BIN = Path(__file__).parent / "nim_parser.exe"


def parse_with_nim(
    file_path: Path,
    project_id: str,
    output_path: Optional[Path] = None
) -> Path:
    """
    Parse file using Nim parser and output binary snapshot.

    Args:
        file_path: Input file to parse
        project_id: Project ID for binary header
        output_path: Output path (defaults to input_path.snap)

    Returns:
        Path to output binary file
    """
    if not NIM_PARSER_BIN.exists():
        raise FileNotFoundError(
            f"Nim parser not compiled. Run: nimble build -d:release"
        )

    if output_path is None:
        output_path = file_path.with_suffix(file_path.suffix + ".snap")

    try:
        result = subprocess.run(
            [str(NIM_PARSER_BIN), str(file_path), project_id, str(output_path)],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )

        logger.info(f"Nim parser output: {result.stdout}")

        if not output_path.exists():
            raise RuntimeError(f"Nim parser failed to create output: {output_path}")

        return output_path

    except subprocess.CalledProcessError as e:
        logger.error(f"Nim parser failed: {e.stderr}")
        raise RuntimeError(f"Nim parser error: {e.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("Nim parser timed out")
        raise RuntimeError("Nim parser timed out after 60s")


def is_nim_parser_available() -> bool:
    """Check if Nim parser is compiled and available."""
    return NIM_PARSER_BIN.exists()
