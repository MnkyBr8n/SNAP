# app/ingest/file_router.py
"""
Routes ingested files to appropriate parsers based on file type.

- Code files (.py, .ts, .js, etc.) → tree_sitter + semgrep
- Doc / data / config files        → nim_parser
- Unknown files                    → skipped
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from dataclasses import dataclass

from app.logging.logger import get_logger

logger = get_logger("ingest.router")


class FileRoutingError(Exception):
    pass


@dataclass
class FileRoute:
    """Route decision for a single file."""
    path:       Path
    parsers:    List[str]  # "tree_sitter", "semgrep", "nim_parser"
    field_type: str       
    language:   str        # file extension without dot


CODE_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx",
    ".java", ".go", ".rs", ".cpp", ".c",
    ".cs", ".rb", ".php", ".swift", ".kt", ".scala", ".nim",
}

DOC_EXTENSIONS = {".pdf", ".txt", ".md", ".docx", ".html", ".htm", ".rtf"}
CSV_EXTENSIONS = {".csv", ".tsv", ".jsonl"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".xml", ".toml"}  


def route_file(path: Path) -> FileRoute | None:
    suffix = path.suffix.lower()

    if suffix in CODE_EXTENSIONS:
        return FileRoute(
            path=path,
            parsers=["tree_sitter", "semgrep"],
            field_type="code",
            language=suffix.lstrip("."),
        )

    if suffix in DOC_EXTENSIONS:
        return FileRoute(path=path, parsers=["nim_parser"], field_type="doc", language=suffix.lstrip("."))

    if suffix in CSV_EXTENSIONS:
        return FileRoute(path=path, parsers=["nim_parser"], field_type="csv", language=suffix.lstrip("."))

    if suffix in CONFIG_EXTENSIONS:
        return FileRoute(path=path, parsers=["nim_parser"], field_type="config", language=suffix.lstrip("."))


    logger.debug(f"No parser for file type: {path}")
    return None


def route_files(files: List[Path]) -> List[FileRoute]:
    routes = []
    skipped = 0

    for path in files:
        route = route_file(path)
        if route:
            routes.append(route)
        else:
            skipped += 1

    parser_counts: dict = {}
    for route in routes:
        for parser in route.parsers:
            parser_counts[parser] = parser_counts.get(parser, 0) + 1

    logger.info("File routing complete", extra={
        "total_files": len(files),
        "routed_files": len(routes),
        "skipped_files": skipped,
        "parser_assignments": parser_counts,
    })

    return routes
