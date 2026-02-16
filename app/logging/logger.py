# SNAP/app/logging/logger.py
"""
Purpose: Centralized structured logging for SNAP services.

Enhanced logging for multi-snapshot architecture:
- File categorization tags (normal, large, potential_god, rejected)
- Snapshot counts per file and per repo
- Snapshot type (one of 15 categories)  
- Parser tracking (tree_sitter, semgrep, text_extractor, csv_parser)
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from app.config.settings import get_settings


class SafeJSONEncoder(json.JSONEncoder):
    """JSON encoder that handles UUID, datetime, and circular references."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seen = set()

    def default(self, o: Any) -> Any:
        # Handle UUID
        if isinstance(o, UUID):
            return str(o)
        # Handle datetime
        if isinstance(o, datetime):
            return o.isoformat()
        # Handle Path
        if isinstance(o, Path):
            return str(o)
        # Fallback for other types
        try:
            return str(o)
        except (TypeError, ValueError):
            return f"<unserializable:{type(o).__name__}>"

    def encode(self, o: Any) -> str:
        """Override encode to catch circular references."""
        try:
            return super().encode(o)
        except ValueError as e:
            if "Circular reference" in str(e):
                # Flatten the object to avoid circular refs
                return super().encode(self._flatten(o))
            raise

    def _flatten(self, obj: Any, depth: int = 0) -> Any:
        """Flatten object to avoid circular references."""
        if depth > 5:
            return "<max_depth>"

        if isinstance(obj, dict):
            return {k: self._flatten(v, depth + 1) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._flatten(v, depth + 1) for v in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return self.default(obj)


class StructuredFormatter(logging.Formatter):
    """Custom formatter that handles structured logging with extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "name": record.name,
            "msg": record.getMessage()
        }

        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        return json.dumps(log_data, cls=SafeJSONEncoder)


class StructuredLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds structured fields to log records."""
    
    def process(self, msg, kwargs):
        extra = dict(kwargs.get('extra', {}))  # copy — prevents circular ref
        kwargs['extra'] = {'extra_fields': extra}
        return msg, kwargs


_logger_cache: Dict[str, StructuredLoggerAdapter] = {}
_settings_cache = None
_shared_warning_handler: Optional[logging.Handler] = None
_shared_debug_handler: Optional[logging.Handler] = None


def _build_stderr_handler(json_logs: bool) -> logging.Handler:
    """Build handler for stderr output (MCP compatible)."""
    handler = logging.StreamHandler(sys.stderr)

    if json_logs:
        handler.setFormatter(StructuredFormatter())
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
        )
        handler.setFormatter(formatter)

    return handler


def _build_warning_handler(log_dir: Path) -> logging.Handler:
    """Build WARNING+ handler → app.log (plain FileHandler, no rotation, VSCode-safe)."""
    global _shared_warning_handler
    if _shared_warning_handler is not None:
        return _shared_warning_handler

    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(str(log_dir / "app.log"), encoding='utf-8')
    handler.setLevel(logging.WARNING)
    handler.setFormatter(StructuredFormatter())
    _shared_warning_handler = handler
    return handler


def _build_debug_handler(log_dir: Path) -> logging.Handler:
    """Build INFO+ handler → app_debug.log (RotatingFileHandler, 5 MB × 3)."""
    global _shared_debug_handler
    if _shared_debug_handler is not None:
        return _shared_debug_handler

    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        str(log_dir / "app_debug.log"), maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8'
    )
    handler.setLevel(logging.INFO)
    handler.setFormatter(StructuredFormatter())
    _shared_debug_handler = handler
    return handler


def get_logger(name: str = "snap") -> StructuredLoggerAdapter:
    """
    Get or create logger with given name.

    Returns logger adapter with structured logging support.
    Logs to both stderr (for MCP) and file (for dashboard).
    Uses caching to avoid repeated settings lookups.
    """
    global _settings_cache

    # Return cached logger if available
    if name in _logger_cache:
        return _logger_cache[name]

    # Cache settings on first call
    if _settings_cache is None:
        _settings_cache = get_settings()

    settings = _settings_cache

    base_logger = logging.getLogger(name)
    base_logger.setLevel(settings.log_level.upper())
    base_logger.propagate = False

    if not base_logger.handlers:
        # Always log to stderr for MCP compatibility
        base_logger.addHandler(_build_stderr_handler(settings.log_json))

        # app.log — WARNING+ only, plain FileHandler, no rotation (VSCode-safe)
        # app_debug.log — INFO+, RotatingFileHandler (5 MB × 3)
        log_dir = settings.data_dir / "logs"
        base_logger.addHandler(_build_warning_handler(log_dir))
        base_logger.addHandler(_build_debug_handler(log_dir))

    adapter = StructuredLoggerAdapter(base_logger, {})
    _logger_cache[name] = adapter
    return adapter


def log_file_parsed(
    logger: StructuredLoggerAdapter,
    path: str,
    tag: str,
    size: int,
    language: str,
    project_id: str,
    parse_duration_ms: float,
    snapshots_created: int,
    snapshot_types: list,
    snapshot_ids: list,
    parsers: list
) -> None:
    """Standard log format for file parsing events."""
    logger.debug("File parsed", extra={
        "path": path,
        "file": path.split('/')[-1],
        "tag": tag,
        "size": size,
        "language": language,
        "project_id": project_id,
        "parse_duration_ms": parse_duration_ms,
        "snapshots_created": snapshots_created,
        "snapshot_types": snapshot_types,
        "snapshot_ids": snapshot_ids,
        "parsers": parsers
    })


def log_snapshot_created(
    logger: StructuredLoggerAdapter,
    snapshot_id: str,
    project_id: str,
    file_path: str,
    snapshot_type: str,
    parser: str,
    fields_count: int
) -> None:
    """Standard log format for snapshot creation events."""
    logger.info("Snapshot created", extra={
        "snapshot_id": snapshot_id,
        "project_id": project_id,
        "file_path": file_path,
        "snapshot_type": snapshot_type,
        "parser": parser,
        "fields_count": fields_count
    })


def log_repo_complete(
    logger: StructuredLoggerAdapter,
    project_id: str,
    files_processed: int,
    files_attempted: int,
    snapshots_created: int,
    snapshots_attempted: int,
    snapshots_failed: int,
    snapshots_rejected: int,
    snapshot_types_summary: Dict[str, int],
    parsers_summary: Dict[str, int],
    total_duration_ms: float
) -> None:
    """Standard log format for repo processing completion."""
    logger.info("Repo processing complete", extra={
        "project_id": project_id,
        "files_attempted": files_attempted,
        "files_processed": files_processed,
        "files_failed": files_attempted - files_processed,
        "snapshots_attempted": snapshots_attempted,
        "snapshots_created": snapshots_created,
        "snapshots_failed": snapshots_failed,
        "snapshots_rejected": snapshots_rejected,
        "snapshot_types_summary": snapshot_types_summary,
        "parsers_summary": parsers_summary,
        "total_duration_ms": total_duration_ms
    })


def log_file_categorization(
    logger: StructuredLoggerAdapter,
    path: str,
    size: int,
    tag: str,
    reason: Optional[str] = None
) -> None:
    """Log file size categorization."""
    level = logging.INFO
    if tag == "large":
        level = logging.WARNING
    elif tag == "potential_god":
        level = logging.WARNING
    elif tag == "rejected":
        level = logging.ERROR
    
    logger.log(level, f"File categorized: {tag}", extra={
        "path": path,
        "size": size,
        "tag": tag,
        "reason": reason
    })
