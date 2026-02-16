# SNAP/app/security/snap_limits.py
"""
Purpose: Enforce SNAP size, file, and runtime limits defined in config settings.

Enhanced with:
- LOC thresholds for file categorization (normal/large/potential_god/rejected)
- Parser timeout enforcement (tree_sitter, semgrep)
- CSV-specific limits (file size, rows, cells)
- Snapshot limits per file
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable, Literal

from app.config.settings import get_settings
from app.logging.logger import get_logger

logger = get_logger("security.snap_limits")


class SnapLimitError(Exception):
    pass


FileCategoryType = Literal["normal", "large", "potential_god", "rejected"]


class SnapLimitsEnforcer:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.limits = self.settings.limits
        self.parser_limits = self.settings.parser_limits
        self._project_start_ts = time.time()

    # ---------- Runtime enforcement ----------

    def check_job_time(self, job_start_ts: float) -> None:
        elapsed = time.time() - job_start_ts
        if elapsed > self.limits.max_job_seconds:
            raise SnapLimitError(
                f"Job runtime exceeded {self.limits.max_job_seconds} seconds"
            )

    def check_project_time(self) -> None:
        elapsed = time.time() - self._project_start_ts
        if elapsed > self.limits.max_project_run_seconds:
            raise SnapLimitError(
                f"Project runtime exceeded {self.limits.max_project_run_seconds} seconds"
            )

    # ---------- File and repo enforcement ----------

    def check_file_size(self, path: Path) -> None:
        size = path.stat().st_size

        suffix = path.suffix.lower()
        if suffix == ".pdf" and size > self.limits.max_pdf_bytes:
            raise SnapLimitError("PDF file exceeds size limit")

        if suffix in {".txt", ".json", ".yaml", ".yml", ".csv"} and size > self.limits.max_text_bytes:
            raise SnapLimitError("Text file exceeds size limit")

        if size > self.limits.max_code_file_bytes:
            raise SnapLimitError("Code file exceeds size limit")

    def check_repo_bounds(self, files: Iterable[Path], repo_root: Path) -> None:
        total_bytes = 0
        file_count = 0

        for path in files:
            file_count += 1
            total_bytes += path.stat().st_size

            depth = len(path.relative_to(repo_root).parts)
            if depth > self.limits.max_repo_depth:
                raise SnapLimitError("Repository directory depth exceeded")

            if file_count > self.limits.max_repo_files:
                raise SnapLimitError("Repository file count exceeded")

            if total_bytes > self.limits.max_repo_bytes:
                raise SnapLimitError("Repository total size exceeded")

    # ---------- LOC enforcement (file categorization) ----------

    def check_code_file_loc(self, loc: int, path: Path) -> FileCategoryType:
        """
        Categorize code file by LOC and enforce hard cap.
        
        Args:
            loc: Lines of code count
            path: File path (for logging)
        
        Returns:
            'normal', 'large', 'potential_god'
        
        Raises:
            SnapLimitError: If file exceeds hard cap (rejected)
        """
        if loc >= self.parser_limits.hard_cap_loc:
            logger.error(f"File rejected: {path} ({loc} LOC >= {self.parser_limits.hard_cap_loc} LOC hard cap)")
            raise SnapLimitError(
                f"File exceeds hard cap: {loc} LOC >= {self.parser_limits.hard_cap_loc} LOC"
            )
        
        if loc >= self.parser_limits.potential_god_loc:
            logger.warning(f"Potential god file: {path} ({loc} LOC)")
            return "potential_god"
        
        if loc >= self.parser_limits.soft_cap_loc:
            logger.warning(f"Large file: {path} ({loc} LOC, refactor recommended)")
            return "large"
        
        return "normal"

    # ---------- Parser timeout enforcement ----------

    def check_parser_timeout(self, parser_name: str, duration_ms: float) -> None:
        """
        Check if parser exceeded timeout.
        
        Args:
            parser_name: 'tree_sitter', 'semgrep', etc.
            duration_ms: Parse duration in milliseconds
        
        Raises:
            SnapLimitError: If parser exceeded timeout
        """
        timeout_map = {
            "tree_sitter": self.parser_limits.tree_sitter_timeout_initial,
            "semgrep": self.parser_limits.semgrep_timeout_per_file * 1000,  # Convert to ms
        }
        
        timeout_ms = timeout_map.get(parser_name)
        if timeout_ms is None:
            logger.warning(f"No timeout configured for parser: {parser_name}")
            return
        
        if duration_ms > timeout_ms:
            raise SnapLimitError(
                f"Parser {parser_name} exceeded timeout: {duration_ms}ms > {timeout_ms}ms"
            )

    # ---------- CSV enforcement ----------

    def check_csv_limits(
        self,
        file_size_mb: float,
        row_count: int,
        path: Path
    ) -> None:
        """
        Check CSV-specific limits.
        
        Args:
            file_size_mb: File size in megabytes
            row_count: Number of rows
            path: File path (for logging)
        
        Raises:
            SnapLimitError: If CSV exceeds limits
        """
        # Hard caps
        if file_size_mb > self.parser_limits.csv_hard_cap_file_size_mb:
            raise SnapLimitError(
                f"CSV file exceeds hard cap: {file_size_mb:.2f} MB > {self.parser_limits.csv_hard_cap_file_size_mb} MB"
            )
        
        if row_count > self.parser_limits.csv_hard_cap_rows:
            raise SnapLimitError(
                f"CSV rows exceed hard cap: {row_count} > {self.parser_limits.csv_hard_cap_rows}"
            )
        
        # Soft caps (warnings)
        if file_size_mb > self.parser_limits.csv_soft_cap_file_size_mb:
            logger.warning(f"CSV file exceeds soft cap: {path} ({file_size_mb:.2f} MB)")
        
        if row_count > self.parser_limits.csv_soft_cap_rows:
            logger.warning(f"CSV rows exceed soft cap: {path} ({row_count} rows)")

    def check_csv_cell_size(self, cell_length: int, row_num: int, path: Path) -> None:
        """
        Check individual CSV cell size.
        
        Args:
            cell_length: Length of cell content
            row_num: Row number (for logging)
            path: File path (for logging)
        
        Raises:
            SnapLimitError: If cell exceeds limit
        """
        if cell_length > self.parser_limits.csv_hard_cap_cell_chars:
            logger.warning(
                f"CSV cell truncated: {path} row {row_num} "
                f"({cell_length} chars > {self.parser_limits.csv_hard_cap_cell_chars} chars)"
            )

    # ---------- Snapshot enforcement ----------

    def check_snapshot_size(self, snapshot_bytes: int) -> None:
        if snapshot_bytes > self.limits.snapshot_notebook_cap_bytes:
            raise SnapLimitError("Snapshot notebook size cap exceeded")

    def check_snapshot_count_per_file(self, snapshot_count: int) -> None:
        """
        Check number of snapshots per file.
        
        Args:
            snapshot_count: Number of snapshots created for file
        
        Raises:
            SnapLimitError: If exceeds max (12)
        """
        max_snapshots = 12  # Max snapshot categories
        
        if snapshot_count > max_snapshots:
            raise SnapLimitError(
                f"Too many snapshots per file: {snapshot_count} > {max_snapshots}"
            )
