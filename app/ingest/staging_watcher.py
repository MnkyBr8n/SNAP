# app/ingest/staging_watcher.py
"""
Staging directory watcher for auto-ingest.

Monitors data/staging/ for new project directories, tracks size stability,
and auto-triggers processing when copying is complete.
"""

from __future__ import annotations

import time
import threading
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass

from app.config.settings import get_settings
from app.logging.logger import get_logger


logger = get_logger("ingest.staging_watcher")


@dataclass
class DirectoryState:
    """Track staging directory state for stability detection."""
    project_id: str
    path: Path
    size_bytes: int
    file_count: int
    last_check: float
    stable_checks: int  # Consecutive checks with same size
    processing: bool    # True if processing already triggered


class StagingWatcher:
    """
    Monitor staging directories and auto-trigger processing when stable.

    Flow:
    1. Detect new directories in data/staging/
    2. Track size every CHECK_INTERVAL_SECONDS
    3. When size stable for STABLE_CHECKS consecutive checks, trigger processing
    4. Processing happens in background (walk away pattern)
    """

    CHECK_INTERVAL_SECONDS = 10  # Check size every 10s
    STABLE_CHECKS_REQUIRED = 3   # 3 consecutive stable checks = 30s stable

    def __init__(self):
        self.settings = get_settings()
        self.staging_root = self.settings.data_dir / "staging"
        self.tracked: Dict[str, DirectoryState] = {}
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def _get_directory_size(self, path: Path) -> tuple[int, int]:
        """
        Get total size and file count for directory.

        Returns:
            (size_bytes, file_count)
        """
        total_size = 0
        file_count = 0

        try:
            for item in path.rglob("*"):
                if item.is_file():
                    try:
                        total_size += item.stat().st_size
                        file_count += 1
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError) as e:
            logger.warning(f"Error reading directory {path}: {e}")

        return total_size, file_count

    def _scan_staging_directories(self) -> None:
        """Scan staging root for project directories."""
        if not self.staging_root.exists():
            return

        try:
            for project_dir in self.staging_root.iterdir():
                if not project_dir.is_dir():
                    continue

                project_id = project_dir.name

                # Skip if already tracked and processing
                if project_id in self.tracked:
                    state = self.tracked[project_id]
                    if state.processing:
                        continue

                # Get current size
                size_bytes, file_count = self._get_directory_size(project_dir)

                # Skip empty directories
                if file_count == 0:
                    continue

                current_time = time.time()

                if project_id not in self.tracked:
                    # New directory detected
                    self.tracked[project_id] = DirectoryState(
                        project_id=project_id,
                        path=project_dir,
                        size_bytes=size_bytes,
                        file_count=file_count,
                        last_check=current_time,
                        stable_checks=0,
                        processing=False,
                    )
                    logger.info(f"Detected new staging directory: {project_id}", extra={
                        "project_id": project_id,
                        "size_bytes": size_bytes,
                        "file_count": file_count
                    })
                else:
                    # Update existing tracking
                    state = self.tracked[project_id]

                    # Check if size is stable
                    if size_bytes == state.size_bytes and file_count == state.file_count:
                        state.stable_checks += 1
                        logger.debug(f"Staging stable check {state.stable_checks}/{self.STABLE_CHECKS_REQUIRED}: {project_id}")
                    else:
                        # Size changed, reset stability counter
                        state.stable_checks = 0
                        state.size_bytes = size_bytes
                        state.file_count = file_count
                        logger.debug(f"Staging size changed: {project_id} ({file_count} files, {size_bytes} bytes)")

                    state.last_check = current_time

                    # Check if ready to process
                    if state.stable_checks >= self.STABLE_CHECKS_REQUIRED and not state.processing:
                        self._trigger_processing(state)

        except (OSError, PermissionError) as e:
            logger.error(f"Error scanning staging directories: {e}")

    def _trigger_processing(self, state: DirectoryState) -> None:
        """
        Trigger background processing for stable directory.

        Uses threading to process in background (walk away pattern).
        """
        state.processing = True

        logger.info(f"Staging stable - triggering auto-ingest: {state.project_id}", extra={
            "project_id": state.project_id,
            "size_bytes": state.size_bytes,
            "file_count": state.file_count,
            "stable_duration_seconds": self.STABLE_CHECKS_REQUIRED * self.CHECK_INTERVAL_SECONDS
        })

        # Process in background thread
        process_thread = threading.Thread(
            target=self._process_in_background,
            args=(state.project_id, state.path),
            daemon=True
        )
        process_thread.start()

    def _process_in_background(self, project_id: str, staging_path: Path) -> None:
        """
        Process project in background thread.

        This is the "walk away" pattern - processing happens asynchronously.
        """
        try:
            from app.main import process_project, startup

            # Ensure startup is called
            startup()

            logger.info(f"Starting background processing: {project_id}")

            # Process the project
            manifest = process_project(
                project_id=project_id,
                vendor_id="staging-watcher",
                local_path=staging_path
            )

            logger.info(f"Background processing complete: {project_id}", extra={
                "project_id": project_id,
                "manifest": manifest
            })

            # Clean up ALL file copies after successful processing
            # Database snapshots are the only source of truth - NO COPIES ANYWHERE
            from app.ingest.local_loader import delete_project_staging
            import shutil

            # Clean staging (independent try/except)
            staging_cleaned = False
            try:
                delete_project_staging(project_id)
                staging_cleaned = not (self.staging_root / project_id).exists()
                if staging_cleaned:
                    logger.info(f"Cleaned up staging: {project_id}")
                else:
                    logger.error(f"Staging directory persists after cleanup (locked files?): {project_id}")
            except Exception as e:
                logger.error(f"Failed to clean staging for {project_id}: {e}")

            # Remove from tracking only if staging was fully removed.
            # If staging still exists, keep processing=True to block re-triggering
            # until files are cleared by an operator or next process cycle.
            if staging_cleaned:
                if project_id in self.tracked:
                    del self.tracked[project_id]
            else:
                logger.warning(
                    f"Keeping {project_id} in tracking (processing=True) because staging was not fully removed. "
                    "Clear the directory manually to allow re-processing."
                )

        except Exception as e:
            logger.error(f"Background processing failed: {project_id}", extra={
                "project_id": project_id,
                "error": str(e)
            }, exc_info=True)

            # Clear all /data in-dirs on failure.
            try:
                from app.ingest.local_loader import delete_project_staging
                import shutil
                delete_project_staging(project_id)
            except Exception as cleanup_err:
                logger.error(f"Failed staging cleanup after processing failure: {project_id}: {cleanup_err}")

            try:
                repos_path = self.settings.repos_dir / project_id
                if repos_path.exists():
                    shutil.rmtree(repos_path, ignore_errors=True)
            except Exception as cleanup_err:
                logger.error(f"Failed repos cleanup after processing failure: {project_id}: {cleanup_err}")

            if project_id in self.tracked:
                self.tracked[project_id].processing = True

    def _monitor_loop(self) -> None:
        """Main monitoring loop - runs in background thread."""
        logger.info("Staging watcher started", extra={
            "check_interval_seconds": self.CHECK_INTERVAL_SECONDS,
            "stable_checks_required": self.STABLE_CHECKS_REQUIRED,
            "staging_root": str(self.staging_root)
        })

        while self.running:
            try:
                self._scan_staging_directories()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)

            # Sleep until next check
            time.sleep(self.CHECK_INTERVAL_SECONDS)

        logger.info("Staging watcher stopped")

    def start(self) -> None:
        """Start the staging watcher in a background thread."""
        if self.running:
            logger.warning("Staging watcher already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Staging watcher thread started")

    def stop(self) -> None:
        """Stop the staging watcher."""
        if not self.running:
            return

        logger.info("Stopping staging watcher...")
        self.running = False

        if self.thread:
            self.thread.join(timeout=5.0)
            self.thread = None


# Global instance
_watcher: Optional[StagingWatcher] = None


def get_watcher() -> StagingWatcher:
    """Get or create the global staging watcher instance."""
    global _watcher
    if _watcher is None:
        _watcher = StagingWatcher()
    return _watcher


def start_watcher() -> None:
    """Start the global staging watcher."""
    watcher = get_watcher()
    watcher.start()


def stop_watcher() -> None:
    """Stop the global staging watcher."""
    global _watcher
    if _watcher:
        _watcher.stop()
        _watcher = None
