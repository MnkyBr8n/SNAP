# app/ingest/repos_watcher.py
"""
Repos directory watcher for auto-ingest of cloned GitHub repositories.

Monitors data/repos/ for project directories containing a .snap_ready marker,
then triggers ingest via main.ingest_cloned_repo() and cleans repos/ after.

Flow:
1. clone_github_repo() clones repo → writes .snap_ready marker
2. ReposWatcher detects .snap_ready → triggers ingest_cloned_repo() in background
3. ingest_cloned_repo() runs pipeline → _run_ingest_pipeline() cleans repos/ on completion
"""

from __future__ import annotations

import time
import threading
from pathlib import Path
from typing import Dict, Optional

from app.config.settings import get_settings
from app.logging.logger import get_logger


logger = get_logger("ingest.repos_watcher")

READY_MARKER = ".snap_ready"


class ReposWatcher:
    """
    Monitor repos/ for .snap_ready markers and auto-trigger ingest.

    GitHub clones are atomic — no stability detection needed.
    The .snap_ready marker written by clone_github_repo() is the trigger.
    """

    CHECK_INTERVAL_SECONDS = 5

    def __init__(self):
        self.settings = get_settings()
        self.repos_root = self.settings.repos_dir
        self.tracked: Dict[str, bool] = {}  # project_id -> processing
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def _scan_repos_directories(self) -> None:
        """Scan repos root for project directories containing .snap_ready."""
        if not self.repos_root.exists():
            return

        try:
            for project_dir in self.repos_root.iterdir():
                if not project_dir.is_dir():
                    continue

                project_id = project_dir.name

                # Skip if already processing
                if self.tracked.get(project_id):
                    continue

                # Only trigger on .snap_ready marker
                marker = project_dir / READY_MARKER
                if not marker.exists():
                    continue

                logger.info(f"Detected .snap_ready marker: {project_id}", extra={
                    "project_id": project_id,
                    "marker": str(marker),
                })

                self.tracked[project_id] = True
                self._trigger_ingest(project_id, project_dir)

        except (OSError, PermissionError) as e:
            logger.error(f"Error scanning repos directories: {e}")

    def _trigger_ingest(self, project_id: str, project_dir: Path) -> None:
        """Trigger background ingest for a cloned repo."""
        logger.info(f"Triggering auto-ingest for cloned repo: {project_id}", extra={
            "project_id": project_id,
        })

        ingest_thread = threading.Thread(
            target=self._ingest_in_background,
            args=(project_id,),
            daemon=True,
        )
        ingest_thread.start()

    def _ingest_in_background(self, project_id: str) -> None:
        """
        Ingest cloned repo in background thread.

        ingest_cloned_repo() runs the pipeline and cleans repos/{project_id}/
        on success. On failure, we clean up here.
        """
        try:
            from app.main import ingest_cloned_repo, startup

            startup()

            logger.info(f"Starting background ingest: {project_id}")

            manifest = ingest_cloned_repo(project_id=project_id, vendor_id="repos-watcher")

            logger.info(f"Background ingest complete: {project_id}", extra={
                "project_id": project_id,
                "run_status": manifest.get("run_status"),
                "snapshots": manifest.get("stats", {}).get("snapshots_created"),
            })

        except Exception as e:
            logger.error(f"Background ingest failed: {project_id}", extra={
                "project_id": project_id,
                "error": str(e),
            }, exc_info=True)

            # Clean up repos dir on failure
            import shutil
            repos_path = self.repos_root / project_id
            try:
                if repos_path.exists():
                    shutil.rmtree(repos_path, ignore_errors=True)
                    logger.info(f"Cleaned repos after ingest failure: {project_id}")
            except Exception as cleanup_err:
                logger.error(f"Failed repos cleanup after ingest failure: {project_id}: {cleanup_err}")

        finally:
            # Always remove from tracking so re-clone can re-trigger
            self.tracked.pop(project_id, None)

    def _monitor_loop(self) -> None:
        """Main monitoring loop — runs in background thread."""
        logger.info("Repos watcher started", extra={
            "check_interval_seconds": self.CHECK_INTERVAL_SECONDS,
            "repos_root": str(self.repos_root),
            "trigger": READY_MARKER,
        })

        while self.running:
            try:
                self._scan_repos_directories()
            except Exception as e:
                logger.error(f"Error in repos monitor loop: {e}", exc_info=True)

            time.sleep(self.CHECK_INTERVAL_SECONDS)

        logger.info("Repos watcher stopped")

    def start(self) -> None:
        """Start the repos watcher in a background thread."""
        if self.running:
            logger.warning("Repos watcher already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Repos watcher thread started")

    def stop(self) -> None:
        """Stop the repos watcher."""
        if not self.running:
            return

        logger.info("Stopping repos watcher...")
        self.running = False

        if self.thread:
            self.thread.join(timeout=5.0)
            self.thread = None


_watcher: Optional[ReposWatcher] = None


def get_watcher() -> ReposWatcher:
    """Get or create the global repos watcher instance."""
    global _watcher
    if _watcher is None:
        _watcher = ReposWatcher()
    return _watcher


def start_watcher() -> None:
    """Start the global repos watcher."""
    watcher = get_watcher()
    watcher.start()


def stop_watcher() -> None:
    """Stop the global repos watcher."""
    global _watcher
    if _watcher:
        _watcher.stop()
        _watcher = None
