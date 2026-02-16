# /app/ingest/github_cloner.py
"""
Purpose: Ingest remote repository via HTTPS git clone with security and cleanup on failure.

Enhancements:
- Cleanup on failure (no partial repos)
- Git credential leakage protection
- Malicious git hooks removal
- Clone progress logging
- Performance metrics
"""

from __future__ import annotations

import shutil
import signal
import subprocess
import sys
import time
import os
from pathlib import Path
from typing import List, Optional

from app.config.settings import get_settings
from app.logging.logger import get_logger
from app.security.network_policy import NetworkPolicyError, validate_git_remote
from app.security.snap_limits import SnapLimitError, SnapLimitsEnforcer
from app.ingest.local_loader import _should_ignore


_IS_WINDOWS = sys.platform == "win32"


def _rmtree_robust(path: Path) -> None:
    """Remove directory tree, forcing read-only file removal on Windows (.git objects)."""
    def _force_readonly(func, p, _):
        try:
            os.chmod(p, 0o777)
            func(p)
        except Exception:
            pass
    rm_kwargs = (
        {"onexc": _force_readonly}
        if sys.version_info >= (3, 12)
        else {"onerror": _force_readonly}
    )
    shutil.rmtree(path, **rm_kwargs)


class GitCloneError(Exception):
    pass


def _kill_process_tree(proc: subprocess.Popen, logger) -> None:
    """Kill a subprocess and all its children. On Windows, uses taskkill /T
    to kill the entire process tree. On Unix, kills the process group."""
    pid = proc.pid
    try:
        if _IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=10,
                check=False,
            )
        else:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning(f"Failed to kill process tree (pid={pid}): {exc}")
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _enumerate_cloned_files(dest_root: Path, logger) -> List[Path]:
    """
    Enumerate files in a cloned repo using git ls-files (fast, index-based).
    Falls back to rglob if git ls-files fails.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "--full-name"],
            cwd=str(dest_root),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        paths = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if line:
                p = dest_root / line
                if p.is_file():
                    paths.append(p)
        logger.info(f"Enumerated {len(paths)} files via git ls-files")
        return paths
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning(f"git ls-files failed, falling back to rglob: {exc}")
        return [
            p for p in dest_root.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]


def clone_github_repo(
    repo_remote: str,
    project_id: str,
    *,
    branch: Optional[str] = None,
    include_submodules: bool = False,
) -> List[Path]:
    """
    Clone repo_remote into SNAP repos dir under project_id.
    
    Security:
    - Network policy validation
    - Credential leakage protection
    - Git hooks removal
    - Cleanup on failure
    
    Reliability:
    - Progress logging
    - Performance metrics
    
    Args:
        repo_remote: Git remote URL (HTTPS or git@)
        project_id: Project identifier
        branch: Optional branch to clone
        include_submodules: Clone with submodules (default: False)
    
    Returns:
        List of file paths (excluding .git contents)
    
    Raises:
        GitCloneError: If clone fails or limits exceeded
    """
    settings = get_settings()
    logger = get_logger("ingest.github")
    limits = SnapLimitsEnforcer()

    # Validate remote against network policy
    try:
        safe_remote = validate_git_remote(repo_remote)
    except NetworkPolicyError as exc:
        raise GitCloneError(str(exc)) from exc

    dest_root = settings.repos_dir / project_id

    # Clean up existing directory (handles Windows read-only .git files)
    if dest_root.exists():
        _rmtree_robust(dest_root)
        if dest_root.exists():
            raise GitCloneError(f"Failed to remove existing repo directory: {dest_root}")
        logger.debug(f"Cleaned up existing directory: {dest_root}")
    dest_root.mkdir(parents=True, exist_ok=True)

    job_start = time.time()
    files: List[Path] = []

    try:
        # Build git clone command
        depth = settings.git_clone_depth
        cmd: list[str] = [
            "git",
            "clone",
            "--single-branch",
            "--no-tags",
            "--depth",
            str(depth),
            safe_remote,
            str(dest_root),
        ]
        
        if branch:
            cmd[2:2] = ["--branch", branch]
        
        if include_submodules:
            cmd.extend(["--recurse-submodules", "--shallow-submodules"])
        
        # Security: Use explicit env allowlist (prevents leaking sensitive vars)
        # Include Windows-specific vars required for DNS/network operations
        safe_env_keys = {
            "PATH", "HOME", "USER", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP",
            # Windows-specific (required for network/DNS)
            "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC",
            "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        }
        env = {k: v for k, v in os.environ.items() if k in safe_env_keys}
        env["GIT_TERMINAL_PROMPT"] = "0"  # Prevent password prompts
        env["GIT_ASKPASS"] = "echo"        # Prevent credential popups
        
        clone_timeout = settings.git_clone_timeout_seconds
        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        if not _IS_WINDOWS:
            popen_kwargs["preexec_fn"] = os.setsid
        else:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        limits.check_project_time()

        logger.info("Cloning repository", extra={
            "project_id": project_id,
            "remote": safe_remote,
            "branch": branch or "default",
            "depth": depth,
            "timeout": clone_timeout,
        })

        try:
            with subprocess.Popen(cmd, **popen_kwargs) as proc:
                try:
                    _stdout, stderr = proc.communicate(timeout=clone_timeout)
                except subprocess.TimeoutExpired as exc:
                    _kill_process_tree(proc, logger)
                    if dest_root.exists():
                        _rmtree_robust(dest_root)
                    raise GitCloneError(
                        f"git clone timed out after {clone_timeout}s"
                    ) from exc

                if proc.returncode != 0:
                    stderr_text = (stderr.decode("utf-8", errors="replace") if stderr else "").strip()
                    if dest_root.exists():
                        _rmtree_robust(dest_root)
                    raise GitCloneError(f"git clone failed: {stderr_text or 'UNKNOWN'}")

                if stderr:
                    for line in stderr.decode("utf-8", errors="replace").strip().split('\n'):
                        if line:
                            logger.debug(f"Git: {line}")

                limits.check_job_time(job_start)

        except SnapLimitError as exc:
            raise GitCloneError(str(exc)) from exc
        
        # Security: Remove git hooks (prevent malicious hook execution)
        git_hooks_dir = dest_root / ".git" / "hooks"
        if git_hooks_dir.exists():
            shutil.rmtree(git_hooks_dir)
            logger.info("Removed git hooks for security", extra={
                "project_id": project_id,
                "hooks_path": str(git_hooks_dir)
            })
        
        # Enumerate files via git ls-files (faster than rglob, respects .gitignore)
        candidate_paths = _enumerate_cloned_files(dest_root, logger)

        # Filter + collect sizes in single pass (matches local_loader IGNORE_PATTERNS)
        total_size_bytes = 0
        skipped_count = 0

        for path in candidate_paths:
            try:
                rel = path.relative_to(dest_root)
            except ValueError:
                continue

            if _should_ignore(path, rel):
                skipped_count += 1
                continue

            try:
                limits.check_project_time()
                limits.check_file_size(path)
                files.append(path)
                total_size_bytes += path.stat().st_size
            except SnapLimitError as exc:
                logger.warning(f"Skipping file due to limit: {path} ({exc})")
                skipped_count += 1

        # Repo bounds check
        try:
            limits.check_repo_bounds(files=files, repo_root=dest_root)
        except SnapLimitError as exc:
            raise GitCloneError(str(exc)) from exc

        # Performance metrics (sizes already collected above)
        clone_duration = time.time() - job_start
        total_size_mb = total_size_bytes / (1024 * 1024)

        logger.info("Clone complete", extra={
            "project_id": project_id,
            "remote": safe_remote,
            "branch": branch or "default",
            "files_cloned": len(files),
            "files_skipped": skipped_count,
            "clone_duration_seconds": round(clone_duration, 2),
            "total_size_mb": round(total_size_mb, 2),
            "avg_file_size_kb": round(total_size_bytes / len(files) / 1024, 2) if files else 0
        })

        # Signal repos_watcher that clone is complete and ready for ingest
        ready_marker = dest_root / ".snap_ready"
        ready_marker.write_text(safe_remote, encoding="utf-8")
        logger.info(f"Wrote .snap_ready marker: {project_id}")

        return files
    
    except Exception as e:
        # Cleanup on failure (no partial repos)
        logger.error(f"Clone failed, cleaning up: {e}", extra={
            "project_id": project_id,
            "remote": safe_remote
        })
        
        if dest_root.exists():
            _rmtree_robust(dest_root)
            logger.info(f"Cleaned up failed clone: {dest_root}")

        raise
