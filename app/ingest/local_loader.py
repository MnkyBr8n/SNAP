# app/ingest/local_loader.py
"""
Purpose: Stage and filter local project files for SNAP ingest.

Architecture:
- stage_directory(): copies source → staging/{project_id}/ with security filtering
- staging_watcher detects stable staging dirs and triggers ingest via main.process_project()
- repos/{project_id}/ is ONLY for GitHub clones — never used here
- Snapshots filtered by project_id (no global notebook)
- Delete project = delete staging + snapshots

Security:
- IGNORE_PATTERNS: secrets, credentials, deps, build artifacts
- _PRUNE_DIRS: fast os.walk pruning of large dirs
- Symlink rejection
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
import fnmatch

from app.config.settings import get_settings
from app.logging.logger import get_logger


class LocalIngestError(Exception):
    pass


# Security: Patterns to ignore during ingestion and staging.
# Applied aggressively at BOTH staging time and ingest time (defense-in-depth).
# Any file matching any pattern is rejected before it ever enters SNAP.
IGNORE_PATTERNS = [
    # -------------------------------------------------------------------------
    # Version control (never ingest history or metadata)
    # -------------------------------------------------------------------------
    ".git", ".svn", ".hg", ".bzr",

    # -------------------------------------------------------------------------
    # Dependencies — large, not source code, contain executable/binary content
    # -------------------------------------------------------------------------
    "node_modules",
    "__pycache__",
    ".venv", "venv", "env", ".env-*",
    "vendor",           # Go, PHP, Ruby vendored deps
    "target",           # Rust, Java/Maven build output
    "build", "dist",    # Generic build outputs
    ".gradle",          # Android/Gradle cache
    "Pods",             # iOS CocoaPods dependencies
    ".expo",            # Expo cache
    ".next",            # Next.js build output
    ".nuxt",            # Nuxt.js build output
    ".svelte-kit",      # SvelteKit build output
    ".pytest_cache", ".tox",
    "coverage",         # Test coverage reports
    ".cache",           # Generic tool caches
    "__snapshots__",    # Jest snapshot files

    # -------------------------------------------------------------------------
    # Secrets & credentials — CRITICAL, NEVER ingest
    # -------------------------------------------------------------------------
    # Environment files
    ".env", ".env.*",
    "*.env",

    # Private keys & certificates
    "*.pem", "*.key", "*.pfx", "*.p12", "*.p8",
    "*.ppk",            # PuTTY private key
    "*.jks",            # Java KeyStore
    "*.keystore",       # Android keystore
    "*.crt", "*.cer", "*.der",  # Certificates

    # SSH / GPG
    ".ssh", ".gnupg",
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
    "*_rsa", "*_ecdsa", "*_ed25519",

    # Cloud provider credentials
    ".aws",
    ".azure",
    ".gcloud",
    "serviceAccountKey.json",
    "*service_account*.json",
    "*credentials*.json",

    # Auth/token files
    ".npmrc",           # npm auth tokens
    ".pypirc",          # PyPI credentials
    ".netrc",           # FTP/HTTP credentials
    ".htpasswd",        # Apache passwords
    "*.token",
    "*.password",
    "credentials", "credentials.*",
    "secrets", "secrets.*",

    # -------------------------------------------------------------------------
    # IDE / editor metadata
    # -------------------------------------------------------------------------
    ".vscode", ".idea", ".vs",
    "*.swp", "*.swo", "*~",
    ".project", ".settings",

    # -------------------------------------------------------------------------
    # OS metadata
    # -------------------------------------------------------------------------
    ".DS_Store", "Thumbs.db", "desktop.ini",

    # -------------------------------------------------------------------------
    # Build artifacts & compiled output
    # -------------------------------------------------------------------------
    "*.pyc", "*.pyo",
    "*.class",
    "*.o", "*.obj",
    "*.so", "*.dll", "*.dylib",
    "*.min.js", "*.min.css",  # Minified — not useful for analysis

    # -------------------------------------------------------------------------
    # Logs
    # -------------------------------------------------------------------------
    "*.log", "logs",

    # -------------------------------------------------------------------------
    # Databases — potentially sensitive data
    # -------------------------------------------------------------------------
    "*.db", "*.sqlite", "*.sqlite3",

    # -------------------------------------------------------------------------
    # Misc
    # -------------------------------------------------------------------------
    "*.bak", "*.backup", "*.tmp",
]

# Directories that will be pruned during os.walk — os.walk will NOT descend
# into these at all, making staging fast even on large projects.
# Must be plain directory names (no globs).
_PRUNE_DIRS = {
    ".git", ".svn", ".hg", ".bzr",
    "node_modules", "__pycache__",
    ".venv", "venv", "env",
    "vendor", "target", "build", "dist",
    ".gradle", "Pods", ".expo",
    ".next", ".nuxt", ".svelte-kit",
    ".pytest_cache", ".tox", "coverage", ".cache",
    "__snapshots__",
    ".aws", ".ssh", ".gnupg", ".azure", ".gcloud",
    ".vscode", ".idea", ".vs",
    "logs",
}


def _should_ignore(path: Path, relative_path: Path) -> bool:
    """
    Check if path should be ignored based on patterns.
    
    Args:
        path: Absolute path
        relative_path: Path relative to source root
    
    Returns:
        True if should be ignored
    """
    path_str = str(relative_path)
    
    for pattern in IGNORE_PATTERNS:
        # Check each part of the path
        for part in relative_path.parts:
            if fnmatch.fnmatch(part, pattern):
                return True
        
        # Check full relative path
        if fnmatch.fnmatch(path_str, pattern):
            return True
        
        # Check filename
        if fnmatch.fnmatch(path.name, pattern):
            return True
    
    return False


def stage_directory(source: Path, project_id: str) -> int:
    """
    THE canonical entry point for copying any local directory into SNAP staging.

    All copy-to-staging paths (MCP tool, scripts, etc.) MUST go through here.
    Security filtering is applied at copy time so the staging area only ever
    contains clean, processable files — never secrets, credentials, or deps.

    Security applied at staging time (defense-in-depth before ingest):
    - _PRUNE_DIRS: os.walk never descends into ignored dirs (fast + safe)
    - IGNORE_PATTERNS: per-file filter on name, extension, and path components
    - Symlink rejection: no symlink following into or out of the source tree

    Args:
        source:     Source directory to copy from
        project_id: Destination project identifier (staging/{project_id}/)

    Returns:
        Number of files staged

    Raises:
        LocalIngestError: If source is not an existing directory
    """
    if not source.exists() or not source.is_dir():
        raise LocalIngestError(f"Source must be an existing directory: {source}")

    logger = get_logger("ingest.local")
    staging_path = get_settings().data_dir / "staging" / project_id
    staging_path.mkdir(parents=True, exist_ok=True)

    staged = 0
    rejected = 0

    for dirpath, dirnames, filenames in os.walk(source):
        dir_path = Path(dirpath)
        try:
            rel_dir = dir_path.relative_to(source)
        except ValueError:
            continue

        # Prune ignored and symlinked directories so os.walk never enters them
        dirnames[:] = [
            d for d in dirnames
            if d not in _PRUNE_DIRS
            and not _should_ignore(dir_path / d, rel_dir / d)
            and not (dir_path / d).is_symlink()
        ]

        for filename in filenames:
            src_file = dir_path / filename
            try:
                rel = src_file.relative_to(source)
            except ValueError:
                continue

            if src_file.is_symlink():
                logger.warning(f"Staging rejected symlink: {src_file}")
                rejected += 1
                continue

            if _should_ignore(src_file, rel):
                rejected += 1
                continue

            dest = staging_path / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest)
            staged += 1

    logger.info("Staged directory", extra={
        "project_id": project_id,
        "source": str(source),
        "files_staged": staged,
        "files_rejected": rejected,
    })
    return staged




def get_project_staging_path(project_id: str) -> Path:
    """
    Get the staging path for a specific project.
    
    Helper function for agents/users to know where to upload files.
    
    Args:
        project_id: Project identifier
    
    Returns:
        Path to project staging directory (staging/{project_id}/)
    """
    settings = get_settings()
    staging_path = settings.data_dir / "staging" / project_id
    staging_path.mkdir(parents=True, exist_ok=True)
    return staging_path


def delete_project_staging(project_id: str) -> None:
    """
    Delete project staging area.
    
    Called during project deletion to clean up staging files.
    
    Args:
        project_id: Project identifier
    """
    settings = get_settings()
    logger = get_logger("ingest.local")

    staging_path = settings.data_dir / "staging" / project_id
    
    if staging_path.exists():
        import sys

        def _force_remove_readonly(func, path, _):
            """Clear read-only bit (Windows node_modules/.git) then retry."""
            try:
                os.chmod(path, 0o777)
                func(path)
            except Exception:
                pass

        rm_kwargs = (
            {"onexc": _force_remove_readonly}
            if sys.version_info >= (3, 12)
            else {"onerror": _force_remove_readonly}
        )
        shutil.rmtree(staging_path, **rm_kwargs)
        if staging_path.exists():
            logger.warning(f"Staging directory not fully removed (locked files?): {staging_path}")
        else:
            logger.info(f"Deleted project staging: {staging_path}")
    else:
        logger.debug(f"Project staging does not exist: {staging_path}")


