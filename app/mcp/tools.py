# app/mcp/tools.py
"""
MCP tool handler implementations.

Each function wraps existing SNAP functionality and returns
JSON-serializable results for MCP responses.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from app.mcp.security import (
    validate_project_id,
    validate_vendor_id,
    validate_repo_url,
    validate_filename,
    validate_snapshot_type,
    get_safe_staging_path,
    ValidationError,
)
from app.config.settings import get_settings
from app.logging.logger import get_logger
from app.ingest.local_loader import (
    get_project_staging_path,
    delete_project_staging,
    stage_directory,
)

logger = get_logger("mcp.tools")


# =============================================================================
# Tool Permission Enforcement
# LLM has NO write, delete, or processing rights — no exceptions, no trust.
# DB snapshot reads are allowed without approval.
# Staging uploads and GitHub clone triggers require explicit per-call user approval.
# Any tool in NOT_ALLOWED_TOOLS raises ToolError immediately when called.
# =============================================================================

ALLOWED_TOOLS: frozenset[str] = frozenset({
    # [ALLOWED] DB snapshot reads — no approval needed
    "get_project_notebook",
    "get_project_manifest",
    "query_snapshots",
    "get_system_metrics",
    "list_projects",
    "list_runs",
    # [REQUIRES EXPLICIT USER APPROVAL per call]
    "get_staging_info",
    "clone_to_repos",     # clone trigger only — repos_watcher ingests, LLM does not
    "upload_to_staging",
    "copy_to_staging",
    "clear_staging",
    "kill_task",
})

# Tools the LLM is never permitted to call — no exceptions, no trust.
NOT_ALLOWED_TOOLS: frozenset[str] = frozenset({
    "delete_project",       # NO DELETE RIGHTS
    "promote_run",          # NO WRITE RIGHTS
    "process_local_project",  # NO PROCESSING
})

# Actions the LLM is never permitted to perform — enforced by SNAP, not by the LLM.
NOT_ALLOWED_ACTIONS: frozenset[str] = frozenset({
    "read_raw_files",       # LLM never reads raw file content
    "read_github_raw",      # LLM never reads raw GitHub file content
    "process_files",        # SNAP processes files — LLM never processes files
    "sort_filter_files",    # SNAP filters — LLM has no role in filtering decisions
    "ingest_files",         # SNAP ingests — LLM never ingests
})


def _assert_tool_allowed(tool_name: str) -> None:
    """Raise ToolError if tool_name is not in ALLOWED_TOOLS."""
    if tool_name not in ALLOWED_TOOLS:
        raise ToolError(
            f"Tool '{tool_name}' is not in ALLOWED_TOOLS. "
            f"Allowed: {', '.join(sorted(ALLOWED_TOOLS))}"
        )


class ToolError(Exception):
    """Raised when a tool execution fails."""
    pass


def _to_xml(data: Any, tag: str = "response", indent: int = 0) -> str:
    """
    

    Args:
        data: Dict, list, or primitive to convert
        tag: XML tag name
        indent: Current indentation level

    Returns:
        XML-formatted string
    """
    prefix = "  " * indent

    if isinstance(data, dict):
        if not data:
            return f"{prefix}<{tag}/>"
        lines = [f"{prefix}<{tag}>"]
        for key, value in data.items():
            lines.append(_to_xml(value, key, indent + 1))
        lines.append(f"{prefix}</{tag}>")
        return "\n".join(lines)

    elif isinstance(data, list):
        if not data:
            return f"{prefix}<{tag}/>"
        lines = [f"{prefix}<{tag}>"]
        for item in data:
            lines.append(_to_xml(item, "item", indent + 1))
        lines.append(f"{prefix}</{tag}>")
        return "\n".join(lines)

    elif data is None:
        return f"{prefix}<{tag}/>"

    else:
        # Escape XML special chars in string values
        value = str(data)
        value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"{prefix}<{tag}>{value}</{tag}>"


def xml_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrap response dict with XML-framed version for LLM consumption.

    Returns original dict with added 'xml' field containing XML representation.
    """
    data["xml"] = _to_xml(data, "snap_response")
    return data


# =============================================================================
# Core Tools
# =============================================================================

def _derive_project_id_from_repo(repo_url: str) -> str:
    """
    Derive a canonical project_id from the GitHub repo URL.

    Uses the repo name only — LLM cannot supply or rename the project.
    Normalizes to lowercase, replaces hyphens with underscores.
    Pads with '_' if shorter than 3 characters.
    """
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = name.lower().replace("-", "_")
    if len(name) < 3:
        name = name + "_" * (3 - len(name))
    return name


async def handle_clone_to_repos(
    repo_url: str,
    vendor_id: str,
    branch: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] Clone a GitHub repository into repos/.

    project_id is derived from the repo name — LLM cannot supply or rename it.
    This tool clones only. repos_watcher detects .snap_ready and handles all
    ingest. LLM does not read, ingest, filter, or process any files.

    Args:
        repo_url: GitHub repository URL (https://github.com/owner/repo)
        vendor_id: Vendor/caller identifier for audit
        branch: Optional branch to clone (default: default branch)

    Returns:
        Clone confirmation. Ingest runs in background via repos_watcher.

    Raises:
        ToolError: If repo_url is invalid or clone fails
    """
    vendor_id = validate_vendor_id(vendor_id)
    repo_url = validate_repo_url(repo_url)

    # Enforce project_id = repo name. LLM cannot supply or override this.
    project_id = _derive_project_id_from_repo(repo_url)

    logger.info("MCP tool: clone_to_repos", extra={
        "project_id": project_id,
        "vendor_id": vendor_id,
        "repo_url": repo_url,
        "branch": branch,
    })

    from app.ingest.github_cloner import clone_github_repo
    from app.main import startup

    startup()

    try:
        await asyncio.to_thread(
            clone_github_repo,
            repo_remote=repo_url,
            project_id=project_id,
            branch=branch,
        )

        return xml_response({
            "status": "cloning_complete",
            "project_id": project_id,
            "message": "Clone finished. SNAP repos_watcher will ingest automatically.",
        })

    except Exception as e:
        logger.error(f"clone_to_repos failed: {e}", extra={
            "project_id": project_id,
            "error": str(e),
        })
        raise ToolError(f"Failed to clone repository: {e}") from e


async def handle_process_local_project(
    project_id: str,
    vendor_id: str,
) -> Dict[str, Any]:
    """
    [NOT ALLOWED] LLM has no processing rights. Raises immediately.

    Args:
        project_id: Project identifier
        vendor_id: Vendor/caller identifier for audit

    Returns:
        Never returns — always raises ToolError
    """
    raise ToolError("Tool 'process_local_project' is prohibited. LLM has no processing rights.")


async def handle_get_project_notebook(
    project_id: str,
    vendor_id: str,
) -> Dict[str, Any]:
    """
    [ALLOWED] Read the complete analysis notebook for a project.

    Args:
        project_id: Project identifier
        vendor_id: Vendor/caller identifier for audit

    Returns:
        Complete project notebook with all snapshots
    """
    project_id = validate_project_id(project_id)
    vendor_id = validate_vendor_id(vendor_id)

    logger.info("MCP tool: get_project_notebook", extra={
        "project_id": project_id,
        "vendor_id": vendor_id,
    })

    from app.main import get_project_notebook, startup

    startup()

    try:
        notebook = get_project_notebook(project_id, vendor_id)

        return xml_response({
            "status": "success",
            "project_id": project_id,
            "notebook": notebook,
        })

    except Exception as e:
        logger.error(f"get_project_notebook failed: {e}", extra={
            "project_id": project_id,
            "error": str(e),
        })
        raise ToolError(f"Failed to retrieve notebook: {e}")


async def handle_delete_project(
    project_id: str,
) -> Dict[str, Any]:
    """
    [NOT ALLOWED] LLM has no delete rights. Raises immediately.

    Args:
        project_id: Project identifier

    Returns:
        Never returns — always raises ToolError
    """
    raise ToolError("Tool 'delete_project' is prohibited. LLM has no delete rights.")


async def handle_list_projects() -> Dict[str, Any]:
    """[ALLOWED] List all projects with snapshot counts and timestamps."""
    from app.storage.snapshot_repo import SnapshotRepository
    from app.main import startup

    startup()
    repo = SnapshotRepository()
    projects = repo.list_projects()
    return xml_response({"projects": projects, "total": len(projects)})


async def handle_list_runs(project_id: str) -> Dict[str, Any]:
    """
    [ALLOWED] List all processing runs for a project, newest first.

    Args:
        project_id: Project identifier

    Returns:
        List of runs with status, counts, and timestamps
    """
    project_id = validate_project_id(project_id)

    logger.info("MCP tool: list_runs", extra={"project_id": project_id})

    from app.storage.snapshot_repo import SnapshotRepository
    from app.main import startup

    startup()
    repo = SnapshotRepository()

    try:
        runs = repo.get_runs(project_id)
        return xml_response({
            "project_id": project_id,
            "runs": runs,
            "total": len(runs),
        })
    except Exception as e:
        logger.error(f"list_runs failed: {e}", extra={"project_id": project_id, "error": str(e)})
        raise ToolError(f"Failed to list runs: {e}")


async def handle_promote_run(project_id: str, run_id: str) -> Dict[str, Any]:
    """
    [NOT ALLOWED] LLM has no write rights. Raises immediately.

    Args:
        project_id: Project identifier
        run_id: Run ID to promote

    Returns:
        Never returns — always raises ToolError
    """
    raise ToolError("Tool 'promote_run' is prohibited. LLM has no write rights.")


# =============================================================================
# Staging Tools (Secure)
# =============================================================================

async def handle_get_staging_info(
    project_id: str,
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] List staging file names, sizes, and timestamps only.

    Returns file system stat data — no file content is read.

    Args:
        project_id: Project identifier

    Returns:
        File names, sizes, and last-modified timestamps only
    """
    project_id = validate_project_id(project_id)

    logger.info("MCP tool: get_staging_info", extra={
        "project_id": project_id,
    })

    staging_path = get_project_staging_path(project_id)

    files = []
    total_size = 0

    for path in staging_path.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                stat = path.stat()
                rel_path = path.relative_to(staging_path)
                files.append({
                    "name": str(rel_path),
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
                total_size += stat.st_size
            except (OSError, ValueError):
                continue

    return xml_response({
        "status": "success",
        "project_id": project_id,
        "staging_path": f"staging/{project_id}",
        "files": files,
        "file_count": len(files),
        "total_size_bytes": total_size,
    })


async def handle_upload_to_staging(
    project_id: str,
    filename: str,
    content: str,
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] Upload a file or directory to project staging.

    The LLM uploads. SNAP staging handles all filtering and cleaning — the LLM
    does not filter, sort, or process content.

    Args:
        project_id: Project identifier
        filename: Relative filename (can include subdirectories like "src/main.py")
        content: File content (text or base64-encoded binary)
        encoding: Content encoding - "utf-8" for text, "base64" for binary

    Returns:
        Upload confirmation with file path

    Raises:
        ValidationError: If SNAP staging rejects the file
    """
    project_id = validate_project_id(project_id)
    filename = validate_filename(filename)

    logger.info("MCP tool: upload_to_staging", extra={
        "project_id": project_id,
        "upload_filename": filename,  # "filename" conflicts with LogRecord.filename
        "encoding": encoding,
    })

    from app.ingest.local_loader import _should_ignore

    rel_path = Path(filename)
    dummy_path = Path(filename)  # Just for ignore checking

    if _should_ignore(dummy_path, rel_path):
        logger.warning(f"File rejected by IGNORE_PATTERNS: {filename}")
        raise ValidationError(
            f"File rejected during staging/cleaning: {filename}. "
            f"This file type is ignored (secrets, dependencies, build artifacts, etc.)"
        )

    # Get safe path (validates and prevents traversal)
    safe_path = get_safe_staging_path(project_id, filename)

    # Decode content
    if encoding == "base64":
        try:
            file_content = base64.b64decode(content)
        except Exception as e:
            raise ValidationError(f"Invalid base64 content: {e}")
    elif encoding == "utf-8":
        file_content = content.encode("utf-8")
    else:
        raise ValidationError(f"Invalid encoding: {encoding}. Use 'utf-8' or 'base64'")

    # Check file size limits
    settings = get_settings()
    max_size = settings.limits.max_code_file_bytes

    if len(file_content) > max_size:
        raise ValidationError(
            f"File too large: {len(file_content)} bytes. Max: {max_size} bytes"
        )

    # Create parent directories and write file
    safe_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(safe_path, "wb") as f:
            f.write(file_content)
    except OSError as e:
        raise ToolError(f"Failed to write file: {e}")

    return xml_response({
        "status": "uploaded",
        "project_id": project_id,
        "filename": filename,
        "path": str(safe_path.relative_to(settings.data_dir.resolve())),
        "size": len(file_content),
    })


async def handle_clear_staging(
    project_id: str,
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] Clear all files from project staging area.

    Args:
        project_id: Project identifier

    Returns:
        Deletion confirmation
    """
    project_id = validate_project_id(project_id)

    logger.info("MCP tool: clear_staging", extra={
        "project_id": project_id,
    })

    staging_path = get_project_staging_path(project_id)

    # Count files before deletion
    files = list(staging_path.rglob("*"))
    file_count = len([f for f in files if f.is_file()])

    delete_project_staging(project_id)

    return xml_response({
        "status": "cleared",
        "project_id": project_id,
        "files_deleted": file_count,
    })


async def handle_copy_to_staging(
    project_id: str,
    source_path: str,
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] Copy a local directory into project staging.

    The LLM performs the copy. SNAP handles all filtering — the LLM does not
    sort, filter, or process files.

    Args:
        project_id: Project identifier
        source_path: Absolute path to a local directory

    Returns:
        Copy confirmation with staged file count
    """
    project_id = validate_project_id(project_id)

    source = Path(source_path).resolve()
    if not source.exists():
        raise ToolError(f"Source does not exist: {source_path}")
    if not source.is_dir():
        raise ToolError(f"Source must be a directory: {source_path}")

    try:
        file_count = stage_directory(source, project_id)
    except Exception as e:
        raise ToolError(f"Failed to stage directory: {e}") from e

    logger.info("MCP tool: copy_to_staging", extra={
        "project_id": project_id,
        "source": str(source),
        "files_staged": file_count,
    })

    return xml_response({
        "status": "staged",
        "project_id": project_id,
        "source": str(source),
        "destination": f"staging/{project_id}",
        "files_staged": file_count,
    })


# =============================================================================
# Query Tools
# =============================================================================

async def handle_get_project_manifest(
    project_id: str,
) -> Dict[str, Any]:
    """
    [ALLOWED] Read processing statistics for a project from the DB.

    Args:
        project_id: Project identifier

    Returns:
        Project manifest with processing stats
    """
    project_id = validate_project_id(project_id)

    logger.info("MCP tool: get_project_manifest", extra={
        "project_id": project_id,
    })

    from app.main import get_project_manifest, startup

    startup()

    try:
        manifest = get_project_manifest(project_id)

        return xml_response({
            "status": "success",
            "project_id": project_id,
            "manifest": manifest,
        })

    except Exception as e:
        logger.error(f"get_project_manifest failed: {e}", extra={
            "project_id": project_id,
            "error": str(e),
        })
        raise ToolError(f"Failed to retrieve manifest: {e}")


async def handle_query_snapshots(
    project_id: str,
    snapshot_type: Optional[str] = None,
    file_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    [ALLOWED] Query DB snapshots by type or file.

    Args:
        project_id: Project identifier
        snapshot_type: Optional filter by snapshot type (e.g., "security", "imports")
        file_path: Optional filter by source file path

    Returns:
        List of matching snapshots
    """
    project_id = validate_project_id(project_id)

    if snapshot_type:
        snapshot_type = validate_snapshot_type(snapshot_type)

    logger.info("MCP tool: query_snapshots", extra={
        "project_id": project_id,
        "snapshot_type": snapshot_type,
        "file_path": file_path,
    })

    from app.main import startup
    from app.storage.snapshot_repo import SnapshotRepository

    startup()

    repo = SnapshotRepository()

    try:
        if file_path and snapshot_type:
            # Get specific snapshot for file and type
            snapshots = repo.get_by_file(project_id, file_path)
            snapshots = [s for s in snapshots if s.snapshot_type == snapshot_type]
        elif file_path:
            # Get all snapshots for file
            snapshots = repo.get_by_file(project_id, file_path)
        elif snapshot_type:
            # Get all snapshots of type
            snapshots = repo.get_by_type(project_id, snapshot_type)
        else:
            # Get all project snapshots
            snapshots = repo.get_by_project(project_id)

        # Convert to dicts
        result = []
        for s in snapshots:
            result.append({
                "snapshot_id": s.snapshot_id,
                "snapshot_type": s.snapshot_type,
                "source_file": s.source_file,
                "field_values": s.field_values,
                "created_at": s.created_at.isoformat(),
            })

        return xml_response({
            "status": "success",
            "project_id": project_id,
            "filters": {
                "snapshot_type": snapshot_type,
                "file_path": file_path,
            },
            "count": len(result),
            "snapshots": result,
        })

    except Exception as e:
        logger.error(f"query_snapshots failed: {e}", extra={
            "project_id": project_id,
            "error": str(e),
        })
        raise ToolError(f"Failed to query snapshots: {e}")


async def handle_get_system_metrics() -> Dict[str, Any]:
    """
    [ALLOWED] Read system-wide metrics from the DB.

    Returns:
        Project counts, snapshot stats, etc.
    """
    logger.info("MCP tool: get_system_metrics")

    from app.main import get_metrics, startup

    startup()

    try:
        metrics = get_metrics()

        return xml_response({
            "status": "success",
            "metrics": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    except Exception as e:
        logger.error(f"get_system_metrics failed: {e}")
        raise ToolError(f"Failed to retrieve metrics: {e}")


# =============================================================================
# Task Control
# =============================================================================

_running_tasks: Dict[str, "asyncio.Task[Any]"] = {}


async def handle_kill_task(
    task_id: str,
) -> Dict[str, Any]:
    """
    [REQUIRES EXPLICIT APPROVAL] Cancel a running tool task by ID.

    Args:
        task_id: ID of the task to cancel (returned when the task was started)

    Returns:
        Cancellation confirmation

    Raises:
        ToolError: If task_id is not found or already completed
    """
    if not task_id or not task_id.strip():
        raise ToolError("task_id is required")
    task_id = task_id.strip()

    task = _running_tasks.get(task_id)
    if task is None:
        raise ToolError(f"No running task with id '{task_id}'")

    if task.done():
        _running_tasks.pop(task_id, None)
        raise ToolError(f"Task '{task_id}' is already completed")

    task.cancel()
    _running_tasks.pop(task_id, None)

    logger.info("MCP tool: kill_task", extra={"task_id": task_id})

    return xml_response({
        "status": "cancelled",
        "task_id": task_id,
    })
