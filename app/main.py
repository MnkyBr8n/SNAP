# /app/main.py
"""
Main orchestration for SNAP snapshot notebook tool.

Multi-parser architecture:
- Routes code files to tree_sitter + semgrep
- Routes doc/data/config files to nim_parser
- Creates snapshots per file
- Tracks accepted/failed/rejected snapshots
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import shutil
import sys
import yaml
import json
import time
import threading

from app.config.settings import get_settings
from app.logging.logger import (
    get_logger,
    log_file_parsed,
    log_repo_complete,
    log_file_categorization,
    log_new_file,
    log_duplicate_detected,
    log_version_conflict,
)
from app.ingest.local_loader import _should_ignore
from app.ingest.github_cloner import clone_github_repo
from app.ingest.file_router import route_files, FileRoute
from app.parsers.tree_sitter_parser import parse_code_tree_sitter
from app.parsers.semgrep_parser import parse_code_semgrep, batch_semgrep_scan
from app.parsers.nim_parser import parse_with_nim
from app.extraction.field_mapper import FieldMapper
from app.extraction.snapshot_builder import SnapshotBuilder
from app.storage.snapshot_repo import SnapshotRepository
from app.storage.db import get_engine


_logger = get_logger(__name__)


class SnapToolError(Exception):
    pass


_master_schema: Optional[Dict[str, Any]] = None
_field_mapper: Optional[FieldMapper] = None
_snapshot_builder: Optional[SnapshotBuilder] = None
_startup_lock = threading.Lock()

def startup() -> None:
    """Initialize SNAP tool: load schema, validate parsers, ensure DB tables."""
    global _master_schema, _field_mapper, _snapshot_builder

    # Fast path - already initialized (no lock needed for read)
    if _master_schema is not None:
        return

    # Thread-safe initialization
    with _startup_lock:
        if _master_schema is not None:
            _logger.info("Startup already completed")
            return

        _logger.info("Starting SNAP tool initialization")

        settings = get_settings()
        schema_path = settings.notebook_schema_path

        if not schema_path.exists():
            raise SnapToolError(f"Master schema not found: {schema_path}")

        with open(schema_path) as f:
            _master_schema = yaml.safe_load(f)

        _logger.info(f"Loaded master schema from {schema_path}")

        _templates_dir = Path(__file__).parent / "schemas" / "snapshot_templates"
        _field_mapper = FieldMapper(master_schema=_master_schema, templates_dir=_templates_dir)
        _snapshot_builder = SnapshotBuilder(_master_schema)

        from app.parsers.tree_sitter_parser import validate_tree_sitter_installation
        validate_tree_sitter_installation()  # raises if any grammar missing

        from app.parsers.semgrep_parser import validate_semgrep_installation
        validate_semgrep_installation()  # raises if semgrep missing, incompatible, or fails to run

        from sqlalchemy import text
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        _logger.info("SNAP tool initialization complete")


def process_project(
    project_id: str,
    vendor_id: str,
    repo_url: Optional[str] = None,
    local_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Collect files then run ingest pipeline."""
    if _snapshot_builder is None or _field_mapper is None:
        raise SnapToolError("Tool not initialized. Call startup() first.")

    if not repo_url and not local_path:
        raise SnapToolError("Must provide either repo_url or local_path")

    _logger.info("Vendor call", extra={
        "vendor_id": vendor_id,
        "project_id": project_id,
        "action": "ingest_project"
    })

    settings = get_settings()
    files = []

    if repo_url:
        _logger.info(f"Cloning repo: {repo_url}")
        files.extend(clone_github_repo(repo_remote=repo_url, project_id=project_id))
        project_root = settings.repos_dir / project_id
        ingest_source = "github"
        source_ref = repo_url
        ingest_source_meta: Dict[str, Any] = {"type": "github", "url": repo_url}
    else:
        _logger.info(f"Ingesting local: {local_path}")
        for p in local_path.rglob("*"):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(local_path)
            except ValueError:
                continue
            if not _should_ignore(p, rel):
                files.append(p)
        project_root = local_path
        ingest_source = "local"
        source_ref = str(local_path)
        ingest_source_meta = {"type": "local", "path": str(local_path)}

    if not files:
        raise SnapToolError("No files ingested")

    return _run_ingest_pipeline(
        project_id=project_id,
        vendor_id=vendor_id,
        files=files,
        project_root=project_root,
        ingest_source=ingest_source,
        source_ref=source_ref,
        ingest_source_meta=ingest_source_meta,
    )


def ingest_cloned_repo(project_id: str, vendor_id: str = "repos-watcher") -> Dict[str, Any]:
    """
    Ingest an already-cloned repo from repos/{project_id}/.

    Called by the repos_watcher after clone_github_repo() writes .snap_ready.
    Does NOT re-clone — uses files already present in repos/{project_id}/.
    Cleans repos/{project_id}/ after ingest (DB snapshots are canonical).
    """
    if _snapshot_builder is None or _field_mapper is None:
        raise SnapToolError("Tool not initialized. Call startup() first.")

    settings = get_settings()
    repos_path = settings.repos_dir / project_id

    if not repos_path.exists():
        raise SnapToolError(f"repos dir not found: {repos_path}")

    from app.ingest.github_cloner import _enumerate_cloned_files

    _logger.info(f"Ingest from cloned repo: {project_id}")

    files = []
    for p in _enumerate_cloned_files(repos_path, _logger):
        try:
            rel = p.relative_to(repos_path)
        except ValueError:
            continue
        if not _should_ignore(p, rel):
            files.append(p)

    if not files:
        raise SnapToolError(f"No files found in repos/{project_id}/")

    return _run_ingest_pipeline(
        project_id=project_id,
        vendor_id=vendor_id,
        files=files,
        project_root=repos_path,
        ingest_source="github",
        source_ref=str(repos_path),
        ingest_source_meta={"type": "github", "path": str(repos_path)},
    )


def _force_rmtree(path: Path) -> None:
    """Remove directory tree including read-only git files (Windows .git packs)."""
    def _on_error(func, p, _):
        try:
            import os
            os.chmod(p, 0o777)
            func(p)
        except Exception:
            pass
    rm_kwargs = (
        {"onexc": _on_error} if sys.version_info >= (3, 12)
        else {"onerror": _on_error}
    )
    shutil.rmtree(path, **rm_kwargs)


def _run_ingest_pipeline(
    project_id: str,
    vendor_id: str,
    files: List[Path],
    project_root: Path,
    ingest_source: str,
    source_ref: str,
    ingest_source_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """Route, parse, snapshot, and store. Cleans source dir after."""
    start_time = time.time()

    settings = get_settings()
    project_dir = settings.data_dir / "projects" / project_id
    project_dir.mkdir(parents=True, exist_ok=True)

    _logger.info("Ingest pipeline started", extra={
        "project_id": project_id,
        "vendor_id": vendor_id,
        "file_count": len(files),
    })

    routes = route_files(files)

    stats = {
        "files_attempted": len(routes),
        "files_processed": 0,
        "files_failed": 0,
        "snapshots_attempted": 0,
        "snapshots_created": 0,
        "snapshots_failed": 0,
        "snapshots_rejected": 0,
        "snapshot_types": {},
        "parsers_used": {},
        "file_categorization": {"normal": 0, "large": 0, "potential_god": 0, "rejected": 0},
        "source_hashes": {},
        "source_bytes_total": 0,
    }

    repo = SnapshotRepository()
    # Fail stale runs stuck in 'running' (process died mid-ingest)
    _STALE_THRESHOLD_S = 2 * 3600
    for _stale in repo.get_runs(project_id):
        if getattr(_stale, "status", None) == "running":
            try:
                _age = datetime.now(timezone.utc) - _stale.created_at
                if _age.total_seconds() > _STALE_THRESHOLD_S:
                    repo.fail_run(_stale.run_id)
                    _logger.warning("Failed stale run", extra={"run_id": _stale.run_id})
            except Exception:
                pass
    _logger.info("Creating run in DB...")
    run = repo.create_run(project_id, ingest_source, source_ref)
    _logger.info(f"Run created: {run.run_id}")
    run_status = "running"
    validation: Dict[str, Any] = {}

    # Pre-run batch semgrep in chunks before the per-file loop
    semgrep_batch_results: Dict[str, Dict[str, Any]] = {}
    semgrep_paths = [r.path for r in routes if "semgrep" in r.parsers]
    _SEMGREP_CHUNK = 30
    for _i in range(0, len(semgrep_paths), _SEMGREP_CHUNK):
        chunk = semgrep_paths[_i: _i + _SEMGREP_CHUNK]
        try:
            _logger.info(f"Batch semgrep chunk {_i // _SEMGREP_CHUNK + 1}: {len(chunk)} files")
            semgrep_batch_results.update(batch_semgrep_scan(chunk))
        except Exception as _batch_err:
            _logger.warning(
                f"Batch semgrep chunk failed, falling back to per-file for chunk — {_batch_err}"
            )

    try:
        for route in routes:
            _logger.info(f"Processing file: {route.path}")
            file_start = time.time()

            file_size = _get_file_size(route.path, route.field_type)
            file_tag = _categorize_file(file_size, route.field_type)

            stats["file_categorization"][file_tag] += 1

            if file_tag == "rejected":
                unit = "LOC" if route.field_type == "code" else "bytes"
                limit = get_settings().parser_limits.hard_cap_loc if route.field_type == "code" else get_settings().parser_limits.hard_cap_bytes
                log_file_categorization(_logger, str(route.path), file_size, "rejected", f"exceeds {limit} {unit} hard cap")
                stats["files_failed"] += 1
                stats["snapshots_rejected"] += 1
                continue

            if file_tag in ("large", "potential_god"):
                limits = get_settings().parser_limits
                if route.field_type == "code":
                    reason = {
                        "large": f"exceeds {limits.soft_cap_loc} LOC soft cap",
                        "potential_god": f"exceeds {limits.potential_god_loc} LOC"
                    }[file_tag]
                else:
                    reason = {
                        "large": f"exceeds {limits.soft_cap_bytes} bytes soft cap",
                        "potential_god": f"exceeds {limits.potential_god_bytes} bytes"
                    }[file_tag]
                log_file_categorization(_logger, str(route.path), file_size, file_tag, reason)

            # Normalize to relative path — portable across machines and run types
            try:
                rel_path = str(route.path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                _logger.warning(
                    "Path not under expected project_root, using filename only",
                    extra={"project_root": str(project_root), "file": str(route.path)},
                )
                rel_path = route.path.name

            source_hash = _compute_source_hash(route.path)
            if source_hash:
                stats["source_hashes"][rel_path] = source_hash

            # Versioning check � classify file against previous run
            _prev = repo.get_by_file(project_id, rel_path)
            if not _prev:
                log_new_file(_logger, project_id, rel_path, source_hash or "")
            else:
                _prev_hash = getattr(_prev[0], "source_hash", None)
                if _prev_hash and _prev_hash == source_hash:
                    log_duplicate_detected(_logger, project_id, rel_path, source_hash or "")
                else:
                    log_version_conflict(
                        _logger,
                        project_id,
                        rel_path,
                        _prev_hash or "",
                        source_hash or "",
                        getattr(_prev[0], "snapshot_id", ""),
                        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    )

            # Track source file size (pre-snap)
            try:
                stats["source_bytes_total"] += route.path.stat().st_size
            except (OSError, IOError):
                pass

            categorized_fields = _parse_file_multi_parser(route, semgrep_batch_results)
            if "file_metadata" in categorized_fields:
                categorized_fields["file_metadata"]["code.file.path"] = rel_path
            if "config_metadata" in categorized_fields:
                categorized_fields["config_metadata"]["config.file.path"] = rel_path
            if not categorized_fields:
                _logger.warning(
                    "All parsers failed for file — skipping",
                    extra={"file": str(route.path)},
                )
                stats["files_failed"] += 1

            snapshots = _snapshot_builder.create_snapshots(
                project_id=project_id,
                run_id=run.run_id,
                file_path=rel_path,
                categorized_fields=categorized_fields,
                parsers_used=route.parsers,
                source_hash=source_hash,
            )

            stats["snapshots_attempted"] += len(categorized_fields)
            stats["snapshots_created"] += len(snapshots)

            for snapshot in snapshots:
                stype = snapshot["snapshot_type"]
                stats["snapshot_types"][stype] = stats["snapshot_types"].get(stype, 0) + 1

            for parser in route.parsers:
                stats["parsers_used"][parser] = stats["parsers_used"].get(parser, 0) + 1

            file_duration = (time.time() - file_start) * 1000

            log_file_parsed(
                _logger,
                str(route.path),
                file_tag,
                file_size,
                route.language,
                project_id,
                file_duration,
                len(snapshots),
                [s["snapshot_type"] for s in snapshots],
                [s["snapshot_id"] for s in snapshots],
                route.parsers
            )

            stats["files_processed"] += 1

        # Seal the run and transition to draft, then promote to active
        repo.complete_run(
            run.run_id,
            snapshot_count=stats["snapshots_created"],
            file_count=stats["files_processed"],
        )
        repo.promote_run(run.run_id)
        run_status = "completed"

        with get_engine().connect() as _conn:
            from sqlalchemy import text as _text
            _row = _conn.execute(
                _text("SELECT COALESCE(SUM(LENGTH(binary_data)), 0) FROM snapshot_notebooks WHERE run_id = :rid"),
                {"rid": run.run_id},
            ).fetchone()
            snapshot_bytes_total = int(_row[0]) if _row else 0


        # Source copies no longer needed — DB snapshots are canonical
        if project_root.exists():
            _force_rmtree(project_root)
            _logger.info(f"Cleaned source dir after ingest: {project_root}")

    except Exception:
        repo.fail_run(run.run_id)
        run_status = "failed"
        if project_root.exists():
            _force_rmtree(project_root)
        raise

    total_duration = (time.time() - start_time) * 1000

    log_repo_complete(
        _logger,
        project_id,
        stats["files_processed"],
        stats["files_attempted"],
        stats["snapshots_created"],
        stats["snapshots_attempted"],
        stats["snapshots_failed"],
        stats["snapshots_rejected"],
        stats["snapshot_types"],
        stats["parsers_used"],
        total_duration
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Calculate compression ratio
    compression_ratio = 0.0
    if stats["source_bytes_total"] > 0:
        compression_ratio = round(snapshot_bytes_total / stats["source_bytes_total"], 3)

    manifest = {
        "project_id": project_id,
        "schema_version": "2",
        "run_id": run.run_id,
        "run_status": run_status,
        "ingest_source": ingest_source_meta,
        "validation": validation,
        "created_at": now_iso,
        "last_processed_at": now_iso,
        "processing_time": {
            "start_time": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "end_time": now_iso,
            "duration_seconds": round(time.time() - start_time, 2)
        },
        "size_metrics": {
            "source_bytes": stats["source_bytes_total"],
            "snapshot_bytes": snapshot_bytes_total,
            "compression_ratio": compression_ratio
        },
        "stats": stats
    }

    manifest_path = project_dir / "project_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    _logger.info(f"Ingest complete: {stats['snapshots_created']} snapshots, run_status={run_status}")

    return manifest


def _compute_source_hash(path: Path) -> Optional[str]:
    """SHA256 of file content at processing time for integrity tracking."""
    import hashlib
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError):
        return None


def _get_file_size(path: Path, snapshot_type: str) -> int:
    """Get file size (LOC for code, bytes for others)."""
    if snapshot_type == "code":
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except (IOError, OSError, UnicodeDecodeError):
            return 0
    return path.stat().st_size


def _categorize_file(size: int, snapshot_type: str) -> str:
    """Categorize file by size (LOC for code, bytes for text)."""
    settings = get_settings()
    limits = settings.parser_limits

    if snapshot_type == "code":
        # Use LOC limits for code files
        if size >= limits.hard_cap_loc:
            return "rejected"
        elif size >= limits.potential_god_loc:
            return "potential_god"
        elif size >= limits.soft_cap_loc:
            return "large"
    else:
        # Use byte limits for text/other files
        if size >= limits.hard_cap_bytes:
            return "rejected"
        elif size >= limits.potential_god_bytes:
            return "potential_god"
        elif size >= limits.soft_cap_bytes:
            return "large"

    return "normal"


def _parse_file_multi_parser(
    route: FileRoute,
    semgrep_batch_results: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Parse file with multiple parsers and merge."""
    categorized_results = []

    for parser in route.parsers:
        try:
            if parser == "tree_sitter":
                _logger.info(f"[{route.path.name}] Running tree_sitter parser")
                output = parse_code_tree_sitter(path=route.path, language=route.language)
                _logger.info(f"[{route.path.name}] tree_sitter complete")
                categorized = _field_mapper.categorize_parser_output(output, "tree_sitter", str(route.path))
                categorized_results.append(categorized)

            elif parser == "semgrep":
                fp_str = str(route.path)
                if semgrep_batch_results and fp_str in semgrep_batch_results:
                    output = semgrep_batch_results[fp_str]
                else:
                    _logger.info(f"[{route.path.name}] Running semgrep parser (fallback)")
                    output = parse_code_semgrep(path=route.path, language=route.language)
                categorized = _field_mapper.categorize_parser_output(output, "semgrep", fp_str)
                categorized_results.append(categorized)

            elif parser == "nim_parser":
                _logger.info(f"[{route.path.name}] Running nim_parser")
                output = parse_with_nim(route.path)
                _logger.info(f"[{route.path.name}] nim_parser complete")
                categorized = _field_mapper.categorize_parser_output(output, "nim_parser", str(route.path))
                categorized_results.append(categorized)

            else:
                raise RuntimeError(
                    f"Unknown parser {parser!r} assigned to {route.path} — "
                    "add it to _parse_file_multi_parser or remove it from the router"
                )
        except Exception as _parser_err:
            _logger.warning(
                f"Parser '{parser}' failed for {route.path.name} — other parsers for this file continue",
                extra={"parser": parser, "file": str(route.path), "error": str(_parser_err)},
            )

    return _field_mapper.merge_categorized_fields(*categorized_results)


def delete_project(project_id: str) -> None:
    """Delete all snapshots for project."""
    repo = SnapshotRepository()
    deleted = repo.delete_by_project(project_id)

    settings = get_settings()

    # Delete project manifest dir
    project_dir = settings.data_dir / "projects" / project_id
    if project_dir.exists():
        _force_rmtree(project_dir)

    # Delete GitHub clone (repos/) if present
    repos_dir = settings.repos_dir / project_id
    if repos_dir.exists():
        _force_rmtree(repos_dir)

    # Delete local staging if present
    staging_dir = settings.data_dir / "staging" / project_id
    if staging_dir.exists():
        _force_rmtree(staging_dir)

    _logger.info(f"Deleted project {project_id}: {deleted} snapshots")


def get_project_notebook(project_id: str, vendor_id: str) -> Dict[str, Any]:
    """Retrieve assembled project notebook."""
    if _snapshot_builder is None:
        raise SnapToolError("Tool not initialized")
    
    _logger.info("Vendor call", extra={
        "vendor_id": vendor_id,
        "project_id": project_id,
        "action": "get_notebook"
    })
    
    return _snapshot_builder.assemble_project_notebook(project_id)


def get_project_manifest(project_id: str) -> Dict[str, Any]:
    """Retrieve project manifest."""
    settings = get_settings()
    path = settings.data_dir / "projects" / project_id / "project_manifest.json"

    if not path.exists():
        raise SnapToolError(f"Manifest not found: {project_id}")

    with open(path) as f:
        return json.load(f)


def get_metrics() -> Dict[str, Any]:
    """Get aggregated metrics for dashboard."""
    settings = get_settings()
    projects_dir = settings.data_dir / "projects"

    metrics = {
        "projects": {"total": 0, "list": []},
        "files": {"processed": 0, "categorization": {"normal": 0, "large": 0, "potential_god": 0, "rejected": 0}},
        "snapshots": {"created": 0, "failed": 0, "by_type": {}},
        "parsers": {}
    }

    if not projects_dir.exists():
        return metrics

    # Find all manifest files recursively
    manifest_files = list(projects_dir.glob("**/project_manifest.json"))

    for manifest_path in manifest_files:

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except (IOError, json.JSONDecodeError):
            continue

        stats = manifest.get("stats", {})

        metrics["projects"]["total"] += 1
        metrics["projects"]["list"].append({
            "project_id": manifest.get("project_id", manifest_path.parent.name),
            "snapshots": stats.get("snapshots_created", 0),
            "files": stats.get("files_processed", 0)
        })

        metrics["files"]["processed"] += stats.get("files_processed", 0)
        metrics["snapshots"]["created"] += stats.get("snapshots_created", 0)
        metrics["snapshots"]["failed"] += stats.get("snapshots_failed", 0)

        # Aggregate file categorization
        file_cat = stats.get("file_categorization", {})
        if file_cat:
            for cat, count in file_cat.items():
                if cat in metrics["files"]["categorization"]:
                    metrics["files"]["categorization"][cat] += count
        else:
            # Backfill from legacy stats: rejected = snapshots_rejected, rest = normal
            rejected = stats.get("snapshots_rejected", 0)
            processed = stats.get("files_processed", 0)
            metrics["files"]["categorization"]["rejected"] += rejected
            metrics["files"]["categorization"]["normal"] += processed

        # Aggregate snapshot types
        for stype, count in stats.get("snapshot_types", {}).items():
            metrics["snapshots"]["by_type"][stype] = metrics["snapshots"]["by_type"].get(stype, 0) + count

        # Aggregate parser usage
        for parser, count in stats.get("parsers_used", {}).items():
            metrics["parsers"][parser] = metrics["parsers"].get(parser, 0) + count

    return metrics
