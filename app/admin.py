# app/admin.py
"""
Admin CLI for SNAP — human-only operations not available to the LLM.

Usage:
    python -m app.admin list-projects
    python -m app.admin runs <project_id>
    python -m app.admin manifest <project_id>
    python -m app.admin snapshots <project_id> [--type <type>] [--file <path>]
    python -m app.admin delete-project <project_id>
    python -m app.admin upload-to-staging <project_id> <source_path>
    python -m app.admin clone-github <repo_url>
"""

import argparse
import sys
from collections import Counter


def _derive_project_id(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = name.lower().replace("-", "_")
    if len(name) < 3:
        name = name + "_" * (3 - len(name))
    return name


def _db_only() -> "SnapshotRepository":  # type: ignore[name-defined]
    from app.config.settings import get_settings
    from app.storage.snapshot_repo import SnapshotRepository
    get_settings()  # initialise config (no semgrep validation)
    return SnapshotRepository()


# =============================================================================
# Query commands
# =============================================================================

def cmd_list_projects() -> None:
    from app.main import startup
    from app.storage.snapshot_repo import SnapshotRepository

    startup()
    repo = SnapshotRepository()
    projects = repo.list_projects()

    if not projects:
        print("No projects.")
        return

    print(f"  {'PROJECT_ID':40s}  {'SNAPSHOTS':>9}  {'RUNS':>4}")
    print("  " + "-" * 60)
    for p in projects:
        sources = p.get("sources", [])
        snapshots = sum(s.get("snapshot_count") or 0 for s in sources)
        runs = len(sources)
        print(f"  {p['project_id']:40s}  {snapshots:>9}  {runs:>4}")


def cmd_runs(project_id: str) -> None:
    from app.main import startup
    from app.storage.snapshot_repo import SnapshotRepository

    startup()
    repo = SnapshotRepository()
    runs = repo.get_runs(project_id)

    if not runs:
        print(f"No runs found for project '{project_id}'.")
        return

    print(f"\n  Runs for: {project_id}")
    print(f"  {'RUN_ID':36s}  {'SOURCE':8s}  {'STATUS':11s}  {'FILES':>6}  {'SNAPS':>6}  CREATED")
    print("  " + "-" * 95)
    for r in runs:
        created = r["created_at"][:19].replace("T", " ")
        print(
            f"  {r['run_id']:36s}  {r['ingest_source']:8s}  {r['status']:11s}"
            f"  {r['file_count'] or 0:>6}  {r['snapshot_count'] or 0:>6}  {created}"
        )


def cmd_manifest(project_id: str) -> None:
    from app.main import startup
    from app.storage.snapshot_repo import SnapshotRepository

    startup()
    repo = SnapshotRepository()

    # Active run overview from list_projects
    projects = repo.list_projects()
    project = next((p for p in projects if p["project_id"] == project_id), None)

    # All runs (includes failed/superseded) for health check
    runs = repo.get_runs(project_id)

    if not project and not runs:
        print(f"Project '{project_id}' not found.")
        return

    print(f"\n  Manifest: {project_id}")
    print("  " + "=" * 70)

    # Active sources
    if project:
        sources = project.get("sources", [])
        print(f"\n  Active sources ({len(sources)}):")
        for s in sources:
            completed = s.get("completed_at") or "in-progress"
            if completed != "in-progress":
                completed = completed[:19].replace("T", " ")
            print(
                f"    [{s['ingest_source']:8s}]  files={s['file_count'] or 0:>6}"
                f"  snapshots={s['snapshot_count'] or 0:>6}  completed={completed}"
            )
            print(f"              ref: {s['source_ref']}")
    else:
        print("\n  No active runs.")

    # Run history summary
    if runs:
        status_counts: Counter = Counter(r["status"] for r in runs)
        print(f"\n  Run history ({len(runs)} total):")
        for status, count in sorted(status_counts.items()):
            flag = "  <-- ATTENTION" if status in ("failed", "draft") else ""
            print(f"    {status:12s}  {count:>3}{flag}")

    # Health flags
    issues = []
    for r in runs:
        if r["status"] == "failed":
            issues.append(f"  FAILED run: {r['run_id']} ({r['ingest_source']})")
        if r["status"] == "draft":
            issues.append(f"  DRAFT run (not promoted): {r['run_id']} ({r['ingest_source']})")
        if r["status"] == "active" and (r["file_count"] or 0) == 0:
            issues.append(f"  Active run has 0 files: {r['run_id']}")
        if r["status"] == "active" and (r["snapshot_count"] or 0) == 0:
            issues.append(f"  Active run has 0 snapshots: {r['run_id']}")

    if issues:
        print("\n  HEALTH ISSUES:")
        for issue in issues:
            print(f"  ! {issue}")
    else:
        print("\n  Health: OK")


def cmd_snapshots(project_id: str, snap_type: str | None, file_path: str | None) -> None:
    from app.main import startup
    from app.storage.snapshot_repo import SnapshotRepository

    startup()
    repo = SnapshotRepository()

    if file_path:
        records = repo.get_by_file(project_id, file_path)
        print(f"\n  Snapshots for file '{file_path}' in project '{project_id}':")
    elif snap_type:
        records = repo.get_by_type(project_id, snap_type)
        print(f"\n  Snapshots of type '{snap_type}' in project '{project_id}':")
    else:
        records = repo.get_by_project(project_id)
        print(f"\n  All snapshots in project '{project_id}':")

    if not records:
        print("  (none)")
        return

    if not file_path and not snap_type:
        # Summary view: group by type
        by_type: Counter = Counter(r.snapshot_type for r in records)
        by_file: Counter = Counter(r.source_file for r in records)
        print(f"\n  Total: {len(records)} snapshots across {len(by_file)} files\n")
        print(f"  {'SNAPSHOT TYPE':30s}  {'COUNT':>6}")
        print("  " + "-" * 40)
        for stype, count in sorted(by_type.items()):
            print(f"  {stype:30s}  {count:>6}")
        print(f"\n  Use --type <type> or --file <path> to drill in.")
    else:
        # Detail view
        print(f"  {'FILE':50s}  {'TYPE':20s}  SNAPSHOT_ID")
        print("  " + "-" * 95)
        for r in records:
            print(f"  {r.source_file[:50]:50s}  {r.snapshot_type:20s}  {r.snapshot_id}")


# =============================================================================
# Mutation commands
# =============================================================================

def cmd_delete_project(project_id: str) -> None:
    from app.main import delete_project, startup

    startup()
    delete_project(project_id)
    print(f"Deleted project '{project_id}' — DB, repos, and staging cleared.")


def cmd_upload_to_staging(project_id: str, source_path: str) -> None:
    from pathlib import Path
    from app.ingest.local_loader import stage_directory

    source = Path(source_path).resolve()
    if not source.exists():
        print(f"Error: source path does not exist: {source_path}", file=sys.stderr)
        sys.exit(1)
    if not source.is_dir():
        print(f"Error: source must be a directory: {source_path}", file=sys.stderr)
        sys.exit(1)

    count = stage_directory(source, project_id)
    print(f"Staged {count} files from '{source}' into staging/{project_id}/")


def cmd_clone_github(repo_url: str) -> None:
    from app.main import startup
    from app.ingest.github_cloner import clone_github_repo

    startup()
    project_id = _derive_project_id(repo_url)
    print(f"Cloning '{repo_url}' as project '{project_id}'...")

    clone_github_repo(repo_remote=repo_url, project_id=project_id)

    print(
        f"Clone complete: project_id='{project_id}'"
        f"  repos_watcher will ingest automatically."
    )


# =============================================================================
# CLI entry point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="snap-admin",
        description="SNAP admin commands — human use only, not callable by LLM.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list-projects
    sub.add_parser("list-projects", help="List all ingested projects with snapshot/run counts.")

    # runs
    p_runs = sub.add_parser("runs", help="Show all runs for a project (active/superseded/failed).")
    p_runs.add_argument("project_id")

    # manifest
    p_manifest = sub.add_parser("manifest", help="Health check and active-run summary for a project.")
    p_manifest.add_argument("project_id")

    # snapshots
    p_snaps = sub.add_parser("snapshots", help="Browse snapshots for a project.")
    p_snaps.add_argument("project_id")
    p_snaps.add_argument("--type", dest="snap_type", default=None, help="Filter by snapshot type.")
    p_snaps.add_argument("--file", dest="file_path", default=None, help="Filter by source file path.")

    # delete-project
    p_del = sub.add_parser("delete-project", help="Delete a project and all its data.")
    p_del.add_argument("project_id")

    # upload-to-staging
    p_up = sub.add_parser("upload-to-staging", help="Copy a local directory into project staging.")
    p_up.add_argument("project_id")
    p_up.add_argument("source_path", help="Absolute path to source directory")

    # clone-github
    p_clone = sub.add_parser("clone-github", help="Clone a GitHub repo — repos_watcher ingests automatically.")
    p_clone.add_argument("repo_url", help="GitHub repository URL (https://github.com/owner/repo)")

    args = parser.parse_args()

    if args.command == "list-projects":
        cmd_list_projects()
    elif args.command == "runs":
        cmd_runs(args.project_id)
    elif args.command == "manifest":
        cmd_manifest(args.project_id)
    elif args.command == "snapshots":
        cmd_snapshots(args.project_id, args.snap_type, args.file_path)
    elif args.command == "delete-project":
        cmd_delete_project(args.project_id)
    elif args.command == "upload-to-staging":
        cmd_upload_to_staging(args.project_id, args.source_path)
    elif args.command == "clone-github":
        cmd_clone_github(args.repo_url)


if __name__ == "__main__":
    main()
