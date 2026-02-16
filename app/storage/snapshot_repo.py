#/app/storage/snapshot_repo.py
"""
Snapshot persistence with run-based branching.

Architecture:
- Every process_project() call creates a ProjectRun (run_id, status='running')
- Snapshots are written under that run_id — isolated from all other runs
- On success: run → 'draft' → validate() → promote() → 'active'
- On failure: run → 'failed' — snapshots are orphaned, never queried
- project_active_runs tracks the live run_id per (project_id, ingest_source)
- All queries go through project_active_runs — stale/failed runs invisible
- UNIQUE: (run_id, source_file, snapshot_type) — retry-safe within same run
- source_file stored as RELATIVE path from project root (portable)
- snapshot_type MUST exist in snapshot_templates/ — enforced at upsert()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from datetime import datetime
from uuid import uuid4
import yaml
import json

from sqlalchemy import text

from app.logging.logger import get_logger
from app.storage.db import db_session, get_engine
from app.config.settings import get_settings


class SnapshotRepoError(Exception):
    pass


@dataclass(frozen=True)
class FieldConfig:
    field_id: str
    value_type: str
    multi: bool
    required: bool


@dataclass(frozen=True)
class ProjectRun:
    run_id: str
    project_id: str
    ingest_source: str         # 'github' | 'local' | 'legacy'
    source_ref: Optional[str]  # URL or local path
    status: str                # 'running' | 'draft' | 'active' | 'failed' | 'superseded'
    created_at: datetime
    completed_at: Optional[datetime]
    snapshot_count: Optional[int]
    file_count: Optional[int]


@dataclass(frozen=True)
class SnapshotRecord:
    snapshot_id: str
    run_id: str
    project_id: str
    snapshot_type: str
    source_file: str           # relative path from project root
    field_values: Dict[str, Any]
    source_hash: Optional[str]
    created_at: datetime


# Module-level caches — reset on process restart
_table_ensured = False
_field_configs_cache: Dict[str, FieldConfig] = {}
_valid_snapshot_types_cache: set = set()


class SnapshotRepository:
    def __init__(self) -> None:
        global _table_ensured, _field_configs_cache, _valid_snapshot_types_cache
        self.logger = get_logger("storage.snapshot_repo")

        if not _table_ensured:
            self._ensure_table()
            _table_ensured = True

        if not _field_configs_cache:
            self._load_field_configs()
            _field_configs_cache = self.field_configs
            _valid_snapshot_types_cache = self.valid_snapshot_types
        else:
            self.field_configs = _field_configs_cache
            self.valid_snapshot_types = _valid_snapshot_types_cache

    # =========================================================================
    # Schema loading
    # =========================================================================

    def _load_field_configs(self) -> None:
        """
        Build valid_snapshot_types from snapshot_templates/*.json (source of truth).
        Build field_configs from master_notebook.yaml.

        A snapshot_type with no template file is rejected at upsert().
        To add a new type: create the template JSON, restart, then process.
        """
        settings = get_settings()
        schema_path = settings.notebook_schema_path

        if not schema_path.exists():
            raise SnapshotRepoError(f"Master schema not found: {schema_path}")

        templates_dir = settings.schemas_dir / "snapshot_templates"
        if not templates_dir.exists():
            raise SnapshotRepoError(
                f"snapshot_templates dir not found: {templates_dir}"
            )

        self.valid_snapshot_types: set = {
            p.stem for p in templates_dir.glob("*.json")
        }
        if not self.valid_snapshot_types:
            raise SnapshotRepoError(
                "No snapshot templates found — cannot validate snapshot types"
            )

        self.logger.info(
            "Loaded valid snapshot types",
            extra={"types": sorted(self.valid_snapshot_types)},
        )

        with open(schema_path, encoding="utf-8") as f:
            schema = yaml.safe_load(f)

        self.field_configs: Dict[str, FieldConfig] = {}
        for _stype, fields in schema.get("field_id_registry", {}).items():
            for field_def in fields:
                fid = field_def["field_id"]
                self.field_configs[fid] = FieldConfig(
                    field_id=fid,
                    value_type=field_def["value_type"],
                    multi=field_def["multi"],
                    required=field_def["required"],
                )

    # =========================================================================
    # DDL — safe to run on every startup
    # =========================================================================

    def _ensure_table(self) -> None:
        engine = get_engine()
        with engine.connect() as conn:

            # -----------------------------------------------------------------
            # project_runs: one row per processing attempt
            # -----------------------------------------------------------------
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS project_runs (
                    run_id        TEXT PRIMARY KEY,
                    project_id    TEXT NOT NULL,
                    ingest_source TEXT NOT NULL DEFAULT 'local',
                    source_ref    TEXT,
                    status        TEXT NOT NULL DEFAULT 'running',
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at  TIMESTAMPTZ,
                    snapshot_count INT,
                    file_count     INT
                )
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_runs_project
                ON project_runs(project_id, status)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_runs_source
                ON project_runs(project_id, ingest_source, status)
            """))

            # -----------------------------------------------------------------
            # project_active_runs: pointer to live run per (project, source)
            # -----------------------------------------------------------------
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS project_active_runs (
                    project_id    TEXT NOT NULL,
                    ingest_source TEXT NOT NULL,
                    active_run_id TEXT NOT NULL,
                    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (project_id, ingest_source)
                )
            """))

            # -----------------------------------------------------------------
            # snapshot_notebooks
            # -----------------------------------------------------------------
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS snapshot_notebooks (
                    snapshot_id   TEXT PRIMARY KEY,
                    run_id        TEXT NOT NULL,
                    project_id    TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    source_file   TEXT NOT NULL,
                    field_values  JSONB NOT NULL,
                    source_hash   TEXT,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))

            # -----------------------------------------------------------------
            # Migration: wire existing rows into legacy runs
            # -----------------------------------------------------------------

            # Add run_id column to existing tables (no-op if already present)
            conn.execute(text("""
                ALTER TABLE snapshot_notebooks
                ADD COLUMN IF NOT EXISTS run_id TEXT
            """))

            # Create one 'legacy' run per project that has untagged snapshots
            conn.execute(text("""
                INSERT INTO project_runs
                    (run_id, project_id, ingest_source, status,
                     source_ref, completed_at)
                SELECT
                    gen_random_uuid()::TEXT,
                    p.project_id,
                    'legacy',
                    'active',
                    'pre-run-tracking',
                    NOW()
                FROM (
                    SELECT DISTINCT sn.project_id
                    FROM snapshot_notebooks sn
                    WHERE sn.run_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM project_runs pr
                        WHERE pr.project_id    = sn.project_id
                          AND pr.ingest_source = 'legacy'
                    )
                ) p
            """))

            # Tag untagged snapshots with their project's legacy run
            conn.execute(text("""
                UPDATE snapshot_notebooks sn
                SET run_id = pr.run_id
                FROM (
                    SELECT DISTINCT ON (project_id) run_id, project_id
                    FROM project_runs
                    WHERE ingest_source = 'legacy'
                    ORDER BY project_id, created_at
                ) pr
                WHERE sn.project_id = pr.project_id
                  AND sn.run_id IS NULL
            """))

            # Populate active_run pointers for legacy projects
            conn.execute(text("""
                INSERT INTO project_active_runs
                    (project_id, ingest_source, active_run_id)
                SELECT pr.project_id, pr.ingest_source, pr.run_id
                FROM project_runs pr
                WHERE pr.status = 'active'
                ON CONFLICT (project_id, ingest_source) DO NOTHING
            """))

            # Backfill run counts for legacy runs
            conn.execute(text("""
                UPDATE project_runs pr SET
                    snapshot_count = sub.snap_count,
                    file_count     = sub.fc
                FROM (
                    SELECT run_id,
                           COUNT(*)                    AS snap_count,
                           COUNT(DISTINCT source_file) AS fc
                    FROM snapshot_notebooks
                    GROUP BY run_id
                ) sub
                WHERE pr.run_id = sub.run_id
                  AND pr.snapshot_count IS NULL
            """))

            # -----------------------------------------------------------------
            # UNIQUE constraint: drop old, add new scoped to run_id
            # -----------------------------------------------------------------
            conn.execute(text("""
                ALTER TABLE snapshot_notebooks DROP CONSTRAINT IF EXISTS
                snapshot_notebooks_project_id_source_file_snapshot_type_key
            """))
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_snapshot_run
                ON snapshot_notebooks(run_id, source_file, snapshot_type)
            """))

            # Working indexes
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_run
                ON snapshot_notebooks(run_id)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_type
                ON snapshot_notebooks(run_id, snapshot_type)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_project
                ON snapshot_notebooks(project_id)
            """))

            conn.commit()

    # =========================================================================
    # Run lifecycle
    # =========================================================================

    def create_run(
        self,
        project_id: str,
        ingest_source: str,
        source_ref: Optional[str] = None,
    ) -> ProjectRun:
        """Open a new processing run. Status = 'running'."""
        run_id = str(uuid4())
        with db_session() as session:
            session.execute(
                text("""
                    INSERT INTO project_runs
                        (run_id, project_id, ingest_source, source_ref, status)
                    VALUES (:rid, :pid, :isrc, :sref, 'running')
                """),
                {"rid": run_id, "pid": project_id,
                 "isrc": ingest_source, "sref": source_ref},
            )
        self.logger.info("Run created", extra={
            "run_id": run_id,
            "project_id": project_id,
            "ingest_source": ingest_source,
        })
        return self._get_run(run_id)

    def complete_run(
        self, run_id: str, snapshot_count: int, file_count: int
    ) -> ProjectRun:
        """Mark run as 'draft' after all snapshots written. Ready for validation."""
        with db_session() as session:
            session.execute(
                text("""
                    UPDATE project_runs
                    SET status         = 'draft',
                        completed_at   = NOW(),
                        snapshot_count = :sc,
                        file_count     = :fc
                    WHERE run_id = :rid
                """),
                {"rid": run_id, "sc": snapshot_count, "fc": file_count},
            )
        return self._get_run(run_id)

    def fail_run(self, run_id: str) -> None:
        """Mark run as 'failed'. Its snapshots are never queried."""
        with db_session() as session:
            session.execute(
                text("""
                    UPDATE project_runs
                    SET status = 'failed', completed_at = NOW()
                    WHERE run_id = :rid
                """),
                {"rid": run_id},
            )
        self.logger.warning("Run failed — snapshots isolated", extra={"run_id": run_id})

    def validate_run(self, run_id: str) -> Dict[str, Any]:
        """
        Compare draft run against current active run for same (project_id, ingest_source).

        Returns:
            {passed, critical, warnings, first_ingest, previous_run_id,
             previous_files, previous_snapshots, new_files, new_snapshots}

        critical=True means file count dropped >50% — auto-promote blocked.
        """
        run = self._get_run(run_id)
        if not run:
            return {"passed": False, "critical": True,
                    "warnings": ["run not found"]}

        with db_session() as session:
            row = session.execute(
                text("""
                    SELECT pr.run_id, pr.file_count, pr.snapshot_count
                    FROM project_active_runs par
                    JOIN project_runs pr ON par.active_run_id = pr.run_id
                    WHERE par.project_id    = :pid
                      AND par.ingest_source = :isrc
                """),
                {"pid": run.project_id, "isrc": run.ingest_source},
            ).fetchone()

        # First ingest for this project+source — always passes
        if not row:
            return {
                "passed": True, "critical": False, "warnings": [],
                "first_ingest": True,
                "new_files": run.file_count or 0,
                "new_snapshots": run.snapshot_count or 0,
            }

        prev_run_id, prev_files, prev_snaps = row
        new_files = run.file_count or 0
        new_snaps = run.snapshot_count or 0
        prev_files = prev_files or 0
        prev_snaps = prev_snaps or 0

        warnings = []
        critical = False

        if prev_files > 0:
            drop = (prev_files - new_files) / prev_files
            if drop > 0.50:
                warnings.append(
                    f"CRITICAL: file count dropped {drop:.0%} "
                    f"({prev_files} → {new_files})"
                )
                critical = True
            elif drop > 0.20:
                warnings.append(
                    f"File count dropped {drop:.0%} "
                    f"({prev_files} → {new_files})"
                )

        if prev_snaps > 0:
            drop = (prev_snaps - new_snaps) / prev_snaps
            if drop > 0.50:
                warnings.append(
                    f"Snapshot count dropped {drop:.0%} "
                    f"({prev_snaps} → {new_snaps})"
                )

        return {
            "passed": not critical,
            "critical": critical,
            "warnings": warnings,
            "first_ingest": False,
            "previous_run_id": prev_run_id,
            "previous_files": prev_files,
            "previous_snapshots": prev_snaps,
            "new_files": new_files,
            "new_snapshots": new_snaps,
        }

    def promote_run(self, run_id: str) -> ProjectRun:
        """
        Promote a draft run to active for its (project_id, ingest_source).

        1. Previous active run → 'superseded'
        2. project_active_runs pointer updated
        3. This run → 'active'
        """
        run = self._get_run(run_id)
        if not run:
            raise SnapshotRepoError(f"Run not found: {run_id}")

        with db_session() as session:
            session.execute(
                text("""
                    UPDATE project_runs
                    SET status = 'superseded'
                    WHERE project_id    = :pid
                      AND ingest_source = :isrc
                      AND status        = 'active'
                      AND run_id       != :rid
                """),
                {"pid": run.project_id, "isrc": run.ingest_source, "rid": run_id},
            )
            session.execute(
                text("""
                    INSERT INTO project_active_runs
                        (project_id, ingest_source, active_run_id, updated_at)
                    VALUES (:pid, :isrc, :rid, NOW())
                    ON CONFLICT (project_id, ingest_source)
                    DO UPDATE SET
                        active_run_id = EXCLUDED.active_run_id,
                        updated_at    = EXCLUDED.updated_at
                """),
                {"pid": run.project_id, "isrc": run.ingest_source, "rid": run_id},
            )
            session.execute(
                text("UPDATE project_runs SET status = 'active' WHERE run_id = :rid"),
                {"rid": run_id},
            )

        self.logger.info("Run promoted to active", extra={
            "run_id": run_id,
            "project_id": run.project_id,
            "ingest_source": run.ingest_source,
        })
        return self._get_run(run_id)

    def _get_run(self, run_id: str) -> Optional[ProjectRun]:
        with db_session() as session:
            row = session.execute(
                text("""
                    SELECT run_id, project_id, ingest_source, source_ref,
                           status, created_at, completed_at,
                           snapshot_count, file_count
                    FROM project_runs WHERE run_id = :rid
                """),
                {"rid": run_id},
            ).fetchone()
        if not row:
            return None
        return ProjectRun(
            run_id=row[0], project_id=row[1], ingest_source=row[2],
            source_ref=row[3], status=row[4], created_at=row[5],
            completed_at=row[6], snapshot_count=row[7], file_count=row[8],
        )

    def get_runs(self, project_id: str) -> List[Dict[str, Any]]:
        """List all runs for a project, newest first."""
        with db_session() as session:
            rows = session.execute(
                text("""
                    SELECT run_id, ingest_source, source_ref, status,
                           created_at, completed_at, snapshot_count, file_count
                    FROM project_runs
                    WHERE project_id = :pid
                    ORDER BY created_at DESC
                """),
                {"pid": project_id},
            ).fetchall()
        return [
            {
                "run_id": r[0],
                "ingest_source": r[1],
                "source_ref": r[2],
                "status": r[3],
                "created_at": r[4].isoformat() + "Z",
                "completed_at": r[5].isoformat() + "Z" if r[5] else None,
                "snapshot_count": r[6],
                "file_count": r[7],
            }
            for r in rows
        ]

    def purge_old_runs(self, project_id: str, keep_superseded: int = 2) -> int:
        """
        Delete superseded/failed runs beyond keep_superseded most recent.
        Snapshots deleted first (no DB-level cascade since run_id is TEXT).
        Returns count of runs purged.
        """
        with db_session() as session:
            rows = session.execute(
                text("""
                    SELECT run_id FROM project_runs
                    WHERE project_id = :pid
                      AND status IN ('superseded', 'failed')
                    ORDER BY created_at DESC
                    OFFSET :keep
                """),
                {"pid": project_id, "keep": keep_superseded},
            ).fetchall()

            if not rows:
                return 0

            old_ids = [r[0] for r in rows]
            session.execute(
                text("DELETE FROM snapshot_notebooks WHERE run_id = ANY(:ids)"),
                {"ids": old_ids},
            )
            session.execute(
                text("DELETE FROM project_runs WHERE run_id = ANY(:ids)"),
                {"ids": old_ids},
            )

        self.logger.info("Purged old runs", extra={
            "project_id": project_id,
            "purged": len(old_ids),
        })
        return len(old_ids)

    # =========================================================================
    # Snapshot write — scoped to run_id
    # =========================================================================

    def upsert(
        self,
        run_id: str,
        project_id: str,
        snapshot_type: str,
        source_file: str,
        field_values: Dict[str, Any],
        snapshot_id: Optional[str] = None,
        source_hash: Optional[str] = None,
    ) -> SnapshotRecord:
        """
        Write one snapshot within a run.

        Enforcement gate: snapshot_type must exist in snapshot_templates/.
        UNIQUE: (run_id, source_file, snapshot_type) — safe to retry within run.
        source_file must be a RELATIVE path from the project root.

        Raises:
            SnapshotRepoError: If snapshot_type not registered in templates.
        """
        # Schema enforcement — single source of truth
        if snapshot_type not in self.valid_snapshot_types:
            raise SnapshotRepoError(
                f"snapshot_type '{snapshot_type}' is not registered. "
                f"Valid types: {sorted(self.valid_snapshot_types)}. "
                f"Add app/schemas/snapshot_templates/{snapshot_type}.json to register it."
            )

        if snapshot_id is None:
            snapshot_id = str(uuid4())

        with db_session() as session:
            result = session.execute(
                text("""
                    INSERT INTO snapshot_notebooks
                        (snapshot_id, run_id, project_id, snapshot_type,
                         source_file, field_values, source_hash)
                    VALUES (:sid, :rid, :pid, :stype, :sf, :fv, :sh)
                    ON CONFLICT (run_id, source_file, snapshot_type)
                    DO UPDATE SET
                        field_values = EXCLUDED.field_values,
                        source_hash  = EXCLUDED.source_hash
                    RETURNING snapshot_id, run_id, field_values, source_hash, created_at
                """),
                {
                    "sid": snapshot_id, "rid": run_id,
                    "pid": project_id,  "stype": snapshot_type,
                    "sf":  source_file,
                    "fv":  json.dumps(field_values),
                    "sh":  source_hash,
                },
            )
            row = result.fetchone()

        self.logger.debug("Upserted snapshot", extra={
            "snapshot_type": snapshot_type,
            "source_file": source_file,
            "run_id": run_id,
        })
        return SnapshotRecord(
            snapshot_id=row[0], run_id=row[1],
            project_id=project_id, snapshot_type=snapshot_type,
            source_file=source_file, field_values=row[2],
            source_hash=row[3], created_at=row[4],
        )

    # =========================================================================
    # Queries — always through active run(s)
    # =========================================================================

    def _active_run_ids(
        self,
        session: Any,
        project_id: str,
        ingest_source: Optional[str] = None,
    ) -> List[str]:
        """Return active run_id list for project. Filter by source if given."""
        if ingest_source:
            rows = session.execute(
                text("""
                    SELECT active_run_id FROM project_active_runs
                    WHERE project_id = :pid AND ingest_source = :isrc
                """),
                {"pid": project_id, "isrc": ingest_source},
            ).fetchall()
        else:
            rows = session.execute(
                text("""
                    SELECT active_run_id FROM project_active_runs
                    WHERE project_id = :pid
                """),
                {"pid": project_id},
            ).fetchall()
        return [r[0] for r in rows]

    def _to_record(self, row: Any, project_id: str) -> SnapshotRecord:
        # row columns: snapshot_id, run_id, snapshot_type, source_file,
        #              field_values, source_hash, created_at
        return SnapshotRecord(
            snapshot_id=row[0], run_id=row[1],
            project_id=project_id,
            snapshot_type=row[2], source_file=row[3],
            field_values=row[4], source_hash=row[5], created_at=row[6],
        )

    def get_by_snapshot_id(
        self, snapshot_id: str, project_id: str
    ) -> Optional[SnapshotRecord]:
        with db_session() as session:
            row = session.execute(
                text("""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           field_values, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE snapshot_id = :sid AND project_id = :pid
                """),
                {"sid": snapshot_id, "pid": project_id},
            ).fetchone()
        return self._to_record(row, project_id) if row else None

    def get_by_project(
        self,
        project_id: str,
        ingest_source: Optional[str] = None,
    ) -> List[SnapshotRecord]:
        """All snapshots for a project via active run(s)."""
        with db_session() as session:
            run_ids = self._active_run_ids(session, project_id, ingest_source)
            if not run_ids:
                return []
            rows = session.execute(
                text("""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           field_values, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id = ANY(:rids)
                    ORDER BY source_file, snapshot_type
                """),
                {"rids": run_ids},
            ).fetchall()
        return [self._to_record(r, project_id) for r in rows]

    def get_by_type(
        self,
        project_id: str,
        snapshot_type: str,
        ingest_source: Optional[str] = None,
    ) -> List[SnapshotRecord]:
        """All snapshots of a specific type via active run(s)."""
        with db_session() as session:
            run_ids = self._active_run_ids(session, project_id, ingest_source)
            if not run_ids:
                return []
            rows = session.execute(
                text("""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           field_values, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id = ANY(:rids) AND snapshot_type = :stype
                    ORDER BY source_file
                """),
                {"rids": run_ids, "stype": snapshot_type},
            ).fetchall()
        return [self._to_record(r, project_id) for r in rows]

    def get_by_file(
        self,
        project_id: str,
        source_file: str,
        ingest_source: Optional[str] = None,
    ) -> List[SnapshotRecord]:
        """All snapshot types for a specific file via active run(s)."""
        with db_session() as session:
            run_ids = self._active_run_ids(session, project_id, ingest_source)
            if not run_ids:
                return []
            rows = session.execute(
                text("""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           field_values, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id = ANY(:rids) AND source_file = :sf
                    ORDER BY snapshot_type
                """),
                {"rids": run_ids, "sf": source_file},
            ).fetchall()
        return [self._to_record(r, project_id) for r in rows]

    # =========================================================================
    # Delete
    # =========================================================================

    def delete_by_file(self, project_id: str, source_file: str) -> int:
        """Delete snapshots for a file across all runs of a project."""
        with db_session() as session:
            result = session.execute(
                text("""
                    DELETE FROM snapshot_notebooks
                    WHERE project_id = :pid AND source_file = :sf
                    RETURNING snapshot_id
                """),
                {"pid": project_id, "sf": source_file},
            )
            count = len(result.fetchall())
        self.logger.info("Deleted file snapshots", extra={
            "project_id": project_id,
            "source_file": source_file,
            "deleted_count": count,
        })
        return count

    def delete_by_project(self, project_id: str) -> int:
        """Delete all snapshots, runs, and active pointers for a project."""
        with db_session() as session:
            result = session.execute(
                text("""
                    DELETE FROM snapshot_notebooks
                    WHERE project_id = :pid
                    RETURNING snapshot_id
                """),
                {"pid": project_id},
            )
            snap_count = len(result.fetchall())
            session.execute(
                text("DELETE FROM project_active_runs WHERE project_id = :pid"),
                {"pid": project_id},
            )
            session.execute(
                text("DELETE FROM project_runs WHERE project_id = :pid"),
                {"pid": project_id},
            )
        self.logger.info("Deleted project", extra={
            "project_id": project_id,
            "deleted_snapshots": snap_count,
        })
        return snap_count

    # =========================================================================
    # Listing
    # =========================================================================

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List projects with active run info grouped by project_id.
        Only projects with at least one active run are returned.
        """
        with db_session() as session:
            rows = session.execute(
                text("""
                    SELECT
                        par.project_id,
                        par.ingest_source,
                        pr.run_id,
                        pr.source_ref,
                        pr.snapshot_count,
                        pr.file_count,
                        pr.created_at,
                        pr.completed_at
                    FROM project_active_runs par
                    JOIN project_runs pr ON par.active_run_id = pr.run_id
                    ORDER BY par.project_id, par.ingest_source
                """)
            ).fetchall()

        projects: Dict[str, Dict] = {}
        for r in rows:
            pid = r[0]
            if pid not in projects:
                projects[pid] = {"project_id": pid, "sources": []}
            projects[pid]["sources"].append({
                "ingest_source": r[1],
                "run_id": r[2],
                "source_ref": r[3],
                "snapshot_count": r[4],
                "file_count": r[5],
                "ingested_at": r[6].isoformat() + "Z",
                "completed_at": r[7].isoformat() + "Z" if r[7] else None,
            })

        return list(projects.values())
