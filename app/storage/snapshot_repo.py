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
from app.extraction.binary_packer import BinaryPacker, BinaryUnpacker, type_id as fnv_type_id, build_field_reverse_map


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
    source_file: str
    field_values: Dict[str, Any]
    source_hash: Optional[str]
    created_at: datetime


# Module-level caches — reset on process restart
_table_ensured = False
_field_configs_cache: Dict[str, FieldConfig] = {}
_valid_snapshot_types_cache: set = set()
_master_schema_cache: dict = {}


class SnapshotRepository:
    def __init__(self) -> None:
        global _table_ensured, _field_configs_cache, _valid_snapshot_types_cache, _master_schema_cache
        self.logger = get_logger("storage.snapshot_repo")

        if not _table_ensured:
            self._ensure_table()
            _table_ensured = True

        if not _field_configs_cache:
            self._load_field_configs()
            _field_configs_cache = self.field_configs
            _valid_snapshot_types_cache = self.valid_snapshot_types
            _master_schema_cache = self.master_schema
        else:
            self.field_configs = _field_configs_cache
            self.valid_snapshot_types = _valid_snapshot_types_cache
            self.master_schema = _master_schema_cache

        # Build reverse map for unpacker: fnv1a(field_name) → field_name
        all_field_names = [
            fdef["field_id"]
            for fields in self.master_schema.get("field_id_registry", {}).values()
            for fdef in fields
        ]
        self._unpacker = BinaryUnpacker()
        self._unpacker.set_field_map(build_field_reverse_map(all_field_names))

    # =========================================================================
    # Schema loading
    # =========================================================================

    def _load_field_configs(self) -> None:
        """
        Build valid_snapshot_types from snapshot_templates/*.json.
        Build field_configs from master_notebook.yaml.(source of truth)

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
            self.master_schema = yaml.safe_load(f)

        self.field_configs: Dict[str, FieldConfig] = {}
        for _stype, fields in self.master_schema.get("field_id_registry", {}).items():
            for field_def in fields:
                fid = field_def["field_id"]
                self.field_configs[fid] = FieldConfig(
                    field_id=fid,
                    value_type=field_def["value_type"],
                    multi=field_def["multi"],
                    required=field_def["required"],
                )

    def _build_field_id_maps(self) -> tuple:
        """Build field name <-> ID mappings from cached schema."""
        name_to_id = {}
        id_to_name = {}
        field_id = 1

        field_registry = self.master_schema.get("field_id_registry", {})
        for category in sorted(field_registry.keys()):
            for field_def in field_registry[category]:
                field_name = field_def["field_id"]
                name_to_id[field_name] = field_id
                id_to_name[field_id] = field_name
                field_id += 1

        return name_to_id, id_to_name

    # =========================================================================
    # DDL — safe to run on every startup
    # =========================================================================


    def _get_ddl_for_db(self, is_postgres: bool) -> dict:
        """Return database-specific DDL types."""
        return {
            'timestamp': 'TIMESTAMPTZ' if is_postgres else 'TEXT',
            'now': 'NOW()' if is_postgres else 'CURRENT_TIMESTAMP',
            'bytea': 'BYTEA' if is_postgres else 'BLOB',
        }


    def _ensure_table(self) -> None:
        engine = get_engine()
        is_postgres = str(engine.url).startswith("postgresql")
        ddl = self._get_ddl_for_db(is_postgres)

        with engine.begin() as conn:
            # PostgreSQL advisory lock only for PostgreSQL
            if is_postgres:
                conn.execute(text("SELECT pg_advisory_xact_lock(19700101)"))

            # project_runs table
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS project_runs (
                    run_id        TEXT PRIMARY KEY,
                    project_id    TEXT NOT NULL,
                    ingest_source TEXT NOT NULL DEFAULT 'local',
                    source_ref    TEXT,
                    status        TEXT NOT NULL DEFAULT 'running',
                    created_at    {ddl['timestamp']} NOT NULL DEFAULT {ddl['now']},
                    completed_at  {ddl['timestamp']},
                    snapshot_count INTEGER,
                    file_count     INTEGER
                )
            """))

            # project_active_runs table  
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS project_active_runs (
                    project_id    TEXT NOT NULL,
                    ingest_source TEXT NOT NULL,
                    active_run_id TEXT NOT NULL,
                    updated_at    {ddl['timestamp']} NOT NULL DEFAULT {ddl['now']},
                    PRIMARY KEY (project_id, ingest_source)
                )
            """))

            # snapshot_notebooks table
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS snapshot_notebooks (
                    snapshot_id   TEXT PRIMARY KEY,
                    run_id        TEXT NOT NULL,
                    project_id    TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    source_file   TEXT NOT NULL,
                    binary_data   {ddl['bytea']} NOT NULL,
                    field_values  TEXT NOT NULL,
                    source_hash   TEXT,
                    content_hash  TEXT,
                    simhash       BIGINT,
                    minhash       TEXT,
                    created_at    {ddl['timestamp']} NOT NULL DEFAULT {ddl['now']}
                )
            """))

            # Migrate existing tables: add hash columns if missing
            try:
                if is_postgres:
                    conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN IF NOT EXISTS content_hash TEXT"))
                    conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN IF NOT EXISTS simhash BIGINT"))
                    conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN IF NOT EXISTS minhash TEXT"))
                else:
                    # SQLite: check columns exist, add if missing
                    pragma = conn.execute(text("PRAGMA table_info(snapshot_notebooks)")).fetchall()
                    existing = {row[1] for row in pragma}
                    if 'binary_data' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN binary_data BLOB"))
                    if 'content_hash' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN content_hash TEXT"))
                    if 'source_hash' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN source_hash TEXT"))
                    if 'simhash' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN simhash BIGINT"))
                    if 'minhash' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN minhash TEXT"))
                    if 'field_values' not in existing:
                        conn.execute(text("ALTER TABLE snapshot_notebooks ADD COLUMN field_values TEXT"))
    
            except Exception:  # noqa: BLE001 — column already exists is expected
                pass

            # Indexes for hash-based lookups
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_content_hash
                ON snapshot_notebooks(content_hash)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_simhash
                ON snapshot_notebooks(simhash)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_snapshot_run_project
                ON snapshot_notebooks(run_id, project_id)
            """))
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshot_unique
                ON snapshot_notebooks(source_file, snapshot_type, content_hash)
            """))

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
            "event_code": "R001",
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
                        completed_at   = CURRENT_TIMESTAMP,
                        snapshot_count = :sc,
                        file_count     = :fc
                    WHERE run_id = :rid
                """),
                {"rid": run_id, "sc": snapshot_count, "fc": file_count},
            )
        run = self._get_run(run_id)
        self.logger.info("Run completed", extra={
            "event_code": "R002",
            "run_id": run_id,
            "snapshot_count": snapshot_count,
            "file_count": file_count,
        })
        return run

    def fail_run(self, run_id: str) -> None:
        """Mark run as 'failed'. Its snapshots are never queried."""
        with db_session() as session:
            session.execute(
                text("""
                    UPDATE project_runs
                    SET status = 'failed', completed_at = CURRENT_TIMESTAMP
                    WHERE run_id = :rid
                """),
                {"rid": run_id},
            )
        self.logger.warning("Run failed — snapshots isolated", extra={
            "event_code": "R003",
            "run_id": run_id,
        })

    def validate_run(self, run_id: str) -> Dict[str, Any]:
        """
        Hash-based validation comparing current run vs previous active run.

        Auto-promotes if content_hashes match exactly (no changes detected).
        Flags for review if hashes differ (content changed).
        """
        run = self._get_run(run_id)
        if not run:
            return {"passed": False, "critical": True, "warnings": ["run not found"]}

        # Get previous active run for this project + source
        previous_run = self.get_active_run(run.project_id, run.ingest_source)
        if not previous_run:
            # First run - auto-approve
            return {
                "passed": True,
                "critical": False,
                "warnings": ["first run for this project+source"],
                "new_files": run.file_count or 0,
                "new_snapshots": run.snapshot_count or 0,
            }

        # Get content_hashes from both runs
        with db_session() as session:
            # Previous run hashes
            prev_hashes_result = session.execute(
                text("""
                    SELECT source_file, snapshot_type, content_hash
                    FROM snapshot_notebooks
                    WHERE run_id = :rid AND content_hash IS NOT NULL
                """),
                {"rid": previous_run.run_id},
            )
            prev_hashes = {
                (row[0], row[1]): row[2]
                for row in prev_hashes_result.fetchall()
            }

            # Current run hashes
            curr_hashes_result = session.execute(
                text("""
                    SELECT source_file, snapshot_type, content_hash
                    FROM snapshot_notebooks
                    WHERE run_id = :rid AND content_hash IS NOT NULL
                """),
                {"rid": run_id},
            )
            curr_hashes = {
                (row[0], row[1]): row[2]
                for row in curr_hashes_result.fetchall()
            }

        # Compare
        warnings = []
        prev_keys = set(prev_hashes.keys())
        curr_keys = set(curr_hashes.keys())

        new_snapshots = curr_keys - prev_keys
        deleted_snapshots = prev_keys - curr_keys
        common_snapshots = prev_keys & curr_keys

        changed_snapshots = {
            key for key in common_snapshots
            if prev_hashes[key] != curr_hashes[key]
        }

        if new_snapshots:
            warnings.append(f"{len(new_snapshots)} new snapshots")
        if deleted_snapshots:
            warnings.append(f"{len(deleted_snapshots)} deleted snapshots")
        if changed_snapshots:
            warnings.append(f"{len(changed_snapshots)} changed snapshots")

        # Auto-approve if exactly identical
        critical = bool(new_snapshots or deleted_snapshots or changed_snapshots)

        return {
            "passed": True,
            "critical": critical,
            "warnings": warnings,
            "new_files": run.file_count or 0,
            "new_snapshots": run.snapshot_count or 0,
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
                    VALUES (:pid, :isrc, :rid, CURRENT_TIMESTAMP)
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
                "created_at": (r[4] if isinstance(r[4], str) else r[4].isoformat() + "Z"),
                "completed_at": (r[5] if isinstance(r[5], str) else r[5].isoformat() + "Z") if r[5] else None,
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
            _id_params = {f"id{i}": v for i, v in enumerate(old_ids)}
            _in = ",".join(f":id{i}" for i in range(len(old_ids)))
            session.execute(
                text(f"DELETE FROM snapshot_notebooks WHERE run_id IN ({_in})"),
                _id_params,
            )
            session.execute(
                text(f"DELETE FROM project_runs WHERE run_id IN ({_in})"),
                _id_params,
            )

        self.logger.info("Purged old runs", extra={
            "project_id": project_id,
            "purged": len(old_ids),
        })
        return len(old_ids)

    def delete_run(self, run_id: str) -> Dict[str, Any]:
        """Delete run and all its snapshots."""
        run = self._get_run(run_id)
        if not run:
            raise SnapshotRepoError(f"Run not found: {run_id}")

        with db_session() as session:
            snap_count = session.execute(
                text("DELETE FROM snapshot_notebooks WHERE run_id = :rid RETURNING snapshot_id"),
                {"rid": run_id}
            ).rowcount

            session.execute(text("DELETE FROM project_runs WHERE run_id = :rid"), {"rid": run_id})
            session.execute(
                text("DELETE FROM project_active_runs WHERE active_run_id = :rid"),
                {"rid": run_id}
            )

        self.logger.info("Deleted run", extra={"run_id": run_id, "snapshots_deleted": snap_count})
        return {"run_id": run_id, "snapshots_deleted": snap_count}

    def delete_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
        """Delete single snapshot."""
        with db_session() as session:
            row = session.execute(
                text("DELETE FROM snapshot_notebooks WHERE snapshot_id = :sid RETURNING run_id, source_file"),
                {"sid": snapshot_id}
            ).fetchone()

        if not row:
            raise SnapshotRepoError(f"Snapshot not found: {snapshot_id}")

        self.logger.info("Deleted snapshot", extra={"snapshot_id": snapshot_id})
        return {"snapshot_id": snapshot_id, "run_id": row[0], "source_file": row[1]}

    def revalidate_run(self, run_id: str) -> Dict[str, Any]:
        """Re-run hash-based validation against previous active run."""
        validation = self.validate_run(run_id)

        self.logger.info("Revalidated run", extra={"run_id": run_id, "critical": validation.get("critical")})
        return validation

    def update_snapshot(self, snapshot_id: str, field_values: Dict[str, Any]) -> SnapshotRecord:
        """Update snapshot binary_data."""
        # Get snapshot type and hashes for repacking
        with db_session() as session:
            existing = session.execute(
                text("SELECT snapshot_type, content_hash, simhash, minhash FROM snapshot_notebooks WHERE snapshot_id = :sid"),
                {"sid": snapshot_id}
            ).fetchone()

            if not existing:
                raise SnapshotRepoError(f"Snapshot not found: {snapshot_id}")

            # Repack to binary
            packer = BinaryPacker()

            content_hash_bytes = bytes.fromhex(existing[1]) if existing[1] else bytes(32)
            simhash_int = int(existing[2], 16) if existing[2] else 0
            minhash_list = [int(x, 16) for x in existing[3].split(',')] if existing[3] else [0] * 128
            snapshot_type_int = fnv_type_id(existing[0])

            binary_data = packer.pack(snapshot_type_int, field_values, content_hash_bytes, simhash_int, minhash_list)

            row = session.execute(
                text("""
                    UPDATE snapshot_notebooks
                    SET binary_data = :bd
                    WHERE snapshot_id = :sid
                    RETURNING snapshot_id, run_id, project_id, snapshot_type, source_file, source_hash, created_at
                """),
                {"sid": snapshot_id, "bd": binary_data}
            ).fetchone()

        self.logger.info("Updated snapshot", extra={"snapshot_id": snapshot_id})
        return SnapshotRecord(
            snapshot_id=row[0], run_id=row[1], project_id=row[2],
            snapshot_type=row[3], source_file=row[4], field_values=field_values,
            source_hash=row[5], created_at=row[6]
        )

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
        content_hash: Optional[str] = None,
        simhash: Optional[str] = None,
        minhash: Optional[str] = None,
    ) -> SnapshotRecord:
        """
        Write one snapshot within a run.

        Enforcement gate: snapshot_type must exist in snapshot_templates/.
        UNIQUE: (run_id, source_file, snapshot_type) — safe to retry within run.
        source_file must be a RELATIVE path from the project root.

        Raises:
            SnapshotRepoError: If snapshot_type not registered in templates.
        Create or update snapshot for (project_id, source_file, snapshot_type).
        
        Each file can have multiple snapshots (one per category).
        Idempotency: same (project_id, source_file, snapshot_type) will not create duplicates.
        
        Args:
            project_id: unique project identifier
            snapshot_type: One of 14 categories (file_metadata, imports, etc.)
            source_file: source file path
            field_values: Dict with field_id -> value mappings (direct, not wrapped)
            snapshot_id: Optional pre-generated UUID (for logging correlation)
        
        Returns:
            SnapshotRecord with final state
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

        # Pack to binary format
        packer = BinaryPacker()

        # Convert hashes to binary format
        content_hash_bytes = bytes.fromhex(content_hash) if content_hash else bytes(32)
        simhash_unsigned = int(simhash, 16) if simhash else 0
        minhash_list = [int(x, 16) for x in minhash.split(',')] if minhash else [0] * 128

        snapshot_type_int = fnv_type_id(snapshot_type)

        binary_data = packer.pack(
            snapshot_type_int,
            field_values,
            content_hash_bytes,
            simhash_unsigned,
            minhash_list
        )

        # Convert unsigned 64-bit to signed for PostgreSQL BIGINT
        simhash_signed = simhash_unsigned
        if simhash_unsigned >= 2**63:
            simhash_signed = simhash_unsigned - 2**64

        with db_session() as session:
            result = session.execute(
                text("""
                    INSERT INTO snapshot_notebooks
                        (snapshot_id, run_id, project_id, snapshot_type,
                         source_file, binary_data, source_hash, content_hash, simhash, minhash, field_values)
                    VALUES (:sid, :rid, :pid, :stype, :sf, :bd, :sh, :ch, :simh, :minh, :fv)
                    ON CONFLICT (source_file, snapshot_type, content_hash)
                    DO NOTHING
                    RETURNING snapshot_id, run_id, source_hash, content_hash, created_at
                """),
                {
                    "sid": snapshot_id, "rid": run_id,
                    "pid": project_id,  "stype": snapshot_type,
                    "sf":  source_file,
                    "bd":  binary_data,
                    "sh":  source_hash,
                    "ch":  content_hash,
                    "simh": simhash_signed,
                    "minh": ','.join(str(x) for x in minhash_list),
                    "fv": json.dumps(field_values),
                },
            )
            row = result.fetchone()

            if row is None:
                # Duplicate — file unchanged, update run_id and fetch existing row
                self.logger.info("Snapshot unchanged", extra={
                    "event_code": "S002",
                    "source_file": source_file,
                    "snapshot_type": snapshot_type,
                    "content_hash": content_hash,
                    "run_id": run_id,
                })
                session.execute(
                    text("""
                        UPDATE snapshot_notebooks SET run_id = :rid
                        WHERE source_file = :sf
                          AND snapshot_type = :stype
                          AND content_hash = :ch
                    """),
                    {"rid": run_id, "sf": source_file, "stype": snapshot_type, "ch": content_hash},
                )
                row = session.execute(
                    text("""
                        SELECT snapshot_id, run_id, source_hash, content_hash, created_at
                        FROM snapshot_notebooks
                        WHERE source_file = :sf
                          AND snapshot_type = :stype
                          AND content_hash = :ch
                    """),
                    {"sf": source_file, "stype": snapshot_type, "ch": content_hash},
                ).fetchone()
                if row is None:
                    self.logger.error("Snapshot fetch after conflict returned nothing", extra={
                        "event_code": "S003",
                        "source_file": source_file,
                        "snapshot_type": snapshot_type,
                        "content_hash": content_hash,
                    })
                    raise RuntimeError(f"S003: snapshot upsert failed for {source_file} / {snapshot_type}")
            else:
                self.logger.info("Snapshot inserted", extra={
                    "event_code": "S001",
                    "source_file": source_file,
                    "snapshot_type": snapshot_type,
                    "run_id": run_id,
                })

        return SnapshotRecord(
            snapshot_id=row[0], run_id=row[1],
            project_id=project_id, snapshot_type=snapshot_type,
            source_file=source_file, field_values=field_values,
            source_hash=row[2], created_at=row[4],
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
        #              binary_data, source_hash, created_at
        try:
            field_values = self._unpacker.unpack(bytes(row[4]))["field_values"]
        except (ValueError, KeyError):
            field_values = {}
        return SnapshotRecord(
            snapshot_id=row[0], run_id=row[1],
            project_id=project_id,
            snapshot_type=row[2], source_file=row[3],
            field_values=field_values, source_hash=row[5], created_at=row[6],
        )

    def get_by_snapshot_id(
        self, snapshot_id: str, project_id: str
    ) -> Optional[SnapshotRecord]:
        with db_session() as session:
            row = session.execute(
                text("""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           binary_data, source_hash, created_at
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
            _rid_params = {f"rid{i}": v for i, v in enumerate(run_ids)}
            _in = ",".join(f":rid{i}" for i in range(len(run_ids)))
            rows = session.execute(
                text(f"""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           binary_data, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id IN ({_in})
                    ORDER BY source_file, snapshot_type
                """),
                _rid_params,
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
                text(f"""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           binary_data, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id IN ({",".join(f":rid{i}" for i in range(len(run_ids)))}) AND snapshot_type = :stype
                    ORDER BY source_file
                """),
                {**{f"rid{i}": v for i, v in enumerate(run_ids)}, "stype": snapshot_type},
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
                text(f"""
                    SELECT snapshot_id, run_id, snapshot_type, source_file,
                           binary_data, source_hash, created_at
                    FROM snapshot_notebooks
                    WHERE run_id IN ({",".join(f":rid{i}" for i in range(len(run_ids)))}) AND source_file = :sf
                    ORDER BY snapshot_type
                """),
                {**{f"rid{i}": v for i, v in enumerate(run_ids)}, "sf": source_file},
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
                "ingested_at": (r[6] if isinstance(r[6], str) else r[6].isoformat() + "Z"),
                "completed_at": (r[7] if isinstance(r[7], str) else r[7].isoformat() + "Z") if r[7] else None,
            })

        return list(projects.values())
