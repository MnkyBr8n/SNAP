"""
pg_sync.py — One-shot SQLite → Postgres sync.
Triggered manually via: python -m app.admin sync <project_id>
No background threads, no retry loops, no polling.
"""

from __future__ import annotations

from sqlalchemy import text

from app.storage.db import get_sqlite_engine, get_postgres_engine


def _ensure_postgres_schema(pg_conn) -> None:
    """Create tables in Postgres if they don't exist."""
    pg_conn.execute(text("""
        CREATE TABLE IF NOT EXISTS project_runs (
            run_id        TEXT PRIMARY KEY,
            project_id    TEXT NOT NULL,
            ingest_source TEXT NOT NULL DEFAULT 'local',
            source_ref    TEXT,
            status        TEXT NOT NULL DEFAULT 'running',
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at  TIMESTAMPTZ,
            snapshot_count INTEGER,
            file_count     INTEGER
        )
    """))
    pg_conn.execute(text("""
        CREATE TABLE IF NOT EXISTS project_active_runs (
            project_id    TEXT NOT NULL,
            ingest_source TEXT NOT NULL,
            active_run_id TEXT NOT NULL,
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (project_id, ingest_source)
        )
    """))
    pg_conn.execute(text("""
        CREATE TABLE IF NOT EXISTS snapshot_notebooks (
            snapshot_id   TEXT PRIMARY KEY,
            run_id        TEXT NOT NULL,
            project_id    TEXT NOT NULL,
            snapshot_type TEXT NOT NULL,
            source_file   TEXT NOT NULL,
            binary_data   BYTEA NOT NULL,
            source_hash   TEXT,
            content_hash  TEXT,
            simhash       BIGINT,
            minhash       TEXT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """))
    pg_conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_snapshot_content_hash
        ON snapshot_notebooks(content_hash)
    """))
    pg_conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_snapshot_run_project
        ON snapshot_notebooks(run_id, project_id)
    """))
    pg_conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshot_unique
        ON snapshot_notebooks(source_file, snapshot_type, content_hash)
    """))


def sync_project(project_id: str) -> dict:
    """
    Sync a project from SQLite to Postgres.
    One-shot: reads SQLite, diffs by content_hash, inserts missing records.
    Returns stats dict.
    """
    pg_engine = get_postgres_engine()
    if pg_engine is None:
        raise RuntimeError("Postgres not configured — set SNAP_POSTGRES_DSN")

    sqlite_engine = get_sqlite_engine()
    stats = {"runs_synced": 0, "snapshots_synced": 0, "snapshots_skipped": 0}

    with sqlite_engine.connect() as sqlite_conn, pg_engine.begin() as pg_conn:
        _ensure_postgres_schema(pg_conn)

        # --- Sync project_runs ---
        runs = sqlite_conn.execute(
            text("""
                SELECT run_id, project_id, ingest_source, source_ref,
                       status, created_at, completed_at, snapshot_count, file_count
                FROM project_runs WHERE project_id = :pid
            """),
            {"pid": project_id},
        ).fetchall()

        for r in runs:
            pg_conn.execute(text("""
                INSERT INTO project_runs
                    (run_id, project_id, ingest_source, source_ref,
                     status, created_at, completed_at, snapshot_count, file_count)
                VALUES (:rid, :pid, :isrc, :sref, :status, :cat, :coat, :sc, :fc)
                ON CONFLICT (run_id) DO NOTHING
            """), {
                "rid": r[0], "pid": r[1], "isrc": r[2], "sref": r[3],
                "status": r[4], "cat": r[5], "coat": r[6], "sc": r[7], "fc": r[8],
            })
            stats["runs_synced"] += 1

        # --- Sync snapshot_notebooks ---
        snapshots = sqlite_conn.execute(
            text("""
                SELECT snapshot_id, run_id, project_id, snapshot_type, source_file,
                       binary_data, source_hash, content_hash, simhash, minhash, created_at
                FROM snapshot_notebooks WHERE project_id = :pid
            """),
            {"pid": project_id},
        ).fetchall()

        for s in snapshots:
            exists = pg_conn.execute(
                text("SELECT 1 FROM snapshot_notebooks WHERE snapshot_id = :sid"),
                {"sid": s[0]},
            ).fetchone()

            if exists:
                stats["snapshots_skipped"] += 1
                continue

            pg_conn.execute(text("""
                INSERT INTO snapshot_notebooks
                    (snapshot_id, run_id, project_id, snapshot_type, source_file,
                     binary_data, source_hash, content_hash, simhash, minhash, created_at)
                VALUES (:sid, :rid, :pid, :stype, :sf, :bd, :sh, :ch, :simh, :minh, :cat)
                ON CONFLICT (snapshot_id) DO NOTHING
            """), {
                "sid": s[0], "rid": s[1], "pid": s[2], "stype": s[3], "sf": s[4],
                "bd": s[5], "sh": s[6], "ch": s[7], "simh": s[8], "minh": s[9], "cat": s[10],
            })
            stats["snapshots_synced"] += 1

        # --- Sync project_active_runs ---
        active = sqlite_conn.execute(
            text("""
                SELECT project_id, ingest_source, active_run_id, updated_at
                FROM project_active_runs WHERE project_id = :pid
            """),
            {"pid": project_id},
        ).fetchone()

        if active:
            pg_conn.execute(text("""
                INSERT INTO project_active_runs
                    (project_id, ingest_source, active_run_id, updated_at)
                VALUES (:pid, :isrc, :rid, :uat)
                ON CONFLICT (project_id, ingest_source)
                DO UPDATE SET active_run_id = EXCLUDED.active_run_id,
                              updated_at    = EXCLUDED.updated_at
            """), {
                "pid": active[0], "isrc": active[1], "rid": active[2], "uat": active[3],
            })

    return stats
