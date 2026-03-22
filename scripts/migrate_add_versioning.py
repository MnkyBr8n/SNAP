#!/usr/bin/env python3
"""
Migration: Add file versioning and confidence/MinHash fields

Adds:
- file_versions table for git-like file versioning
- confidence_score, temperature, minhash_signature to snapshot_notebooks
- Supports both SQLite3 and PostgreSQL
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.storage.db import db_session
from app.config.settings import get_settings


def migrate():
    settings = get_settings()
    db_mode = getattr(settings, 'db_mode', 'sqlite')

    if db_mode == 'sqlite':
        blob_type = 'BLOB'
        timestamp_type = 'TIMESTAMP'
    else:
        blob_type = 'BYTEA'
        timestamp_type = 'TIMESTAMP WITH TIME ZONE'

    with db_session() as conn:
        print("Creating file_versions table...")
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS file_versions (
                version_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                source_file TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                created_at {timestamp_type} NOT NULL DEFAULT CURRENT_TIMESTAMP,
                run_id TEXT,
                parent_version_id TEXT,
                confidence_score REAL,
                minhash_signature {blob_type},
                sync_status TEXT DEFAULT 'local-only',
                security_level TEXT DEFAULT 'private',
                is_current BOOLEAN DEFAULT TRUE
            )
        """))

        print("Creating indexes on file_versions...")
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_file_versions_lookup
            ON file_versions(project_id, source_file, is_current)
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_file_versions_hash
            ON file_versions(content_hash)
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_file_versions_project
            ON file_versions(project_id, created_at DESC)
        """))

        print("Adding confidence/MinHash fields to snapshot_notebooks...")

        for column_name, column_def in [
            ('confidence_score', 'REAL DEFAULT 0.8'),
            ('temperature', 'REAL DEFAULT NULL'),
            ('minhash_signature', f'{blob_type} DEFAULT NULL'),
            ('validation_status', "TEXT DEFAULT 'auto-validated'"),
            ('validated_at', f'{timestamp_type} DEFAULT NULL'),
        ]:
            try:
                conn.execute(text(f"""
                    ALTER TABLE snapshot_notebooks
                    ADD COLUMN {column_name} {column_def}
                """))
                print(f"  Added {column_name}")
            except Exception:
                print(f"  {column_name} already exists")

        print("Migration complete!")


if __name__ == '__main__':
    migrate()
