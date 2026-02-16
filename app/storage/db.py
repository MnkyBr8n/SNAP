# snap/app/storage/db.py
"""
Purpose: Centralized Postgres connection and session management.
Uses project_id partitioning strategy
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

from app.config.settings import get_settings

_ENGINE: Engine | None = None
_SessionFactory: sessionmaker | None = None


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        settings = get_settings()
        _ENGINE = create_engine(
            settings.postgres_dsn,
            pool_pre_ping=True,
            pool_size=5,           # Default connections in pool
            max_overflow=10,       # Extra connections allowed beyond pool_size
            pool_recycle=1800,     # Recycle connections after 30 minutes
            pool_timeout=30,       # Wait max 30s for connection from pool
            future=True,
        )
    return _ENGINE


def get_session_factory() -> sessionmaker:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            future=True,
        )
    return _SessionFactory


@contextmanager
def db_session() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()