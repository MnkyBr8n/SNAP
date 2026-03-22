# snap/app/storage/db.py
"""
Purpose: Centralized DB engine management.
SQLite is primary (local, fast). Postgres is secondary (sync target).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

from app.config.settings import get_settings

_ENGINE: Engine | None = None         # SQLite primary
_PG_ENGINE: Engine | None = None      # Postgres secondary
_SessionFactory: sessionmaker | None = None


def get_sqlite_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        settings = get_settings()
        dsn = f"sqlite:///{settings.data_dir / 'snap.db'}"
        _ENGINE = create_engine(dsn, future=True)
    return _ENGINE


def get_postgres_engine() -> Engine | None:
    global _PG_ENGINE
    if _PG_ENGINE is None:
        settings = get_settings()
        dsn = getattr(settings, 'postgres_dsn', None)
        if not dsn:
            return None
        _PG_ENGINE = create_engine(
            dsn,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_recycle=1800,
            pool_timeout=30,
            future=True,
        )
    return _PG_ENGINE


def get_engine() -> Engine:
    """Returns SQLite engine. SQLite is always primary."""
    return get_sqlite_engine()


def get_session_factory() -> sessionmaker:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_sqlite_engine(),
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


@contextmanager
def db_session_postgres() -> Iterator[Session]:
    engine = get_postgres_engine()
    if engine is None:
        raise RuntimeError("Postgres not configured - set SNAP_POSTGRES_DSN")
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
