"""SQLite database setup and session management."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.config import DATABASE_PATH
from app.models.alert import Base

logger = logging.getLogger(__name__)

Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

_database_url = f"sqlite:///{DATABASE_PATH.replace(os.sep, '/')}"

engine = create_engine(
    _database_url,
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    # This MVP predates a migration framework.  Apply only additive SQLite
    # changes before create_all so existing alert history is retained.
    inspector = inspect(engine)
    if "alerts" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("alerts")}
        with engine.begin() as connection:
            if "occurrences" not in columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1"))
            if "last_seen" not in columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN last_seen DATETIME"))
                connection.execute(text("UPDATE alerts SET last_seen = timestamp WHERE last_seen IS NULL"))
    if "trusted_devices" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("trusted_devices")}
        if "policy" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE trusted_devices ADD COLUMN policy TEXT NOT NULL DEFAULT '{\"suppressed_types\": []}'"))
    if "ai_threat_investigations" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("ai_threat_investigations")}
        if "language" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE ai_threat_investigations ADD COLUMN language VARCHAR(8) NOT NULL DEFAULT 'en'"))
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized at %s", DATABASE_PATH)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
