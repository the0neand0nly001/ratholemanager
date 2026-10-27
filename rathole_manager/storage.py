import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.directory.chmod(0o700)
        self.path = self.directory / "manager.sqlite3"
        with self.connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS drafts (id TEXT PRIMARY KEY, value TEXT NOT NULL, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, level TEXT NOT NULL);
            """)
        if os.name != "nt":
            self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def get(self, name, default=None):
        with self.connection() as connection:
            row = connection.execute("SELECT value FROM settings WHERE name = ?", (name,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, name, value):
        with self.connection() as connection:
            connection.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (name, json.dumps(value)))

    def draft(self):
        with self.connection() as connection:
            row = connection.execute("SELECT id, value, created FROM drafts LIMIT 1").fetchone()
            return {"id": row["id"], **json.loads(row["value"]), "created": row["created"]} if row else None

    def save_draft(self, draft_id, value):
        with self.connection() as connection:
            connection.execute("DELETE FROM drafts")
            connection.execute("INSERT INTO drafts VALUES (?, ?, ?)", (draft_id, json.dumps(value), utc_now()))

    def clear_draft(self):
        with self.connection() as connection:
            connection.execute("DELETE FROM drafts")

    def event(self, action, detail, level="info"):
        with self.connection() as connection:
            connection.execute("INSERT INTO events (created, action, detail, level) VALUES (?, ?, ?, ?)", (utc_now(), action, detail, level))
            connection.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)")

    def events(self):
        with self.connection() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")]
