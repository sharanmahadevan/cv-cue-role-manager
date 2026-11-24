"""SQLite storage: rule sets (draft + published versions) and publish history."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

from . import rules as R

SCHEMA = """
CREATE TABLE IF NOT EXISTS rulesets (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    draft       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS versions (
    ruleset      TEXT NOT NULL,
    version      INTEGER NOT NULL,
    content      TEXT NOT NULL,
    published_at REAL NOT NULL,
    published_by TEXT NOT NULL,
    PRIMARY KEY (ruleset, version)
);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    ruleset     TEXT NOT NULL,
    version     INTEGER,
    started_at  REAL NOT NULL,
    finished_at REAL,
    started_by  TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS results (
    run_id      INTEGER NOT NULL,
    template_id INTEGER NOT NULL,
    role_name   TEXT NOT NULL,
    location_id INTEGER,
    ok          INTEGER NOT NULL,
    message     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS applied (
    template_id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    rulesets    TEXT NOT NULL,
    applied_at  REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.execute("PRAGMA journal_mode=WAL")

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.lastrowid or 0

    # ---------------------------------------------------------- rule sets
    def list_rulesets(self) -> list[dict]:
        rows = self._q("SELECT r.*, (SELECT MAX(version) FROM versions v WHERE v.ruleset = r.name) AS latest "
                       "FROM rulesets r ORDER BY name")
        return [self._ruleset(r) for r in rows]

    def get_ruleset(self, name: str) -> dict | None:
        rows = self._q("SELECT r.*, (SELECT MAX(version) FROM versions v WHERE v.ruleset = r.name) AS latest "
                       "FROM rulesets r WHERE name = ?", (name,))
        return self._ruleset(rows[0]) if rows else None

    def _ruleset(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["draft"] = R.normalize(json.loads(d["draft"]))
        latest = self.get_version(d["name"], d["latest"]) if d["latest"] else None
        d["published"] = latest["content"] if latest else None
        d["has_changes"] = latest is None or R.fingerprint(d["draft"]) != R.fingerprint(latest["content"])
        return d

    def create_ruleset(self, name: str, description: str, content: dict, by: str) -> None:
        now = time.time()
        self._x("INSERT INTO rulesets (name, description, draft, created_at, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?, ?)", (name, description, json.dumps(R.normalize(content)), now, now, by))

    def save_draft(self, name: str, content: dict, by: str, description: str | None = None) -> None:
        if description is None:
            self._x("UPDATE rulesets SET draft = ?, updated_at = ?, updated_by = ? WHERE name = ?",
                    (json.dumps(R.normalize(content)), time.time(), by, name))
        else:
            self._x("UPDATE rulesets SET draft = ?, description = ?, updated_at = ?, updated_by = ? WHERE name = ?",
                    (json.dumps(R.normalize(content)), description, time.time(), by, name))

    def delete_ruleset(self, name: str) -> None:
        self._x("DELETE FROM versions WHERE ruleset = ?", (name,))
        self._x("DELETE FROM rulesets WHERE name = ?", (name,))

    # ---------------------------------------------------------- versions
    def versions(self, name: str) -> list[dict]:
        rows = self._q("SELECT * FROM versions WHERE ruleset = ? ORDER BY version DESC", (name,))
        return [{**dict(r), "content": R.normalize(json.loads(r["content"]))} for r in rows]

    def get_version(self, name: str, version: int) -> dict | None:
        rows = self._q("SELECT * FROM versions WHERE ruleset = ? AND version = ?", (name, version))
        return {**dict(rows[0]), "content": R.normalize(json.loads(rows[0]["content"]))} if rows else None

    def add_version(self, name: str, content: dict, by: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM versions WHERE ruleset = ?",
                                   (name,)).fetchone()
            version = row[0]
            self._db.execute("INSERT INTO versions VALUES (?, ?, ?, ?, ?)",
                             (name, version, json.dumps(R.normalize(content)), time.time(), by))
            self._db.commit()
        return version

    # ---------------------------------------------------------- runs
    def start_run(self, kind: str, ruleset: str, version: int | None, by: str) -> int:
        return self._x("INSERT INTO runs (kind, ruleset, version, started_at, started_by) VALUES (?, ?, ?, ?, ?)",
                       (kind, ruleset, version, time.time(), by))

    def add_result(self, run_id: int, template_id: int, role_name: str, location_id: Any, ok: bool,
                   message: str = "") -> None:
        self._x("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, template_id, role_name, location_id, int(ok), message[:500]))

    def finish_run(self, run_id: int, summary: str) -> None:
        self._x("UPDATE runs SET finished_at = ?, summary = ? WHERE id = ?", (time.time(), summary, run_id))

    def get_run(self, run_id: int) -> dict | None:
        rows = self._q("SELECT * FROM runs WHERE id = ?", (run_id,))
        if not rows:
            return None
        run = dict(rows[0])
        run["results"] = [dict(r) for r in self._q("SELECT * FROM results WHERE run_id = ? ORDER BY rowid", (run_id,))]
        return run

    def recent_runs(self, limit: int = 50, ruleset: str | None = None) -> list[dict]:
        sql = ("SELECT r.*, (SELECT COUNT(*) FROM results x WHERE x.run_id = r.id AND x.ok = 1) AS ok_count, "
               "(SELECT COUNT(*) FROM results x WHERE x.run_id = r.id AND x.ok = 0) AS fail_count FROM runs r ")
        args: tuple = ()
        if ruleset:
            sql += "WHERE ruleset = ? "
            args = (ruleset,)
        return [dict(r) for r in self._q(sql + "ORDER BY id DESC LIMIT ?", (*args, limit))]

    # ---------------------------------------------------------- what was last pushed to each role profile
    def record_applied(self, template_id: int, fingerprint: str, rulesets: dict) -> None:
        """Remember the combined rules last pushed, so an older combination reads as "update pending"."""
        self._x("INSERT OR REPLACE INTO applied VALUES (?, ?, ?, ?)",
                (template_id, fingerprint, json.dumps(rulesets), time.time()))

    def applied_fingerprints(self) -> dict[int, str]:
        return {r["template_id"]: r["fingerprint"] for r in self._q("SELECT template_id, fingerprint FROM applied")}
