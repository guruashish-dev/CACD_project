"""SQLite persistence for the honeypot network.

One ``Database`` instance is shared by every honeypot thread, the intel
engine, the alert rules, and the dashboard.  All writes go through a single
connection guarded by a lock, which is plenty for demonstration traffic.

The database subscribes to the event bus, so *any* event that is emitted —
from the real honeypots or from the offline demo model — is persisted and
immediately queryable by the dashboard and the report generator.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from . import eventlog
from .config import data_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    details TEXT
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    username TEXT,
    password TEXT,
    outcome TEXT
);
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    command TEXT,
    response TEXT
);
CREATE TABLE IF NOT EXISTS intel (
    src_ip TEXT PRIMARY KEY,
    score INTEGER NOT NULL DEFAULT 0,
    classification TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    protocols_hit TEXT,
    first_seen TEXT,
    last_seen TEXT,
    details TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    src_ip TEXT
);
"""

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_conn_proto ON connections(protocol)",
    "CREATE INDEX IF NOT EXISTS idx_conn_ip ON connections(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_cred_ip ON credentials(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_alert_ts ON alerts(ts)",
]


class Database:
    def __init__(self, path: str | Path | None = None):
        if path is None:
            path = data_path("honey.db")
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            for idx in _INDEXES:
                self._conn.execute(idx)
            self._conn.commit()
        eventlog.subscribe(self._on_event)

    # ------------------------------------------------------------------
    # Event handling (subscriber)
    # ------------------------------------------------------------------
    def _on_event(self, event: dict) -> None:
        kind = event.get("kind")
        if kind == "connection":
            self.add_connection(
                event.get("ts"), event.get("protocol", ""), event.get("src_ip", ""),
                event.get("src_port"), event.get("dst_port"), event.get("details"),
            )
        elif kind == "credential":
            self.add_credential(
                event.get("ts"), event.get("protocol", ""), event.get("src_ip", ""),
                event.get("src_port"), event.get("username"), event.get("password"),
                event.get("outcome", "failed"),
            )
        elif kind == "command":
            self.add_command(
                event.get("ts"), event.get("protocol", ""), event.get("src_ip", ""),
                event.get("command"), event.get("response"),
            )
        elif kind == "alert":
            self.add_alert(
                event.get("ts"), event.get("severity", "info"), event.get("title", ""),
                event.get("detail"), event.get("src_ip"),
            )
        elif kind == "intel":
            self.upsert_intel(event)

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------
    def add_connection(self, ts, protocol, src_ip, src_port=None, dst_port=None, details=None):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO connections(ts, protocol, src_ip, src_port, dst_port, details)"
                " VALUES (?,?,?,?,?,?)",
                (ts, protocol, src_ip, src_port, dst_port,
                 json.dumps(details) if details else None),
            )
            self._conn.commit()
            return cur.lastrowid

    def add_credential(self, ts, protocol, src_ip, src_port, username, password, outcome="failed"):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO credentials(ts, protocol, src_ip, src_port, username, password, outcome)"
                " VALUES (?,?,?,?,?,?,?)",
                (ts, protocol, src_ip, src_port, username, password, outcome),
            )
            self._conn.commit()
            return cur.lastrowid

    def add_command(self, ts, protocol, src_ip, command, response=None):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO commands(ts, protocol, src_ip, command, response) VALUES (?,?,?,?,?)",
                (ts, protocol, src_ip, command, response),
            )
            self._conn.commit()
            return cur.lastrowid

    def add_alert(self, ts, severity, title, detail=None, src_ip=None):
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts(ts, severity, title, detail, src_ip) VALUES (?,?,?,?,?)",
                (ts, severity, title, detail, src_ip),
            )
            self._conn.commit()
            return cur.lastrowid

    def upsert_intel(self, event: dict) -> None:
        src_ip = event.get("src_ip", "")
        with self._lock:
            self._conn.execute(
                "INSERT INTO intel(src_ip, score, classification, attempts, protocols_hit,"
                " first_seen, last_seen, details)"
                " VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(src_ip) DO UPDATE SET"
                " score=excluded.score, classification=excluded.classification,"
                " attempts=excluded.attempts, protocols_hit=excluded.protocols_hit,"
                " last_seen=excluded.last_seen, details=excluded.details",
                (src_ip, event.get("risk", 0), event.get("classification", ""),
                 event.get("attempts", 0), event.get("protocols", ""),
                 event.get("first_seen"), event.get("last_seen"),
                 json.dumps(event.get("details", {})) if event.get("details") else None),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Readers (used by dashboard API + report generator)
    # ------------------------------------------------------------------
    def _query(self, sql, args=()):
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT 'connections', COUNT(*) FROM connections"
                " UNION ALL SELECT 'credentials', COUNT(*) FROM credentials"
                " UNION ALL SELECT 'commands', COUNT(*) FROM commands"
                " UNION ALL SELECT 'alerts', COUNT(*) FROM alerts"
                " UNION ALL SELECT 'sources', COUNT(DISTINCT src_ip) FROM connections"
            ).fetchall()
        return {name: count for name, count in rows}

    def protocol_counts(self) -> list[dict]:
        rows = self._query(
            "SELECT protocol, COUNT(*) AS n FROM connections GROUP BY protocol ORDER BY n DESC")
        return [{"protocol": r[0], "count": r[1]} for r in rows]

    def timeline(self, bucket="minute", minutes=10) -> list[dict]:
        """Attack-rate series; bucket in {minute, second, hour}."""
        step = {"second": "%Y-%m-%dT%H:%M:%S", "minute": "%Y-%m-%dT%H:%M",
                "hour": "%Y-%m-%dT%H"}[bucket]
        sql = f"""
            SELECT strftime('{step}', ts) AS b, COUNT(*) AS n
            FROM connections GROUP BY b ORDER BY b DESC LIMIT ?
        """
        rows = self._query(sql, (minutes * 60,))
        return [{"bucket": r[0], "count": r[1]} for r in reversed(rows)]

    def recent_connections(self, limit=100) -> list[dict]:
        rows = self._query(
            "SELECT id, ts, protocol, src_ip, src_port, dst_port, details"
            " FROM connections ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r, ["id", "ts", "protocol", "src_ip", "src_port",
                                      "dst_port", "details"]) for r in rows]

    def recent_credentials(self, limit=100) -> list[dict]:
        rows = self._query(
            "SELECT id, ts, protocol, src_ip, src_port, username, password, outcome"
            " FROM credentials ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r, ["id", "ts", "protocol", "src_ip", "src_port",
                                      "username", "password", "outcome"]) for r in rows]

    def recent_commands(self, limit=100) -> list[dict]:
        rows = self._query(
            "SELECT id, ts, protocol, src_ip, command, response"
            " FROM commands ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r, ["id", "ts", "protocol", "src_ip", "command", "response"])
                for r in rows]

    def recent_alerts(self, limit=100) -> list[dict]:
        rows = self._query(
            "SELECT id, ts, severity, title, detail, src_ip"
            " FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r, ["id", "ts", "severity", "title", "detail", "src_ip"])
                for r in rows]

    def intel_table(self, limit=200) -> list[dict]:
        rows = self._query(
            "SELECT src_ip, score, classification, attempts, protocols_hit, first_seen, last_seen"
            " FROM intel ORDER BY score DESC LIMIT ?", (limit,))
        return [self._row_to_dict(r, ["src_ip", "score", "classification", "attempts",
                                      "protocols_hit", "first_seen", "last_seen"])
                for r in rows]

    def top_sources(self, limit=10) -> list[dict]:
        rows = self._query(
            "SELECT src_ip, COUNT(*) AS attempts, COUNT(DISTINCT protocol) AS protos"
            " FROM connections GROUP BY src_ip ORDER BY attempts DESC LIMIT ?", (limit,))
        return [{"src_ip": r[0], "attempts": r[1], "protocols": r[2]} for r in rows]

    def classification_counts(self) -> list[dict]:
        rows = self._query(
            "SELECT classification, COUNT(*) AS n FROM intel"
            " WHERE classification IS NOT NULL AND classification != ''"
            " GROUP BY classification ORDER BY n DESC")
        return [{"classification": r[0], "count": r[1]} for r in rows]

    def all_connections(self):
        return self.recent_connections(10_000_000)

    @staticmethod
    def _row_to_dict(row, cols) -> dict:
        d = {}
        for i, c in enumerate(cols):
            v = row[i]
            if c == "details":
                try:
                    v = json.loads(v) if v else None
                except (TypeError, json.JSONDecodeError):
                    v = None
            d[c] = v
        return d

    def close(self) -> None:
        with self._lock:
            self._conn.close()
