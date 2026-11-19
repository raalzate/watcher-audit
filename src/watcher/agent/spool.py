"""Local durable queue (RNF-05) + agent state. Events are chained when they enter the spool."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from ..common.chain import GENESIS, seal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS evidence_queue (sha256 TEXT PRIMARY KEY, size INTEGER, queued_at REAL);
CREATE TABLE IF NOT EXISTS evidence_done (sha256 TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS file_index (path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime REAL, captured INTEGER);
CREATE INDEX IF NOT EXISTS file_index_sha ON file_index(sha256);
"""


class Spool:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self.count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # --- key/value state -------------------------------------------------
    def kv_get(self, k: str, default: str | None = None) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def kv_set(self, k: str, v: str) -> None:
        with self.lock:
            self.db.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    # --- event chain -----------------------------------------------------
    def head(self) -> dict:
        raw = self.kv_get("head")
        return json.loads(raw) if raw else {"seq": 0, "hash": GENESIS}

    def append(self, event: dict) -> dict:
        with self.lock:
            head = self.head()
            event["seq"] = head["seq"] + 1
            seal(event, head["hash"])
            self.db.execute("BEGIN")
            self.db.execute("INSERT INTO events(seq, body) VALUES(?,?)", (event["seq"], json.dumps(event)))
            self.db.execute("INSERT INTO kv(k,v) VALUES('head',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                            (json.dumps({"seq": event["seq"], "hash": event["integrity"]["event_hash"]}),))
            self.db.execute("COMMIT")
            self.count += 1
        return event

    def pending(self, limit: int) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT body FROM events ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def ack(self, up_to_seq: int) -> None:
        with self.lock:
            self.db.execute("DELETE FROM events WHERE seq<=?", (up_to_seq,))
            self.count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def rechain(self, server_seq: int, server_hash: str) -> int:
        """Re-number and re-seal unconfirmed events on top of the server's chain head."""
        with self.lock:
            rows = self.db.execute("SELECT body FROM events ORDER BY seq").fetchall()
            seq, prev = server_seq, server_hash
            self.db.execute("BEGIN")
            self.db.execute("DELETE FROM events")
            for (body,) in rows:
                ev = json.loads(body)
                seq += 1
                ev["seq"] = seq
                seal(ev, prev)
                prev = ev["integrity"]["event_hash"]
                self.db.execute("INSERT INTO events(seq, body) VALUES(?,?)", (seq, json.dumps(ev)))
            self.db.execute("INSERT INTO kv(k,v) VALUES('head',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                            (json.dumps({"seq": seq, "hash": prev}),))
            self.db.execute("COMMIT")
            return len(rows)

    # --- evidence queue --------------------------------------------------
    def evidence_known(self, sha: str) -> bool:
        with self.lock:
            return self.db.execute(
                "SELECT 1 FROM evidence_queue WHERE sha256=? UNION SELECT 1 FROM evidence_done WHERE sha256=?",
                (sha, sha)).fetchone() is not None

    def evidence_enqueue(self, sha: str, size: int) -> None:
        with self.lock:
            self.db.execute("INSERT OR IGNORE INTO evidence_queue VALUES(?,?,?)", (sha, size, time.time()))

    def evidence_pending(self, limit: int = 20) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT sha256 FROM evidence_queue ORDER BY queued_at LIMIT ?", (limit,))]

    def evidence_finish(self, sha: str, uploaded: bool) -> None:
        with self.lock:
            self.db.execute("DELETE FROM evidence_queue WHERE sha256=?", (sha,))
            if uploaded:
                self.db.execute("INSERT OR IGNORE INTO evidence_done VALUES(?)", (sha,))

    # --- file index (last known hash per path) ----------------------------
    def index_get(self, path: str):
        with self.lock:
            return self.db.execute(
                "SELECT sha256, size, mtime, captured FROM file_index WHERE path=?", (path,)).fetchone()

    def index_put(self, path: str, sha: str | None, size: int, mtime: float, captured: bool) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO file_index VALUES(?,?,?,?,?)",
                            (path, sha, size, mtime, int(captured)))

    def index_del(self, path: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM file_index WHERE path=?", (path,))

    def index_by_hash(self, sha: str, exclude: str) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT path FROM file_index WHERE sha256=? AND path<>?", (sha, exclude))]

    def index_children(self, prefix: str) -> list[tuple]:
        """Rows whose path lies under directory `prefix` (prefix must end with a separator)."""
        with self.lock:
            return self.db.execute(
                "SELECT path, sha256, size, mtime, captured FROM file_index WHERE substr(path,1,?)=?",
                (len(prefix), prefix)).fetchall()

    def close(self) -> None:
        with self.lock:
            self.db.close()
