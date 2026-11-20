"""Central repository: event store, evidence repository, integrity, alerts.

Append-only by construction: the API has no update/delete for events or evidence,
and SQLite triggers reject UPDATE/DELETE on the audit tables. See docs/LIMITACIONES.md
for what this does and does not protect against (real WORM needs immutable storage underneath).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from ..common.chain import GENESIS, compute_hash, iso, verify

_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
IMMUTABLE = ("events", "evidence", "checkpoints", "evidence_access", "admin_actions")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY, hostname TEXT, platform TEXT, os_version TEXT, agent_version TEXT,
  api_key_hash TEXT UNIQUE, enrolled_at TEXT, last_seen REAL, reported_state TEXT, enabled INTEGER,
  detail TEXT, spool_depth INTEGER, clock_skew REAL, last_seq INTEGER DEFAULT 0, last_hash TEXT,
  desired_enabled INTEGER, desired_rev INTEGER DEFAULT 0, desired_by TEXT,
  disconnected INTEGER DEFAULT 0, stopped INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, endpoint_id TEXT, seq INTEGER, ts TEXT,
  received_at TEXT, event_type TEXT, user TEXT, process TEXT, interpreter TEXT, path TEXT, sha256 TEXT,
  session_id TEXT, evidence_sha256 TEXT, event_hash TEXT, previous_hash TEXT, body TEXT,
  UNIQUE(endpoint_id, seq));
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_type ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS events_evidence ON events(evidence_sha256);
CREATE TABLE IF NOT EXISTS evidence (
  sha256 TEXT PRIMARY KEY, size INTEGER, stored_at TEXT, endpoint_id TEXT, rel_path TEXT);
CREATE TABLE IF NOT EXISTS evidence_access (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, who TEXT, sha256 TEXT, action TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, who TEXT, action TEXT, detail TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, endpoint_id TEXT, seq INTEGER, event_hash TEXT, signature TEXT);
CREATE TABLE IF NOT EXISTS sessions (
  endpoint_id TEXT, session_id TEXT, provider TEXT, started TEXT, ended TEXT, user TEXT, remote TEXT,
  detail TEXT, PRIMARY KEY(endpoint_id, session_id));
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, endpoint_id TEXT, kind TEXT, severity TEXT, message TEXT,
  event_id TEXT, acknowledged_at TEXT, acknowledged_by TEXT);
"""

# event types that always raise an alert when they reach the repository
EVENT_ALERTS = {
    "TAMPER_DETECTED": ("critical", "El agente detectó una alteración de su propio código"),
    "CHAIN_RESYNC": ("critical", "La cadena local del agente no coincidía con el repositorio (cola local perdida o alterada)"),
    "AGENT_UNCLEAN_SHUTDOWN": ("high", "El agente terminó sin apagado limpio (proceso terminado, fallo o corte de energía)"),
    "AGENT_STOPPED": ("high", "El agente fue detenido"),
    "AUDIT_STOPPED": ("high", "La auditoría fue desactivada"),
    "EVENTS_DROPPED": ("high", "El agente descartó eventos por cola local llena"),
    "CONFIG_CHANGED": ("medium", "La configuración del agente cambió"),
    "SOURCE_FAILED": ("medium", "Una fuente de auditoría no pudo iniciar o falló"),
}


class Store:
    def __init__(self, data_dir: Path | str):
        self.dir = Path(data_dir)
        self.evidence_dir = self.dir / "evidence"
        (self.evidence_dir / "tmp").mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.dir / "audit.db", check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)
        for table in IMMUTABLE:
            for op in ("UPDATE", "DELETE"):
                self.db.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_{op.lower()} BEFORE {op} ON {table} "
                    f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
        self.secrets = self._load_secrets()

    def _load_secrets(self) -> dict:
        path = self.dir / "server_secrets.json"
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        changed = False
        for key, env in (("admin_password", "WATCHER_ADMIN_PASSWORD"), ("enroll_token", "WATCHER_ENROLL_TOKEN"),
                         ("checkpoint_key", None)):
            if env and os.environ.get(env):
                data[key] = os.environ[env]
            elif key not in data:
                data[key] = secrets.token_urlsafe(24)
                changed = True
        if changed:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({k: data[k] for k in ("admin_password", "enroll_token", "checkpoint_key")}, f, indent=2)
        return data

    # ------------------------------------------------------------ helpers
    def q(self, sql: str, params=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    def x(self, sql: str, params=()) -> None:
        with self.lock:
            self.db.execute(sql, params)

    def alert(self, endpoint_id, kind, severity, message, event_id=None) -> None:
        self.x("INSERT INTO alerts(ts, endpoint_id, kind, severity, message, event_id) VALUES(?,?,?,?,?,?)",
               (iso(), endpoint_id, kind, severity, message, event_id))

    def admin_action(self, who, action, detail, ip) -> None:
        self.x("INSERT INTO admin_actions(ts, who, action, detail, ip) VALUES(?,?,?,?,?)",
               (iso(), who, action, json.dumps(detail), ip))

    # ------------------------------------------------------------ agents
    def enroll(self, token: str, info: dict) -> dict | None:
        if not hmac.compare_digest(token or "", self.secrets["enroll_token"]):
            return None
        endpoint_id = "ep-" + uuid.uuid4().hex[:12]
        api_key = secrets.token_urlsafe(32)
        self.x("INSERT INTO endpoints(id, hostname, platform, os_version, agent_version, api_key_hash, enrolled_at,"
               " last_seen, reported_state, last_hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
               (endpoint_id, str(info.get("hostname"))[:200], str(info.get("platform"))[:50],
                str(info.get("os_version"))[:200], str(info.get("agent_version"))[:50],
                hashlib.sha256(api_key.encode()).hexdigest(), iso(), time.time(), "STOPPED", GENESIS))
        return {"endpoint_id": endpoint_id, "api_key": api_key}

    def auth_agent(self, api_key: str) -> str | None:
        rows = self.q("SELECT id FROM endpoints WHERE api_key_hash=?", (hashlib.sha256(api_key.encode()).hexdigest(),))
        return rows[0]["id"] if rows else None

    def head(self, endpoint_id: str) -> dict:
        row = self.q("SELECT last_seq, last_hash FROM endpoints WHERE id=?", (endpoint_id,))[0]
        return {"seq": row["last_seq"], "hash": row["last_hash"]}

    def heartbeat(self, endpoint_id: str, body: dict) -> dict:
        now = time.time()
        skew = None
        try:
            from datetime import datetime
            skew = round(datetime.fromisoformat(body["agent_time"].replace("Z", "+00:00")).timestamp() - now, 1)
        except (KeyError, ValueError, AttributeError):
            pass
        with self.lock:
            ep = self.q("SELECT * FROM endpoints WHERE id=?", (endpoint_id,))[0]
            if ep["disconnected"]:
                self.alert(endpoint_id, "AGENT_RECONNECTED", "info", "El agente volvió a comunicarse")
            if skew is not None and abs(skew) > 60 and abs(ep["clock_skew"] or 0) <= 60:
                self.alert(endpoint_id, "CLOCK_SKEW", "medium", f"Reloj del endpoint desfasado {skew:+.0f}s")
            self.x("UPDATE endpoints SET last_seen=?, reported_state=?, enabled=?, detail=?, spool_depth=?,"
                   " clock_skew=?, agent_version=?, disconnected=0, stopped=0 WHERE id=?",
                   (now, str(body.get("state"))[:30], int(bool(body.get("enabled"))),
                    json.dumps(body.get("detail") or {})[:4000], body.get("spool_depth"), skew,
                    str(body.get("version"))[:50], endpoint_id))
        return {"server_time": iso(), "desired_rev": ep["desired_rev"], "desired_by": ep["desired_by"],
                "desired_enabled": None if ep["desired_enabled"] is None else bool(ep["desired_enabled"])}

    # ------------------------------------------------------------ ingest
    @staticmethod
    def _invalid(ev, endpoint_id: str) -> str | None:
        if not isinstance(ev, dict):
            return "event is not an object"
        for key, kind in (("event_id", str), ("seq", int), ("timestamp", str), ("event_type", str),
                          ("integrity", dict)):
            if not isinstance(ev.get(key), kind):
                return f"missing or invalid field {key}"
        if ev.get("endpoint_id") != endpoint_id:
            return "endpoint_id does not match the authenticated agent"
        if not _TS.match(ev["timestamp"]):
            return "timestamp must be UTC ISO-8601 with milliseconds"
        if not verify(ev):
            return "event_hash does not match event content"
        return None

    def ingest(self, endpoint_id: str, events: list) -> tuple[int, dict]:
        accepted = duplicates = 0
        error = None
        with self.lock:
            head = self.head(endpoint_id)
            seq, last_hash = head["seq"], head["hash"]
            self.db.execute("BEGIN")
            try:
                for ev in events:
                    error = self._invalid(ev, endpoint_id)
                    if error:
                        break
                    if ev["seq"] <= seq:
                        row = self.db.execute("SELECT event_hash FROM events WHERE endpoint_id=? AND seq=?",
                                              (endpoint_id, ev["seq"])).fetchone()
                        if row and row[0] == ev["integrity"]["event_hash"]:
                            duplicates += 1
                            continue
                        error = f"seq {ev['seq']} already stored with different content"
                        break
                    if ev["seq"] != seq + 1 or ev["integrity"]["previous_hash"] != last_hash:
                        error = f"chain break: expected seq {seq + 1} on top of {last_hash[:12]}…, got seq {ev['seq']}"
                        break
                    self._insert(endpoint_id, ev)
                    seq, last_hash = ev["seq"], ev["integrity"]["event_hash"]
                    accepted += 1
                self.db.execute("UPDATE endpoints SET last_seq=?, last_hash=? WHERE id=?", (seq, last_hash, endpoint_id))
                if error:
                    self.alert(endpoint_id, "CHAIN_BREAK", "critical", f"Lote rechazado: {error}")
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        payload = {"accepted": accepted, "duplicates": duplicates, "head": {"seq": seq, "hash": last_hash}}
        if error:
            payload["error"] = error
            return 409, payload
        return 200, payload

    def _insert(self, endpoint_id: str, ev: dict) -> None:
        actor = ev.get("actor") if isinstance(ev.get("actor"), dict) else {}
        resource = ev.get("resource") if isinstance(ev.get("resource"), dict) else {}
        session = ev.get("session") if isinstance(ev.get("session"), dict) else {}
        evidence = ev.get("evidence") if isinstance(ev.get("evidence"), dict) else {}
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        etype = ev["event_type"]
        self.db.execute(
            "INSERT INTO events(event_id, endpoint_id, seq, ts, received_at, event_type, user, process, interpreter,"
            " path, sha256, session_id, evidence_sha256, event_hash, previous_hash, body)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev["event_id"], endpoint_id, ev["seq"], ev["timestamp"], iso(), etype,
             actor.get("user") or data.get("user"), actor.get("process"), actor.get("interpreter"),
             resource.get("path"), resource.get("sha256"), session.get("session_id") or data.get("session_id"),
             evidence.get("repository_reference") if evidence.get("captured") else None,
             ev["integrity"]["event_hash"], ev["integrity"]["previous_hash"], json.dumps(ev)))
        # projections (derived, rebuildable from the events)
        if etype == "REMOTE_SESSION_STARTED" and data.get("session_id"):
            self.db.execute(
                "INSERT OR IGNORE INTO sessions(endpoint_id, session_id, provider, started, user, remote, detail)"
                " VALUES(?,?,?,?,?,?,?)",
                (endpoint_id, data["session_id"], data.get("provider"), ev["timestamp"], data.get("user"),
                 data.get("remote_host"), json.dumps(data)))
        elif etype in ("REMOTE_SESSION_ENDED", "REMOTE_CONNECTION_LOST") and data.get("session_id"):
            self.db.execute("UPDATE sessions SET ended=? WHERE endpoint_id=? AND session_id=? AND ended IS NULL",
                            (ev["timestamp"], endpoint_id, data["session_id"]))
        if etype == "AGENT_STOPPED":
            self.db.execute("UPDATE endpoints SET stopped=1, reported_state='STOPPED' WHERE id=?", (endpoint_id,))
        elif etype == "AGENT_STARTED":
            self.db.execute("UPDATE endpoints SET stopped=0 WHERE id=?", (endpoint_id,))
        if etype in EVENT_ALERTS:
            severity, message = EVENT_ALERTS[etype]
            extra = data.get("by") or data.get("reason") or data.get("source") or data.get("what")
            self.db.execute(
                "INSERT INTO alerts(ts, endpoint_id, kind, severity, message, event_id) VALUES(?,?,?,?,?,?)",
                (iso(), endpoint_id, etype, severity, f"{message} ({extra})" if extra else message, ev["event_id"]))

    # ------------------------------------------------------------ evidence
    def evidence_path(self, sha: str) -> Path:
        return self.evidence_dir / sha[:2] / sha[2:4] / sha

    def store_evidence(self, endpoint_id: str, sha: str, tmp: Path, size: int) -> str:
        """Move a verified upload into the content-addressed store. Never overwrites."""
        final = self.evidence_path(sha)
        final.parent.mkdir(parents=True, exist_ok=True)
        status = "exists"
        try:
            os.chmod(tmp, 0o444)
            os.link(tmp, final)  # atomic, fails if the object already exists
            status = "stored"
        except FileExistsError:
            pass
        finally:
            tmp.unlink(missing_ok=True)
        self.x("INSERT OR IGNORE INTO evidence(sha256, size, stored_at, endpoint_id, rel_path) VALUES(?,?,?,?,?)",
               (sha, size, iso(), endpoint_id, str(final.relative_to(self.dir))))
        return status

    # ------------------------------------------------------------ queries
    def endpoints(self) -> list[dict]:
        out = []
        for ep in self.q("SELECT * FROM endpoints ORDER BY hostname"):
            ep.pop("api_key_hash")
            ep["state"] = ("STOPPED" if ep["stopped"] else "DISCONNECTED") if (ep["disconnected"] or ep["stopped"]) \
                else ep["reported_state"]
            ep["detail"] = json.loads(ep["detail"] or "{}")
            ep["last_seen"] = iso(ep["last_seen"]) if ep["last_seen"] else None
            out.append(ep)
        return out

    def events(self, f: dict, limit: int = 200, offset: int = 0) -> list[dict]:
        where, params = ["1=1"], []
        if f.get("endpoint"):
            where.append("endpoint_id=?"); params.append(f["endpoint"])
        if f.get("type"):
            where.append("event_type=?"); params.append(f["type"])
        category = f.get("category")
        if category == "processes":
            where.append("event_type='PROCESS_STARTED'")
        elif category == "commands":
            where.append("((event_type='PROCESS_STARTED' AND interpreter IS NOT NULL) OR event_type='POWERSHELL_SCRIPTBLOCK')")
        elif category == "files":
            where.append("event_type LIKE 'FILE_%'")
        elif category == "remote":
            where.append("event_type LIKE 'REMOTE_%'")
        elif category == "agent":
            where.append("(event_type LIKE 'AGENT_%' OR event_type LIKE 'AUDIT_%' OR event_type IN"
                         " ('CONFIG_CHANGED','TAMPER_DETECTED','CHAIN_RESYNC','EVENTS_DROPPED','SOURCE_FAILED'))")
        if f.get("from"):
            where.append("ts>=?"); params.append(f["from"])
        if f.get("to"):
            where.append("ts<=?"); params.append(f["to"])
        if f.get("session"):
            rows = self.q("SELECT * FROM sessions WHERE session_id=?", (f["session"],))
            if not rows:
                return []
            s = rows[0]  # everything the endpoint recorded while the session was open
            where.append("endpoint_id=? AND ts>=? AND ts<=?")
            params += [s["endpoint_id"], s["started"], s["ended"] or iso()]
        if f.get("q"):
            where.append("body LIKE ?"); params.append(f"%{f['q']}%")
        sql = ("SELECT id, event_id, endpoint_id, seq, ts, received_at, event_type, user, process, interpreter, path,"
               f" sha256, session_id, evidence_sha256, event_hash, body FROM events WHERE {' AND '.join(where)}"
               " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?")
        rows = self.q(sql, (*params, limit, offset))
        for r in rows:
            r["body"] = json.loads(r["body"])
        return rows

    # ------------------------------------------------------------ integrity
    def _sign(self, endpoint_id: str, seq: int, event_hash: str, ts: str) -> str:
        msg = f"{endpoint_id}|{seq}|{event_hash}|{ts}".encode()
        return hmac.new(self.secrets["checkpoint_key"].encode(), msg, hashlib.sha256).hexdigest()

    def checkpoint_all(self) -> int:
        made = 0
        with self.lock:
            for ep in self.q("SELECT id, last_seq, last_hash FROM endpoints WHERE last_seq>0"):
                last = self.q("SELECT MAX(seq) AS s FROM checkpoints WHERE endpoint_id=?", (ep["id"],))[0]["s"] or 0
                if ep["last_seq"] > last:
                    ts = iso()
                    self.x("INSERT INTO checkpoints(ts, endpoint_id, seq, event_hash, signature) VALUES(?,?,?,?,?)",
                           (ts, ep["id"], ep["last_seq"], ep["last_hash"],
                            self._sign(ep["id"], ep["last_seq"], ep["last_hash"], ts)))
                    made += 1
        return made

    def verify_all(self, endpoint: str | None = None, with_evidence: bool = True) -> dict:
        report = {"verified_at": iso(), "ok": True, "endpoints": [], "evidence": None}
        for ep in self.q("SELECT id, hostname, last_seq, last_hash FROM endpoints" +
                         (" WHERE id=?" if endpoint else ""), (endpoint,) if endpoint else ()):
            errors: list[str] = []
            expected_seq, prev = 1, GENESIS
            hashes: dict[int, str] = {}
            cur = self.db.cursor()
            with self.lock:
                rows = cur.execute("SELECT seq, event_hash, previous_hash, body FROM events WHERE endpoint_id=?"
                                   " ORDER BY seq", (ep["id"],)).fetchall()
            for row in rows:
                seq = row["seq"]
                try:
                    body = json.loads(row["body"])
                    if compute_hash(body) != row["event_hash"] or body["integrity"]["event_hash"] != row["event_hash"]:
                        errors.append(f"seq {seq}: el contenido no coincide con su hash")
                    if body.get("seq") != seq or body["integrity"]["previous_hash"] != row["previous_hash"]:
                        errors.append(f"seq {seq}: columnas y cuerpo del evento no coinciden")
                except (ValueError, KeyError, TypeError):
                    errors.append(f"seq {seq}: evento ilegible")
                if seq != expected_seq:
                    errors.append(f"faltan eventos: se esperaba seq {expected_seq}, hay {seq}")
                if row["previous_hash"] != prev:
                    errors.append(f"seq {seq}: no enlaza con el evento anterior")
                hashes[seq] = row["event_hash"]
                expected_seq, prev = seq + 1, row["event_hash"]
            if rows and (ep["last_seq"] != rows[-1]["seq"] or ep["last_hash"] != prev):
                errors.append("la cabeza de la cadena no coincide con el último evento (¿eventos finales eliminados?)")
            if not rows and ep["last_seq"]:
                errors.append("el endpoint registra eventos pero no hay ninguno almacenado")
            cps = self.q("SELECT * FROM checkpoints WHERE endpoint_id=? ORDER BY seq", (ep["id"],))
            for cp in cps:
                if not hmac.compare_digest(cp["signature"], self._sign(ep["id"], cp["seq"], cp["event_hash"], cp["ts"])):
                    errors.append(f"checkpoint seq {cp['seq']}: firma inválida")
                elif hashes.get(cp["seq"]) != cp["event_hash"]:
                    errors.append(f"checkpoint seq {cp['seq']}: el evento actual no coincide con el sellado")
            report["endpoints"].append({"endpoint_id": ep["id"], "hostname": ep["hostname"], "events": len(rows),
                                        "checkpoints": len(cps), "ok": not errors, "errors": errors[:50],
                                        "error_count": len(errors)})
            report["ok"] = report["ok"] and not errors
        if with_evidence and not endpoint:
            errors = []
            rows = self.q("SELECT sha256, size FROM evidence")
            for ev in rows:
                path = self.evidence_path(ev["sha256"])
                try:
                    digest = hashlib.sha256()
                    with open(path, "rb") as f:
                        while chunk := f.read(1024 * 1024):
                            digest.update(chunk)
                    if digest.hexdigest() != ev["sha256"]:
                        errors.append(f"{ev['sha256']}: contenido alterado")
                except OSError:
                    errors.append(f"{ev['sha256']}: archivo de evidencia ausente")
            report["evidence"] = {"objects": len(rows), "ok": not errors, "errors": errors[:50]}
            report["ok"] = report["ok"] and not errors
        return report

    # ------------------------------------------------------------ monitor
    def monitor_tick(self, heartbeat_timeout: float) -> None:
        now = time.time()
        with self.lock:
            for ep in self.q("SELECT id, hostname, last_seen, stopped FROM endpoints WHERE disconnected=0"):
                if ep["last_seen"] and now - ep["last_seen"] > heartbeat_timeout:
                    self.x("UPDATE endpoints SET disconnected=1 WHERE id=?", (ep["id"],))
                    how = "tras un apagado ordenado" if ep["stopped"] else "sin aviso de apagado"
                    self.alert(ep["id"], "AGENT_DISCONNECTED", "high",
                               f"Sin comunicación con el agente de {ep['hostname']} desde {iso(ep['last_seen'])} ({how})")
