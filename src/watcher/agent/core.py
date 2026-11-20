"""Agent runtime: state machine, event emission, delivery, self-monitoring.

The agent only observes and records. It never blocks, modifies or deletes anything
outside its own home directory.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from .. import __version__
from ..common.chain import iso
from .config import default_home, load_config, load_credentials
from .evidence import Capturer
from .spool import Spool
from .transport import Client, TransportError


class NotEnrolled(Exception):
    pass


def _file_hash(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _code_hash() -> str:
    """Fingerprint of the agent's own code, to notice tampering while running."""
    root = Path(__file__).resolve().parent.parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


class Agent:
    def __init__(self, home: Path | str | None = None):
        self.home = Path(home) if home else default_home()
        self.cfg = load_config(self.home)
        creds = load_credentials(self.home)
        if not creds:
            raise NotEnrolled(f"no credentials in {self.home}; run `watcher-agent enroll` first")
        self.endpoint_id = creds["endpoint_id"]
        if not self.cfg["server"]["url"]:
            self.cfg["server"]["url"] = creds["server_url"]
        self.client = Client(self.cfg["server"], creds["api_key"])
        self.data_dir = self.home / "data"
        self.spool = Spool(self.data_dir / "spool.db")
        self.capturer = Capturer(self.cfg, self.spool, self.data_dir / "staging")

        self.stop_event = threading.Event()
        self.stop_reason = "unknown"
        self.enabled = False
        self.connected = False
        self.tamper = False
        self.degraded: dict[str, str] = {}
        self.sources: list = []
        self.dropped = 0
        self.sysmon_active = False
        self.attribution: dict[str, tuple[float, dict]] = {}
        self._sessions: dict[str, dict] = {}
        self._lock = threading.RLock()
        self._log_lock = threading.Lock()
        self.last_send_error: str | None = None
        self.last_sent_at: str | None = None

    # ------------------------------------------------------------------ utils
    def log(self, message: str) -> None:
        # Un mensaje de log nunca puede tumbar al agente. UTF-8 explícito: en Windows el default es
        # cp1252 y un carácter fuera de él (p. ej. U+FFFD en un error de wevtutil) lanzaba
        # UnicodeEncodeError dentro de activate() y mataba el proceso.
        line = f"{iso()} {message}\n"
        with self._log_lock:
            try:
                path = self.home / "agent.log"
                if path.exists() and path.stat().st_size > 5 * 1024 * 1024:
                    os.replace(path, self.home / "agent.log.1")
                with open(path, "a", encoding="utf-8", errors="replace") as f:
                    f.write(line)
            except Exception:
                pass
            try:
                if sys.stderr is not None:
                    sys.stderr.write(line)
            except Exception:
                pass

    def session_open(self, sid: str, provider: str) -> None:
        with self._lock:
            self._sessions[sid] = {"type": "remote", "provider": provider, "session_id": sid}

    def session_close(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def current_session(self) -> dict | None:
        """Most recent remote session open right now. Temporal correlation only:
        it does not claim the session caused the event (PRD 4.6)."""
        with self._lock:
            if not self._sessions:
                return None
            session = dict(list(self._sessions.values())[-1])
            if len(self._sessions) > 1:
                session["concurrent_sessions"] = len(self._sessions)
            return session

    def attribute(self, path: str) -> dict | None:
        """Process responsible for a file change, when an instrumented source reported it."""
        now = time.monotonic()
        with self._lock:
            for key in [k for k, (t, _) in self.attribution.items() if now - t > 120]:
                del self.attribution[key]
            hit = self.attribution.get(os.path.normcase(path))
        return hit[1] if hit else None

    # ------------------------------------------------------------------ events
    def emit(self, event_type: str, *, actor=None, resource=None, evidence=None, data=None,
             timestamp: str | None = None, force: bool = False):
        if not force and self.spool.count >= self.cfg["agent"]["spool_max_events"]:
            with self._lock:
                self.dropped += 1  # reported later as EVENTS_DROPPED: never lost silently (RNF-11)
            return None
        event = {
            "event_id": str(uuid.uuid4()),
            "endpoint_id": self.endpoint_id,
            "timestamp": timestamp or iso(),
            "recorded_at": iso(),
            "event_type": event_type,
            "actor": actor,
            "resource": resource,
            "session": self.current_session(),
            "evidence": evidence,
            "data": data or {},
            "agent": {"version": __version__, "platform": sys.platform},
        }
        return self.spool.append(event)

    # ------------------------------------------------------------------ state
    def state(self) -> str:
        if self.stop_event.is_set():
            return "STOPPED"
        if self.tamper:
            return "TAMPER_DETECTED"
        if not self.enabled:
            return "DISABLED"
        if not self.connected:
            return "DISCONNECTED"
        if self.degraded:
            return "DEGRADED"
        return "ACTIVE"

    def write_status(self, state: str | None = None) -> None:
        status = {
            "state": state or self.state(), "enabled": self.enabled, "pid": os.getpid(),
            "endpoint_id": self.endpoint_id, "server": self.client.base, "connected": self.connected,
            "last_sent_at": self.last_sent_at, "last_send_error": self.last_send_error,
            "spool_depth": self.spool.count, "events_dropped_pending_report": self.dropped,
            "sources": [s.name for s in self.sources], "degraded": self.degraded,
            "chain_head": self.spool.head(), "config_sha256": _file_hash(self.home / "config.toml"),
            "version": __version__, "updated_at": iso(),
        }
        tmp = self.home / "status.json.tmp"
        try:
            tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
            os.replace(tmp, self.home / "status.json")
        except OSError:
            pass

    def _build_sources(self) -> list:
        from .sources.files import FileSource
        from .sources.processes import ProcessPollSource
        from .sources.sessions import SessionSource

        sources = []
        if sys.platform == "win32" and self.cfg["windows_eventlog"]["enabled"]:
            from .sources.wineventlog import WinEventLogSource
            sources.append(WinEventLogSource(self))  # must start first: decides who reports processes
        if self.cfg["processes"]["enabled"]:
            sources.append(ProcessPollSource(self))
        if self.cfg["files"]["enabled"]:
            sources.append(FileSource(self))
        if self.cfg["sessions"]["enabled"]:
            sources.append(SessionSource(self))
        return sources

    def activate(self, by: str) -> None:
        self.write_status("STARTING")
        self.degraded = {}
        self.sources = []
        for source in self._build_sources():
            try:
                source.start()
                self.sources.append(source)
                if getattr(source, "warning", None):
                    self.degraded[source.name] = source.warning
            except Exception as e:
                self.degraded[source.name] = str(e)
                self.emit("SOURCE_FAILED", data={"source": source.name, "error": str(e)}, force=True)
        try:
            status, _ = self.client.request("GET", "/api/v1/agent/head", timeout=5)
            self.connected = status == 200
        except TransportError as e:
            self.connected = False
            self.last_send_error = str(e)
        self.enabled = True
        self.emit("AUDIT_STARTED", force=True, data={
            "by": by, "sources": [s.name for s in self.sources], "degraded": self.degraded,
            "repository_reachable": self.connected,
            "config_sha256": _file_hash(self.home / "config.toml")})
        self.log(f"audit started by {by}; sources={[s.name for s in self.sources]} degraded={self.degraded}")

    def deactivate(self, by: str, announce: bool = True) -> None:
        for source in self.sources:
            try:
                source.stop()
            except Exception as e:
                self.log(f"error stopping {source.name}: {e!r}")
        self.sources = []
        self.enabled = False
        with self._lock:
            self._sessions.clear()
        if announce:
            self.emit("AUDIT_STOPPED", data={"by": by, "reason": "disabled"}, force=True)
            self.log(f"audit stopped by {by}")

    def request_stop(self, reason: str) -> None:
        self.stop_reason = reason
        self.stop_event.set()

    # ------------------------------------------------------------------ main
    def run(self) -> None:
        spool = self.spool
        self.write_status("STARTING")
        unclean = spool.kv_get("running") == "1"
        spool.kv_set("running", "1")
        self.emit("AGENT_STARTED", force=True, data={
            "pid": os.getpid(), "hostname": socket.gethostname(), "os": platform.platform(),
            "python": platform.python_version(), "run_as": getpass.getuser(),
            "previous_shutdown_clean": not unclean})
        if unclean:
            self.emit("AGENT_UNCLEAN_SHUTDOWN", force=True, data={
                "last_alive": spool.kv_get("last_alive"),
                "meaning": "the agent stopped without a clean shutdown (killed, crash or power loss)"})

        config_hash = _file_hash(self.home / "config.toml")
        code_hash = _code_hash()
        if spool.kv_get("enabled", "1") == "1":
            self.activate(by=spool.kv_get("enabled_by") or "service_start")
        # started after activation so the first heartbeat already reports the real state
        sender = threading.Thread(target=self._sender, name="sender", daemon=True)
        sender.start()
        tick = 0
        interval = self.cfg["agent"]["integrity_interval"]
        while not self.stop_event.wait(1):
            tick += 1
            want = spool.kv_get("enabled", "1") == "1"
            if want != self.enabled:
                by = spool.kv_get("enabled_by") or "unknown"
                self.activate(by) if want else self.deactivate(by)
            for source in self.sources:
                if source.name not in self.degraded and not source.alive():
                    self.degraded[source.name] = "source thread died"
                    self.emit("SOURCE_FAILED", data={"source": source.name, "error": "thread died"}, force=True)
            if tick % 5 == 0:
                spool.kv_set("last_alive", iso())
            if tick % interval == 0:
                new_config = _file_hash(self.home / "config.toml")
                if new_config != config_hash:
                    self.emit("CONFIG_CHANGED", force=True, data={
                        "previous_sha256": config_hash, "current_sha256": new_config,
                        "note": "takes effect at next agent restart"})
                    config_hash = new_config
                new_code = _code_hash()
                if new_code != code_hash:
                    self.tamper = True
                    self.emit("TAMPER_DETECTED", force=True, data={
                        "what": "agent_code_modified", "previous_sha256": code_hash, "current_sha256": new_code})
                    code_hash = new_code
            self.write_status()

        # orderly shutdown: record it and try to deliver before exiting
        self.deactivate(by=self.stop_reason, announce=False)
        self.emit("AGENT_STOPPED", force=True, data={"reason": self.stop_reason, "pid": os.getpid()})
        sender.join(timeout=5)
        try:
            self._flush_events(timeout=5)
        except TransportError:
            pass
        spool.kv_set("running", "0")
        self.write_status("STOPPED")
        self.log(f"agent stopped ({self.stop_reason})")

    # ------------------------------------------------------------------ delivery
    def _sender(self) -> None:
        acfg = self.cfg["agent"]
        next_heartbeat = 0.0
        failures = 0
        while not self.stop_event.is_set():
            try:
                if time.monotonic() >= next_heartbeat:
                    self._heartbeat()
                    next_heartbeat = time.monotonic() + acfg["heartbeat_interval"]
                if self.dropped and self.spool.count < acfg["spool_max_events"]:
                    with self._lock:
                        count, self.dropped = self.dropped, 0
                    self.emit("EVENTS_DROPPED", force=True, data={"count": count, "reason": "local spool full"})
                self._flush_events()
                self._flush_evidence()
                self.connected = True
                self.last_send_error = None
                failures = 0
            except TransportError as e:
                self.connected = False
                self.last_send_error = str(e)
                failures += 1
            except Exception as e:
                self.log(f"sender error: {e!r}")
            self.stop_event.wait(min(acfg["send_interval"] * (2 ** min(failures, 5)), 60))

    def _heartbeat(self) -> None:
        status, resp = self.client.request("POST", "/api/v1/heartbeat", body={
            "state": self.state(), "enabled": self.enabled, "agent_time": iso(), "version": __version__,
            "spool_depth": self.spool.count, "dropped": self.dropped,
            "detail": {"sources": [s.name for s in self.sources], "degraded": self.degraded}})
        if status != 200:
            raise TransportError(f"heartbeat rejected: HTTP {status} {resp}")
        rev = resp.get("desired_rev", 0)
        if resp.get("desired_enabled") is not None and rev > int(self.spool.kv_get("desired_rev", "0")):
            self.spool.kv_set("desired_rev", str(rev))  # a dashboard toggle is applied once
            self.spool.kv_set("enabled_by", f"dashboard:{resp.get('desired_by') or 'admin'}")
            self.spool.kv_set("enabled", "1" if resp["desired_enabled"] else "0")

    def _flush_events(self, timeout: float | None = None) -> None:
        resyncs = 0
        while True:
            batch = self.spool.pending(self.cfg["agent"]["batch_size"])
            if not batch:
                return
            if resyncs > 2:
                raise TransportError("repository keeps rejecting the event chain")
            status, resp = self.client.request("POST", "/api/v1/events", body={"events": batch}, timeout=timeout)
            head = resp.get("head")
            if status == 200:
                self.spool.ack(head["seq"])
                self.last_sent_at = iso()
            elif status == 409 and head:
                # The repository's chain and ours disagree (spool lost, restored or tampered).
                # Unconfirmed events are re-chained on top of the repository head and the fact is recorded.
                resyncs += 1
                moved = self.spool.rechain(head["seq"], head["hash"])
                self.emit("CHAIN_RESYNC", force=True, data={
                    "server_seq": head["seq"], "rechained_events": moved, "server_error": resp.get("error")})
                self.log(f"chain resync at seq {head['seq']}: {resp.get('error')}")
            else:
                raise TransportError(f"events rejected: HTTP {status} {resp}")
            if self.stop_event.is_set() and timeout is None:
                return

    def _flush_evidence(self) -> None:
        for sha in self.spool.evidence_pending():
            path = self.capturer.staging / sha
            if not path.exists():
                self.spool.evidence_finish(sha, uploaded=False)
                continue
            status, resp = self.client.request("PUT", f"/api/v1/evidence/{sha}", raw=path.read_bytes(), timeout=120)
            if status in (200, 201):
                self.spool.evidence_finish(sha, uploaded=True)
                path.unlink(missing_ok=True)
            elif status in (413, 422):
                self.spool.evidence_finish(sha, uploaded=False)
                path.unlink(missing_ok=True)
                self.emit("EVIDENCE_REJECTED", data={"sha256": sha, "status": status, "error": resp.get("error")})
            else:
                raise TransportError(f"evidence rejected: HTTP {status} {resp}")
