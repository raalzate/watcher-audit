"""Remote access sessions: interactive remote logins (SSH / RDP) and TeamViewer."""
from __future__ import annotations

import glob
import hashlib
import os
import sys
import threading
from datetime import datetime, timezone

import psutil

from ...common.chain import iso

_LOCAL_HOSTS = {"", "localhost", "127.0.0.1", "::1", ":0", ":0.0", "local"}


def parse_teamviewer_line(line: str) -> dict | None:
    """One row of TeamViewer's Connections_incoming.txt (tab separated)."""
    parts = [p.strip() for p in line.rstrip("\r\n").split("\t")]
    if len(parts) < 3 or not parts[0].isdigit():
        return None

    def ts(value: str) -> str | None:
        try:
            return iso(datetime.strptime(value, "%d-%m-%Y %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            return None

    def col(i: int) -> str | None:
        return parts[i] if len(parts) > i and parts[i] else None

    return {"partner_id": parts[0], "partner_name": parts[1], "start": ts(parts[2]),
            "end": ts(parts[3]) if len(parts) > 3 else None, "local_user": col(4), "mode": col(5),
            "guid": (col(6) or "").strip("{}") or None}


def _sid(provider: str, *key) -> str:
    return f"{provider.lower()}-" + hashlib.sha1("|".join(map(str, key)).encode()).hexdigest()[:12]


class SessionSource:
    name = "sessions"

    def __init__(self, agent):
        self.agent = agent
        self.cfg = agent.cfg["sessions"]
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.logins: dict[tuple, str] = {}
        self.tv_proc_sid: str | None = None

    def start(self) -> None:
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, name="sessions", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=5)

    def alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def _loop(self) -> None:
        while True:
            for step in (self._poll_logins, self._poll_teamviewer_log, self._poll_teamviewer_process):
                try:
                    step()
                except Exception as e:
                    self.agent.log(f"session poll failed ({step.__name__}): {e!r}")
            if self._stop.wait(self.cfg["poll_interval"]):
                return

    # --- remote interactive logins (sshd / RDP as reported by the OS) -----
    def _poll_logins(self) -> None:
        current = {}
        for u in psutil.users():
            host = (u.host or "").strip()
            if host.lower() in _LOCAL_HOSTS:
                continue
            current[(u.name, u.terminal, host, int(u.started))] = u
        provider = "RDP" if sys.platform == "win32" else "SSH"
        for key, u in current.items():
            if key in self.logins:
                continue
            sid = _sid(provider, *key)
            self.logins[key] = sid
            info = {"session_id": sid, "provider": provider, "user": u.name, "remote_host": key[2],
                    "terminal": u.terminal, "detection": "os_login_table"}
            self.agent.session_open(sid, provider)
            self.agent.emit("REMOTE_AUTHENTICATION", data={**info, "result": "success"}, timestamp=iso(u.started))
            self.agent.emit("REMOTE_SESSION_STARTED", data=info, timestamp=iso(u.started))
        for key in [k for k in self.logins if k not in current]:
            sid = self.logins.pop(key)
            self.agent.emit("REMOTE_SESSION_ENDED", data={"session_id": sid, "provider": provider, "user": key[0],
                                                          "remote_host": key[2]})
            self.agent.session_close(sid)

    # --- TeamViewer: connection log (authoritative, written by TeamViewer itself) ---
    def _poll_teamviewer_log(self) -> None:
        for pattern in self.cfg["teamviewer_logs"]:
            for path in glob.glob(pattern):
                self._tail(path)

    def _tail(self, path: str) -> None:
        spool = self.agent.spool
        key = f"tv_offset:{path}"
        size = os.path.getsize(path)
        raw = spool.kv_get(key)
        if raw is None:  # first sight: do not replay history from before auditing began
            spool.kv_set(key, str(size))
            return
        offset = int(raw)
        if size < offset:
            offset = 0  # rotated / truncated
        if size == offset:
            return
        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
        end = chunk.rfind(b"\n") + 1  # only complete lines
        for line in chunk[:end].decode("utf-8", "replace").splitlines():
            rec = parse_teamviewer_line(line)
            if rec:
                self._emit_teamviewer(rec, path)
        spool.kv_set(key, str(offset + end))

    def _emit_teamviewer(self, rec: dict, path: str) -> None:
        sid = _sid("TeamViewer", rec["guid"] or (rec["partner_id"], rec["start"]))
        info = {"session_id": sid, "provider": "TeamViewer", "remote_host": rec["partner_id"],
                "partner_name": rec["partner_name"], "user": rec["local_user"], "mode": rec["mode"],
                "detection": "connections_incoming_log", "log_file": path, "started": rec["start"]}
        self.agent.emit("REMOTE_SESSION_STARTED", data=info, timestamp=rec["start"])
        if rec["mode"] and "filetransfer" in rec["mode"].lower().replace(" ", ""):
            self.agent.emit("REMOTE_TRANSFER_DETECTED", data=info, timestamp=rec["start"])
        if rec["end"]:
            self.agent.emit("REMOTE_SESSION_ENDED", data=info, timestamp=rec["end"])

    # --- TeamViewer: live hint on Windows (TeamViewer_Desktop.exe exists during a session) ---
    def _poll_teamviewer_process(self) -> None:
        if sys.platform != "win32" or not self.cfg["teamviewer_process_heuristic"]:
            return
        running = any((p.info["name"] or "").lower() == "teamviewer_desktop.exe"
                      for p in psutil.process_iter(["name"]))
        if running and not self.tv_proc_sid:
            self.tv_proc_sid = _sid("TeamViewer", "proc", iso())
            self.agent.session_open(self.tv_proc_sid, "TeamViewer")
            self.agent.emit("REMOTE_SESSION_STARTED", data={
                "session_id": self.tv_proc_sid, "provider": "TeamViewer", "detection": "process_heuristic"})
        elif not running and self.tv_proc_sid:
            self.agent.emit("REMOTE_SESSION_ENDED", data={
                "session_id": self.tv_proc_sid, "provider": "TeamViewer", "detection": "process_heuristic"})
            self.agent.session_close(self.tv_proc_sid)
            self.tv_proc_sid = None
