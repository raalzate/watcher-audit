"""Windows Event Log integration (Sysmon, PowerShell script blocks, RDP session manager).

Reads channels with the built-in `wevtutil` so no extra native dependency is needed.
The XML parsing/mapping is pure Python and unit-tested; the polling loop only runs on Windows.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from ...common.chain import iso
from ...common.redact import redact_text
from ..procinfo import emit_process

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def _decode_console(raw: bytes) -> str:
    """Salida de wevtutil: UTF-8 si lo es; si no, la página ANSI del sistema ("mbcs": cp1252 en
    Windows en español). Visto en Windows real: "encontró" llega como byte 0xF3 (ANSI); leído como
    UTF-8 daba U+FFFD y leído como OEM/cp850 daba "encontr¾"."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("mbcs")         # codec que solo existe en Windows
        except LookupError:
            return raw.decode("utf-8", "replace")


def parse_events(xml_text: str) -> list[dict]:
    """Parse the concatenated <Event> elements printed by `wevtutil qe /f:xml`."""
    root = ET.fromstring("<Events>" + xml_text + "</Events>")
    out = []
    for ev in root:
        system = ev.find(NS + "System")
        if system is None:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.iter(NS + "Data") if d.get("Name")}
        user_data = ev.find(NS + "UserData")
        if user_data is not None:  # LocalSessionManager uses UserData/EventXML
            for el in user_data.iter():
                if el.text and el.text.strip():
                    data[el.tag.split("}")[-1]] = el.text.strip()
        out.append({
            "event_id": int(system.findtext(NS + "EventID")),
            "record_id": int(system.findtext(NS + "EventRecordID")),
            "time": system.find(NS + "TimeCreated").get("SystemTime"),
            "data": data,
        })
    return out


def _ts(rec: dict) -> str:
    """Sysmon UtcTime ('2026-11-09 08:30:00.123') or System time -> our ISO format."""
    raw = rec["data"].get("UtcTime") or rec["time"] or ""
    raw = raw.replace(" ", "T").rstrip("Z")
    head, _, frac = raw.partition(".")
    return f"{head}.{(frac + '000')[:3]}Z" if head else iso()


def _sha256(hashes: str) -> str | None:
    for part in (hashes or "").split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].lower()
    return None


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def map_event(channel: str, rec: dict) -> dict | None:
    """Translate one event-log record into a neutral description the agent can emit."""
    d, eid, ts = rec["data"], rec["event_id"], _ts(rec)
    base = lambda p: os.path.basename((p or "").replace("\\", "/")) or None  # noqa: E731
    if channel == SYSMON:
        proc = {"user": d.get("User"), "process": base(d.get("Image")), "pid": _int(d.get("ProcessId")),
                "exe": d.get("Image")}
        if eid == 1:
            return {"kind": "process", "ts": ts, "name": base(d.get("Image")), "exe": d.get("Image"),
                    "pid": _int(d.get("ProcessId")), "ppid": _int(d.get("ParentProcessId")),
                    "parent": base(d.get("ParentImage")), "user": d.get("User"), "cmdline": d.get("CommandLine"),
                    "cwd": d.get("CurrentDirectory"), "exe_sha256": _sha256(d.get("Hashes", "")),
                    "extra": {"parent_cmdline": redact_text(d.get("ParentCommandLine", ""))[0],
                              "integrity_level": d.get("IntegrityLevel"), "logon_id": d.get("LogonId")}}
        if eid == 11:
            return {"kind": "file_actor", "ts": ts, "path": d.get("TargetFilename"), "actor": proc}
        if eid in (23, 26):
            return {"kind": "file_actor", "ts": ts, "path": d.get("TargetFilename"), "actor": proc}
        if eid == 3:
            return {"kind": "network", "ts": ts, "actor": proc, "data": {
                "protocol": d.get("Protocol"), "initiated": d.get("Initiated"),
                "source_ip": d.get("SourceIp"), "source_port": _int(d.get("SourcePort")),
                "destination_ip": d.get("DestinationIp"), "destination_port": _int(d.get("DestinationPort")),
                "destination_host": d.get("DestinationHostname") or None}}
        return None
    if channel == POWERSHELL and eid == 4104:
        text, n = redact_text(d.get("ScriptBlockText", ""))
        return {"kind": "scriptblock", "ts": ts, "data": {
            "script_block_id": d.get("ScriptBlockId"), "part": _int(d.get("MessageNumber")),
            "parts": _int(d.get("MessageTotal")), "path": d.get("Path") or None, "text": text[:20000],
            "truncated": len(text) > 20000, "secrets_redacted": n}}
    if channel == LSM and eid in (21, 23, 24, 25):
        address = d.get("Address", "")
        if eid in (21, 25) and address.upper() in ("", "LOCAL"):
            return None  # console logon, not remote
        kind = {21: "REMOTE_SESSION_STARTED", 25: "REMOTE_SESSION_STARTED", 23: "REMOTE_SESSION_ENDED",
                24: "REMOTE_CONNECTION_LOST"}[eid]
        return {"kind": "session", "ts": ts, "event_type": kind, "data": {
            "provider": "RDP", "user": d.get("User"), "remote_host": address or None,
            "windows_session": d.get("SessionID"), "detection": f"event_log_{eid}"}}
    return None


class WinEventLogSource:
    name = "windows_eventlog"

    def __init__(self, agent):
        self.agent = agent
        self.cfg = agent.cfg["windows_eventlog"]
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.channels: list[str] = []

    def _query(self, channel: str, extra: list[str]) -> str:
        res = subprocess.run(["wevtutil", "qe", channel, "/f:xml", *extra], capture_output=True, timeout=30,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if res.returncode != 0:
            raise RuntimeError(_decode_console(res.stderr).strip() or f"wevtutil exit {res.returncode}")
        return _decode_console(res.stdout)

    def start(self) -> None:
        missing = []
        for channel in self.cfg["channels"]:
            key = f"evtlog:{channel}"
            try:
                if self.agent.spool.kv_get(key) is None:  # begin at the newest record
                    latest = parse_events(self._query(channel, ["/c:1", "/rd:true"]))
                    self.agent.spool.kv_set(key, str(latest[0]["record_id"] if latest else 0))
                else:
                    self._query(channel, ["/c:1", "/rd:true"])
                self.channels.append(channel)
            except Exception as e:
                missing.append(f"{channel}: {e}")
        self.agent.sysmon_active = SYSMON in self.channels
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, name="evtlog", daemon=True)
        self.thread.start()
        self.warning = ("channels unavailable -> " + "; ".join(missing)) if missing else None

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=5)

    def alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def _loop(self) -> None:
        while not self._stop.wait(self.cfg["poll_interval"]):
            for channel in self.channels:
                try:
                    self._drain(channel)
                except Exception as e:
                    self.agent.log(f"event log read failed ({channel}): {e!r}")

    def _drain(self, channel: str) -> None:
        key = f"evtlog:{channel}"
        last = int(self.agent.spool.kv_get(key, "0"))
        xml = self._query(channel, [f"/q:*[System[EventRecordID>{last}]]", "/c:500", "/rd:false"])
        for rec in parse_events(xml):
            mapped = map_event(channel, rec)
            if mapped:
                self.dispatch(mapped)
            last = max(last, rec["record_id"])
        self.agent.spool.kv_set(key, str(last))

    def dispatch(self, m: dict) -> None:
        agent = self.agent
        if m["kind"] == "process":
            if m["ppid"] == os.getpid():
                return  # our own wevtutil calls
            emit_process(agent, name=m["name"], exe=m["exe"], pid=m["pid"], ppid=m["ppid"], parent=m["parent"],
                         user=m["user"], cmdline=m["cmdline"], cwd=m["cwd"], started=m["ts"],
                         exe_sha256=m["exe_sha256"], source="sysmon", extra=m["extra"])
        elif m["kind"] == "file_actor":
            if m["path"] and m["actor"]["pid"] != os.getpid():
                agent.attribution[os.path.normcase(m["path"])] = (time.monotonic(), m["actor"])
        elif m["kind"] == "network":
            agent.emit("NETWORK_CONNECTION", actor=m["actor"], data={**m["data"], "source": "sysmon"},
                       timestamp=m["ts"])
        elif m["kind"] == "scriptblock":
            agent.emit("POWERSHELL_SCRIPTBLOCK", actor={"interpreter": "powershell", "cmdline": m["data"]["text"]},
                       data=m["data"], timestamp=m["ts"])
        elif m["kind"] == "session":
            d = m["data"]
            sid = f"rdp-{d['windows_session']}-{(d['user'] or '').lower()}"
            d["session_id"] = sid
            if m["event_type"] == "REMOTE_SESSION_STARTED":
                agent.session_open(sid, "RDP")
            agent.emit(m["event_type"], data=d, timestamp=m["ts"])
            if m["event_type"] != "REMOTE_SESSION_STARTED":
                agent.session_close(sid)
