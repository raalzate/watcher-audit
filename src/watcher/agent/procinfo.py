"""Turns raw process data (from polling or Sysmon) into a PROCESS_STARTED event."""
from __future__ import annotations

import os
import re

from ..common.redact import redact_args, redact_text

INTERPRETERS = {"powershell", "pwsh", "cmd", "python", "pythonw", "bash", "zsh", "sh", "dash", "fish", "java",
                "javaw", "node", "ruby", "perl", "php", "osascript", "wscript", "cscript"}
_NO_SCRIPT_AFTER = {"-c", "-e", "-m", "-command", "-encodedcommand", "-enc", "-ec"}


def interpreter_of(name: str | None, exe: str | None, extra: list[str]) -> str | None:
    base = os.path.basename((exe or name or "").replace("\\", "/")).lower()
    base = base.removesuffix(".exe")
    base = re.sub(r"[\d.]+$", "", base)  # python3.13 -> python
    if base in INTERPRETERS or base in {e.lower() for e in extra}:
        return {"pythonw": "python", "javaw": "java"}.get(base, base)
    return None


def find_script(interp: str, args: list[str], cwd: str | None) -> str | None:
    """Path of the script file an interpreter was asked to run, if any."""
    def resolve(arg: str | None) -> str | None:
        if not arg:
            return None
        path = arg if os.path.isabs(arg) else (os.path.join(cwd, arg) if cwd else None)
        return path if path and os.path.isfile(path) else None

    rest = iter(args[1:])
    for arg in rest:
        low = arg.lower()
        if interp == "java":
            if low == "-jar":
                return resolve(next(rest, None))
            continue
        if interp == "cmd":
            if low in ("/c", "/k"):
                return resolve(next(rest, None))
            continue
        if interp in ("powershell", "pwsh") and low in ("-file", "-f"):
            return resolve(next(rest, None))
        if low in _NO_SCRIPT_AFTER:
            return None
        if arg.startswith("-"):
            continue
        return resolve(arg)
    return None


def emit_process(agent, *, name, exe, pid, ppid, parent, user, args: list[str] | None = None,
                 cmdline: str | None = None, cwd=None, started=None, exe_sha256=None, source="poll",
                 extra: dict | None = None):
    pcfg = agent.cfg["processes"]
    redactions = 0
    if args is not None:
        args, redactions = redact_args(args)
        cmdline = " ".join(args)
    elif cmdline is not None:
        cmdline, redactions = redact_text(cmdline)
    interp = interpreter_of(name, exe, pcfg["extra_interpreters"])
    script = find_script(interp, args, cwd) if interp and args else None
    if exe_sha256 is None and pcfg["hash_executables"]:
        exe_sha256 = agent.capturer.exe_hash(exe)

    actor = {"user": user, "process": name, "pid": pid, "parent_process": parent, "ppid": ppid, "exe": exe,
             "cmdline": cmdline, "interpreter": interp, "exe_sha256": exe_sha256}
    data = {"source": source, "secrets_redacted": redactions, **(extra or {})}
    resource = evidence = None
    if script:
        info = agent.capturer.process(script, kind="script", capture=pcfg["capture_scripts"])
        resource = {"path": script, "name": os.path.basename(script),
                    "extension": os.path.splitext(script)[1].lower(), "size": info["size"], "sha256": info["sha256"]}
        evidence = info["evidence"]
        data["script"] = script
    agent.emit("PROCESS_STARTED", actor=actor, resource=resource, evidence=evidence, data=data, timestamp=started)
