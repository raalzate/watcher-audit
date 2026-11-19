"""Agent configuration: TOML file merged over defaults."""
from __future__ import annotations

import copy
import json
import os
import sys
import tomllib
from pathlib import Path

WIN = sys.platform == "win32"
_USERS = "C:/Users/*" if WIN else "/Users/*"

DEFAULTS: dict = {
    "server": {"url": "", "ca_file": "", "client_cert": "", "client_key": "", "allow_insecure": False, "timeout": 15},
    "agent": {"heartbeat_interval": 15, "send_interval": 2, "batch_size": 200, "spool_max_events": 200000,
              "integrity_interval": 30},
    "processes": {"enabled": True, "poll_interval": 0.5, "exclude_names": ["mdworker", "mdworker_shared"],
                  "extra_interpreters": [], "capture_scripts": True, "hash_executables": True},
    "files": {
        "enabled": True,
        "watch_paths": [f"{_USERS}/Documents", f"{_USERS}/Desktop", f"{_USERS}/Downloads"],
        "exclude": ["*/.git/*", "*/node_modules/*", "*/__pycache__/*", "*/.venv/*", "*.tmp", "*.swp", "*~",
                    "*/.DS_Store", "*/~$*", "*.crdownload", "*.part", "*-journal", "*-wal", "*-shm"],
        "settle_seconds": 1.5,
        "hash_max_bytes": 200 * 1024 * 1024,
        "baseline": True,
    },
    "capture": {
        "enabled": True,
        "extensions": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".md", ".json",
                       ".xml", ".rtf", ".odt", ".ods", ".zip", ".py", ".ps1", ".sh", ".bat", ".cmd", ".js"],
        "max_bytes": 25 * 1024 * 1024,
        "script_max_bytes": 5 * 1024 * 1024,
        # never copied, whatever the extension policy says (PRD 4.3 / 12)
        "sensitive": ["*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx", "*.keychain*", "*/id_rsa*", "*/id_ed25519*",
                      "*/.env", "*/.env.*", "*/.ssh/*", "*/.aws/*", "*/.gnupg/*", "*credentials*", "*secret*"],
        "baseline_capture": False,
    },
    "sessions": {
        "enabled": True,
        "poll_interval": 3,
        "teamviewer_logs": [
            "C:/Program Files/TeamViewer/Connections_incoming.txt",
            "C:/Program Files (x86)/TeamViewer/Connections_incoming.txt",
            "/Library/Logs/TeamViewer/Connections_incoming.txt",
            "/Users/*/Library/Logs/TeamViewer/Connections_incoming.txt",
        ],
        "teamviewer_process_heuristic": True,
    },
    "windows_eventlog": {
        "enabled": True,
        "poll_interval": 1,
        "channels": [
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        ],
    },
}


def default_home() -> Path:
    if os.environ.get("WATCHER_HOME"):
        return Path(os.environ["WATCHER_HOME"])
    if WIN:
        return Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Watcher"
    return Path("/Library/Application Support/Watcher")


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(home: Path) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    path = home / "config.toml"
    if path.exists():
        with open(path, "rb") as f:
            _merge(cfg, tomllib.load(f))
    return cfg


def load_credentials(home: Path) -> dict | None:
    path = home / "credentials.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def save_credentials(home: Path, creds: dict) -> None:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "credentials.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(creds, f, indent=2)
