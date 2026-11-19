"""watcher-agent: enroll | run | enable | disable | status"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import signal
import socket
import sys
from pathlib import Path

from .. import __version__
from .config import default_home, load_config, load_credentials, save_credentials
from .spool import Spool
from .transport import Client, TransportError


def cmd_enroll(home: Path, args) -> int:
    if load_credentials(home) and not args.force:
        print(f"already enrolled ({home / 'credentials.json'}); use --force to re-enroll", file=sys.stderr)
        return 1
    cfg = load_config(home)["server"]
    cfg["url"] = args.server or cfg["url"]
    if args.ca_file:
        cfg["ca_file"] = args.ca_file
    try:
        status, resp = Client(cfg).request(
            "POST", "/api/v1/enroll", headers={"X-Enroll-Token": args.token},
            body={"hostname": socket.gethostname(), "platform": sys.platform, "os_version": platform.platform(),
                  "agent_version": __version__})
    except TransportError as e:
        print(f"cannot reach repository: {e}", file=sys.stderr)
        return 2
    if status != 200:
        print(f"enrollment rejected: HTTP {status} {resp}", file=sys.stderr)
        return 2
    save_credentials(home, {"endpoint_id": resp["endpoint_id"], "api_key": resp["api_key"], "server_url": cfg["url"]})
    print(f"enrolled as {resp['endpoint_id']}")
    return 0


def cmd_run(home: Path, _args) -> int:
    from .core import Agent, NotEnrolled
    try:
        agent = Agent(home)
    except (NotEnrolled, TransportError) as e:
        print(str(e), file=sys.stderr)
        return 2
    for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, lambda *_a, n=name: agent.request_stop(f"signal:{n}"))
    agent.run()
    return 0


def cmd_toggle(home: Path, enable: bool) -> int:
    if not load_credentials(home):
        print("agent is not enrolled", file=sys.stderr)
        return 2
    spool = Spool(home / "data" / "spool.db")
    spool.kv_set("enabled_by", f"local_cli:{getpass.getuser()}")
    spool.kv_set("enabled", "1" if enable else "0")
    spool.close()
    print("audit ENABLE requested" if enable else "audit DISABLE requested",
          "(the running agent applies it within a second and records it centrally)")
    return 0


def _pid_alive(pid: int) -> bool:
    import psutil
    return psutil.pid_exists(pid)


def cmd_status(home: Path, args) -> int:
    path = home / "status.json"
    if not path.exists():
        print(json.dumps({"state": "STOPPED", "detail": "agent has never run", "home": str(home)}, indent=2))
        return 3
    status = json.loads(path.read_text())
    if status["state"] != "STOPPED" and not _pid_alive(status.get("pid", -1)):
        status["state"] = "STOPPED"
        status["detail"] = "process not running and no clean shutdown recorded"
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print(f"Watcher audit agent {status['version']}  —  {status['state']}")
        for key in ("endpoint_id", "server", "connected", "enabled", "sources", "degraded", "spool_depth",
                    "last_sent_at", "last_send_error", "config_sha256", "updated_at"):
            print(f"  {key:16} {status.get(key)}")
    return 0 if status["state"] in ("ACTIVE", "DISABLED") else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="watcher-agent", description="Endpoint audit agent (observe and record only)")
    parser.add_argument("--home", default=os.environ.get("WATCHER_HOME"), help="agent directory (config, data)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    enroll = sub.add_parser("enroll", help="register this endpoint with the central repository")
    enroll.add_argument("--server", help="https://host:port of the repository")
    enroll.add_argument("--token", required=True, help="enrollment token issued by the repository")
    enroll.add_argument("--ca-file", help="CA bundle for the repository certificate")
    enroll.add_argument("--force", action="store_true")
    sub.add_parser("run", help="run in the foreground (what the service/daemon executes)")
    sub.add_parser("enable", help="turn auditing on")
    sub.add_parser("disable", help="turn auditing off (recorded centrally)")
    status = sub.add_parser("status", help="show the verifiable agent state")
    status.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    home = Path(args.home) if args.home else default_home()
    if args.cmd == "enroll":
        return cmd_enroll(home, args)
    if args.cmd == "run":
        return cmd_run(home, args)
    if args.cmd in ("enable", "disable"):
        return cmd_toggle(home, args.cmd == "enable")
    return cmd_status(home, args)


if __name__ == "__main__":
    sys.exit(main())
