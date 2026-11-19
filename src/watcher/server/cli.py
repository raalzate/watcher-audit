"""watcher-server: run | info | verify"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="watcher-server", description="Central audit repository + dashboard")
    parser.add_argument("--data", default=os.environ.get("WATCHER_SERVER_DATA", "./server-data"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="start the repository and dashboard")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8443)
    run.add_argument("--tls-cert")
    run.add_argument("--tls-key")
    run.add_argument("--tls-client-ca", help="require client certificates signed by this CA (mutual TLS)")
    run.add_argument("--heartbeat-timeout", type=float, default=45)
    run.add_argument("--checkpoint-interval", type=float, default=300)
    sub.add_parser("info", help="print the enrollment token and the dashboard password")
    sub.add_parser("verify", help="verify the hash chain, checkpoints and evidence; exit 1 on failure")
    args = parser.parse_args(argv)
    data = Path(args.data)
    data.mkdir(parents=True, exist_ok=True)

    if args.cmd == "run":
        import uvicorn
        from .app import create_app
        if not args.tls_cert and args.host not in ("127.0.0.1", "localhost", "::1"):
            print("refusing to listen without TLS on a non-loopback address (pass --tls-cert/--tls-key)",
                  file=sys.stderr)
            return 2
        app = create_app(data, heartbeat_timeout=args.heartbeat_timeout,
                         checkpoint_interval=args.checkpoint_interval)
        tls = {}
        if args.tls_cert:
            tls = {"ssl_certfile": args.tls_cert, "ssl_keyfile": args.tls_key}
            if args.tls_client_ca:
                tls |= {"ssl_ca_certs": args.tls_client_ca, "ssl_cert_reqs": ssl.CERT_REQUIRED}
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning", **tls)
        return 0

    from .store import Store
    store = Store(data)
    if args.cmd == "info":
        print(f"data directory : {data.resolve()}")
        print(f"enroll token   : {store.secrets['enroll_token']}")
        print(f"admin password : {store.secrets['admin_password']}")
        return 0
    report = store.verify_all()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
