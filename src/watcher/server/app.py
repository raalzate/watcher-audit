"""HTTP API: agent ingest (/api/v1/*) and audit dashboard (/api/*)."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from .store import _SHA, LOG_GROUP_KEYS, Store

STATIC = Path(__file__).parent / "static"
SESSION_TTL = 8 * 3600


def create_app(data_dir: Path | str, *, heartbeat_timeout: float = 45, checkpoint_interval: float = 300,
               verify_interval: float = 3600, max_evidence_bytes: int = 100 * 1024 * 1024,
               monitor: bool = True) -> FastAPI:
    store = Store(data_dir)
    # Al arrancar no hay subidas en curso: lo que quede en tmp/ es de un proceso anterior (en Windows,
    # temporales read-only que dejó el fallo de store_evidence). Se quita el read-only y se borran.
    for leftover in (store.evidence_dir / "tmp").iterdir():
        try:
            os.chmod(leftover, 0o644)
            leftover.unlink()
        except OSError:
            pass
    app = FastAPI(title="Watcher Audit Repository", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    admin_sessions: dict[str, float] = {}
    failed_logins: dict[str, list[float]] = {}

    # ------------------------------------------------------------ background monitor
    def monitor_loop():
        last_checkpoint = last_verify = time.time()
        while True:
            time.sleep(min(10, heartbeat_timeout / 3))
            try:
                store.monitor_tick(heartbeat_timeout)
                if time.time() - last_checkpoint >= checkpoint_interval:
                    last_checkpoint = time.time()
                    store.checkpoint_all()
                if time.time() - last_verify >= verify_interval:
                    last_verify = time.time()
                    report = store.verify_all()
                    if not report["ok"]:
                        store.alert(None, "INTEGRITY_FAILURE", "critical",
                                    "La verificación periódica de integridad encontró inconsistencias")
            except Exception as e:  # keep monitoring alive
                print(f"monitor error: {e!r}")

    if monitor:
        threading.Thread(target=monitor_loop, name="monitor", daemon=True).start()

    # ------------------------------------------------------------ auth
    def agent(request: Request) -> str:
        header = request.headers.get("authorization", "")
        endpoint_id = store.auth_agent(header[7:]) if header.lower().startswith("bearer ") else None
        if not endpoint_id:
            raise HTTPException(401, "invalid agent credentials")
        return endpoint_id

    def admin(request: Request) -> str:
        token = request.cookies.get("watcher_session", "")
        if admin_sessions.get(token, 0) < time.time():
            admin_sessions.pop(token, None)
            raise HTTPException(401, "login required")
        return "admin"

    def ip(request: Request) -> str:
        return request.client.host if request.client else "?"

    # ------------------------------------------------------------ agent API
    @app.post("/api/v1/enroll")
    async def enroll(request: Request):
        result = store.enroll(request.headers.get("x-enroll-token", ""), await request.json())
        if not result:
            raise HTTPException(403, "invalid enrollment token")
        return result

    @app.get("/api/v1/agent/head")
    def agent_head(endpoint_id: str = Depends(agent)):
        return store.head(endpoint_id)

    @app.post("/api/v1/heartbeat")
    async def heartbeat(request: Request, endpoint_id: str = Depends(agent)):
        return store.heartbeat(endpoint_id, await request.json())

    @app.post("/api/v1/events")
    async def post_events(request: Request, endpoint_id: str = Depends(agent)):
        body = await request.json()
        events = body.get("events") if isinstance(body, dict) else None
        if not isinstance(events, list) or len(events) > 1000:
            raise HTTPException(400, "expected {events: [...]} with at most 1000 events")
        status, payload = store.ingest(endpoint_id, events)
        return JSONResponse(payload, status_code=status)

    @app.put("/api/v1/evidence/{sha}")
    async def put_evidence(sha: str, request: Request, endpoint_id: str = Depends(agent)):
        if not _SHA.match(sha):
            raise HTTPException(400, "invalid sha256")
        tmp = store.evidence_dir / "tmp" / uuid.uuid4().hex
        digest, size = hashlib.sha256(), 0
        try:
            with open(tmp, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > max_evidence_bytes:
                        return JSONResponse({"error": "evidence too large"}, status_code=413)
                    digest.update(chunk)
                    f.write(chunk)
            if digest.hexdigest() != sha:
                return JSONResponse({"error": "content does not match sha256"}, status_code=422)
            status = store.store_evidence(endpoint_id, sha, tmp, size)
        finally:
            tmp.unlink(missing_ok=True)
        return JSONResponse({"status": status, "sha256": sha}, status_code=201 if status == "stored" else 200)

    # ------------------------------------------------------------ dashboard auth
    @app.post("/api/login")
    async def login(request: Request):
        who = ip(request)
        recent = [t for t in failed_logins.get(who, []) if time.time() - t < 300]
        if len(recent) >= 10:
            raise HTTPException(429, "too many failed attempts; wait a few minutes")
        body = await request.json()
        if not hmac.compare_digest(str(body.get("password", "")), store.secrets["admin_password"]):
            failed_logins[who] = recent + [time.time()]
            store.admin_action("?", "LOGIN_FAILED", {}, who)
            raise HTTPException(401, "wrong password")
        token = secrets.token_urlsafe(32)
        admin_sessions[token] = time.time() + SESSION_TTL
        store.admin_action("admin", "LOGIN", {}, who)
        resp = JSONResponse({"ok": True})
        resp.set_cookie("watcher_session", token, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", max_age=SESSION_TTL)
        return resp

    @app.post("/api/logout")
    def logout(request: Request):
        admin_sessions.pop(request.cookies.get("watcher_session", ""), None)
        return {"ok": True}

    # ------------------------------------------------------------ dashboard API
    @app.get("/api/overview")
    def overview(_: str = Depends(admin)):
        day_ago = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 86400))
        one = lambda sql, p=(): store.q(sql, p)[0]["n"]  # noqa: E731
        endpoints = store.endpoints()
        return {
            "endpoints": len(endpoints),
            "states": {s: sum(1 for e in endpoints if e["state"] == s) for s in {e["state"] for e in endpoints}},
            "events_total": one("SELECT COUNT(*) AS n FROM events"),
            "events_24h": one("SELECT COUNT(*) AS n FROM events WHERE ts>=?", (day_ago,)),
            "evidence_objects": one("SELECT COUNT(*) AS n FROM evidence"),
            "evidence_bytes": one("SELECT COALESCE(SUM(size),0) AS n FROM evidence"),
            "open_alerts": one("SELECT COUNT(*) AS n FROM alerts WHERE acknowledged_at IS NULL AND severity<>'info'"),
            "active_sessions": one("SELECT COUNT(*) AS n FROM sessions WHERE ended IS NULL"),
            "by_type_24h": store.q("SELECT event_type, COUNT(*) AS n FROM events WHERE ts>=? GROUP BY event_type"
                                   " ORDER BY n DESC", (day_ago,)),
        }

    @app.get("/api/endpoints")
    def endpoints(_: str = Depends(admin)):
        return store.endpoints()

    @app.post("/api/endpoints/{endpoint_id}/audit")
    async def set_audit(endpoint_id: str, request: Request, who: str = Depends(admin)):
        enabled = bool((await request.json()).get("enabled"))
        if not store.q("SELECT 1 FROM endpoints WHERE id=?", (endpoint_id,)):
            raise HTTPException(404, "unknown endpoint")
        store.x("UPDATE endpoints SET desired_enabled=?, desired_rev=desired_rev+1, desired_by=? WHERE id=?",
                (int(enabled), who, endpoint_id))
        store.admin_action(who, "AUDIT_ENABLE" if enabled else "AUDIT_DISABLE", {"endpoint": endpoint_id}, ip(request))
        return {"ok": True, "note": "the agent applies it at its next heartbeat and records AUDIT_STARTED/AUDIT_STOPPED"}

    def filters(request: Request) -> dict:
        return {k: v for k, v in request.query_params.items()
                if k in ("endpoint", "type", "category", "from", "to", "session", "q", "prefix", "order") and v}

    @app.get("/api/events")
    def events(request: Request, limit: int = 200, offset: int = 0, _: str = Depends(admin)):
        return store.events(filters(request), min(max(limit, 1), 1000), max(offset, 0))

    @app.get("/api/logs/groups")
    def log_groups(_: str = Depends(admin)):
        return store.log_groups()

    @app.get("/api/logs/streams")
    def log_streams(group: str = "all", bucket: str = "hour", endpoint: str = "", since: str = "",
                    limit: int = 100, offset: int = 0, _: str = Depends(admin)):
        if group not in LOG_GROUP_KEYS:
            raise HTTPException(404, "unknown log group")
        return store.log_streams(group, bucket, endpoint or None, since or None,
                                 min(max(limit, 1), 500), max(offset, 0))

    @app.get("/api/event-types")
    def event_types(_: str = Depends(admin)):
        return [r["event_type"] for r in store.q("SELECT DISTINCT event_type FROM events ORDER BY 1")]

    @app.get("/api/sessions")
    def sessions(_: str = Depends(admin)):
        rows = store.q("SELECT s.*, e.hostname FROM sessions s LEFT JOIN endpoints e ON e.id=s.endpoint_id"
                       " ORDER BY s.started DESC LIMIT 500")
        for r in rows:
            r["detail"] = json.loads(r["detail"] or "{}")
        return rows

    @app.get("/api/evidence")
    def evidence(_: str = Depends(admin)):
        return store.q(
            "SELECT v.sha256, v.size, v.stored_at, v.endpoint_id,"
            " (SELECT COUNT(*) FROM events e WHERE e.evidence_sha256=v.sha256) AS events,"
            " (SELECT e.path FROM events e WHERE e.evidence_sha256=v.sha256 AND e.path IS NOT NULL LIMIT 1) AS path"
            " FROM evidence v ORDER BY v.stored_at DESC LIMIT 1000")

    @app.get("/api/evidence/{sha}/download")
    def download(sha: str, request: Request, who: str = Depends(admin)):
        if not _SHA.match(sha) or not store.q("SELECT 1 FROM evidence WHERE sha256=?", (sha,)):
            raise HTTPException(404, "evidence not found")
        store.x("INSERT INTO evidence_access(ts, who, sha256, action, ip) VALUES(?,?,?,?,?)",
                (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), who, sha, "DOWNLOAD", ip(request)))
        name = store.q("SELECT path FROM events WHERE evidence_sha256=? AND path IS NOT NULL LIMIT 1", (sha,))
        base = (name[0]["path"].replace("\\", "/").rsplit("/", 1)[-1] if name else "evidence").replace('"', "")
        return FileResponse(store.evidence_path(sha), media_type="application/octet-stream",
                            filename=f"{sha[:12]}_{base}", headers={"X-Evidence-SHA256": sha})

    @app.get("/api/alerts")
    def alerts(_: str = Depends(admin)):
        return store.q("SELECT a.*, e.hostname FROM alerts a LEFT JOIN endpoints e ON e.id=a.endpoint_id"
                       " ORDER BY a.id DESC LIMIT 500")

    @app.post("/api/alerts/{alert_id}/ack")
    def ack(alert_id: int, request: Request, who: str = Depends(admin)):
        store.x("UPDATE alerts SET acknowledged_at=?, acknowledged_by=? WHERE id=? AND acknowledged_at IS NULL",
                (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), who, alert_id))
        store.admin_action(who, "ALERT_ACK", {"alert": alert_id}, ip(request))
        return {"ok": True}

    @app.post("/api/integrity/verify")
    def integrity(request: Request, who: str = Depends(admin)):
        report = store.verify_all()
        store.admin_action(who, "INTEGRITY_VERIFY", {"ok": report["ok"]}, ip(request))
        if not report["ok"]:
            store.alert(None, "INTEGRITY_FAILURE", "critical", "La verificación de integridad encontró inconsistencias")
        return report

    @app.post("/api/integrity/checkpoint")
    def checkpoint(request: Request, who: str = Depends(admin)):
        made = store.checkpoint_all()
        store.admin_action(who, "CHECKPOINT", {"created": made}, ip(request))
        return {"created": made}

    @app.get("/api/checkpoints")
    def checkpoints(_: str = Depends(admin)):
        return store.q("SELECT c.*, e.hostname FROM checkpoints c LEFT JOIN endpoints e ON e.id=c.endpoint_id"
                       " ORDER BY c.id DESC LIMIT 200")

    @app.get("/api/access-log")
    def access_log(_: str = Depends(admin)):
        return {"evidence": store.q("SELECT * FROM evidence_access ORDER BY id DESC LIMIT 200"),
                "admin": store.q("SELECT * FROM admin_actions ORDER BY id DESC LIMIT 200")}

    @app.get("/api/export")
    def export(request: Request, format: str = "json", who: str = Depends(admin)):
        f = filters(request)
        rows = store.events(f, limit=100000)
        rows.reverse()  # chronological
        store.admin_action(who, "EXPORT", {"format": format, "filters": f, "events": len(rows)}, ip(request))
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        if format == "csv":
            buf = io.StringIO()
            out = csv.writer(buf)
            out.writerow(["timestamp", "endpoint_id", "seq", "event_type", "user", "process", "pid", "cmdline", "path",
                          "sha256", "session_id", "evidence_sha256", "event_hash", "previous_hash", "event_id"])
            for r in rows:
                actor = r["body"].get("actor") or {}
                cells = [r["ts"], r["endpoint_id"], r["seq"], r["event_type"], r["user"], r["process"],
                         actor.get("pid"), actor.get("cmdline"), r["path"], r["sha256"], r["session_id"],
                         r["evidence_sha256"], r["event_hash"], r["body"]["integrity"]["previous_hash"], r["event_id"]]
                # neutralise spreadsheet formulas: file names and command lines are attacker-controlled
                out.writerow(["'" + c if isinstance(c, str) and c[:1] in "=+-@\t\r" else c for c in cells])
            return Response(buf.getvalue(), media_type="text/csv", headers={
                "Content-Disposition": f'attachment; filename="watcher-export-{stamp}.csv"'})
        bodies = [r["body"] for r in rows]
        payload = {"exported_at": stamp, "filters": f, "count": len(bodies),
                   "content_sha256": hashlib.sha256(json.dumps(bodies, sort_keys=True).encode()).hexdigest(),
                   "events": bodies}
        return Response(json.dumps(payload, indent=1), media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="watcher-export-{stamp}.json"'})

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", headers={
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                       "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    return app
