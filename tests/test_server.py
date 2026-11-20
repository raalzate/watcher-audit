import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from watcher.common.chain import GENESIS, iso, seal
from watcher.server.app import create_app


@pytest.fixture()
def ctx(tmp_path):
    app = create_app(tmp_path, monitor=False)
    store = app.state.store
    client = TestClient(app)
    r = client.post("/api/v1/enroll", headers={"X-Enroll-Token": store.secrets["enroll_token"]},
                    json={"hostname": "pc-1", "platform": "win32"})
    creds = r.json()
    return client, store, creds["endpoint_id"], {"Authorization": f"Bearer {creds['api_key']}"}


def make(endpoint_id, n, start_seq=1, prev=GENESIS, etype="FILE_CREATED"):
    out = []
    for i in range(n):
        ev = {"event_id": f"{endpoint_id}-{start_seq + i}", "endpoint_id": endpoint_id, "seq": start_seq + i,
              "timestamp": iso(), "event_type": etype, "actor": {"user": "op", "process": "python.exe"},
              "resource": {"path": f"C:/docs/f{i}.csv"}, "data": {}}
        seal(ev, prev)
        prev = ev["integrity"]["event_hash"]
        out.append(ev)
    return out


def login(client, store):
    assert client.post("/api/login", json={"password": store.secrets["admin_password"]}).status_code == 200


def test_enroll_requires_token(ctx):
    client, *_ = ctx
    assert client.post("/api/v1/enroll", headers={"X-Enroll-Token": "nope"}, json={}).status_code == 403


def test_ingest_chain_duplicates_and_breaks(ctx):
    client, store, ep, auth = ctx
    events = make(ep, 3)
    r = client.post("/api/v1/events", json={"events": events}, headers=auth)
    assert r.status_code == 200 and r.json()["accepted"] == 3
    r = client.post("/api/v1/events", json={"events": events}, headers=auth)  # resend
    assert r.json() == {"accepted": 0, "duplicates": 3, "head": r.json()["head"]}
    head = r.json()["head"]
    # a gap (seq 5 instead of 4) is refused and raises an alert
    r = client.post("/api/v1/events", json={"events": make(ep, 1, 5, head["hash"])}, headers=auth)
    assert r.status_code == 409 and r.json()["head"]["seq"] == 3
    # tampered content is refused
    bad = make(ep, 1, 4, head["hash"])
    bad[0]["resource"]["path"] = "C:/other"
    assert client.post("/api/v1/events", json={"events": bad}, headers=auth).status_code == 409
    # another endpoint's id is refused
    assert client.post("/api/v1/events", json={"events": make("ep-other", 1, 4, head["hash"])},
                       headers=auth).status_code == 409
    assert len(store.q("SELECT 1 FROM alerts WHERE kind='CHAIN_BREAK'")) == 3
    assert client.post("/api/v1/events", json={"events": events}).status_code == 401


def test_events_and_evidence_are_append_only(ctx):
    client, store, ep, auth = ctx
    client.post("/api/v1/events", json={"events": make(ep, 2)}, headers=auth)
    with pytest.raises(sqlite3.DatabaseError):
        store.x("DELETE FROM events")
    with pytest.raises(sqlite3.DatabaseError):
        store.x("UPDATE events SET body='{}'")
    # the agent credential cannot read or delete anything
    for method, path in [("GET", "/api/events"), ("DELETE", "/api/v1/events"), ("GET", "/api/evidence"),
                         ("DELETE", "/api/v1/evidence/" + "a" * 64)]:
        assert client.request(method, path, headers=auth).status_code in (401, 404, 405)


def test_evidence_store(ctx):
    client, store, ep, auth = ctx
    content = b"quarterly report"
    sha = hashlib.sha256(content).hexdigest()
    assert client.put(f"/api/v1/evidence/{sha}", content=content, headers=auth).status_code == 201
    assert client.put(f"/api/v1/evidence/{sha}", content=content, headers=auth).json()["status"] == "exists"
    assert client.put(f"/api/v1/evidence/{sha}", content=b"forged", headers=auth).status_code == 422
    assert store.evidence_path(sha).read_bytes() == content
    assert client.get(f"/api/evidence/{sha}/download").status_code == 401
    login(client, store)
    assert client.get(f"/api/evidence/{sha}/download").content == content
    assert client.get("/api/access-log").json()["evidence"][0]["sha256"] == sha


def test_evidence_store_with_windows_readonly_semantics(ctx, monkeypatch):
    """Windows no deja borrar un archivo read-only (y los hard links comparten el atributo).
    Antes: chmod 0o444 al temporal -> link -> unlink -> PermissionError -> HTTP 500 en cada evidencia."""
    import os
    import stat
    from pathlib import Path

    real_unlink = Path.unlink

    def windows_unlink(self, missing_ok=False):
        if self.exists() and not (self.stat().st_mode & stat.S_IWUSR):
            raise PermissionError(13, "Acceso denegado", str(self))
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", windows_unlink)
    client, store, ep, auth = ctx
    content = b"informe trimestral"
    sha = hashlib.sha256(content).hexdigest()
    assert client.put(f"/api/v1/evidence/{sha}", content=content, headers=auth).status_code == 201
    final = store.evidence_path(sha)
    assert final.read_bytes() == content
    assert not (final.stat().st_mode & stat.S_IWUSR)          # la copia final sí queda read-only
    assert list((store.evidence_dir / "tmp").iterdir()) == []  # y no queda basura en tmp
    assert os.path.exists(final)


def test_startup_cleans_readonly_leftovers(tmp_path):
    tmpdir = tmp_path / "evidence" / "tmp"
    tmpdir.mkdir(parents=True)
    leftover = tmpdir / "deadbeef"
    leftover.write_bytes(b"x")
    leftover.chmod(0o444)
    create_app(tmp_path, monitor=False)
    assert not leftover.exists()


def test_integrity_verification_detects_tampering(ctx):
    client, store, ep, auth = ctx
    client.post("/api/v1/events", json={"events": make(ep, 5)}, headers=auth)
    content = b"evidence"
    sha = hashlib.sha256(content).hexdigest()
    client.put(f"/api/v1/evidence/{sha}", content=content, headers=auth)
    assert store.checkpoint_all() == 1
    assert store.verify_all()["ok"]
    # an attacker with direct access to the database file removes the triggers and edits a record
    store.db.execute("DROP TRIGGER events_no_update")
    store.db.execute("UPDATE events SET body=replace(body,'f2.csv','x.csv') WHERE seq=3")
    report = store.verify_all()
    assert not report["ok"] and "seq 3" in report["endpoints"][0]["errors"][0]
    # ... or deletes the newest records
    store.db.execute("DROP TRIGGER events_no_delete")
    store.db.execute("DELETE FROM events WHERE seq>=4")
    assert any("checkpoint" in e or "cabeza" in e for e in store.verify_all()["endpoints"][0]["errors"])
    # ... or alters stored evidence
    path = store.evidence_path(sha)
    path.chmod(0o644)
    path.write_bytes(b"altered")
    assert not store.verify_all()["evidence"]["ok"]


def test_heartbeat_loss_and_remote_toggle(ctx):
    client, store, ep, auth = ctx
    beat = {"state": "ACTIVE", "enabled": True, "agent_time": iso(), "spool_depth": 0}
    assert client.post("/api/v1/heartbeat", json=beat, headers=auth).json()["desired_enabled"] is None
    store.x("UPDATE endpoints SET last_seen=last_seen-120 WHERE id=?", (ep,))
    store.monitor_tick(45)
    assert store.endpoints()[0]["state"] == "DISCONNECTED"
    assert store.q("SELECT kind FROM alerts")[0]["kind"] == "AGENT_DISCONNECTED"
    login(client, store)
    assert client.post(f"/api/endpoints/{ep}/audit", json={"enabled": False}).status_code == 200
    resp = client.post("/api/v1/heartbeat", json=beat, headers=auth).json()
    assert resp["desired_enabled"] is False and resp["desired_rev"] == 1
    assert store.endpoints()[0]["state"] == "ACTIVE"
    assert [a["kind"] for a in store.q("SELECT kind FROM alerts ORDER BY id")] == ["AGENT_DISCONNECTED", "AGENT_RECONNECTED"]


def test_sessions_and_timeline_window(ctx):
    client, store, ep, auth = ctx
    def ev(seq, prev, etype, ts, data=None):
        e = {"event_id": f"e{seq}", "endpoint_id": ep, "seq": seq, "timestamp": ts, "event_type": etype,
             "actor": None, "resource": None, "data": data or {}}
        return seal(e, prev)
    s = {"session_id": "teamviewer-1", "provider": "TeamViewer", "remote_host": "123"}
    chain, prev = [], GENESIS
    for seq, (etype, ts, data) in enumerate([
            ("PROCESS_STARTED", "2026-11-09T07:59:00.000Z", None),
            ("REMOTE_SESSION_STARTED", "2026-11-09T08:00:00.000Z", s),
            ("FILE_DELETED", "2026-11-09T08:06:00.000Z", None),
            ("REMOTE_SESSION_ENDED", "2026-11-09T08:30:00.000Z", s),
            ("FILE_CREATED", "2026-11-09T09:00:00.000Z", None)], start=1):
        chain.append(ev(seq, prev, etype, ts, data))
        prev = chain[-1]["integrity"]["event_hash"]
    assert client.post("/api/v1/events", json={"events": chain}, headers=auth).status_code == 200
    login(client, store)
    session = client.get("/api/sessions").json()[0]
    assert session["started"] == "2026-11-09T08:00:00.000Z" and session["ended"] == "2026-11-09T08:30:00.000Z"
    inside = client.get("/api/events?session=teamviewer-1").json()
    assert [e["event_type"] for e in inside] == ["REMOTE_SESSION_ENDED", "FILE_DELETED", "REMOTE_SESSION_STARTED"]
    csv_text = client.get("/api/export?format=csv").text
    assert csv_text.count("\n") == 6 and "FILE_DELETED" in csv_text


def test_log_groups_and_streams(ctx):
    client, store, ep, auth = ctx
    events = make(ep, 3)
    events[0]["timestamp"], events[1]["timestamp"], events[2]["timestamp"] = (
        "2026-11-20T01:10:00.000Z", "2026-11-20T01:50:00.000Z", "2026-11-20T02:05:00.000Z")
    prev = GENESIS
    for ev in events:                      # re-sellar: cambiamos el timestamp
        seal(ev, prev)
        prev = ev["integrity"]["event_hash"]
    assert client.post("/api/v1/events", json={"events": events}, headers=auth).status_code == 200
    assert client.get("/api/logs/groups").status_code == 401
    login(client, store)

    groups = {g["group"]: g for g in client.get("/api/logs/groups").json()}
    assert groups["files"]["name"] == "/watcher/archivos" and groups["files"]["events"] == 3
    assert groups["processes"]["events"] == 0

    streams = client.get("/api/logs/streams", params={"group": "files"}).json()
    assert [(s["name"], s["events"]) for s in streams] == [("pc-1/2026/11/20/02h", 1), ("pc-1/2026/11/20/01h", 2)]
    by_day = client.get("/api/logs/streams", params={"group": "files", "bucket": "day"}).json()
    assert [(s["name"], s["events"]) for s in by_day] == [("pc-1/2026/11/20", 3)]
    assert client.get("/api/logs/streams", params={"group": "nope"}).status_code == 404

    one = client.get("/api/events", params={"category": "files", "endpoint": ep, "prefix": "2026-11-20T01",
                                            "order": "asc"}).json()
    assert [e["ts"] for e in one] == ["2026-11-20T01:10:00.000Z", "2026-11-20T01:50:00.000Z"]
