"""Ciclo de vida del agente sin red: latido independiente de la entrega y parada limpia pedida."""
import json
import threading
import time

from watcher.agent import cli
from watcher.agent.core import Agent
from watcher.agent.spool import Spool


class FakeRepository:
    """Repositorio que acepta latidos pero rechaza toda entrega (como el 500 de evidencias en Windows)."""

    def __init__(self):
        self.heartbeats = 0
        self.base = "http://fake"

    def request(self, method, path, **_kw):
        if path == "/api/v1/heartbeat":
            self.heartbeats += 1
            return 200, {}
        if path == "/api/v1/agent/head":
            return 200, {}
        return 500, {}


def make_agent(tmp_path) -> Agent:
    (tmp_path / "credentials.json").write_text(json.dumps(
        {"endpoint_id": "ep-test", "api_key": "k", "server_url": "http://127.0.0.1:9"}), encoding="utf-8")
    (tmp_path / "config.toml").write_text(
        "[agent]\nheartbeat_interval = 0.2\nsend_interval = 0.5\n"
        "[processes]\nenabled = false\n[files]\nenabled = false\n[sessions]\nenabled = false\n"
        "[windows_eventlog]\nenabled = false\n", encoding="utf-8")
    agent = Agent(tmp_path)
    agent.client = FakeRepository()
    return agent


def test_heartbeat_keeps_going_while_delivery_fails(tmp_path):
    agent = make_agent(tmp_path)
    runner = threading.Thread(target=agent.run, daemon=True)
    runner.start()
    try:
        time.sleep(3)
        # Con el latido dentro del bucle de entrega, el backoff (0.5 s * 2^n) dejaba ~3 latidos en 3 s
        # y en producción huecos de 60 s > timeout de 45 s del repositorio.
        assert agent.client.heartbeats >= 8
        assert agent.connected is True
        assert "HTTP 500" in (agent.last_send_error or "")
    finally:
        agent.request_stop("test")
        runner.join(10)


def test_stop_command_stops_cleanly(tmp_path):
    agent = make_agent(tmp_path)
    runner = threading.Thread(target=agent.run, daemon=True)
    runner.start()
    time.sleep(1)
    assert cli.main(["--home", str(tmp_path), "stop", "--wait", "10"]) == 0
    runner.join(5)
    assert not runner.is_alive()
    events = Spool(tmp_path / "data" / "spool.db").pending(1000)
    stopped = [e for e in events if e["event_type"] == "AGENT_STOPPED"]
    assert stopped and stopped[-1]["data"]["reason"].startswith("local_cli:")
    status = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))
    assert status["state"] == "STOPPED"


def test_stale_stop_request_does_not_stop_next_start(tmp_path):
    agent = make_agent(tmp_path)
    agent.spool.kv_set("stop_request", "local_cli:old")   # pedido que quedó sin agente corriendo
    runner = threading.Thread(target=agent.run, daemon=True)
    runner.start()
    try:
        time.sleep(2)
        assert runner.is_alive()
    finally:
        agent.request_stop("test")
        runner.join(10)
