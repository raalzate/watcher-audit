"""HTTPS client for the central repository (stdlib only)."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request


class TransportError(Exception):
    pass


class Client:
    def __init__(self, server_cfg: dict, api_key: str | None = None):
        self.base = server_cfg["url"].rstrip("/")
        self.timeout = server_cfg.get("timeout", 15)
        self.api_key = api_key
        parsed = urllib.parse.urlparse(self.base)
        self.ctx = None
        if parsed.scheme == "https":
            self.ctx = ssl.create_default_context(cafile=server_cfg.get("ca_file") or None)
            if server_cfg.get("client_cert"):  # mutual TLS
                self.ctx.load_cert_chain(server_cfg["client_cert"], server_cfg.get("client_key") or None)
        elif parsed.scheme == "http":
            local = parsed.hostname in ("127.0.0.1", "localhost", "::1")
            if not (local or server_cfg.get("allow_insecure")):
                raise TransportError("refusing plain http to a non-local server (set server.allow_insecure to override)")
        else:
            raise TransportError(f"invalid server url: {self.base!r}")

    def request(self, method: str, path: str, *, body=None, raw: bytes | None = None,
                headers: dict | None = None, timeout: float | None = None) -> tuple[int, dict]:
        hdrs = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif raw is not None:
            hdrs["Content-Type"] = "application/octet-stream"
        if self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self.ctx) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read() or b"{}")
            except ValueError:
                payload = {}
            return e.code, payload
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise TransportError(str(e)) from e
