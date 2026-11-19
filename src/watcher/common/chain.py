"""Canonical serialization and hash chain shared by agent and server."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone

GENESIS = "0" * 64


def iso(ts: float | None = None) -> str:
    """UTC timestamp with fixed millisecond precision (sortable as text)."""
    dt = datetime.fromtimestamp(time.time() if ts is None else ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def compute_hash(event: dict) -> str:
    """SHA-256 over the whole event except integrity.event_hash."""
    body = {k: v for k, v in event.items() if k != "integrity"}
    body["previous_hash"] = event["integrity"]["previous_hash"]
    return hashlib.sha256(canonical(body)).hexdigest()


def seal(event: dict, previous_hash: str) -> dict:
    event["integrity"] = {"previous_hash": previous_hash, "event_hash": ""}
    event["integrity"]["event_hash"] = compute_hash(event)
    return event


def verify(event: dict) -> bool:
    try:
        return event["integrity"]["event_hash"] == compute_hash(event)
    except (KeyError, TypeError):
        return False
