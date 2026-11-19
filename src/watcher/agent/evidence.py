"""Hashing and evidence capture. Files are copied to a local staging area in the same
pass that hashes them, so the evidence survives even if the original is deleted before upload."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import uuid
from pathlib import Path


def match_any(path: str, patterns: list[str]) -> bool:
    p = path.replace("\\", "/")
    low = p.lower()
    return any(fnmatch.fnmatch(low, pat.lower()) for pat in patterns)


class Capturer:
    def __init__(self, cfg: dict, spool, staging: Path):
        self.cap = cfg["capture"]
        self.hash_max = cfg["files"]["hash_max_bytes"]
        self.spool = spool
        self.staging = staging
        staging.mkdir(parents=True, exist_ok=True)
        self._exe_cache: dict[str, tuple[float, int, str | None]] = {}

    def policy(self, path: str, size: int, kind: str) -> tuple[bool, str]:
        if not self.cap["enabled"]:
            return False, "capture_disabled"
        if match_any(path, self.cap["sensitive"]):
            return False, "excluded_sensitive"
        if kind == "script":
            return (True, "script_policy") if size <= self.cap["script_max_bytes"] else (False, "too_large")
        if os.path.splitext(path)[1].lower() not in self.cap["extensions"]:
            return False, "not_in_policy"
        if size > self.cap["max_bytes"]:
            return False, "too_large"
        return True, "document_policy"

    def process(self, path: str, kind: str = "document", capture: bool = True) -> dict:
        """Hash a file and, when policy allows, stage a copy for upload."""
        result = {"sha256": None, "size": None, "evidence": {"captured": False, "repository_reference": None}}
        try:
            size = os.path.getsize(path)
            result["size"] = size
            if size > self.hash_max:
                result["evidence"]["reason"] = "too_large_to_hash"
                return result
            want, reason = self.policy(path, size, kind) if capture else (False, "capture_not_requested")
            digest = hashlib.sha256()
            tmp = self.staging / f"tmp-{uuid.uuid4().hex}" if want else None
            out = open(tmp, "wb") if tmp else None
            try:
                with open(path, "rb") as f:
                    while chunk := f.read(1024 * 1024):
                        digest.update(chunk)
                        if out:
                            out.write(chunk)
            finally:
                if out:
                    out.close()
            sha = digest.hexdigest()
            result["sha256"] = sha
            if tmp:
                if self.spool.evidence_known(sha):
                    tmp.unlink(missing_ok=True)
                else:
                    os.replace(tmp, self.staging / sha)
                    self.spool.evidence_enqueue(sha, size)
                result["evidence"] = {"captured": True, "repository_reference": sha, "reason": reason}
            else:
                result["evidence"]["reason"] = reason
        except OSError as e:
            result["evidence"]["reason"] = f"unreadable: {e.__class__.__name__}"
        return result

    def exe_hash(self, path: str | None) -> str | None:
        if not path:
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        cached = self._exe_cache.get(path)
        if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
            return cached[2]
        sha = None
        if st.st_size <= self.hash_max:
            try:
                digest = hashlib.sha256()
                with open(path, "rb") as f:
                    while chunk := f.read(1024 * 1024):
                        digest.update(chunk)
                sha = digest.hexdigest()
            except OSError:
                sha = None
        self._exe_cache[path] = (st.st_mtime, st.st_size, sha)
        return sha
