"""File activity: create / modify / delete / move / rename / copy (by hash correlation)."""
from __future__ import annotations

import glob
import os
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ...common.chain import iso
from ..evidence import match_any


class _Handler(FileSystemEventHandler):
    def __init__(self, src: "FileSource"):
        self.src = src

    def on_created(self, e):
        path = os.fsdecode(e.src_path)
        if e.is_directory:
            self.src.created_dir(path)
        else:
            self.src.touch(path, created=True)

    def on_modified(self, e):
        if not e.is_directory:
            self.src.touch(os.fsdecode(e.src_path), created=False)

    def on_deleted(self, e):
        self.src.deleted(os.fsdecode(e.src_path), e.is_directory)

    def on_moved(self, e):
        self.src.moved(os.fsdecode(e.src_path), os.fsdecode(e.dest_path), e.is_directory)


class FileSource:
    name = "files"

    def __init__(self, agent):
        self.agent = agent
        self.cfg = agent.cfg["files"]
        self.spool = agent.spool
        self.exclude = list(self.cfg["exclude"]) + [str(agent.home).replace("\\", "/") + "/*"]
        self.pending: dict[str, tuple[float, bool, bool]] = {}  # path -> (due, created, quiet)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.observer = None
        self.threads: list[threading.Thread] = []
        self.roots: list[str] = []

    # --- lifecycle -------------------------------------------------------
    def start(self) -> None:
        roots: list[str] = []
        for pattern in self.cfg["watch_paths"]:
            roots += [p for p in glob.glob(os.path.expanduser(pattern)) if os.path.isdir(p)]
        self.roots = sorted({os.path.realpath(r) for r in roots})
        if not self.roots:
            raise RuntimeError("none of files.watch_paths exists")
        self._stop.clear()
        self.observer = Observer()
        handler = _Handler(self)
        for root in self.roots:
            self.observer.schedule(handler, root, recursive=True)
        self.observer.start()
        self.threads = [threading.Thread(target=self._work, name="file-work", daemon=True)]
        if self.cfg["baseline"]:
            self.threads.append(threading.Thread(target=self._baseline, name="file-baseline", daemon=True))
        for t in self.threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        for t in self.threads:
            t.join(timeout=5)

    def alive(self) -> bool:
        return bool(self.observer and self.observer.is_alive() and self.threads and self.threads[0].is_alive())

    def excluded(self, path: str) -> bool:
        return match_any(path, self.exclude)

    def watched(self, path: str) -> bool:
        return any(path == r or path.startswith(r + os.sep) for r in self.roots)

    # --- watchdog callbacks ----------------------------------------------
    def touch(self, path: str, created: bool, quiet: bool = False) -> None:
        if self.excluded(path):
            return
        with self.lock:
            prev = self.pending.get(path)
            self.pending[path] = (time.monotonic() + self.cfg["settle_seconds"],
                                  created or bool(prev and prev[1]), quiet and (prev is None or prev[2]))

    def created_dir(self, path: str) -> None:
        if self.excluded(path):
            return
        self.agent.emit(
            "DIRECTORY_CREATED",
            actor=self.agent.attribute(path),
            resource={"path": path, "name": os.path.basename(path), "is_directory": True},
        )

    def deleted(self, path: str, is_dir: bool) -> None:
        if self.excluded(path):
            return
        with self.lock:
            pend = self.pending.pop(path, None)
        idx = self.spool.index_get(path)
        children = self.spool.index_children(path + os.sep)
        if idx or pend or not (is_dir or children):
            self._emit_deleted(path, idx, never_hashed=bool(pend and not idx))
        for cpath, sha, size, mtime, captured in children:
            if not os.path.exists(cpath):
                self._emit_deleted(cpath, (sha, size, mtime, captured))

    def moved(self, src: str, dst: str, is_dir: bool) -> None:
        if is_dir:
            children = self.spool.index_children(src + os.sep)
            for cpath, sha, size, mtime, captured in children:
                self.spool.index_del(cpath)
                self.spool.index_put(dst + cpath[len(src):], sha, size, mtime, bool(captured))
            self.agent.emit("FILE_RENAMED" if os.path.dirname(src) == os.path.dirname(dst) else "FILE_MOVED",
                            resource={"path": dst, "previous_path": src, "is_directory": True},
                            data={"files_inside": len(children)})
            return
        idx = self.spool.index_get(src)
        with self.lock:
            self.pending.pop(src, None)
        if idx is None and self.excluded(src):
            # "atomic save": editor wrote a temp file and renamed it over the real one
            if self.watched(dst):
                self.touch(dst, created=self.spool.index_get(dst) is None)
            return
        if self.excluded(src) and self.excluded(dst):
            return
        etype = "FILE_RENAMED" if os.path.dirname(src) == os.path.dirname(dst) else "FILE_MOVED"
        resource = {"path": dst, "previous_path": src, "name": os.path.basename(dst),
                    "extension": os.path.splitext(dst)[1].lower(),
                    "sha256": idx[0] if idx else None, "size": idx[1] if idx else None}
        self.agent.emit(etype, actor=self.agent.attribute(dst), resource=resource,
                        data={"to_trash": "/.Trash/" in dst.replace("\\", "/") or "$Recycle.Bin" in dst})
        self.spool.index_del(src)
        if self.watched(dst) and not self.excluded(dst):
            if idx:
                self.spool.index_put(dst, idx[0], idx[1], idx[2], bool(idx[3]))
            else:
                self.touch(dst, created=False, quiet=True)

    def _emit_deleted(self, path: str, idx, never_hashed: bool = False) -> None:
        sha = idx[0] if idx else None
        captured = bool(idx and idx[3])
        data = {}
        if never_hashed:
            data["note"] = "deleted before its content could be read"
        self.agent.emit(
            "FILE_DELETED", actor=self.agent.attribute(path),
            resource={"path": path, "name": os.path.basename(path), "extension": os.path.splitext(path)[1].lower(),
                      "size": idx[1] if idx else None, "sha256": sha},
            evidence={"captured": captured, "repository_reference": sha if captured else None,
                      "reason": "captured_before_deletion" if captured else "no_prior_copy"},
            data=data)
        self.spool.index_del(path)

    # --- deferred hashing ------------------------------------------------
    def _work(self) -> None:
        while not self._stop.wait(0.25):
            now = time.monotonic()
            with self.lock:
                due = [(p, v) for p, v in self.pending.items() if v[0] <= now]
                for p, _ in due:
                    del self.pending[p]
            for path, (_, created, quiet) in due:
                try:
                    self._process(path, created, quiet)
                except Exception as e:
                    self.agent.log(f"file processing failed {path}: {e!r}")

    def _process(self, path: str, created: bool, quiet: bool) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return  # gone again; the delete event reports it
        if not os.path.isfile(path):
            return
        idx = self.spool.index_get(path)
        info = self.agent.capturer.process(path, kind="document")
        sha = info["sha256"]
        if idx and sha is not None and idx[0] == sha:
            return  # metadata-only change
        captured = info["evidence"]["captured"]
        self.spool.index_put(path, sha, st.st_size, st.st_mtime, captured)
        if quiet:
            return
        etype = "FILE_MODIFIED" if (idx or not created) else "FILE_CREATED"
        resource = {"path": path, "name": os.path.basename(path), "extension": os.path.splitext(path)[1].lower(),
                    "size": st.st_size, "sha256": sha,
                    "created": iso(getattr(st, "st_birthtime", st.st_ctime)), "modified": iso(st.st_mtime)}
        data = {}
        if idx:
            data["previous_sha256"] = idx[0]
        elif not created:
            data["previously_unindexed"] = True
        actor = self.agent.attribute(path)
        self.agent.emit(etype, actor=actor, resource=resource, evidence=info["evidence"], data=data)
        if etype == "FILE_CREATED" and sha and st.st_size > 0:
            sources = [p for p in self.spool.index_by_hash(sha, path) if os.path.exists(p)]
            if sources:
                self.agent.emit("FILE_COPIED", actor=actor, resource=resource, evidence=info["evidence"],
                                data={"source_path": sources[0], "other_matches": len(sources) - 1,
                                      "method": "sha256_correlation"})

    # --- baseline: index what already exists, reconcile what changed while stopped ---
    def _baseline(self) -> None:
        first = self.spool.kv_get("baseline_done") is None
        capture = self.agent.cfg["capture"]["baseline_capture"]
        t0 = time.time()
        seen: set[str] = set()
        files = changed = 0
        for root in self.roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if not self.excluded(os.path.join(dirpath, d) + "/x")]
                for fname in filenames:
                    if self._stop.is_set():
                        return
                    path = os.path.join(dirpath, fname)
                    if self.excluded(path):
                        continue
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    seen.add(path)
                    files += 1
                    idx = self.spool.index_get(path)
                    if idx and idx[1] == st.st_size and idx[2] == st.st_mtime:
                        continue
                    if first:
                        info = self.agent.capturer.process(path, capture=capture)
                        self.spool.index_put(path, info["sha256"], st.st_size, st.st_mtime,
                                             info["evidence"]["captured"])
                    else:
                        changed += 1
                        self.touch(path, created=idx is None)  # changed while the agent was not running
        removed = 0
        if not first:
            for root in self.roots:
                for cpath, sha, size, mtime, captured in self.spool.index_children(root + os.sep):
                    if cpath not in seen and not os.path.exists(cpath):
                        removed += 1
                        self._emit_deleted(cpath, (sha, size, mtime, captured))
        self.spool.kv_set("baseline_done", iso())
        self.agent.emit("BASELINE_COMPLETED", data={
            "first_run": first, "files": files, "changed_while_stopped": changed,
            "deleted_while_stopped": removed, "seconds": round(time.time() - t0, 2), "roots": self.roots})
