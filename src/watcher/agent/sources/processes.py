"""Process creation by polling the process table.

Portable fallback: sees every process that lives longer than one poll interval.
Processes that start and exit between two polls are NOT observed (see docs/LIMITACIONES.md);
on Windows the Sysmon source replaces this one when Sysmon is installed.
"""
from __future__ import annotations

import os
import threading

import psutil

from ...common.chain import iso
from ..procinfo import emit_process


class ProcessPollSource:
    name = "processes"

    def __init__(self, agent):
        self.agent = agent
        self.cfg = agent.cfg["processes"]
        self._stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.missed = 0

    def start(self) -> None:
        if getattr(self.agent, "sysmon_active", False):
            return  # Sysmon already reports every process creation
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, name="proc-poll", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=5)

    def alive(self) -> bool:
        return self.thread is None or self.thread.is_alive()

    def _loop(self) -> None:
        known = set(psutil.pids())
        while not self._stop.wait(self.cfg["poll_interval"]):
            current = set(psutil.pids())
            for pid in current - known:
                try:
                    self._inspect(pid)
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    self.missed += 1  # gone before we could read it
                except Exception as e:  # never let one process kill the source
                    self.agent.log(f"process inspect failed pid={pid}: {e!r}")
            known = current

    def _inspect(self, pid: int) -> None:
        if pid == os.getpid():
            return
        proc = psutil.Process(pid)
        limited = []

        def read(fn, label):
            try:
                return fn()
            except psutil.AccessDenied:
                limited.append(label)
                return None

        with proc.oneshot():
            name = proc.name()
            if name in self.cfg["exclude_names"]:
                return
            ppid = proc.ppid()
            started = proc.create_time()
            exe = read(proc.exe, "exe") or None
            args = read(proc.cmdline, "cmdline")
            user = read(proc.username, "user")
            cwd = read(proc.cwd, "cwd")
        parent = None
        try:
            parent = psutil.Process(ppid).name() if ppid else None
        except psutil.Error:
            pass
        emit_process(self.agent, name=name, exe=exe, pid=pid, ppid=ppid, parent=parent, user=user,
                     args=args or None, cwd=cwd, started=iso(started), source="poll",
                     extra={"fields_denied": limited} if limited else None)
