"""Windows Service wrapper (requires pywin32). Installed by deploy/windows/install.ps1:

    python -m watcher.agent.winservice --startup auto install
    python -m watcher.agent.winservice start
"""
from __future__ import annotations

import sys

import servicemanager  # type: ignore
import win32serviceutil  # type: ignore
import win32service  # type: ignore

# Import absoluto a propósito: el host de servicios de pywin32 (pythonservice.exe) carga este archivo
# como módulo suelto ("winservice"), sin paquete padre, y un import relativo falla al arrancar.
from watcher.agent.core import Agent


class WatcherAuditService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WatcherAudit"
    _svc_display_name_ = "Watcher Audit Agent"
    _svc_description_ = ("Registra actividad del equipo (procesos, archivos, sesiones remotas) "
                         "en un repositorio central de auditoria. Solo observa; no modifica el equipo.")

    def __init__(self, args):
        super().__init__(args)
        self.agent: Agent | None = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.agent:
            self.agent.request_stop("service_stop")

    def SvcShutdown(self):
        if self.agent:
            self.agent.request_stop("system_shutdown")

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("Watcher Audit Agent starting")
        self.agent = Agent()
        self.agent.run()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WatcherAuditService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(WatcherAuditService)
