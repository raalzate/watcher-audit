#!/bin/bash
# Detiene y retira el agente. La parada queda registrada en el repositorio (AGENT_STOPPED + alerta).
# No borra la carpeta de datos local ni nada del repositorio central.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "ejecute con sudo" >&2; exit 1; }
launchctl bootout system/com.watcher.audit-agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.watcher.audit-agent.plist
rm -rf /Library/Watcher
echo "Agente retirado. Datos locales conservados en /Library/Application Support/Watcher"
