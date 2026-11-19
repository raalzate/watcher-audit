#!/bin/bash
# Instala el agente de auditoría como LaunchDaemon (visible en `launchctl print system/com.watcher.audit-agent`).
# Uso: sudo PYTHON=/ruta/python3.11+ ./install.sh https://repositorio:8443 TOKEN_DE_ENROLAMIENTO [ca.pem]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "ejecute con sudo" >&2; exit 1; }
SERVER="${1:?URL del repositorio}"; TOKEN="${2:?token de enrolamiento}"; CA="${3:-}"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "se requiere Python >= 3.11 (indique PYTHON=/ruta/python3)" >&2; exit 1; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
APP=/Library/Watcher; HOME_DIR="/Library/Application Support/Watcher"; LABEL=com.watcher.audit-agent

mkdir -p "$APP" "$HOME_DIR" /Library/Logs/Watcher
chmod 700 "$HOME_DIR"                       # credenciales y cola local: solo root
"$PYTHON" -m venv "$APP/venv"
"$APP/venv/bin/pip" install --quiet "$REPO"
[ -f "$HOME_DIR/config.toml" ] || sed "s|https://audit.example.com:8443|$SERVER|" "$REPO/deploy/config.example.toml" > "$HOME_DIR/config.toml"
if [ -n "$CA" ]; then
  cp "$CA" "$HOME_DIR/ca.pem"
  sed -i '' "s|^ca_file = .*|ca_file = \"$HOME_DIR/ca.pem\"|" "$HOME_DIR/config.toml"
fi
[ -f "$HOME_DIR/credentials.json" ] || "$APP/venv/bin/watcher-agent" enroll --server "$SERVER" --token "$TOKEN" ${CA:+--ca-file "$CA"}

install -m 644 -o root -g wheel "$REPO/deploy/macos/$LABEL.plist" /Library/LaunchDaemons/
launchctl bootout system/$LABEL 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/$LABEL.plist
sleep 3
"$APP/venv/bin/watcher-agent" status || true
cat <<MSG

Pendiente (manual, lo exige macOS): conceda "Acceso total al disco" a
  $APP/venv/bin/python3
en Ajustes del Sistema > Privacidad y seguridad. Sin ello el daemon no puede leer
Documentos, Escritorio ni Descargas y el agente quedará en estado DEGRADED.
MSG
