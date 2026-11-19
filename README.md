# Watcher — Endpoint Audit System

Agente de auditoría para Windows y macOS + repositorio central de evidencias con dashboard.
El agente **solo observa y registra**: no bloquea, no modifica ni borra nada del equipo, no captura
teclas, pantalla, portapapeles ni contraseñas. Requisitos de producto: [docs/PRD.md](docs/PRD.md).
Qué no captura y qué no protege: [docs/LIMITACIONES.md](docs/LIMITACIONES.md) — léalo antes de
confiar en una línea de tiempo.

## Componentes

| PRD | Dónde |
|---|---|
| Endpoint Agent | `src/watcher/agent/` — `core.py` (estados, envío, autovigilancia), `sources/` (procesos, archivos, sesiones, Event Log de Windows), `spool.py` (cola local + cadena) |
| Event Collector + Event Store + Evidence Repository | `src/watcher/server/store.py` (SQLite solo-añadir + almacén por SHA-256) |
| Audit Dashboard | `src/watcher/server/app.py` + `static/index.html` |
| Modelo de evento y cadena de hashes | `src/watcher/common/chain.py` |
| Enmascarado de secretos | `src/watcher/common/redact.py` |

## Probarlo en una máquina (5 minutos)

```bash
uv venv && uv pip install -e ".[server,dev]"      # o: python -m venv .venv && pip install -e ".[server,dev]"
.venv/bin/python -m pytest -q

# 1. Repositorio + dashboard (solo en loopback sin TLS)
.venv/bin/watcher-server --data ./server-data run --port 8443 &
.venv/bin/watcher-server --data ./server-data info          # token de enrolamiento y contraseña del dashboard

# 2. Agente en primer plano, vigilando una carpeta de prueba
mkdir -p dev-home /tmp/watched
printf '[server]\nurl = "http://127.0.0.1:8443"\n[files]\nwatch_paths = ["/tmp/watched"]\n' > dev-home/config.toml
.venv/bin/watcher-agent --home dev-home enroll --token <TOKEN>
.venv/bin/watcher-agent --home dev-home run &
.venv/bin/watcher-agent --home dev-home status

# 3. Genere actividad y abra http://127.0.0.1:8443
echo hola > /tmp/watched/nota.txt; python3 -c "import time; time.sleep(2)"; rm /tmp/watched/nota.txt
```

## Despliegue

Repositorio central, **en un equipo distinto del auditado**, con TLS:

```bash
watcher-server --data /var/lib/watcher run --host 0.0.0.0 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

Agente (instalación administrativa, arranque automático):

- macOS: `sudo PYTHON=/ruta/python3.11+ deploy/macos/install.sh https://repo:8443 TOKEN [ca.pem]` → LaunchDaemon `com.watcher.audit-agent`
- Windows: `deploy\windows\install.ps1 -Server https://repo:8443 -Token TOKEN [-CaFile ca.pem]` → servicio `WatcherAudit`

Activar / desactivar (queda registrado en el repositorio, con quién lo hizo):

```bash
watcher-agent disable | enable | status        # en el equipo, como administrador
```

o desde el dashboard, en *Endpoints y agentes*.

## Estados del agente

`DISABLED` · `STARTING` · `ACTIVE` · `DEGRADED` (alguna fuente falló) · `DISCONNECTED` (sin repositorio; los eventos
esperan en la cola local) · `STOPPED` · `TAMPER_DETECTED`. El repositorio marca `DISCONNECTED` por su cuenta
cuando deja de recibir latidos.

## Integridad

Cada evento lleva `seq`, `previous_hash` y `event_hash` (SHA-256 del evento completo). El repositorio rechaza
huecos, duplicados con contenido distinto y eventos alterados; sella checkpoints firmados cada 5 minutos y
verifica todo cada hora. A demanda: botón *Verificar ahora* o `watcher-server --data DIR verify` (sale con 1 si falla).
