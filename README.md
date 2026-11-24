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

## Instalar en Windows (receta única, con uv)

No hace falta instalar Python: el script instala [uv](https://docs.astral.sh/uv/) y uv baja su propio
Python dentro de `C:\Program Files\Watcher`. Si no abrís la consola como Administrador, el script
la vuelve a abrir con permisos. Se puede correr de nuevo: actualiza el código y conserva la
configuración, la identidad del equipo y las evidencias.

**Probar todo en un solo equipo** (repositorio y agente en el mismo PC, solo loopback):

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

Al final abre el dashboard e imprime la clave.

**Producción** (el repositorio va en un equipo distinto del auditado):

```powershell
# 1. En el equipo del repositorio: TLS con CA propia generada en el momento, firewall y arranque con Windows
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Modo repositorio
#    imprime el token, dónde quedó ca.pem y el comando exacto del paso 2

# 2. En cada equipo auditado (con este repo y ca.pem copiados):
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Modo agente -Server https://REPO:8443 -Token TOKEN -CaFile ca.pem

# Retirar (conserva datos y evidencias en C:\ProgramData):
powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1
# Quitar TODO, también evidencias e identidad del equipo (pide escribir BORRAR):
powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1 -BorrarDatos
```

El agente se instala como servicio `WatcherAudit`. Si el servicio de pywin32 no se mantiene
arriba, el script lo avisa y usa una tarea programada `WatcherAuditAgent` (SYSTEM, arranca con
Windows): es el mismo agente, solo cambia quién lo lanza. Para usar un certificado propio en vez
de la CA generada: `-TlsCert cert.pem -TlsKey key.pem`.

Comandos de operación en Windows para pausar, detener, limpiar datos, volver a enrolar o desinstalar:
[docs/OPERACION_WINDOWS.md](docs/OPERACION_WINDOWS.md).

## Probarlo en una máquina de desarrollo (5 minutos, cualquier SO)

```bash
uv run --extra server --extra dev pytest -q        # uv crea .venv con Python y dependencias
uv run --extra server watcher-server --data ./server-data info   # token y clave del dashboard
uv run --script deploy/gen_cert.py --out ./certs    # CA + certificado TLS de prueba, sin openssl

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
- Windows: ver [Instalar en Windows](#instalar-en-windows-receta-única-con-uv) → servicio `WatcherAudit`

Activar / desactivar (queda registrado en el repositorio, con quién lo hizo):

```bash
watcher-agent disable | enable | status        # en el equipo, como administrador
```

o desde el dashboard, en *Endpoints y agentes*.

## Estados del agente

`DISABLED` · `STARTING` · `ACTIVE` · `DEGRADED` (alguna fuente falló) · `DISCONNECTED` (sin repositorio; los eventos
esperan en la cola local) · `STOPPED` · `TAMPER_DETECTED`. El repositorio marca `DISCONNECTED` por su cuenta
cuando deja de recibir latidos.

En Windows, las conexiones de red individuales de Sysmon se omiten por defecto para reducir el volumen
de eventos. Para habilitarlas, agrega `network_events = true` bajo `[windows_eventlog]` en
`C:\ProgramData\Watcher\config.toml` y reinicia el agente. Los eventos de procesos, PowerShell,
archivos y sesiones siguen habilitados según las fuentes disponibles.

## Integridad

Cada evento lleva `seq`, `previous_hash` y `event_hash` (SHA-256 del evento completo). El repositorio rechaza
huecos, duplicados con contenido distinto y eventos alterados; sella checkpoints firmados cada 5 minutos y
verifica todo cada hora. A demanda: botón *Verificar ahora* o `watcher-server --data DIR verify` (sale con 1 si falla).
