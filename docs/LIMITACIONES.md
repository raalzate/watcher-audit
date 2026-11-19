# Limitaciones de captura y de protección (RNF-12)

Principio del sistema: **lo que fue observado queda registrado y es verificable**. Este documento
dice con precisión qué *no* se observa o no se protege en la versión 0.1, para que nadie lea una
línea de tiempo vacía como prueba de que no ocurrió nada.

## 1. Estado de verificación de esta versión

| Parte | Estado |
|---|---|
| Servidor, dashboard, cadena de hashes, evidencias, alertas | Probado (tests + ejecución real con TLS) |
| Agente en macOS, ejecutado en primer plano como usuario | Probado de extremo a extremo |
| Instalación como LaunchDaemon (`deploy/macos/install.sh`) | Escrita y validada sintácticamente; **no ejecutada** |
| Agente en Windows: servicio, lectura de Event Log/Sysmon, `install.ps1` | Escrito; solo el análisis de XML tiene tests. **Nunca ejecutado en Windows** |
| Detección de TeamViewer | Analizador probado con el formato documentado de `Connections_incoming.txt`; **no validado contra una instalación real** |
| TLS mutuo (`--tls-client-ca`) | Implementado; no probado |

## 2. Procesos y comandos

- **Sondeo (macOS siempre; Windows sin Sysmon):** se compara la tabla de procesos cada 0,5 s.
  Un proceso que nace y muere entre dos sondeos **no se registra** (p. ej. `ls`, `whoami`,
  un `curl` rápido). Captura fiable: procesos que viven más de ~1 s.
- **Comandos internos del shell** (`cd`, `echo`, `set`, `export`) no crean proceso: no se ven.
  En Windows, PowerShell Script Block Logging (evento 4104) sí los recoge si está habilitado.
- **Resultado de ejecución / código de salida:** no disponible.
- **macOS sin root:** no se puede leer la línea de comandos de procesos de otros usuarios; el
  evento lo indica en `data.fields_denied`. Como LaunchDaemon (root) esto no aplica.
- **Camino a captura completa en macOS:** Endpoint Security (requiere entitlement de Apple) o
  `eslogger`. No incluido en esta versión.

## 3. Archivos

- Solo se auditan las carpetas de `files.watch_paths`. Fuera de ellas no hay eventos.
- **Proceso y usuario responsables de un cambio:** solo en Windows con Sysmon (eventos 11/23/26),
  por coincidencia de ruta en una ventana de 2 minutos. En macOS el campo `actor` queda vacío.
- **Origen de un archivo nuevo** (descarga, transferencia remota, USB): desconocido.
  `FILE_DOWNLOADED`, `FILE_UPLOADED` y `FILE_ACCESSED` **no se emiten**: exigen instrumentar cada
  aplicación de transferencia. El ejemplo del PRD «08:07 archivo enviado a un servicio externo»
  no es reconstruible todavía (en Windows con Sysmon se ve la conexión de red, no el archivo).
- `FILE_COPIED` es una inferencia: archivo nuevo con el mismo SHA-256 que otro existente.
- Un archivo creado y borrado en menos de 1,5 s se registra, pero sin hash ni copia.
- Los documentos que ya existían al instalar se indexan (hash) pero **no se copian** salvo
  `capture.baseline_capture = true`. Si se borran sin haber cambiado antes, el evento
  `FILE_DELETED` trae su último hash pero no hay copia (`no_prior_copy`).
- Archivos mayores de 200 MB no se calculan; mayores de 25 MB no se copian.
- macOS: el daemon necesita «Acceso total al disco» para leer Documentos/Escritorio/Descargas.
- Cambios ocurridos con el agente detenido se detectan al reiniciar (por comparación con el
  índice), con la hora de detección, no la hora real del cambio.

## 4. Sesiones remotas

- **SSH / RDP:** por la tabla de sesiones del sistema operativo y, en Windows, el registro
  LocalSessionManager.
- **TeamViewer:** se lee `Connections_incoming.txt`, que TeamViewer escribe **al terminar** la
  sesión. El inicio y el fin llegan juntos, con las horas reales; por eso la correlación con el
  resto de eventos se hace en el repositorio por ventana de tiempo. En Windows hay además un
  indicio en vivo (proceso `TeamViewer_Desktop.exe`), marcado `process_heuristic`.
- La relación sesión ↔ evento es **temporal**, nunca causal.
- Otras herramientas (AnyDesk, VNC, Chrome Remote Desktop) no están contempladas.

## 5. Secretos

El enmascarado de contraseñas, tokens y claves en líneas de comando es por patrones: reduce el
riesgo, no lo elimina. Un secreto pasado como argumento posicional sin nombre (`mysql -pCLAVE`,
`sshpass CLAVE`) puede quedar registrado. Los archivos que coinciden con `capture.sensitive`
(`*.pem`, `.env`, `.ssh/`, …) nunca se copian.

## 6. Qué protege la inmutabilidad y qué no

Protegido:
- Un administrador del endpoint solo posee la credencial del agente, que **únicamente puede
  añadir** eventos y evidencias de su propio equipo. No existe API de lectura, edición ni borrado
  para esa credencial.
- Cada evento enlaza con el anterior por SHA-256; el repositorio rechaza huecos y reescrituras,
  y sella checkpoints firmados cada 5 minutos.
- Detener el agente deja rastro: `AGENT_STOPPED` si es ordenado; si es `kill -9` o corte de
  energía, alerta por pérdida de latido en ≤45 s y `AGENT_UNCLEAN_SHUTDOWN` al reiniciar.

No protegido (requiere infraestructura, no código):
- **WORM real.** Los disparadores de SQLite y los permisos de solo lectura impiden cambios a
  través de la aplicación, pero quien tenga acceso al disco del servidor puede alterar los
  archivos. La verificación lo **detecta**; no lo **impide**. Para producción: evidencias en
  almacenamiento con bloqueo de objetos (S3 Object Lock en modo compliance o equivalente) y
  copia de los checkpoints fuera del servidor.
- La clave de firma de checkpoints vive en el mismo servidor: un atacante con control total del
  servidor puede rehacer cadena y checkpoints. Mitigación: publicar los checkpoints en un tercero.
- Un administrador local puede, antes de que se envíen, borrar la cola local del agente: se
  pierden esos eventos y queda la alerta `CHAIN_RESYNC`. También puede desinstalar el agente:
  queda la alerta, no la actividad posterior.
- Un único rol de custodio con contraseña compartida. Sin usuarios individuales ni MFA.
- Copias de seguridad y retención configurable: no implementadas.
