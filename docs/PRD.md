# PRD — Endpoint Audit System
## Sistema de auditoría integral de actividad en endpoints

**Versión:** 1.0  
**Estado:** Propuesta inicial  
**Plataformas:** Windows y macOS  
**Tipo de sistema:** Agente de auditoría + repositorio central de evidencias.

---

# 1. Resumen ejecutivo

Endpoint Audit System es una solución de auditoría continua diseñada para registrar, conservar y reconstruir las actividades relevantes realizadas en un equipo Windows o macOS.

El sistema funcionará mediante un agente instalado como servicio o daemon del sistema operativo, con los privilegios administrativos necesarios para observar las actividades autorizadas de auditoría.

Su responsabilidad será exclusivamente de observación y registro. No deberá ejecutar acciones sobre el equipo auditado, modificar archivos del usuario, bloquear operaciones ni intervenir en las actividades de otros programas.

Cada evento detectado deberá convertirse en un registro de auditoría, acompañado de metadatos y, cuando corresponda, de una copia de la evidencia asociada.

Los eventos y evidencias deberán enviarse a un repositorio central independiente del equipo monitoreado, donde se conservarán con mecanismos de integridad criptográfica y retención inmutable.

El sistema permitirá reconstruir cronológicamente qué sucedió en el equipo, qué procesos se ejecutaron, qué comandos se utilizaron, qué documentos se crearon, modificaron, copiaron, movieron o eliminaron y qué actividades ocurrieron durante las sesiones de acceso remoto.

# 2. Problema

Actualmente, cuando una persona obtiene acceso remoto a un equipo mediante herramientas como TeamViewer, puede realizar operaciones que el propietario no necesariamente conoce.

Entre ellas:

- Ejecutar comandos en PowerShell, CMD o Terminal.
- Ejecutar scripts Python, Bash, PowerShell y otros intérpretes.
- Crear documentos y archivos.
- Modificar documentos existentes.
- Eliminar archivos.
- Descargar o cargar documentos.
- Instalar aplicaciones.
- Crear procesos y servicios.
- Modificar configuraciones.
- Establecer conexiones de red.

Los registros convencionales del sistema operativo no siempre ofrecen una historia completa y correlacionada de estas operaciones.

Se necesita una solución que permita mantener un historial independiente y verificable de las actividades relevantes.

# 3. Objetivos

## 3.1 Objetivo general

Desarrollar un sistema multiplataforma que permita auditar continuamente las actividades realizadas en uno o varios equipos, almacenando eventos y evidencias en un repositorio central protegido contra alteraciones.

## 3.2 Objetivos específicos

1. Implementar un agente de auditoría para Windows y macOS.
2. Permitir activar y desactivar el monitoreo mediante una interfaz administrativa.
3. Ejecutar el agente como servicio del sistema operativo.
4. Registrar la ejecución de procesos y comandos.
5. Detectar creación, modificación, movimiento, copia y eliminación de archivos.
6. Capturar documentos incorporados al equipo mediante los mecanismos de transferencia instrumentados.
7. Conservar evidencias digitales y hashes SHA-256.
8. Registrar conexiones y sesiones de acceso remoto.
9. Enviar los eventos a un repositorio externo.
10. Garantizar integridad y trazabilidad de los registros.
11. Proporcionar una línea de tiempo completa de los eventos observados.
12. Alertar cuando el agente sea detenido, alterado o pierda comunicación.

# 4. Alcance funcional

## 4.1 Agente de auditoría

El sistema deberá disponer de un agente independiente para cada plataforma.

### Windows

El agente deberá:

- Ejecutarse como Windows Service.
- Instalarse mediante un proceso administrativo.
- Iniciar automáticamente con el sistema.
- Supervisar procesos y comandos.
- Integrarse con Windows Event Log.
- Integrarse con Sysmon.
- Supervisar cambios en archivos.
- Detectar cambios en configuraciones relevantes.
- Enviar eventos al servidor central.

### macOS

El agente deberá:

- Ejecutarse como LaunchDaemon.
- Instalarse mediante un proceso administrativo autorizado.
- Iniciar automáticamente con el sistema.
- Recopilar eventos disponibles del sistema operativo.
- Supervisar procesos y ejecución de comandos.
- Supervisar cambios en archivos.
- Integrarse con los mecanismos nativos de auditoría.
- Enviar eventos al servidor central.

El agente deberá ser visible en el sistema operativo y disponer de un estado verificable de funcionamiento.

## 4.2 Activación y desactivación

El propietario del equipo podrá activar o desactivar el sistema desde una interfaz administrativa.

Estados:

- DISABLED: auditoría desactivada.
- STARTING: inicialización del agente.
- ACTIVE: auditoría funcionando.
- DEGRADED: auditoría funcionando parcialmente.
- DISCONNECTED: sin comunicación con el repositorio.
- STOPPED: agente detenido.
- TAMPER_DETECTED: alteración o manipulación detectada.

Al activar el sistema:

1. Se verifica la configuración.
2. Se inicializan los componentes de auditoría.
3. Se verifica la conexión con el repositorio.
4. Se registra el evento AUDIT_STARTED.
5. Se inicia la captura de eventos.
6. Se envían periódicamente evidencias y registros.

La desactivación también deberá quedar registrada en el repositorio central.

## 4.3 Auditoría de procesos y comandos

El sistema deberá registrar:

- Nombre del proceso.
- Ruta del ejecutable.
- PID.
- Proceso padre.
- Usuario que ejecuta el proceso.
- Fecha y hora.
- Línea de comandos y argumentos disponibles.
- Intérprete utilizado.
- Hash del ejecutable cuando sea posible.
- Resultado de la ejecución cuando exista instrumentación para obtenerlo.

Intérpretes contemplados:

- PowerShell.
- CMD.
- Python.
- Bash.
- Zsh.
- Java.
- Node.js.
- Otros intérpretes configurables.

No se capturarán contraseñas, tokens, claves privadas ni otros secretos contenidos en argumentos o archivos de configuración.

## 4.4 Auditoría de archivos y documentos

El sistema deberá detectar las siguientes operaciones:

| Evento | Descripción |
|---|---|
| FILE_CREATED | Archivo creado. |
| FILE_MODIFIED | Archivo modificado. |
| FILE_DELETED | Archivo eliminado. |
| FILE_MOVED | Archivo movido. |
| FILE_RENAMED | Archivo renombrado. |
| FILE_COPIED | Copia identificada mediante correlación de eventos. |
| FILE_DOWNLOADED | Archivo recibido mediante una fuente instrumentada. |
| FILE_UPLOADED | Documento transferido mediante una fuente instrumentada. |
| FILE_ACCESSED | Acceso registrado cuando exista instrumentación habilitada. |

### Captura de documentos

Cuando el sistema detecte que se incorpora un documento al equipo deberá:

1. Detectar el evento de creación o transferencia.
2. Identificar la ruta del archivo.
3. Registrar nombre y extensión.
4. Identificar el proceso responsable cuando sea posible.
5. Calcular el hash SHA-256.
6. Obtener tamaño y fecha de creación.
7. Crear una copia de evidencia cuando la política de captura lo permita.
8. Enviar el evento y la evidencia al repositorio central.
9. Asociar la evidencia al evento original.

La captura deberá realizarse respetando las políticas de privacidad y exclusión de información sensible.

La detección de un archivo nuevo no garantiza conocer su origen. Para identificar cargas y descargas será necesario instrumentar también las aplicaciones o mecanismos de transferencia correspondientes.

## 4.5 Auditoría de eliminación

Cuando se elimine un archivo:

1. Registrar FILE_DELETED.
2. Registrar la ruta original.
3. Registrar el usuario y proceso responsable cuando estén disponibles.
4. Registrar fecha y hora.
5. Asociar el último hash conocido.
6. Buscar una copia de evidencia previamente conservada.
7. Registrar si fue posible recuperar o conservar su contenido.

El sistema no deberá depender de intentar recuperar archivos después de eliminados. Las evidencias importantes deberán capturarse antes de que desaparezcan.

## 4.6 Auditoría de conexiones remotas

El sistema deberá registrar las sesiones de acceso remoto disponibles.

Fuentes iniciales:

- TeamViewer.
- Windows Remote Desktop.
- SSH.
- Otros mecanismos configurables.

Eventos:

- REMOTE_SESSION_STARTED.
- REMOTE_SESSION_ENDED.
- REMOTE_AUTHENTICATION.
- REMOTE_TRANSFER_DETECTED.
- REMOTE_CONNECTION_LOST.

Se deberá relacionar cada sesión con los procesos y eventos que ocurran durante su duración, sin asumir que el proceso observado es necesariamente el responsable de toda actividad posterior.

# 5. Arquitectura

La solución estará compuesta por cinco componentes.

## 5.1 Endpoint Agent

Responsable de observar los eventos en Windows y macOS.

Funciones:

- Captura de eventos.
- Normalización.
- Identificación de procesos.
- Monitoreo de archivos.
- Cálculo de hashes.
- Captura de evidencias.
- Cola local temporal.
- Comunicación segura con el servidor.

## 5.2 Event Collector

Servicio central que recibe los eventos.

Funciones:

- Validación de eventos.
- Identificación del endpoint.
- Normalización de formatos.
- Correlación temporal.
- Detección de duplicados.
- Clasificación.
- Envío al almacenamiento.

## 5.3 Event Store

Repositorio de eventos.

Cada evento deberá contener:

- Identificador único.
- Endpoint.
- Usuario.
- Fecha y hora.
- Tipo de evento.
- Proceso.
- Archivo relacionado.
- Datos adicionales.
- Hash del evento.
- Hash del evento anterior.
- Identificador de sesión.
- Referencia a evidencia.

## 5.4 Evidence Repository

Almacenamiento independiente para documentos y evidencias.

Requisitos:

- Versionado.
- Hash SHA-256.
- Control de acceso.
- Retención configurable.
- Protección WORM.
- Registro de accesos.
- Copias de seguridad.
- Separación de permisos entre administradores del endpoint y custodios de evidencias.

## 5.5 Audit Dashboard

Interfaz para consultar los eventos y evidencias.

Módulos:

1. Dashboard general.
2. Endpoints registrados.
3. Estado de agentes.
4. Timeline de actividad.
5. Explorador de procesos.
6. Historial de comandos.
7. Explorador de archivos.
8. Documentos capturados.
9. Sesiones remotas.
10. Evidencias digitales.
11. Integridad de registros.
12. Alertas.
13. Exportación de informes.

# 6. Modelo de eventos

El sistema utilizará un modelo de eventos inspirado en Event Sourcing.

Ejemplo:

```json
{
  "event_id": "evt-000001",
  "endpoint_id": "endpoint-001",
  "timestamp": "2026-11-09T08:30:00Z",
  "event_type": "FILE_CREATED",
  "actor": {
    "user": "operator",
    "process": "python.exe",
    "pid": 4521,
    "parent_process": "powershell.exe"
  },
  "resource": {
    "path": "C:/Documents/report.csv",
    "extension": ".csv",
    "size": 10240,
    "sha256": "abc123..."
  },
  "session": {
    "type": "remote",
    "provider": "TeamViewer",
    "session_id": "session-001"
  },
  "evidence": {
    "captured": true,
    "repository_reference": "evidence-001"
  },
  "integrity": {
    "previous_hash": "previous-event-hash",
    "event_hash": "current-event-hash"
  }
}
```

Los eventos serán inmutables una vez confirmados en el repositorio.

Los cambios posteriores deberán registrarse como nuevos eventos, nunca sobrescribir el registro original.

# 7. Seguridad e inmutabilidad

El sistema deberá cumplir los siguientes requisitos:

- Comunicación cifrada mediante TLS.
- Identidad independiente para cada endpoint.
- Autenticación mutua cuando sea viable.
- Credenciales de agentes protegidas.
- Permisos administrativos mínimos necesarios.
- Repositorio independiente del equipo auditado.
- Separación entre administradores del endpoint y custodios de evidencias.
- Cadena criptográfica de eventos.
- Verificación periódica de hashes.
- Retención protegida de evidencias.
- Registro de intentos de detener o alterar el agente.
- Alertas ante pérdida de comunicación.
- Almacenamiento inmutable con políticas WORM.

La inmutabilidad deberá aplicarse en el almacenamiento central, no depender exclusivamente de permisos locales o cadenas de hashes.

# 8. Requisitos no funcionales

| Código | Requisito |
|---|---|
| RNF-01 | Soportar Windows y macOS. |
| RNF-02 | Ejecutarse automáticamente al iniciar el sistema. |
| RNF-03 | Mantener bajo consumo de CPU y memoria. |
| RNF-04 | Enviar eventos sin bloquear al usuario. |
| RNF-05 | Soportar almacenamiento temporal cuando no exista conexión. |
| RNF-06 | Garantizar integridad criptográfica. |
| RNF-07 | Permitir escalar a múltiples endpoints. |
| RNF-08 | Soportar políticas de retención. |
| RNF-09 | Mantener sincronización horaria. |
| RNF-10 | Permitir exportación de evidencias. |
| RNF-11 | Evitar pérdida silenciosa de eventos. |
| RNF-12 | Documentar las limitaciones de captura de cada plataforma. |

# 9. Modelo de datos

Entidades principales:

- Endpoint.
- Agent.
- User.
- Process.
- ProcessExecution.
- AuditEvent.
- FileResource.
- FileVersion.
- Evidence.
- RemoteSession.
- NetworkConnection.
- IntegrityCheckpoint.
- Alert.
- AuditPolicy.
- RetentionPolicy.

Relaciones principales:

- Un endpoint genera múltiples eventos.
- Un proceso genera múltiples eventos.
- Un archivo puede tener múltiples versiones.
- Una evidencia puede estar asociada a uno o varios eventos.
- Una sesión remota puede agrupar múltiples procesos y eventos.
- Un checkpoint puede verificar un conjunto de eventos.

# 10. MVP — Primera versión

La primera versión deberá concentrarse en:

1. Agente Windows.
2. Agente macOS.
3. Instalación administrativa.
4. Activación y desactivación controladas.
5. Inicio automático del agente.
6. Registro de procesos y comandos.
7. Monitoreo de creación, modificación y eliminación de archivos.
8. Captura de documentos seleccionados.
9. Cálculo de hashes.
10. Registro de sesiones TeamViewer.
11. Envío a repositorio central.
12. Dashboard de auditoría.
13. Almacenamiento protegido.
14. Alertas ante interrupción del agente.

# 11. Criterios de aceptación

El MVP se considerará funcional cuando:

- [ ] El agente pueda instalarse en Windows.
- [ ] El agente pueda instalarse en macOS.
- [ ] El propietario pueda activar la auditoría.
- [ ] El agente se ejecute como servicio o daemon.
- [ ] Se registre la ejecución de PowerShell.
- [ ] Se registre la ejecución de CMD.
- [ ] Se registre la ejecución de Python.
- [ ] Se registren scripts ejecutados.
- [ ] Se detecten archivos nuevos.
- [ ] Se detecten archivos modificados.
- [ ] Se detecten archivos eliminados.
- [ ] Se puedan conservar copias de documentos configurados.
- [ ] Se calcule SHA-256 para las evidencias.
- [ ] Los eventos lleguen al servidor central.
- [ ] Los eventos puedan consultarse cronológicamente.
- [ ] Un administrador local del endpoint no pueda borrar las evidencias centrales.
- [ ] Se detecten interrupciones del agente.
- [ ] Se pueda verificar la integridad de los registros.

# 12. Privacidad y límites de auditoría

El sistema tendrá como principio la auditoría de actividades del equipo, no la vigilancia indiscriminada de personas.

No se implementarán:

- Keylogging.
- Captura de contraseñas.
- Captura indiscriminada del portapapeles.
- Grabación oculta de pantalla.
- Captura indiscriminada de conversaciones.
- Recolección de archivos personales sin una política autorizada.

El agente deberá mostrar su estado de auditoría, mantener una configuración verificable y registrar sus cambios de configuración.

Se deberán establecer políticas de acceso, retención, minimización de datos y autorización de monitoreo.

# 13. Fuera del alcance

La primera versión no será:

- Un antivirus.
- Un EDR de respuesta activa.
- Un sistema de bloqueo de aplicaciones.
- Un sistema de control remoto.
- Un sistema de recuperación garantizada de cualquier archivo eliminado.
- Un sistema de grabación de pantalla.
- Un sistema de captura de teclas.

El producto se limitará a observar, documentar, preservar y permitir investigar.

# 14. Resultado esperado

El propietario deberá poder abrir el dashboard y reconstruir una sesión completa de actividad.

Ejemplo:

08:00 — Inicio de sesión remota.

08:02 — PowerShell ejecutado.

08:03 — Script Python ejecutado.

08:04 — Archivo de configuración creado.

08:05 — Documento modificado.

08:06 — Documento eliminado.

08:07 — Archivo enviado a un servicio externo.

08:30 — Fin de sesión remota.

Cada evento deberá tener sus metadatos, evidencias disponibles y mecanismos de verificación de integridad.

**Principio fundamental: si una actividad fue observada por el sistema, deberá quedar registrada en el repositorio de auditoría; si una evidencia fue capturada, su integridad deberá poder verificarse posteriormente.**
