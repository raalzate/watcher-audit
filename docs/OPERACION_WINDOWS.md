# Operación de Watcher en Windows

Abra PowerShell **como administrador**. Estos comandos aplican a la instalación de `deploy/windows/install.ps1`,
que guarda sus datos en `C:\ProgramData` y el programa en `C:\Program Files\Watcher`.

## Consultar el estado

```powershell
$bin = "$env:ProgramFiles\Watcher\venv\Scripts"
& "$bin\watcher-agent.exe" --home "$env:ProgramData\Watcher" status
```

`connected True` indica que el agente llega al repositorio. `spool_depth` es el número de eventos aún pendientes
de enviar.

## Pausar la auditoría

Esto mantiene instalado y ejecutándose el agente, pero deja de recoger eventos. La acción queda registrada:

```powershell
& "$bin\watcher-agent.exe" --home "$env:ProgramData\Watcher" disable
```

Para reanudarla:

```powershell
& "$bin\watcher-agent.exe" --home "$env:ProgramData\Watcher" enable
```

## Detener o iniciar Watcher

Para detener el agente y el repositorio local sin apagar Windows:

```powershell
& "$bin\watcher-agent.exe" --home "$env:ProgramData\Watcher" stop --wait 15
Stop-Service WatcherAudit -Force -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName WatcherAuditAgent -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName WatcherServer -ErrorAction SilentlyContinue
```

`Stop-ScheduledTask` puede dejar vivo el proceso hijo del servidor. Si el puerto 8443 sigue ocupado o se va a
borrar la base, cierre los procesos de Watcher también:

```powershell
$app = "$env:ProgramFiles\Watcher"
Get-CimInstance Win32_Process | Where-Object {
  ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($app, [StringComparison]::OrdinalIgnoreCase)) -or
  ($_.CommandLine -and $_.CommandLine -match 'watcher-(server|agent)|watcher\.agent|WatcherServer')
} | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object {
  taskkill.exe /PID $_.ProcessId /T /F
}
```

Para iniciar de nuevo:

```powershell
Start-ScheduledTask -TaskName WatcherServer -ErrorAction SilentlyContinue
Start-Service WatcherAudit -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName WatcherAuditAgent -ErrorAction SilentlyContinue
```

La instalación puede usar el servicio o la tarea del agente; que uno de esos comandos indique que no existe es normal.

## Borrar los datos de la instalación local de demostración

Esto borra la cola local, la línea de tiempo central y las evidencias, pero conserva la instalación, configuración,
certificados y secretos. **No se puede deshacer.** Detenga todos los procesos de Watcher con los comandos anteriores
antes de borrar los archivos.

```powershell
$agentHome = "$env:ProgramData\Watcher"
$serverData = "$env:ProgramData\WatcherServer"
Remove-Item "$agentHome\data" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$serverData\audit.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "$serverData\evidence" -Recurse -Force -ErrorAction SilentlyContinue
```

Al borrar `audit.db`, el servidor olvida la identidad del agente, aunque `credentials.json` se conserve. Inicie el
servidor y vuelva a enrolar el agente antes de iniciarlo:

```powershell
Start-ScheduledTask -TaskName WatcherServer
& "$bin\watcher-server.exe" --data "$serverData" info
```

Copie el valor de `enroll token` y úselo en el siguiente comando. No comparta ese token ni la salida de `info`:

```powershell
& "$bin\watcher-agent.exe" --home "$agentHome" enroll --token "PEGA_AQUI_EL_TOKEN" --force
Start-Service WatcherAudit -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName WatcherAuditAgent -ErrorAction SilentlyContinue
& "$bin\watcher-agent.exe" --home "$agentHome" status
```

Compruebe que el estado muestre `connected True`. El dashboard estará vacío salvo por los eventos nuevos.

> Si el repositorio está en otro equipo, borrar `C:\ProgramData\WatcherServer` en el equipo del agente no borra el
> historial central. El borrado central debe hacerse en el equipo que ejecuta el servidor; después hay que enrolar
> de nuevo cada agente.

## Desinstalar

Para quitar el programa pero conservar los datos, ejecute `deploy\windows\uninstall.ps1`. Para quitar también los
datos y la identidad, use `deploy\windows\uninstall.ps1 -BorrarDatos`; el script pide escribir `BORRAR`.
