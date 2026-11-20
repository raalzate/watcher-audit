<#
Retira Watcher de este equipo.

  Desinstalar, conservando datos y evidencias en C:\ProgramData:
      powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1

  Quitar TODO (tambien evidencias, linea de tiempo e identidad del equipo; no se puede deshacer):
      powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1 -BorrarDatos

  -Si salta la confirmacion de -BorrarDatos (para scripts).
#>
param(
  [switch]$BorrarDatos,
  [switch]$Si
)
$ErrorActionPreference = 'Stop'
$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
  $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
  if ($BorrarDatos) { $argv += '-BorrarDatos' }
  if ($Si) { $argv += '-Si' }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $argv
  Write-Host 'La desinstalacion sigue en la ventana de Administrador que se acaba de abrir.'
  exit 0
}

$AppDir     = Join-Path $env:ProgramFiles 'Watcher'
$Bin        = Join-Path $AppDir 'venv\Scripts'
$AgentHome  = Join-Path $env:ProgramData 'Watcher'
$ServerData = Join-Path $env:ProgramData 'WatcherServer'

if ($BorrarDatos -and -not $Si) {
  Write-Host ''
  Write-Host 'ATENCION: se borraran para siempre las evidencias, la linea de tiempo y la identidad del equipo:' -ForegroundColor Red
  Write-Host "  $AgentHome"
  Write-Host "  $ServerData"
  $r = Read-Host 'Escriba BORRAR para confirmar (cualquier otra cosa conserva los datos)'
  if ($r -ne 'BORRAR') { $BorrarDatos = $false; Write-Host 'Se conservan los datos.' }
}

function Paso([string]$Texto) { Write-Host "==> $Texto" -ForegroundColor Cyan }

# Procesos de Watcher. Por CIM y no por Get-Process: Get-Process no siempre ve la ruta de procesos
# SYSTEM, y Stop-ScheduledTask cierra el lanzador de uv pero no el python.exe hijo que sigue
# escuchando en el puerto. Se busca por ruta y por linea de comandos, y se mata el arbol.
function Procesos-Watcher {
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($AppDir, [StringComparison]::OrdinalIgnoreCase)) -or
    ($_.CommandLine -and $_.CommandLine -match 'watcher-(server|agent)|watcher\.agent|WatcherServer')
  } | Where-Object { $_.ProcessId -ne $PID }
}

# 1. Parada limpia del agente: el repositorio registra AGENT_STOPPED en vez de una alerta.
$wa = Join-Path $Bin 'watcher-agent.exe'
if ((Test-Path $wa) -and (Test-Path (Join-Path $AgentHome 'data\spool.db'))) {
  Paso 'Deteniendo el agente (parada limpia)'
  & $wa --home $AgentHome stop --wait 15 | Out-Host
}

# 2. Servicio y tareas programadas (primero se desregistran, para que nada los vuelva a lanzar).
Paso 'Quitando servicio y tareas programadas'
if (Get-Service WatcherAudit -ErrorAction SilentlyContinue) {
  Stop-Service WatcherAudit -Force -ErrorAction SilentlyContinue
  sc.exe delete WatcherAudit | Out-Null
}
foreach ($t in 'WatcherAuditAgent', 'WatcherServer') {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
  }
}

# 3. Lo que siga vivo (el repositorio en localhost, sobre todo) se mata con su arbol.
Paso 'Cerrando procesos de Watcher'
# Continue en este tramo: en PS 5.1, "2>$null" con Stop convierte el stderr de taskkill en excepcion
# (y taskkill escribe en stderr cuando el hijo ya murio junto con el padre).
$ErrorActionPreference = 'Continue'
for ($i = 0; $i -lt 3; $i++) {
  $vivos = @(Procesos-Watcher)
  if (-not $vivos) { break }
  foreach ($p in $vivos) {
    Write-Host "  cerrando PID $($p.ProcessId) $($p.Name)"
    taskkill.exe /PID $p.ProcessId /T /F 2>$null | Out-Null
  }
  Start-Sleep -Seconds 1
}
$ErrorActionPreference = 'Stop'

Get-NetFirewallRule -DisplayName 'Watcher repositorio' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# 4. Archivos.
Paso "Borrando $AppDir"
if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir }

if ($BorrarDatos) {
  Paso 'Borrando datos y evidencias'
  foreach ($d in $AgentHome, $ServerData) {
    if (Test-Path $d) {
      # las evidencias quedan de solo lectura a proposito; se quita el atributo para poder borrarlas
      Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IsReadOnly = $false }
      Remove-Item -Recurse -Force $d
    }
  }
  # DLL que pywin32_postinstall copio a System32 (solo las de este Python 3.12)
  foreach ($dll in 'pywintypes312.dll', 'pythoncom312.dll') {
    $ruta = Join-Path $env:SystemRoot "System32\$dll"
    if (Test-Path $ruta) { Remove-Item -Force $ruta -ErrorAction SilentlyContinue }
  }
}

# 5. Verificacion: que no quede nada escuchando ni registrado.
Write-Host ''
$restos = @()
if (Get-Service WatcherAudit -ErrorAction SilentlyContinue) { $restos += 'servicio WatcherAudit' }
if (Get-ScheduledTask -TaskName 'Watcher*' -ErrorAction SilentlyContinue) { $restos += 'tareas programadas Watcher*' }
if (@(Procesos-Watcher)) { $restos += 'procesos de Watcher' }
if (Test-Path $AppDir) { $restos += $AppDir }
if ($BorrarDatos) { foreach ($d in $AgentHome, $ServerData) { if (Test-Path $d) { $restos += $d } } }

if ($restos) {
  Write-Host "Quedaron restos: $($restos -join ', '). Reinicie el equipo y vuelva a correr este script." -ForegroundColor Yellow
  exit 1
}
Write-Host 'Watcher retirado: sin servicio, sin tareas, sin procesos.' -ForegroundColor Green
if ($BorrarDatos) {
  Write-Host 'Datos y evidencias borrados.'
} else {
  Write-Host "Datos conservados en $AgentHome y $ServerData (borrarlos: -BorrarDatos)."
}
Write-Host 'Puede borrar tambien la carpeta donde descomprimio el repo.'
