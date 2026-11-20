# Retira lo que instalo install.ps1 (servicio, tareas programadas, regla de firewall, C:\Program Files\Watcher).
# La parada del agente queda registrada en el repositorio (AGENT_STOPPED + alerta).
# Conserva los datos: C:\ProgramData\Watcher (identidad, cola) y C:\ProgramData\WatcherServer (evidencias).
#   powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1
$ErrorActionPreference = 'Stop'
$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
  exit 0
}

$AppDir = Join-Path $env:ProgramFiles 'Watcher'
$Py = Join-Path $AppDir 'venv\Scripts\python.exe'
$AgentHome = Join-Path $env:ProgramData 'Watcher'

# Parada limpia primero: el repositorio registra AGENT_STOPPED en vez de una alerta de apagado sucio.
$wa = Join-Path $AppDir 'venv\Scripts\watcher-agent.exe'
if ((Test-Path $wa) -and (Test-Path (Join-Path $AgentHome 'data\spool.db'))) {
  & $wa --home $AgentHome stop --wait 15 | Out-Host
}

if (Get-Service WatcherAudit -ErrorAction SilentlyContinue) {
  Stop-Service WatcherAudit -Force -ErrorAction SilentlyContinue
  if (Test-Path $Py) { & $Py -m watcher.agent.winservice remove | Out-Null }
  if (Get-Service WatcherAudit -ErrorAction SilentlyContinue) { sc.exe delete WatcherAudit | Out-Null }
}
foreach ($t in 'WatcherAuditAgent', 'WatcherServer') {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
  }
}
Get-NetFirewallRule -DisplayName 'Watcher repositorio' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -and $_.Path.StartsWith($AppDir, [StringComparison]::OrdinalIgnoreCase) } |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir }

Write-Host "Watcher retirado. Datos conservados en $env:ProgramData\Watcher y $env:ProgramData\WatcherServer"
