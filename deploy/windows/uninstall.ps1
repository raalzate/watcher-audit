# Detiene y retira el servicio. La parada queda registrada en el repositorio (AGENT_STOPPED + alerta).
$ErrorActionPreference = "Stop"
$App = "$env:ProgramFiles\Watcher"
Stop-Service WatcherAudit -ErrorAction SilentlyContinue
& "$App\venv\Scripts\python.exe" -m watcher.agent.winservice remove
Remove-Item -Recurse -Force $App
Write-Host "Agente retirado. Datos locales conservados en $env:ProgramData\Watcher"
