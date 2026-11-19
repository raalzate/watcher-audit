# Instala el agente de auditoría como servicio de Windows ("Watcher Audit Agent", visible en services.msc).
# Uso (PowerShell como Administrador):
#   .\install.ps1 -Server https://repositorio:8443 -Token TOKEN [-CaFile ca.pem] [-Python C:\Python313\python.exe]
param(
  [Parameter(Mandatory)][string]$Server,
  [Parameter(Mandatory)][string]$Token,
  [string]$CaFile = "",
  [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Ejecute PowerShell como Administrador." }
& $Python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Se requiere Python >= 3.11." }

$Repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$App  = "$env:ProgramFiles\Watcher"
$Home_ = "$env:ProgramData\Watcher"
New-Item -ItemType Directory -Force -Path $App, $Home_ | Out-Null
# credenciales y cola local: solo SYSTEM y Administradores
icacls $Home_ /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

& $Python -m venv "$App\venv"
& "$App\venv\Scripts\python.exe" -m pip install --quiet "$Repo[windows]"
& "$App\venv\Scripts\python.exe" "$App\venv\Scripts\pywin32_postinstall.py" -install | Out-Null

if (-not (Test-Path "$Home_\config.toml")) {
  (Get-Content "$Repo\deploy\config.example.toml") `
    -replace 'https://audit.example.com:8443', $Server `
    -replace '^watch_paths = \["/Users.*$', 'watch_paths = ["C:/Users/*/Documents", "C:/Users/*/Desktop", "C:/Users/*/Downloads"]' |
    Set-Content "$Home_\config.toml" -Encoding utf8
}
$enroll = @("enroll", "--server", $Server, "--token", $Token)
if ($CaFile) {
  Copy-Item $CaFile "$Home_\ca.pem" -Force
  $ca = "$Home_\ca.pem" -replace '\\', '/'
  (Get-Content "$Home_\config.toml") -replace '^ca_file = .*$', "ca_file = `"$ca`"" | Set-Content "$Home_\config.toml" -Encoding utf8
  $enroll += @("--ca-file", "$Home_\ca.pem")
}
if (-not (Test-Path "$Home_\credentials.json")) {
  & "$App\venv\Scripts\watcher-agent.exe" @enroll
  if ($LASTEXITCODE -ne 0) { throw "Enrolamiento rechazado." }
}

& "$App\venv\Scripts\python.exe" -m watcher.agent.winservice --startup auto install
sc.exe failure WatcherAudit reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null
Start-Service WatcherAudit
Start-Sleep 3
& "$App\venv\Scripts\watcher-agent.exe" status

Write-Host ""
Write-Host "Recomendado: instale Sysmon (Sysinternals) para captura completa de procesos con hash y atribucion"
Write-Host "de archivos, y habilite 'PowerShell Script Block Logging'. Sin Sysmon el agente usa sondeo de procesos."
