<#
Watcher - instalacion en Windows con uv. No hace falta instalar Python: uv baja el suyo.

  1) Probar todo en ESTE equipo (repositorio + agente, solo loopback, sin TLS):
       powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1

  2) Repositorio central (en un equipo DISTINTO del auditado, con TLS; genera la CA si no le pasa una):
       powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Modo repositorio

  3) Agente en cada equipo auditado (el modo repositorio imprime este comando ya armado):
       powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Modo agente -Server https://REPO:8443 -Token TOKEN -CaFile ca.pem

  Desinstalar: powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1

Si no se abre como Administrador, se relanza elevado. Todo queda en C:\Program Files\Watcher
(uv, Python y el entorno), asi el servicio SYSTEM no depende del perfil de ningun usuario.
Se puede volver a correr: actualiza el codigo y conserva configuracion, identidad y evidencias.
#>
param(
  [ValidateSet('demo', 'repositorio', 'agente')][string]$Modo = 'demo',
  [string]$Server = '',
  [string]$Token = '',
  [string]$CaFile = '',
  [int]$Puerto = 8443,
  [string]$TlsCert = '',
  [string]$TlsKey = '',
  [string]$PythonVersion = '3.12'
)
$ErrorActionPreference = 'Stop'

# Compatibilidad con la forma anterior: install.ps1 -Server URL -Token TOKEN  => modo agente.
if (-not $PSBoundParameters.ContainsKey('Modo') -and $Server) { $Modo = 'agente' }

# Rutas relativas -> absolutas ANTES de elevar (la ventana elevada arranca en System32).
foreach ($n in 'CaFile', 'TlsCert', 'TlsKey') {
  $v = Get-Variable $n -ValueOnly
  if ($v) { Set-Variable $n (Resolve-Path -LiteralPath $v).Path }
}

$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
  $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"",
            '-Modo', $Modo, '-Puerto', $Puerto, '-PythonVersion', $PythonVersion)
  foreach ($n in 'Server', 'Token', 'CaFile', 'TlsCert', 'TlsKey') {
    $v = Get-Variable $n -ValueOnly
    if ($v) { $argv += "-$n"; $argv += "`"$v`"" }
  }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $argv
  Write-Host 'La instalacion sigue en la ventana de Administrador que se acaba de abrir.'
  exit 0
}

if ($Modo -eq 'agente' -and (-not $Server -or -not $Token)) {
  throw 'El modo agente necesita -Server https://REPO:8443 y -Token TOKEN (los imprime el modo repositorio).'
}
if (($TlsCert -and -not $TlsKey) -or ($TlsKey -and -not $TlsCert)) { throw '-TlsCert y -TlsKey van juntos.' }

$Repo       = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$AppDir     = Join-Path $env:ProgramFiles 'Watcher'
$Venv       = Join-Path $AppDir 'venv'
$Bin        = Join-Path $Venv 'Scripts'
$Py         = Join-Path $Bin 'python.exe'
$AgentHome  = Join-Path $env:ProgramData 'Watcher'
$ServerData = Join-Path $env:ProgramData 'WatcherServer'
$Utf8       = New-Object System.Text.UTF8Encoding($false)   # sin BOM: tomllib rechaza el BOM
$Servicio   = 'WatcherAudit'
$TareaAgente   = 'WatcherAuditAgent'
$TareaServidor = 'WatcherServer'
$ReglaFirewall = 'Watcher repositorio'

function Paso([string]$Texto) { Write-Host ''; Write-Host "==> $Texto" -ForegroundColor Cyan }

# OJO PowerShell: todo lo que un comando imprime dentro de una funcion pasa a ser su VALOR DE RETORNO.
# Por eso la salida de los programas va a Out-Host (pantalla), nunca al pipeline.
function Ejecutar([string]$Exe, [string[]]$Argumentos, [string]$SiFalla) {
  & $Exe @Argumentos | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "$SiFalla (exit $LASTEXITCODE)" }
}

# Solo SYSTEM y Administradores. Por SID: en Windows en espanol el grupo se llama "Administradores".
function Restringir([string]$Dir) {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  icacls $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls no pudo restringir $Dir" }
}

function Existe-Tarea([string]$Nombre) { [bool](Get-ScheduledTask -TaskName $Nombre -ErrorAction SilentlyContinue) }

# Antes de reinstalar: nada de Watcher corriendo (Windows no deja reemplazar un .exe en uso).
# Primero se le PIDE al agente que pare (queda AGENT_STOPPED en el repositorio); matar el proceso
# es el ultimo recurso y deja la alerta "termino sin apagado limpio".
function Detener-Todo {
  $wa = Join-Path $Bin 'watcher-agent.exe'
  if ((Test-Path $wa) -and (Test-Path (Join-Path $AgentHome 'data\spool.db'))) {
    & $wa --home $AgentHome stop --wait 15 | Out-Host
  }
  if (Get-Service $Servicio -ErrorAction SilentlyContinue) { Stop-Service $Servicio -Force -ErrorAction SilentlyContinue }
  foreach ($t in $TareaAgente, $TareaServidor) {
    if (Existe-Tarea $t) { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }
  }
  # Por CIM y con arbol (/T): Get-Process no siempre ve la ruta de procesos SYSTEM, y
  # Stop-ScheduledTask cierra el lanzador de uv pero deja vivo el python.exe hijo (el puerto sigue abierto).
  # Continue local: en PS 5.1, "2>$null" con Stop convierte el stderr de taskkill en excepcion.
  $ErrorActionPreference = 'Continue'
  for ($i = 0; $i -lt 3; $i++) {
    $vivos = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
      $_.ProcessId -ne $PID -and (
        ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($AppDir, [StringComparison]::OrdinalIgnoreCase)) -or
        ($_.CommandLine -and $_.CommandLine -match 'watcher-(server|agent)|watcher\.agent'))
    })
    if (-not $vivos) { break }
    foreach ($p in $vivos) { taskkill.exe /PID $p.ProcessId /T /F 2>$null | Out-Null }
    Start-Sleep -Seconds 1
  }
}

function Asegurar-Uv {
  $dir = Join-Path $AppDir 'uv'
  $propio = Get-ChildItem -Path $dir -Recurse -Filter uv.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($propio) { return $propio.FullName }
  Paso 'Instalando uv (instalador oficial de astral.sh)'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $env:UV_INSTALL_DIR = $dir
  $env:UV_NO_MODIFY_PATH = '1'
  $env:INSTALLER_NO_MODIFY_PATH = '1'
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://astral.sh/uv/install.ps1 | iex" | Out-Host
  $propio = Get-ChildItem -Path $dir -Recurse -Filter uv.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $propio) { throw "uv no quedo instalado en $dir. Sin internet: copie uv.exe a esa carpeta y repita." }
  return $propio.FullName
}

function Instalar-Paquete([string]$Extras) {
  Paso "Python $PythonVersion y watcher[$Extras] con uv"
  $env:UV_PYTHON_INSTALL_DIR = Join-Path $AppDir 'python'
  Ejecutar $script:Uv @('venv', '--python', $PythonVersion, '--python-preference', 'only-managed',
                        '--allow-existing', $Venv) 'uv no pudo crear el entorno'
  Ejecutar $script:Uv @('pip', 'install', '--python', $Py, '--upgrade', '--reinstall-package', 'watcher-audit',
                        ('{0}[{1}]' -f $Repo, $Extras)) 'uv no pudo instalar watcher'
  if ($Extras -match 'windows') {
    # Registra las DLL de pywin32 (necesarias para el servicio). Si falla, el agente cae a tarea programada.
    $post = Join-Path $Bin 'pywin32_postinstall.py'
    if (Test-Path $post) { & $Py $post -install -silent | Out-Null } else { & $Py -m pywin32_postinstall -install -silent | Out-Null }
    if ($LASTEXITCODE -ne 0) { Write-Warning 'pywin32_postinstall fallo; se intentara igual.' }
  }
}

function Registrar-Tarea([string]$Nombre, [string]$Exe, [string]$Argumentos) {
  $accion  = New-ScheduledTaskAction -Execute $Exe -Argument $Argumentos -WorkingDirectory $AppDir
  $inicio  = New-ScheduledTaskTrigger -AtStartup
  $quien   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $ajustes = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName $Nombre -Action $accion -Trigger $inicio -Principal $quien -Settings $ajustes -Force | Out-Null
  Start-ScheduledTask -TaskName $Nombre
}

function Esperar-Puerto([int]$P, [int]$Segundos) {
  $fin = (Get-Date).AddSeconds($Segundos)
  while ((Get-Date) -lt $fin) {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $P); $c.Close(); return $true }
    catch { Start-Sleep -Milliseconds 500 }
  }
  return $false
}

# ---------------------------------------------------------------- repositorio
function Instalar-Repositorio([string]$Escucha, [bool]$ConTls) {
  Paso "Repositorio en ${Escucha}:$Puerto"
  Restringir $ServerData
  $srv = Join-Path $Bin 'watcher-server.exe'
  $argumentos = "--data `"$ServerData`" run --host $Escucha --port $Puerto"
  $ca = $null
  if ($ConTls) {
    $tls = Join-Path $ServerData 'tls'
    New-Item -ItemType Directory -Force -Path $tls | Out-Null
    if ($TlsCert) {
      Copy-Item -LiteralPath $TlsCert (Join-Path $tls 'cert.pem') -Force
      Copy-Item -LiteralPath $TlsKey (Join-Path $tls 'key.pem') -Force
    } elseif (-not (Test-Path (Join-Path $tls 'cert.pem'))) {
      Paso 'Generando CA propia y certificado TLS (uv + cryptography, sin openssl)'
      $gen = @('run', '--script', '--python', $PythonVersion, '--python-preference', 'only-managed',
               (Join-Path $Repo 'deploy\gen_cert.py'), '--out', $tls, '--name', $env:COMPUTERNAME)
      try { $fqdn = [Net.Dns]::GetHostEntry('').HostName; if ($fqdn -and $fqdn -ne $env:COMPUTERNAME) { $gen += @('--name', $fqdn) } } catch { }
      Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
        ForEach-Object { $gen += @('--ip', $_.IPAddress) }
      Ejecutar $script:Uv $gen 'no se pudo generar el certificado'
    }
    $argumentos += " --tls-cert `"$(Join-Path $tls 'cert.pem')`" --tls-key `"$(Join-Path $tls 'key.pem')`""
    if (Test-Path (Join-Path $tls 'ca.pem')) { $ca = Join-Path $tls 'ca.pem' }
  }
  $info = (& $srv --data $ServerData info) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw 'watcher-server info fallo' }
  $tok = [regex]::Match($info, 'enroll token\s*:\s*(\S+)').Groups[1].Value
  $pwd_ = [regex]::Match($info, 'admin password\s*:\s*(\S+)').Groups[1].Value

  Registrar-Tarea $TareaServidor $srv $argumentos
  if (-not (Esperar-Puerto $Puerto 60)) {
    throw "El repositorio no abrio el puerto $Puerto. Mire: Get-ScheduledTaskInfo $TareaServidor (LastTaskResult)"
  }
  Write-Host "Repositorio escuchando (tarea programada '$TareaServidor', arranca con Windows)." -ForegroundColor Green
  return @{ Token = $tok; Password = $pwd_; Ca = $ca }
}

# ---------------------------------------------------------------- agente
function Escribir-ConfigAgente([string]$Url, [string]$Ca) {
  Restringir $AgentHome
  $cfg = Join-Path $AgentHome 'config.toml'
  if (Test-Path $cfg) {
    $texto = [IO.File]::ReadAllText($cfg)   # ReadAllText quita el BOM que dejaba la version anterior
  } else {
    $texto = [IO.File]::ReadAllText((Join-Path $Repo 'deploy\config.example.toml'))
    $texto = $texto -replace '(?m)^watch_paths = \[.*$', 'watch_paths = ["C:/Users/*/Documents", "C:/Users/*/Desktop", "C:/Users/*/Downloads"]'
  }
  $texto = $texto -replace '(?m)^url = .*$', ('url = "{0}"' -f $Url)
  if ($Ca) {
    $destino = Join-Path $AgentHome 'ca.pem'
    if ($Ca -ne $destino) { Copy-Item -LiteralPath $Ca $destino -Force }
    $texto = $texto -replace '(?m)^ca_file = .*$', ('ca_file = "{0}"' -f ($destino -replace '\\', '/'))
  }
  [IO.File]::WriteAllText($cfg, $texto, $Utf8)
}

function Enrolar([string]$Url, [string]$Tok) {
  if (Test-Path (Join-Path $AgentHome 'credentials.json')) {
    Write-Host 'Ya estaba enrolado: se conserva la identidad del equipo.'
    return
  }
  Paso "Enrolando contra $Url"
  $argumentos = @('--home', $AgentHome, 'enroll', '--server', $Url, '--token', $Tok)
  $ca = Join-Path $AgentHome 'ca.pem'
  if (Test-Path $ca) { $argumentos += @('--ca-file', $ca) }
  Ejecutar (Join-Path $Bin 'watcher-agent.exe') $argumentos 'El repositorio rechazo el enrolamiento (token, URL o CA)'
}

# Primero servicio de Windows (visible en services.msc). Si no arranca, tarea programada SYSTEM:
# mismo agente, misma carpeta, reinicio automatico; solo cambia quien lo lanza.
function Iniciar-Agente {
  Paso 'Arrancando el agente'
  $verbo = if (Get-Service $Servicio -ErrorAction SilentlyContinue) { 'update' } else { 'install' }
  & $Py -m watcher.agent.winservice --startup auto $verbo | Out-Host
  if ($LASTEXITCODE -eq 0) {
    sc.exe failure $Servicio reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null
    try { Start-Service $Servicio } catch { }
    for ($i = 0; $i -lt 20; $i++) {
      Start-Sleep -Seconds 1
      if ((Get-Service $Servicio).Status -eq 'Running') {
        Start-Sleep -Seconds 5    # que siga vivo, no que haya arrancado y caido
        if ((Get-Service $Servicio).Status -eq 'Running') {
          if (Existe-Tarea $TareaAgente) { Unregister-ScheduledTask -TaskName $TareaAgente -Confirm:$false }
          Write-Host "Agente corriendo como servicio '$Servicio'." -ForegroundColor Green
          return
        }
        break
      }
    }
    Write-Warning "El servicio '$Servicio' no se mantuvo arriba; se usa tarea programada."
    Stop-Service $Servicio -Force -ErrorAction SilentlyContinue
    & $Py -m watcher.agent.winservice remove | Out-Null
  } else {
    Write-Warning 'No se pudo registrar el servicio (pywin32); se usa tarea programada.'
  }
  Registrar-Tarea $TareaAgente (Join-Path $Bin 'watcher-agent.exe') "--home `"$AgentHome`" run"
  Start-Sleep -Seconds 5
  Write-Host "Agente corriendo como tarea programada '$TareaAgente' (SYSTEM, arranca con Windows)." -ForegroundColor Green
}

function Instalar-Agente([string]$Url, [string]$Tok, [string]$Ca) {
  Escribir-ConfigAgente $Url $Ca
  Enrolar $Url $Tok
  Iniciar-Agente
  & (Join-Path $Bin 'watcher-agent.exe') --home $AgentHome status
}

# ---------------------------------------------------------------- main
Detener-Todo
$script:Uv = @(Asegurar-Uv)[-1]   # [-1]: la ruta, aunque algo se cuele en la salida

switch ($Modo) {
  'demo' {
    Instalar-Paquete 'server,windows'
    $r = Instalar-Repositorio '127.0.0.1' $false
    $url = "http://127.0.0.1:$Puerto"
    Instalar-Agente $url $r.Token ''
    Write-Host ''
    Write-Host '================ LISTO (demo en este equipo) ================' -ForegroundColor Green
    Write-Host "Dashboard : $url"
    Write-Host "Clave     : $($r.Password)"
    Write-Host 'Pruebe    : cree o borre un archivo en Documentos y mire la linea de tiempo.'
    Write-Host 'Ojo       : en produccion el repositorio va en OTRO equipo (-Modo repositorio).'
    Start-Process $url
  }
  'repositorio' {
    Instalar-Paquete 'server'
    $r = Instalar-Repositorio '0.0.0.0' $true
    Get-NetFirewallRule -DisplayName $ReglaFirewall -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $ReglaFirewall -Direction Inbound -Protocol TCP -LocalPort $Puerto `
      -Action Allow -Profile Domain, Private | Out-Null
    $url = "https://$($env:COMPUTERNAME):$Puerto"
    Write-Host ''
    Write-Host '================ LISTO (repositorio) ================' -ForegroundColor Green
    Write-Host "Dashboard : $url   (clave: $($r.Password))"
    Write-Host "Token     : $($r.Token)"
    if ($r.Ca) {
      Write-Host "CA        : $($r.Ca)   <- copie este archivo a cada equipo auditado"
      Write-Host '            (para que el navegador confie: Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\LocalMachine\Root)'
    }
    Write-Host ''
    Write-Host 'En cada equipo auditado, con este repo y ca.pem copiados:' -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Modo agente -Server $url -Token $($r.Token) -CaFile ca.pem"
    Write-Host '  (macOS: sudo deploy/macos/install.sh URL TOKEN ca.pem)'
  }
  'agente' {
    Instalar-Paquete 'windows'
    Instalar-Agente $Server $Token $CaFile
    Write-Host ''
    Write-Host '================ LISTO (agente) ================' -ForegroundColor Green
  }
}

if ($Modo -ne 'repositorio') {
  Write-Host ''
  Write-Host 'Recomendado: Sysmon (Sysinternals) para captura completa de procesos con hash y atribucion de'
  Write-Host "archivos, y 'PowerShell Script Block Logging'. Sin Sysmon el agente sondea procesos (docs/LIMITACIONES.md)."
}
