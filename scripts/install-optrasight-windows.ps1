[CmdletBinding()]
param(
  [string]$SourcePath,
  [string]$InstallPath,
  [string]$BackupRoot,
  [ValidateRange(1, 65535)]
  [int]$Port = 5050,
  [string]$AllowedRemoteAddress = "LocalSubnet",
  [string]$TaskName = "OptraSight Backend"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-InstallLog([string]$Message) {
  $line = "{0} {1}" -f (Get-Date).ToString("o"), $Message
  Write-Host $Message
  if (-not [string]::IsNullOrWhiteSpace($script:InstallLog)) {
    Add-Content -LiteralPath $script:InstallLog -Value $line -Encoding UTF8
  }
}

function Resolve-FullPath([string]$Path) {
  return [System.IO.Path]::GetFullPath($Path.Trim().Trim('"'))
}

function Assert-SafeDirectory([string]$Path) {
  $full = Resolve-FullPath $Path
  $root = [System.IO.Path]::GetPathRoot($full)
  if ($full -eq $root -or $full.Length -le ($root.Length + 3)) {
    throw "Refusing to operate on unsafe directory '$full'. Choose a dedicated OptraSight folder."
  }
  return $full
}

function Copy-DirectoryChecked([string]$Source, [string]$Destination, [string[]]$ExtraArgs) {
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $arguments = @($Source, $Destination, "/E", "/COPY:DAT", "/DCOPY:DAT", "/R:2", "/W:1", "/XJ", "/NFL", "/NDL", "/NJH", "/NJS", "/NP") + $ExtraArgs
  & robocopy.exe @arguments
  if ($LASTEXITCODE -gt 7) {
    throw "Robocopy failed with exit code $LASTEXITCODE while copying '$Source'."
  }
}

function Stop-OptraSightTask {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($null -eq $task -or $task.State -ne "Running") { return }
  Stop-ScheduledTask -TaskName $TaskName
  $deadline = (Get-Date).AddSeconds(30)
  do {
    Start-Sleep -Milliseconds 500
    $state = (Get-ScheduledTask -TaskName $TaskName).State
  } while ($state -eq "Running" -and (Get-Date) -lt $deadline)
  if ($state -eq "Running") { throw "The '$TaskName' task did not stop within 30 seconds." }
}

function Stop-ScopedNodeProcess([string]$InstallDirectory) {
  $needle = (Join-Path $InstallDirectory "dist\index.cjs").ToLowerInvariant()
  $processes = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue
  foreach ($process in $processes) {
    $commandLine = [string]$process.CommandLine
    if (-not [string]::IsNullOrWhiteSpace($commandLine) -and $commandLine.ToLowerInvariant().Contains($needle)) {
      Write-InstallLog ("Stopping existing OptraSight node process PID {0}." -f $process.ProcessId)
      Stop-Process -Id $process.ProcessId -Force
    }
  }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated PowerShell window (Run as Administrator)."
}

if ([string]::IsNullOrWhiteSpace($SourcePath)) {
  $defaultSource = Resolve-FullPath (Join-Path $PSScriptRoot "..")
  $answer = Read-Host "Latest OptraSight source/release folder [$defaultSource]"
  if ([string]::IsNullOrWhiteSpace($answer)) { $SourcePath = $defaultSource } else { $SourcePath = $answer }
}
if ([string]::IsNullOrWhiteSpace($InstallPath)) {
  $answer = Read-Host "Folder where OptraSight code should be installed [D:\OptraSight]"
  if ([string]::IsNullOrWhiteSpace($answer)) { $InstallPath = "D:\OptraSight" } else { $InstallPath = $answer }
}

$source = Assert-SafeDirectory $SourcePath
$install = Assert-SafeDirectory $InstallPath
if (-not (Test-Path -LiteralPath (Join-Path $source "package.json") -PathType Leaf)) {
  throw "Source folder does not contain package.json: $source"
}
if (-not (Test-Path -LiteralPath (Join-Path $source "server") -PathType Container)) {
  throw "Source folder does not contain the server directory: $source"
}

if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
  $BackupRoot = Join-Path (Split-Path -Parent $install) "OptraSight-backups"
}
$backupBase = Assert-SafeDirectory $BackupRoot
$installPrefix = $install.TrimEnd('\') + '\'
if ($backupBase.Equals($install, [StringComparison]::OrdinalIgnoreCase) -or
    $backupBase.StartsWith($installPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "BackupRoot must be outside InstallPath so old-code cleanup cannot remove the backup."
}
New-Item -ItemType Directory -Force -Path $backupBase | Out-Null
$script:InstallLog = Join-Path $backupBase ("install-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType File -Force -Path $script:InstallLog | Out-Null

$nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
if ($null -eq $nodeCommand) { throw "Node.js 20 or 22 is required, but node.exe was not found in PATH." }
$nodePath = $nodeCommand.Source
$nodeMajor = [int]((& $nodePath --version).TrimStart('v').Split('.')[0])
if ($nodeMajor -ne 20 -and $nodeMajor -ne 22) {
  throw "Unsupported Node.js major version $nodeMajor. Install Node.js 20 LTS or 22 LTS."
}
$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($null -eq $npmCommand) { throw "npm.cmd was not found in PATH." }
$npmPath = $npmCommand.Source

$parent = Split-Path -Parent $install
New-Item -ItemType Directory -Force -Path $parent | Out-Null
Set-Location $parent
$stage = Join-Path $parent (".optrasight-stage-{0}" -f [Guid]::NewGuid().ToString("N"))
$oldInstall = Join-Path $parent (".optrasight-old-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$backupPath = $null
$installedNewCode = $false
$installSucceeded = $false
$originalTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$originalTaskWasRunning = $null -ne $originalTask -and $originalTask.State -eq "Running"

try {
  Write-InstallLog "Staging OptraSight from '$source' into '$stage'."
  $excludeDirs = @(
    "/XD",
    (Join-Path $source ".git"),
    (Join-Path $source "node_modules"),
    (Join-Path $source "dist"),
    (Join-Path $source "data"),
    (Join-Path $source "logs")
  )
  $excludeFiles = @(
    "/XF",
    (Join-Path $source ".env"),
    (Join-Path $source "data.db"),
    (Join-Path $source "data.db-wal"),
    (Join-Path $source "data.db-shm")
  )
  Copy-DirectoryChecked $source $stage ($excludeDirs + $excludeFiles)

  $publicData = Join-Path $source "data\public"
  if (Test-Path -LiteralPath $publicData -PathType Container) {
    Copy-DirectoryChecked $publicData (Join-Path $stage "data\public") @()
  }

  Push-Location $stage
  try {
    Write-InstallLog "Installing dependencies."
    & $npmPath ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed with exit code $LASTEXITCODE." }

    Write-InstallLog "Running Windows-compatible typecheck baseline and production build."
    $env:OPTRASIGHT_TSC_BASELINE = "85"
    & $nodePath ".\scripts\typecheck-baseline.cjs"
    if ($LASTEXITCODE -ne 0) { throw "Typecheck baseline failed with exit code $LASTEXITCODE." }
    & (Join-Path $stage "node_modules\.bin\tsx.cmd") ".\script\build.ts"
    if ($LASTEXITCODE -ne 0) { throw "Production build failed with exit code $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath (Join-Path $stage "dist\index.cjs") -PathType Leaf)) {
      throw "Build completed without creating dist\index.cjs."
    }
    & $npmPath prune --omit=dev
    if ($LASTEXITCODE -ne 0) { throw "npm prune --omit=dev failed with exit code $LASTEXITCODE." }
  } finally {
    Pop-Location
  }

  if (Test-Path -LiteralPath $install -PathType Container) {
    Stop-OptraSightTask
    Stop-ScopedNodeProcess $install
    $backupScript = Join-Path $stage "scripts\backup-optrasight-windows.ps1"
    Write-InstallLog "Backing up and verifying existing runtime data."
    $backupOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -InstallPath $install -BackupRoot $backupBase -TaskName $TaskName -KeepStopped
    if ($LASTEXITCODE -ne 0) { throw "Runtime backup failed. Existing code has not been replaced." }
    $backupPath = @($backupOutput)[-1]
    if (-not (Test-Path -LiteralPath (Join-Path $backupPath "backup-manifest.json") -PathType Leaf)) {
      throw "Backup manifest was not created. Existing code has not been replaced."
    }
    Rename-Item -LiteralPath $install -NewName (Split-Path -Leaf $oldInstall)
  }

  Move-Item -LiteralPath $stage -Destination $install
  $installedNewCode = $true

  if ($null -ne $backupPath) {
    $runtime = Join-Path $backupPath "runtime"
    foreach ($name in @("data.db", "data.db-wal", "data.db-shm", ".env")) {
      $saved = Join-Path $runtime $name
      if (Test-Path -LiteralPath $saved -PathType Leaf) {
        Copy-Item -LiteralPath $saved -Destination (Join-Path $install $name) -Force
      }
    }
    $savedData = Join-Path $runtime "data"
    if (Test-Path -LiteralPath $savedData -PathType Container) {
      Copy-DirectoryChecked $savedData (Join-Path $install "data") @("/XD", (Join-Path $savedData "public"))
    }
  }

  if (-not (Test-Path -LiteralPath (Join-Path $install "data.db") -PathType Leaf)) {
    Write-InstallLog "No existing runtime database was found; restoring the sanitized public seed dataset."
    Push-Location $install
    try {
      & $nodePath ".\scripts\restore-public-batchone.cjs"
      if ($LASTEXITCODE -ne 0) { throw "Public seed restore failed with exit code $LASTEXITCODE." }
    } finally {
      Pop-Location
    }
  }

  $envPath = Join-Path $install ".env"
  if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    @(
      "NODE_ENV=production",
      "OPTRASIGHT_STRICT=1",
      "PORT=$Port"
    ) | Set-Content -LiteralPath $envPath -Encoding ASCII
  }

  $logs = Join-Path $install "logs"
  New-Item -ItemType Directory -Force -Path $logs | Out-Null
  $escapedInstall = $install.Replace("'", "''")
  $escapedNode = $nodePath.Replace("'", "''")
  $launcher = @'
$ErrorActionPreference = "Continue"
$optraRoot = '__INSTALL__'
$nodePath = '__NODE__'
$logRoot = Join-Path $optraRoot "logs"
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
Set-Location $optraRoot
$env:NODE_ENV = "production"
$env:OPTRASIGHT_STRICT = "1"
$env:PORT = "__PORT__"

function Rotate-Log([string]$Path) {
  if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -gt 52428800) {
    $previous = "$Path.1"
    if (Test-Path -LiteralPath $previous) { Remove-Item -LiteralPath $previous -Force }
    Move-Item -LiteralPath $Path -Destination $previous -Force
  }
}

$outputLog = Join-Path $logRoot "optrasight-output.log"
$errorLog = Join-Path $logRoot "optrasight-error.log"
$serviceLog = Join-Path $logRoot "optrasight-service.log"
while ($true) {
  Rotate-Log $outputLog
  Rotate-Log $errorLog
  Add-Content -LiteralPath $serviceLog -Value ("{0} starting OptraSight" -f (Get-Date).ToString("o"))
  & $nodePath (Join-Path $optraRoot "dist\index.cjs") 1>> $outputLog 2>> $errorLog
  $exitCode = $LASTEXITCODE
  Add-Content -LiteralPath $serviceLog -Value ("{0} process exited code={1}; restarting in 5 seconds" -f (Get-Date).ToString("o"), $exitCode)
  Start-Sleep -Seconds 5
}
'@
  $launcher = $launcher.Replace("__INSTALL__", $escapedInstall).Replace("__NODE__", $escapedNode).Replace("__PORT__", [string]$Port)
  $launcherPath = Join-Path $install "run-optrasight.ps1"
  Set-Content -LiteralPath $launcherPath -Value $launcher -Encoding UTF8

  $escapedTaskName = $TaskName.Replace("'", "''")
  $watchdog = @'
$ErrorActionPreference = "Continue"
$logPath = '__INSTALL__\logs\optrasight-health.log'
try {
  $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:__PORT__/api/v1/health' -TimeoutSec 15
  if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
} catch {
  Add-Content -LiteralPath $logPath -Value ("{0} health check failed: {1}" -f (Get-Date).ToString("o"), $_.Exception.Message)
  $task = Get-ScheduledTask -TaskName '__TASK__' -ErrorAction SilentlyContinue
  if ($null -ne $task) {
    Stop-ScheduledTask -TaskName '__TASK__' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName '__TASK__'
  }
}
'@
  $watchdog = $watchdog.Replace("__INSTALL__", $escapedInstall).Replace("__PORT__", [string]$Port).Replace("__TASK__", $escapedTaskName)
  $watchdogPath = Join-Path $install "watch-optrasight.ps1"
  Set-Content -LiteralPath $watchdogPath -Value $watchdog -Encoding UTF8

  $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  $action = New-ScheduledTaskAction -Execute $powerShell -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"{0}`"" -f $launcherPath) -WorkingDirectory $install
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

  $healthTaskName = "OptraSight Health Monitor"
  $healthAction = New-ScheduledTaskAction -Execute $powerShell -Argument ("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"{0}`"" -f $watchdogPath) -WorkingDirectory $install
  # Task Scheduler only repeats a trigger for its declared duration. Ten years
  # is deliberately explicit and avoids the compatibility issues some Windows
  # releases have when serialising [TimeSpan]::MaxValue.
  $healthTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
  $healthSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $healthTaskName -Action $healthAction -Trigger $healthTrigger -Settings $healthSettings -User "SYSTEM" -RunLevel Highest -Force | Out-Null

  Get-NetFirewallRule -DisplayName "OptraSight TCP $Port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName "OptraSight TCP $Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Domain,Private -RemoteAddress $AllowedRemoteAddress | Out-Null

  Start-ScheduledTask -TaskName $TaskName
  $healthy = $false
  foreach ($attempt in 1..30) {
    Start-Sleep -Seconds 2
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/api/v1/health" -TimeoutSec 5
      if ($response.StatusCode -eq 200) { $healthy = $true; break }
    } catch {
      Write-InstallLog ("Health check attempt {0}/30 failed: {1}" -f $attempt, $_.Exception.Message)
    }
  }
  if (-not $healthy) {
    throw "The service did not pass its health check. Old code remains at '$oldInstall'; inspect '$logs'."
  }

  if (Test-Path -LiteralPath $oldInstall -PathType Container) {
    Write-InstallLog "Health check passed. Removing superseded application code at '$oldInstall'."
    Remove-Item -LiteralPath $oldInstall -Recurse -Force
  }

  $installSucceeded = $true
  $address = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1 -ExpandProperty IPAddress
  Write-InstallLog "OptraSight is healthy and running as '$TaskName'."
  Write-Host "Local URL:  http://127.0.0.1:$Port" -ForegroundColor Green
  if ($null -ne $address) { Write-Host "Subnet URL: http://${address}:$Port" -ForegroundColor Green }
  Write-Host "Logs:       $logs"
  if ($null -ne $backupPath) { Write-Host "Backup:     $backupPath" }
  Write-Host "Install log: $script:InstallLog"
} catch {
  Write-InstallLog ("INSTALL FAILED: {0}" -f $_.Exception.Message)
  if ($installedNewCode -and (Test-Path -LiteralPath $oldInstall -PathType Container)) {
    Write-InstallLog "Rolling back to the previous application code. The verified backup is retained."
    Stop-OptraSightTask
    Stop-ScopedNodeProcess $install
    Unregister-ScheduledTask -TaskName "OptraSight Health Monitor" -Confirm:$false -ErrorAction SilentlyContinue
    $failedInstall = Join-Path $backupBase ("failed-install-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss-fff"))
    if (Test-Path -LiteralPath $install -PathType Container) {
      Move-Item -LiteralPath $install -Destination $failedInstall
    }
    Rename-Item -LiteralPath $oldInstall -NewName (Split-Path -Leaf $install)
    $installedNewCode = $false
    if ($originalTaskWasRunning) {
      Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Write-InstallLog "Rollback complete. Failed replacement retained at '$failedInstall'."
  }
  throw
} finally {
  if (-not $installedNewCode -and (Test-Path -LiteralPath $stage -PathType Container)) {
    Remove-Item -LiteralPath $stage -Recurse -Force
  }
  if (-not $installSucceeded -and -not $installedNewCode -and $originalTaskWasRunning -and
      (Test-Path -LiteralPath $install -PathType Container)) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $task -and $task.State -ne "Running") {
      Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
  }
}
