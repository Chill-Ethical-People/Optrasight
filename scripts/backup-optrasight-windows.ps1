[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallPath,

  [string]$BackupRoot,

  [string]$TaskName = "OptraSight Backend",

  [switch]$KeepStopped
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated PowerShell window (Run as Administrator)."
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

function Copy-DirectoryChecked([string]$Source, [string]$Destination) {
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  & robocopy.exe $Source $Destination /E /COPY:DAT /DCOPY:DAT /R:2 /W:1 /XJ /NFL /NDL /NJH /NJS /NP
  if ($LASTEXITCODE -gt 7) {
    throw "Robocopy failed with exit code $LASTEXITCODE while copying '$Source'."
  }
}

$install = Assert-SafeDirectory $InstallPath
if (-not (Test-Path -LiteralPath $install -PathType Container)) {
  throw "Install directory does not exist: $install"
}

if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
  $BackupRoot = Join-Path (Split-Path -Parent $install) "OptraSight-backups"
}
$backupBase = Assert-SafeDirectory $BackupRoot
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$backup = Join-Path $backupBase $timestamp
$runtime = Join-Path $backup "runtime"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$currentSidGrant = "*{0}:(OI)(CI)F" -f $identity.User.Value
& icacls.exe $backup /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" $currentSidGrant | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "Could not restrict backup permissions to SYSTEM, Administrators, and the current user."
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$wasRunning = $false
if ($null -ne $task) {
  $wasRunning = $task.State -eq "Running"
  if ($wasRunning) {
    Stop-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(30)
    do {
      Start-Sleep -Milliseconds 500
      $state = (Get-ScheduledTask -TaskName $TaskName).State
    } while ($state -eq "Running" -and (Get-Date) -lt $deadline)
    if ($state -eq "Running") {
      throw "The '$TaskName' task did not stop within 30 seconds. Backup was not attempted."
    }
  }
}

try {
  $files = @("data.db", "data.db-wal", "data.db-shm", ".env")
  foreach ($name in $files) {
    $source = Join-Path $install $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
      Copy-Item -LiteralPath $source -Destination (Join-Path $runtime $name) -Force
    }
  }

  foreach ($name in @("data", "logs")) {
    $source = Join-Path $install $name
    if (Test-Path -LiteralPath $source -PathType Container) {
      Copy-DirectoryChecked $source (Join-Path $runtime $name)
    }
  }

  $manifestFiles = @()
  Get-ChildItem -LiteralPath $runtime -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($runtime.Length).TrimStart('\')
    $manifestFiles += [ordered]@{
      path = $relative
      bytes = $_.Length
      sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }

  $manifest = [ordered]@{
    formatVersion = 1
    createdAt = (Get-Date).ToUniversalTime().ToString("o")
    sourceInstallPath = $install
    serviceTaskWasRunning = $wasRunning
    files = $manifestFiles
  }
  $manifestPath = Join-Path $backup "backup-manifest.json"
  $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

  if ($manifestFiles.Count -eq 0) {
    Write-Warning "No existing runtime data was found. An empty, valid backup manifest was created."
  } else {
    foreach ($entry in $manifestFiles) {
      $candidate = Join-Path $runtime $entry.path
      $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($actual -ne $entry.sha256) {
        throw "Backup verification failed for '$($entry.path)'."
      }
    }
  }

  Write-Host "Verified backup: $backup" -ForegroundColor Green
  Write-Output $backup
} finally {
  if ($wasRunning -and -not $KeepStopped) {
    Start-ScheduledTask -TaskName $TaskName
  }
}
