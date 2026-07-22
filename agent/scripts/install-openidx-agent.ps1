<#
.SYNOPSIS
  One-command installer for the OpenIDX device agent (screen-share / remote
  support over the OpenZiti zero-trust overlay).

.DESCRIPTION
  Downloads and silently installs the OpenIDX agent MSI, enrolls the device,
  wires the Ziti overlay (control-plane name resolution), and starts the tray.
  Safe to re-run: enrollment is idempotent (the device keeps one stable
  identity), and the hosts entries are only added if missing.

  Run in an ELEVATED (Administrator) PowerShell:

    # Minimal (uses the pinned defaults baked in at release time):
    ./install-openidx-agent.ps1

    # Override any value:
    ./install-openidx-agent.ps1 -Server https://openidx.example.com -Token <REUSABLE_ENROLL_TOKEN>

.NOTES
  The __PLACEHOLDER__ values are stamped by CI at release time. When run from a
  release asset they are already filled in, so a bare invocation just works.
#>

[CmdletBinding()]
param(
  [string]$Server        = "__SERVER_URL__",
  [string]$Token         = "__ENROLL_TOKEN__",
  [string]$MsiUrl        = "__MSI_URL__",
  [string]$ManifestUrl   = "__MANIFEST_URL__",
  # Ziti control-plane names -> server IP. Needed only when the controller/router
  # advertise *.localtest.me names that resolve to 127.0.0.1 on the device.
  # Leave -ServerIP empty to skip the hosts step entirely (e.g. when you use
  # real split-DNS for the Ziti names).
  [string]$ServerIP      = "__SERVER_IP__",
  [string[]]$ZitiNames   = @("ziti-controller.localtest.me", "ziti-router.localtest.me")
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

# --- Guard: require elevation (hosts edit + service install need admin) ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "Please run this script in an elevated (Administrator) PowerShell."
}

if (-not $Server -or $Server -like "*__*__*") { throw "Server URL not set. Pass -Server https://..." }
if (-not $Token  -or $Token  -like "*__*__*") { throw "Enroll token not set. Pass -Token <token>" }
if (-not $MsiUrl -or $MsiUrl -like "*__*__*") {
  # Fall back to the 'latest' release asset if the MSI URL wasn't stamped.
  $MsiUrl = "https://github.com/mhmtgngr/openidx/releases/latest/download/OpenIDX.msi"
}
if (-not $ManifestUrl -or $ManifestUrl -like "*__*__*") {
  $ManifestUrl = "https://github.com/mhmtgngr/openidx/releases/latest/download/latest.json"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- 1. Ziti control-plane name resolution (idempotent) -------------------
if ($ServerIP -and $ServerIP -notlike "*__*__*") {
  Write-Step "Ensuring Ziti control-plane hosts entries ($ServerIP)"
  $hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
  $lines = @(Get-Content $hostsPath -ErrorAction SilentlyContinue)
  # Drop any prior entries for these names so we can re-point cleanly.
  $kept = $lines | Where-Object {
    $line = $_
    -not ($ZitiNames | Where-Object { $line -match ("\s" + [regex]::Escape($_) + "(\s|$)") })
  }
  $additions = $ZitiNames | ForEach-Object { "$ServerIP`t$_" }
  ($kept + $additions) | Set-Content $hostsPath -Encoding ASCII
  ipconfig /flushdns | Out-Null
  $ZitiNames | ForEach-Object { Write-Ok "$ServerIP  $_" }
} else {
  Write-Step "Skipping hosts step (no -ServerIP; assuming real DNS for Ziti names)"
}

# --- 2. Stop any running agent so files aren't locked ---------------------
Write-Step "Stopping any running agent"
Get-Process openidx-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Service 'OpenIDX*' -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue

# --- 3. Download + install the MSI ----------------------------------------
$Msi = Join-Path $env:TEMP 'OpenIDX-agent.msi'
$Log = Join-Path $env:TEMP 'openidx-install.log'
Write-Step "Downloading MSI"
Invoke-WebRequest -Uri $MsiUrl -OutFile $Msi
Write-Ok "Saved $Msi"

Write-Step "Installing (silent)"
$msiArgs = @(
  '/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$Log`"",
  "SERVER_URL=$Server", "ENROLL_TOKEN=$Token", "UPDATE_MANIFEST_URL=$ManifestUrl"
)
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
  throw "MSI install failed (exit $($p.ExitCode)). See log: $Log"
}
Write-Ok "msiexec exit code: $($p.ExitCode)"

# --- 4. Enroll (idempotent; picks up Ziti identity + overlay service) -----
$exe = 'C:\Program Files\OpenIDX\openidx-agent.exe'
if (Test-Path $exe) {
  Write-Step "Enrolling device"
  & $exe enroll --server $Server --token $Token
} else {
  Write-Warning "Agent exe not found at $exe; the MSI's enroll action may have already run."
}

# --- 5. Start the tray (remote-support runtime in the user session) -------
if (Test-Path $exe) {
  Write-Step "Starting agent tray"
  Start-Process $exe -ArgumentList 'tray'
}

Write-Host ""
Write-Host "Done. The agent should now report over the Ziti overlay." -ForegroundColor Green
Write-Host "Verify: the tray log shows 'Using resilient transport (Ziti overlay with HTTPS fallback)'." -ForegroundColor Green
