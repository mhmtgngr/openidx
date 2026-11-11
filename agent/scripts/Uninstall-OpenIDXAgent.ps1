<#
.SYNOPSIS
  Removes the OpenIDX device agent silently (Intune uninstall command, GPO,
  or by hand in an elevated PowerShell).

.DESCRIPTION
  Finds every installed product of the agent's UpgradeCode and runs
  msiexec /x on it. The MSI stops the service, cleans up the tunnel's DNS
  rules and adapter, and removes %ProgramData%\OpenIDX\agent (the device's
  credentials and any sealed fleet token). -KeepData leaves that folder.

    .\Uninstall-OpenIDXAgent.ps1
    .\Uninstall-OpenIDXAgent.ps1 -KeepData

  Exit codes: 0 removed or not installed, 3010 removed (restart needed), 1 failure.
#>
[CmdletBinding()]
param([switch]$KeepData)

$ErrorActionPreference = 'Stop'
$UpgradeCode = '{6F4A1E2C-2B7D-4B1A-9C3E-0A1B2C3D4E5F}'
$DataDir = Join-Path $env:ProgramData 'OpenIDX\agent'

try {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $products = @($installer.RelatedProducts($UpgradeCode))
  if ($products.Count -eq 0) { Write-Host "==> OpenIDX Agent is not installed"; exit 0 }

  $backup = $null
  if ($KeepData -and (Test-Path $DataDir)) {
    $backup = Join-Path $env:TEMP "openidx-agent-data-$([guid]::NewGuid())"
    Copy-Item -Path $DataDir -Destination $backup -Recurse
  }

  $rc = 0
  foreach ($code in $products) {
    $log = Join-Path $env:TEMP 'openidx-uninstall.log'
    Write-Host "==> Removing $code"
    $p = Start-Process msiexec.exe -ArgumentList @('/x', $code, '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
    if ($p.ExitCode -eq 3010) { $rc = 3010 }
    elseif ($p.ExitCode -ne 0 -and $p.ExitCode -ne 1605) { throw "msiexec /x $code exit $($p.ExitCode). Log: $log" }
  }

  if ($backup) {
    New-Item -ItemType Directory -Path (Split-Path $DataDir) -Force | Out-Null
    Move-Item -Path $backup -Destination $DataDir -Force
    Write-Host "==> Kept $DataDir"
  }
  Write-Host "==> OpenIDX Agent removed"
  exit $rc
} catch {
  Write-Error $_
  exit 1
}
