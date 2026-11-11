<#
.SYNOPSIS
  Builds a transform (.mst) that carries the OpenIDX agent's install
  properties, for GPO Software Installation (which cannot pass properties on a
  command line).

.DESCRIPTION
  Copies OpenIDX.msi, sets the given properties in the copy's Property table,
  and writes the difference as a transform. Assign the MSI with the transform
  under Modifications in the GPO's Software Installation package.

    .\make-mst.ps1 -Msi .\OpenIDX.msi -ServerUrl https://openidx.example.com `
      -EnrollToken <FLEET_TOKEN> -Out .\OpenIDX-corp.mst

  The transform contains the enrolment token in clear text. Store it on a
  share readable only by Domain Computers (the machine accounts that install
  it), and rotate the fleet token if the file leaks.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [Parameter(Mandatory = $true)][string]$ServerUrl,
  [string]$EnrollToken = "",
  [string]$ManifestUrl,
  [switch]$TunnelEnabled,
  [string]$ProxyUrl = "",
  [string]$ServerCa = "",
  [ValidateSet('', 'debug', 'info', 'warn', 'error')][string]$LogLevel = "",
  [switch]$NoKeepToken,
  [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'
if ($ServerUrl -notmatch '^https://') { throw "-ServerUrl must be an https:// URL." }

$props = [ordered]@{ SERVER_URL = $ServerUrl.TrimEnd('/') }
if ($EnrollToken) { $props.ENROLL_TOKEN = $EnrollToken }
if ($PSBoundParameters.ContainsKey('ManifestUrl')) { $props.UPDATE_MANIFEST_URL = $ManifestUrl }
if ($TunnelEnabled) { $props.TUNNEL_ENABLED = '1' }
if ($ProxyUrl) { $props.PROXY_URL = $ProxyUrl }
if ($ServerCa) { $props.SERVER_CA = $ServerCa }
if ($LogLevel) { $props.LOG_LEVEL = $LogLevel }
$props.KEEP_ENROLL_TOKEN = $(if ($NoKeepToken) { '0' } else { '1' })

$msiPath = (Resolve-Path $Msi).Path
$work = Join-Path $env:TEMP "openidx-mst-$([guid]::NewGuid()).msi"
Copy-Item $msiPath $work

$installer = New-Object -ComObject WindowsInstaller.Installer
try {
  $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($work, 1))
  foreach ($k in $props.Keys) {
    # An empty value cannot be stored in the Property table; drop the row.
    $del = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("DELETE FROM ``Property`` WHERE ``Property``='$k'"))
    $del.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $del, $null) | Out-Null
    $del.GetType().InvokeMember('Close', 'InvokeMethod', $null, $del, $null) | Out-Null
    if ($props[$k] -eq '') { continue }
    $v = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("INSERT INTO ``Property`` (``Property``, ``Value``) VALUES (?, ?)"))
    $rec = $installer.GetType().InvokeMember('CreateRecord', 'InvokeMethod', $null, $installer, @(2))
    $rec.GetType().InvokeMember('StringData', 'SetProperty', $null, $rec, @(1, $k))
    $rec.GetType().InvokeMember('StringData', 'SetProperty', $null, $rec, @(2, [string]$props[$k]))
    $v.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $v, @($rec)) | Out-Null
    $v.GetType().InvokeMember('Close', 'InvokeMethod', $null, $v, $null) | Out-Null
  }
  $db.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $db, $null) | Out-Null

  $base = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($msiPath, 0))
  $outPath = [IO.Path]::GetFullPath($Out)
  $db.GetType().InvokeMember('GenerateTransform', 'InvokeMethod', $null, $db, @($base, $outPath)) | Out-Null
  # 0 = no validation errors suppressed; 0 = no validation; transform usable on this exact MSI.
  $db.GetType().InvokeMember('CreateTransformSummaryInfo', 'InvokeMethod', $null, $db, @($base, $outPath, 0, 0)) | Out-Null
  Write-Host "==> Wrote $outPath ($($props.Keys -join ', '))"
} finally {
  $db = $null; $base = $null
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  Remove-Item $work -Force -ErrorAction SilentlyContinue
}
