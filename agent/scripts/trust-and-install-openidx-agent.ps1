<#
.SYNOPSIS
  Trusts the OpenIDX code-signing certificate on this machine, then downloads,
  verifies and installs the OpenIDX agent MSI from your OpenIDX server.

.DESCRIPTION
  The agent MSI is signed with the project's own certificate ("OpenIDX Code
  Signing"), not one from a public authority, so on a machine that has never
  seen it Windows shows "Unknown publisher" and SmartScreen warns. This script
  is the hand-install path for an organization without GPO or Intune:

    1. Puts the certificate (embedded below, pinned by its SHA-256) into
       LocalMachine\Root and LocalMachine\TrustedPublisher. It is a leaf
       certificate: CA:FALSE, key usage Digital Signature, extended key usage
       Code Signing only, so it cannot vouch for a website or another
       certificate. Both checks run before anything is imported.
    2. Reads <Server>/downloads/agent-manifest.json, downloads the Windows MSI
       it names, and refuses it unless its SHA-256 matches the manifest AND its
       Authenticode signature is valid and made by that same certificate.
    3. Installs it silently. With -Token the MSI also enrolls the device; without
       it, the person opens My Devices -> Add a device on this PC and clicks
       "Open in app", which hands the code to the agent (it asks for
       administrator approval and enrolls).

  Safe to re-run: the certificate is imported only when missing, and the MSI
  upgrades an installed agent in place.

  Run in an elevated (Administrator) PowerShell:

    powershell -ExecutionPolicy Bypass -File .\trust-and-install-openidx-agent.ps1 -Server https://openidx.example.com

  Other modes:
    -TrustOnly     import the certificate and stop (install the MSI by hand)
    -RemoveTrust   remove the certificate from both stores and stop
    -Token <t>     enroll during install (a reusable fleet token, or one code)

.NOTES
  Whoever holds the private key of this certificate can sign software these
  machines will run without a warning. Keep that key off the application
  server; a public OV/EV code-signing certificate makes this script
  unnecessary.
#>

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
  [Parameter(ParameterSetName = 'Install')]
  [Parameter(ParameterSetName = 'Trust')]
  [string]$Server = "",

  [Parameter(ParameterSetName = 'Install')]
  [string]$Token = "",

  [Parameter(ParameterSetName = 'Install')]
  [string]$InstallFolder = "",

  [Parameter(ParameterSetName = 'Trust', Mandatory = $true)]
  [switch]$TrustOnly,

  [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
  [switch]$RemoveTrust
)

$ErrorActionPreference = 'Stop'

# The certificate agent/packaging/openidx-codesign.cer, and its SHA-256.
# scripts/check-trust-script.sh keeps both in step with that file.
$PinnedSha256 = '066733F1A2094B5162A45088636D159770107C221595F3BEE9194B0A3F78BC2B'
$CertBase64 = @'
MIIEaDCCAtCgAwIBAgIUQOX8F418fUQh5c0LdOkiTRjSPMAwDQYJKoZIhvcNAQELBQAwMTEdMBsG
A1UEAwwUT3BlbklEWCBDb2RlIFNpZ25pbmcxEDAOBgNVBAoMB09wZW5JRFgwHhcNMjYwNzE0MDU1
MjQ5WhcNMzEwNzEzMDU1MjQ5WjAxMR0wGwYDVQQDDBRPcGVuSURYIENvZGUgU2lnbmluZzEQMA4G
A1UECgwHT3BlbklEWDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKnGPLjbQjKQ4ruU
sTcNEziCklEpd/jg3iPfmhoJn2gdRvZTAK0ObTRAwLD3WDVuxOhOeFSYtZlSbSv0vM6hKASkUqd4
EclsVS0TWHY5PSvnCajRUTfq0XAHQaCcZQDlRn/Huf8Ps++ezlIONugnVt45psWaUJDCgN3iRJdA
Z2ML0zE1GWKDvFpC1Gkbl1utOz6coXYk/dEOPZBrwVvhb2vwX6U1gjqv+xXsG83ymcc/qOMQUncv
oQQSnjdM+ejXmQHz0rIJaDZWqMWGYT3xRZ1Hrl1Cl5Hq7iGm/FRT0B973jxf2SGWV1aB+vKB9WiY
xiRAgT+3f+guizQJRJpgs9LDQJ9Blys3CnG4yK+IMfR0Bxp9BsV6Fgjv1+nWpvWXEkHUGMWkeiAR
QJVbzVqGf1yuMypSB8mvKIoY5PqsSlqIVwq32aKLPLYiI3Zdr80QAEBREwO5cxtPtTXGEKdRBlD9
t5HPWuE9NSt1W9X8SO7kMZII2gTRcUNa6ode79E5OQIDAQABo3gwdjAdBgNVHQ4EFgQUQqB2sSZz
uR/dtnpjOVPij7xplswwHwYDVR0jBBgwFoAUQqB2sSZzuR/dtnpjOVPij7xplswwDgYDVR0PAQH/
BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
BQADggGBAJH6c+Z5Oa4kVUTES1p9dy1yJA+cRcjVrtoEGFt0vm7KsdoDJ5qtC87X5gjmamDQNbIN
xv2NeMRJuVTV3Ug5jO4Nce7qVAW1SXQGqyyk04TOTxihwttvnvpo5L+SE2j6+W1IPX4mUSo24rIl
bOJPoYXQ9orQ7cIYlHrFm/2hbjjNlXeZOv3INffk8Wh2SDHWvUiO0Kh/vl+GKhEakY4yZl4mL2Cz
QCWnY23fxk0ibvNkFrZ+gbBE1Izwjfu+WFbuzVn1pQLvUeIb6cTVQRNYztXTCAeAgUahJXo0Qg1R
Wc/LgUt5PgymjxRTZQDfIDOCXPon2bn76804nvt3m4Zp8JscmamhyDb06DUR/sbbCPgxL7MJn5J9
OK5DogP/bbHNhWDQX+8e9i41OD6lzJAhohsHL7xnsOyx5zpEA5HSY0LfAPNX3AwJ6L8Pgtf+S+at
u2+xzhl4kUQZl3RZhwBRdZ+CuCop6YcDEwGb2BrgXfhkTNaxMiOUT+FqmhaJ8oR2ug==
'@

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

function Get-Sha256Hex([byte[]]$bytes) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
  finally { $sha.Dispose() }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  throw "Run this script in an elevated (Administrator) PowerShell."
}

# --- The certificate: pinned, and only able to sign code ------------------
$raw = [Convert]::FromBase64String(($CertBase64 -replace '\s', ''))
if ((Get-Sha256Hex $raw) -ne $PinnedSha256) {
  throw "The embedded certificate does not match its pinned SHA-256; this copy of the script was altered. Do not run it."
}
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)

$bc = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
if (-not $bc -or $bc.CertificateAuthority) {
  throw "The certificate is not marked CA:FALSE; refusing to trust it as a root."
}
$eku = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
$ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
if ($ekuOids.Count -ne 1 -or $ekuOids[0] -ne '1.3.6.1.5.5.7.3.3') {
  throw "The certificate is not limited to code signing; refusing to trust it."
}

$stores = @('Root', 'TrustedPublisher')

function Test-InStore($storeName) {
  $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
  $s.Open('ReadOnly')
  try { return [bool]($s.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }) }
  finally { $s.Close() }
}

if ($RemoveTrust) {
  Write-Step "Removing '$($cert.Subject)' from LocalMachine\Root and \TrustedPublisher"
  foreach ($name in $stores) {
    $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, 'LocalMachine')
    $s.Open('ReadWrite')
    try { $s.Remove($cert); Write-Ok "removed from $name" } finally { $s.Close() }
  }
  return
}

Write-Step "Trusting '$($cert.Subject)' (SHA-256 $PinnedSha256)"
foreach ($name in $stores) {
  if (Test-InStore $name) {
    Write-Ok "already in LocalMachine\$name"
    continue
  }
  $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, 'LocalMachine')
  $s.Open('ReadWrite')
  try { $s.Add($cert); Write-Ok "added to LocalMachine\$name" } finally { $s.Close() }
}

if ($TrustOnly) {
  Write-Host ""
  Write-Host "Certificate trusted. Install the agent MSI from My Devices -> Add a device." -ForegroundColor Green
  return
}

# --- The MSI: named by the server, checked twice --------------------------
if (-not $Server) { throw "Pass -Server https://<your OpenIDX host>." }
$Server = $Server.TrimEnd('/')
if ($Server -notmatch '^https://') { throw "-Server must be an https:// URL." }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Step "Reading $Server/downloads/agent-manifest.json"
$manifest = Invoke-RestMethod -Uri "$Server/downloads/agent-manifest.json"
$win = $manifest.windows
if (-not $win -or -not $win.filename -or -not $win.sha256) {
  throw "The server offers no Windows installer (agent-manifest.json has no 'windows' entry)."
}
# [regex]::IsMatch, not -match: Windows PowerShell 5.1's case-insensitive
# -match rejects 'OpenIDX-0.5.0.msi' against this class.
if (-not [regex]::IsMatch([string]$win.filename, '^[A-Za-z0-9._-]+\.msi$')) {
  throw "The server named an unexpected installer file: '$($win.filename)'."
}
Write-Ok "$($win.filename)"

$msi = Join-Path $env:TEMP $win.filename
$log = Join-Path $env:TEMP 'openidx-install.log'
Write-Step "Downloading"
Invoke-WebRequest -Uri "$Server/downloads/$($win.filename)" -OutFile $msi -UseBasicParsing

$got = (Get-FileHash -Path $msi -Algorithm SHA256).Hash
if ($got -ne $win.sha256.ToUpperInvariant()) {
  Remove-Item $msi -Force
  throw "The download's SHA-256 ($got) is not the one the server published ($($win.sha256)); deleted it."
}
Write-Ok "SHA-256 matches the manifest"

$sig = Get-AuthenticodeSignature -FilePath $msi
if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or
    $sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
  Remove-Item $msi -Force
  throw "The MSI is not validly signed by '$($cert.Subject)' (status: $($sig.Status)); deleted it."
}
Write-Ok "signed by $($sig.SignerCertificate.Subject)"

Write-Step "Stopping a running agent, if any"
Get-Service 'OpenIDX*' -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
Get-Process openidx-agent -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Step "Installing (silent)"
$msiArgs = @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$log`"", "SERVER_URL=$Server")
if ($Token) { $msiArgs += "ENROLL_TOKEN=$Token" }
if ($InstallFolder) { $msiArgs += "INSTALLFOLDER=`"$InstallFolder`"" }
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
  throw "The MSI install failed (exit $($p.ExitCode)). Log: $log"
}
Write-Ok "msiexec exit code $($p.ExitCode)$(if ($p.ExitCode -eq 3010) { ' (restart needed)' })"
Remove-Item $msi -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($Token) {
  Write-Host "Installed and enrolled. The device appears under My Devices within a minute." -ForegroundColor Green
} else {
  Write-Host "Installed. Now enroll: on this PC open $Server, go to My Devices -> Add a device," -ForegroundColor Green
  Write-Host "generate a code and click 'Open in app' (approve the administrator prompt)." -ForegroundColor Green
}
