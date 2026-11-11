<#
.SYNOPSIS
  Zero-touch installer for the OpenIDX device agent: Intune Win32 app, GPO
  startup script, SCCM, or a hand run in an elevated PowerShell.

.DESCRIPTION
  Reads the agent release manifest (latest.json: version, url, sha256),
  downloads the MSI it names, refuses it unless its SHA-256 matches the
  manifest AND its Authenticode signature is valid, then installs it silently
  and enrolls the device with a reusable fleet token. The MSI seals the token
  (KEEP_ENROLL_TOKEN=1), so a device installed before its network is up
  finishes enrolling on its own (1m, 5m, 15m, then hourly).

  Idempotent: an agent already at the manifest's version is left alone, an
  older one is upgraded in place.

    # Install / upgrade
    .\Install-OpenIDXAgent.ps1 -ServerUrl https://openidx.example.com -EnrollToken <FLEET_TOKEN>

    # Intune detection script (exit 0 + stdout when installed)
    .\Install-OpenIDXAgent.ps1 -Detect

    # Uninstall (also removes %ProgramData%\OpenIDX\agent)
    .\Install-OpenIDXAgent.ps1 -Uninstall

  Exit codes: 0 ok, 3010 ok (restart needed), 1 failure, 2 not installed (-Detect).

.NOTES
  CI stamps the __PLACEHOLDER__ values at release time, never the token. The
  release asset is public and an enrollment token admits any machine that
  presents it, so -EnrollToken is always yours to pass.
#>

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
  [Parameter(ParameterSetName = 'Install')]
  [string]$ServerUrl     = "__SERVER_URL__",
  [Parameter(ParameterSetName = 'Install')]
  [string]$EnrollToken   = "__ENROLL_TOKEN__",
  [Parameter(ParameterSetName = 'Install')]
  [string]$ManifestUrl   = "__MANIFEST_URL__",
  [Parameter(ParameterSetName = 'Install')]
  [switch]$TunnelEnabled,
  [Parameter(ParameterSetName = 'Install')]
  [string]$ProxyUrl      = "",
  # Path to a PEM CA certificate the agent trusts for the server (private CA).
  [Parameter(ParameterSetName = 'Install')]
  [string]$ServerCa      = "",
  # Path to the publisher's code-signing .cer. Imported into LocalMachine\Root
  # and \TrustedPublisher, and the MSI must then be signed by exactly it. Only
  # for a self-signed publisher; a public OV/EV signature needs nothing.
  [Parameter(ParameterSetName = 'Install')]
  [string]$TrustCert     = "",
  [Parameter(ParameterSetName = 'Detect', Mandatory = $true)]
  [switch]$Detect,
  [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$RegKey = 'HKLM:\SOFTWARE\OpenIDX\Agent'

function Write-Step($msg) { Write-Host "==> $msg" }
function Get-InstalledVersion {
  $v = Get-ItemProperty -Path $RegKey -Name Version -ErrorAction SilentlyContinue
  if ($v) { return [string]$v.Version }
  return $null
}

# --- Detect --------------------------------------------------------------
if ($Detect) {
  $v = Get-InstalledVersion
  $svc = Get-Service -Name OpenIDXAgent -ErrorAction SilentlyContinue
  if ($v -and $svc) { Write-Output "OpenIDX Agent $v installed"; exit 0 }
  exit 2
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Run elevated (Administrator or SYSTEM)."; exit 1 }

# --- Uninstall -----------------------------------------------------------
if ($Uninstall) {
  & (Join-Path $PSScriptRoot 'Uninstall-OpenIDXAgent.ps1')
  exit $LASTEXITCODE
}

try {
  if (-not $ServerUrl -or $ServerUrl -like "*__*__*") { throw "Pass -ServerUrl https://<your OpenIDX host>." }
  $ServerUrl = $ServerUrl.TrimEnd('/')
  if ($ServerUrl -notmatch '^https://') { throw "-ServerUrl must be an https:// URL." }
  if ($EnrollToken -like "*__*__*") { $EnrollToken = "" }
  # Unstamped (run from a checkout): the agent release channel. Not
  # releases/latest/download, which is the newest release of any kind.
  if (-not $ManifestUrl -or $ManifestUrl -like "*__*__*") {
    $ManifestUrl = "https://github.com/mhmtgngr/openidx/releases/download/agent-latest/latest.json"
  }
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $web = @{ UseBasicParsing = $true }
  if ($ProxyUrl) { $web.Proxy = $ProxyUrl; $web.ProxyUseDefaultCredentials = $true }

  # --- Optional publisher certificate -------------------------------------
  $pinned = $null
  if ($TrustCert) {
    $pinned = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $TrustCert).Path)
    $eku = @($pinned.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
    if ($eku -notcontains '1.3.6.1.5.5.7.3.3') { throw "-TrustCert is not a code-signing certificate." }
    foreach ($name in 'Root', 'TrustedPublisher') {
      $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, 'LocalMachine')
      $s.Open('ReadWrite')
      try {
        if (-not ($s.Certificates | Where-Object { $_.Thumbprint -eq $pinned.Thumbprint })) { $s.Add($pinned) }
      } finally { $s.Close() }
    }
    Write-Step "Trusted publisher $($pinned.Subject)"
  }

  # --- Manifest ------------------------------------------------------------
  Write-Step "Reading $ManifestUrl"
  $m = Invoke-RestMethod -Uri $ManifestUrl @web
  if (-not $m.url -or -not $m.sha256 -or -not $m.version) { throw "The manifest names no version/url/sha256." }
  if ([string]$m.url -notmatch '^https://') { throw "The manifest's MSI URL is not https." }
  if (-not [regex]::IsMatch([string]$m.sha256, '^[0-9A-Fa-f]{64}$')) { throw "The manifest's sha256 is malformed." }

  $have = Get-InstalledVersion
  if ($have -and $have -eq [string]$m.version -and -not $EnrollToken) {
    Write-Step "OpenIDX Agent $have is already installed"
    exit 0
  }

  # --- Download + verify ---------------------------------------------------
  $msi = Join-Path $env:TEMP "OpenIDX-$($m.version).msi"
  Write-Step "Downloading $($m.url)"
  Invoke-WebRequest -Uri $m.url -OutFile $msi @web
  $got = (Get-FileHash -Path $msi -Algorithm SHA256).Hash
  if ($got -ne ([string]$m.sha256).ToUpperInvariant()) {
    Remove-Item $msi -Force
    throw "SHA-256 $got does not match the manifest ($($m.sha256)); deleted the download."
  }
  $sig = Get-AuthenticodeSignature -FilePath $msi
  if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) {
    Remove-Item $msi -Force
    throw "The MSI's Authenticode signature is not valid ($($sig.Status)); pass -TrustCert for a self-signed publisher."
  }
  if ($pinned -and $sig.SignerCertificate.Thumbprint -ne $pinned.Thumbprint) {
    Remove-Item $msi -Force
    throw "The MSI is signed by '$($sig.SignerCertificate.Subject)', not the -TrustCert publisher."
  }
  Write-Step "Verified: SHA-256 and signature by $($sig.SignerCertificate.Subject)"

  # --- Install -------------------------------------------------------------
  # The log is verbose; the MSI marks ENROLL_TOKEN and the enrol action Hidden,
  # so the token is written as ***** there.
  $log = Join-Path $env:TEMP 'openidx-install.log'
  $msiArgs = @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$log`"",
    "SERVER_URL=`"$ServerUrl`"", "UPDATE_MANIFEST_URL=`"$ManifestUrl`"", 'KEEP_ENROLL_TOKEN=1')
  if ($EnrollToken) { $msiArgs += "ENROLL_TOKEN=`"$EnrollToken`"" }
  if ($TunnelEnabled) { $msiArgs += 'TUNNEL_ENABLED=1' }
  if ($ProxyUrl) { $msiArgs += "PROXY_URL=`"$ProxyUrl`"" }
  if ($ServerCa) { $msiArgs += "SERVER_CA=`"$((Resolve-Path $ServerCa).Path)`"" }
  Write-Step "Installing OpenIDX Agent $($m.version) (silent)"
  $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
  Remove-Item $msi -Force -ErrorAction SilentlyContinue
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec exit $($p.ExitCode). Log: $log" }
  Write-Step "Installed (msiexec $($p.ExitCode))"
  exit $p.ExitCode
} catch {
  Write-Error $_
  exit 1
}
