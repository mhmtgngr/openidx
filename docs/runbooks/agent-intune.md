# Deploying the OpenIDX agent with Microsoft Intune

This runbook rolls the Windows agent out to Entra-joined (or hybrid-joined)
devices with no one at the keyboard. Each device installs the signed MSI,
enrolls with a reusable **fleet token**, and shows up under **Agent fleet**.

## Before you start

1. **A fleet token.** In the console, mint a reusable enrollment token (or
   call `POST /api/v1/access/agent/tokens` with `{"reusable": true}`). Treat it
   like a password: anyone holding it can enroll a machine into your
   organization. Rotate it when a package that carries it leaks.
2. **The publisher certificate**, only when the MSI is signed with the
   project's self-signed certificate rather than a public OV/EV one. Push
   `agent/packaging/openidx-codesign.cer` to **Trusted Root** and **Trusted
   Publishers** with an Intune *Trusted certificate* profile (Devices ->
   Configuration -> Templates -> Trusted certificate, destination *Computer
   certificate store - Root*, and a second profile for *Trusted Publishers*).
   Or pass `-TrustCert` to the install script below.
3. **Network.** Devices must reach `https://<your host>` (and the release
   channel if you keep self-update on). Behind an explicit proxy, add
   `-ProxyUrl http://proxy:8080`. For a server behind a private CA, add
   `-ServerCa .\corp-root.pem` (packaged with the script).

## Option A (recommended): Win32 app

Package `Install-OpenIDXAgent.ps1` and `Uninstall-OpenIDXAgent.ps1` from the
agent release (plus `corp-root.pem` / the `.cer` if you need them) with the
[Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool):

```powershell
IntuneWinAppUtil.exe -c .\openidx -s Install-OpenIDXAgent.ps1 -o .\out
```

Apps -> Windows -> Add -> *Windows app (Win32)*, upload the `.intunewin`, then:

| Field | Value |
| --- | --- |
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-OpenIDXAgent.ps1 -ServerUrl https://openidx.example.com -EnrollToken <FLEET_TOKEN>` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-OpenIDXAgent.ps1` |
| Install behavior | System |
| Device restart behavior | Determine behavior based on return codes |
| Return codes | `0` success, `3010` soft reboot, `1` failed |
| Requirements | 64-bit, Windows 10 1809+ |

Add `-TunnelEnabled` to turn the bundled tunnel on for these devices.

**Detection rule**, either of:

- *Registry*: `HKEY_LOCAL_MACHINE\SOFTWARE\OpenIDX\Agent`, value `Version`,
  *Version comparison* greater than or equal to the version you ship.
- *Custom script*: `Install-OpenIDXAgent.ps1 -Detect` (exit 0 and a line of
  output when installed and the service exists).

**Assignment.** Assign *Required* to an Entra **device** group (a dynamic group
such as `(device.deviceOSType -eq "Windows")` scoped to corporate devices),
not a user group, so the agent installs before anyone signs in, including
during Autopilot ESP.

The script reads the release manifest, refuses the MSI unless its SHA-256
matches the manifest **and** its Authenticode signature is valid, and installs
it with `KEEP_ENROLL_TOKEN=1`. A device installed before its network is up
(Autopilot, a laptop off-VPN) finishes enrolling on its own: the service
retries after 1 minute, 5 minutes, 15 minutes, then hourly. The token is kept
sealed with DPAPI in `%ProgramData%\OpenIDX\agent\enroll-token.sealed` and is
deleted if the server answers that the device is revoked.

## Option B: Line-of-business MSI

Apps -> Windows -> Add -> *Line-of-business app*, upload `OpenIDX-<ver>.msi`,
and set *Command-line arguments*:

```
SERVER_URL=https://openidx.example.com ENROLL_TOKEN=<FLEET_TOKEN> KEEP_ENROLL_TOKEN=1
```

Optional: `TUNNEL_ENABLED=1`, `PROXY_URL=...`, `LOG_LEVEL=info`. Intune detects
an LOB MSI by its product code itself. LOB apps cannot verify the download
against the manifest, and Intune shows the arguments to every admin with
read access to the app, so prefer Option A.

## Verify

On a device: `Get-ItemProperty HKLM:\SOFTWARE\OpenIDX\Agent` shows `Version`,
`Get-Service OpenIDXAgent` is *Running*, and the device appears under **Agent
fleet** within a minute or two. The verbose MSI log
(`%TEMP%\openidx-install.log`) shows the token as `**********`, never in clear.

## Remove

Unassign (or assign *Uninstall*). The MSI stops the service, removes the
tunnel's DNS (NRPT) rules and adapter, and deletes `%ProgramData%\OpenIDX\agent`,
including the sealed token. Revoke the device in the console as well if it is
leaving the fleet.
