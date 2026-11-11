# Deploying the OpenIDX agent with Group Policy

For domain-joined Windows devices without Intune. Two ways: **Software
Installation** with a transform (`.mst`), or a **computer startup script**.

## 1. Trust the publisher (self-signed builds only)

If the MSI is signed with the project's own certificate rather than a public
OV/EV one, create a GPO linked to the computers' OU and import
`agent/packaging/openidx-codesign.cer` under

*Computer Configuration -> Policies -> Windows Settings -> Security Settings ->
Public Key Policies*:

- **Trusted Root Certification Authorities**, and
- **Trusted Publishers**.

Without both, Windows reports an unknown publisher and the signature check in
the install script fails. A publicly signed MSI needs neither.

## 2a. Software Installation with a transform

GPO Software Installation cannot pass MSI properties, so they go in a
transform. On an admin workstation:

```powershell
.\agent\packaging\wix\make-mst.ps1 -Msi .\OpenIDX-1.2.0.msi `
  -ServerUrl https://openidx.example.com -EnrollToken <FLEET_TOKEN> `
  -Out .\OpenIDX-corp.mst
```

Options: `-TunnelEnabled`, `-ProxyUrl`, `-ServerCa C:\path\corp-root.pem` (a
path that exists on every device), `-LogLevel`, `-NoKeepToken`.

1. Copy the MSI and the `.mst` to a share. The transform holds the fleet token
   in clear text: grant **Read** to *Domain Computers* only, not to users.
2. *Computer Configuration -> Policies -> Software Settings -> Software
   installation -> New -> Package*, pick the MSI by its UNC path, choose
   **Advanced**, and add the `.mst` on the **Modifications** tab.
3. Devices install at the next reboot (Software Installation runs at startup,
   before sign-in).

To upgrade, add the new MSI (with a transform made from it) as a package that
*upgrades* the old one. A transform is tied to the MSI it was made from.

## 2b. Startup script

*Computer Configuration -> Policies -> Windows Settings -> Scripts ->
Startup -> PowerShell Scripts*, add `Install-OpenIDXAgent.ps1` from the share
with parameters:

```
-ServerUrl https://openidx.example.com -EnrollToken <FLEET_TOKEN>
```

The script runs as SYSTEM at each startup. It does nothing when the agent is
already at the release's version, upgrades an older one, and verifies the MSI's
SHA-256 against the release manifest and its Authenticode signature first.
The script and its parameters are readable by anyone who can read the GPO
(by default every authenticated user), so the token is less protected than in
2a; filter the GPO's read permission or prefer 2a.

## Enrollment that the network was not ready for

Both paths install with `KEEP_ENROLL_TOKEN=1`. If the device cannot reach the
server at install time, the agent service keeps the token sealed (DPAPI,
LocalSystem) and retries after 1, 5 and 15 minutes, then hourly, until it
enrolls. A 403 *agent_revoked* deletes the token and stops the retries.

## Verify and remove

`Get-ItemProperty HKLM:\SOFTWARE\OpenIDX\Agent` shows `Version`,
`InstallDir` and `ServerUrl`; `Get-Service OpenIDXAgent` is *Running*.
Removing the package from the GPO (*Immediately uninstall*), or running
`Uninstall-OpenIDXAgent.ps1`, uninstalls it and deletes
`%ProgramData%\OpenIDX\agent`.
