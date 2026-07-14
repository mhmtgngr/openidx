# OpenIDX Windows client — packaging

The MSI wraps the single `openidx-agent.exe`: it registers + auto-starts the
`OpenIDXAgent` Windows service (device-trust posture loop) and launches the tray
at user login.

## Build (CI does this on `windows-latest`)
The **Windows Client Build** GitHub Action builds the `.exe` + MSI and uploads
them as artifacts. Trigger it via Actions → Run workflow (or it runs on
`agent/**` pushes/PRs). To build locally on a Windows machine:

```powershell
# 1. Build the exe (from repo root)
cd agent
go build -trimpath -ldflags "-s -w -X main.Version=1.0.0" -o dist/openidx-agent.exe ./cmd/openidx-agent
cd ..

# 2. Package the MSI (WiX v5)
dotnet tool install --global wix
wix build agent/packaging/wix/OpenIDX.wxs -d Version=1.0.0 -d ExePath=agent/dist/openidx-agent.exe -arch x64 -o dist/OpenIDX.msi
```

## Deploy (silent / GPO / Intune)
Zero-touch fleet enroll with a **reusable** bootstrap token (one token for all
devices — mint via `POST /api/v1/access/agent/tokens {"reusable":true}`):
```
msiexec /i OpenIDX.msi /qn SERVER_URL=https://openidx.example.com ENROLL_TOKEN=<REUSABLE_TOKEN>
```
The MSI installs + starts the service and, when SERVER_URL+ENROLL_TOKEN are
given, enrolls the device during install. Without them it installs silently and
you enroll later (single-use token or the tray's OAuth sign-in):
```
"%ProgramFiles%\OpenIDX\openidx-agent.exe" enroll --server https://openidx.example.com --token <ENROLL_TOKEN>
```
Users then sign in for SSO/PAM from the tray (launched at login).

## Signing
Set `WINDOWS_CERT_PFX_BASE64` (base64 of a code-signing `.pfx`) +
`WINDOWS_CERT_PASSWORD` repo secrets; the CI job then Authenticode-signs **both**
`openidx-agent.exe` (before packaging) and the MSI, with an RFC 3161 timestamp.
When the secrets are unset, signing is skipped and the build still succeeds.

This repo ships a **self-signed** code-signing certificate. That satisfies
Authenticode and lets you silence SmartScreen/Defender on **managed** machines by
distributing the public cert to the **Trusted Publishers** (and Trusted Root)
store — it does *not* establish trust on unmanaged/public machines (only a
public-CA cert does that). The public cert (no private key) is
`agent/packaging/openidx-codesign.cer`.

Push it to your fleet via GPO — *Computer Configuration → Policies → Windows
Settings → Security Settings → Public Key Policies → Trusted Publishers* (import
the `.cer`) — or Intune (a Trusted Certificate profile). To trust it on a single
box for testing:
```powershell
Import-Certificate -FilePath openidx-codesign.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
Import-Certificate -FilePath openidx-codesign.cer -CertStoreLocation Cert:\LocalMachine\Root
```
Rotate by regenerating the `.pfx`, updating the two secrets, and re-distributing
the new `.cer`.

## Releases & auto-update
Push an **`agent-v<version>`** tag (e.g. `agent-v1.2.0`). The Windows Client
Build workflow then builds + signs the MSI and publishes a GitHub Release with:
- `OpenIDX-<version>.msi`
- `latest.json` — `{ "version", "url", "sha256" }` the self-updater polls.

Point clients at the stable "latest" URL (redirects to the newest release):
```
update_manifest_url = https://github.com/mhmtgngr/openidx/releases/latest/download/latest.json
```
Set it in the agent config (or via a deployment script); the service checks
every 6h and applies newer signed MSIs. Manual: `openidx-agent update --apply`.

## winget
`packaging/winget/` holds a manifest template — fill `InstallerUrl` +
`InstallerSha256` from the released MSI and submit to `microsoft/winget-pkgs`.
