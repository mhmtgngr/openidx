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
```
msiexec /i OpenIDX.msi /qn
```
The service starts automatically. Enroll the device (post-install startup script
or Intune command), then users sign in from the tray:
```
"%ProgramFiles%\OpenIDX\openidx-agent.exe" enroll --server https://openidx.example.com --token <ENROLL_TOKEN>
```

## Signing
Set `WINDOWS_CERT_PFX_BASE64` + `WINDOWS_CERT_PASSWORD` repo secrets; the CI job
Authenticode-signs the MSI when they're present.

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
