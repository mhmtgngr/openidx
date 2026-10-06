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

### Screen-share (remote support video) build variant

Remote-support **video** needs the `screenshare` build (real screen capture +
VP8 encode). It requires CGO + libvpx, so it is not the default cross-compile.
The CI `build-msi` job builds it automatically (installs libvpx via vcpkg,
bundles `vpx.dll` into the MSI) and falls back to the pure-Go exe if the native
toolchain is unavailable. To build it locally on Windows:

```powershell
# libvpx via vcpkg (once)
vcpkg install libvpx:x64-windows
cd agent
$env:CGO_ENABLED=1
$env:PKG_CONFIG_PATH="$env:VCPKG_ROOT/installed/x64-windows/lib/pkgconfig"
go build -tags screenshare -o dist/openidx-agent.exe ./cmd/openidx-agent
# copy the runtime DLL next to the exe, then pass it to WiX:
copy "$env:VCPKG_ROOT/installed/x64-windows/bin/vpx*.dll" dist/
wix build packaging/wix/OpenIDX.wxs -d Version=1.0.0 -d ExePath=dist/openidx-agent.exe -d VpxDll=dist/vpx1.dll -arch x64 -o ../dist/OpenIDX.msi
```

The **pure-Go** exe (default) still runs remote support — it negotiates the
session and honors keyboard/mouse control — it just sends no video frames. The
`screenshare` exe adds the live screen stream.

## Deploy (silent / GPO / Intune)
Zero-touch fleet enroll with a **reusable** bootstrap token (one token for all
devices — mint via `POST /api/v1/access/agent/tokens {"reusable":true}`):
```
msiexec /i OpenIDX.msi /qn SERVER_URL=https://openidx.example.com ENROLL_TOKEN=<REUSABLE_TOKEN>
```
The MSI installs + starts the service and, when SERVER_URL+ENROLL_TOKEN are
given, enrolls the device during install. Without them it installs silently and
you enroll later, either from the console's Add-a-device wizard (its
`openidx://enroll?...` link or QR starts the agent, which asks for
administrator approval and enrols; see `packaging/DEEPLINK.md`) or with a
single-use token from an elevated prompt:
```
"%ProgramFiles%\OpenIDX\openidx-agent.exe" enroll --server https://openidx.example.com --token <ENROLL_TOKEN>
```
The service waits for the enrolment and starts its posture loop as soon as it
lands. Users then sign in for SSO/PAM from the tray (launched at login);
signing in does not enrol the device.

The tray menu is the user's whole surface: the status line (sign-in and
device state), **Sign in / Sign out**, **Set up Windows Hello sign-in** (opens
the console's Security Keys page, see `docs/windows/mfa-without-a-phone.md`),
**My Connections** (privileged sessions; a refusal offers a fresh sign-in or
an access request), **Settings** (start at sign-in, check for updates, about)
and **Quit**.

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
Two ways to release, and they publish the same thing:
- push an **`agent-v<version>`** tag (e.g. `agent-v1.2.0`), or
- from a session that cannot push tags, run **Actions → Agent Build & Release →
  Run workflow** on `main` with `version=1.2.0` and `release` ticked, or
  `gh workflow run windows-client-build.yml --ref main -f version=1.2.0 -f release=true`.
  The run refuses a version whose tag already exists, and creates the tag at the
  commit it built.

The workflow builds and signs the MSI and publishes a GitHub Release
`agent-v<version>` with:
- `OpenIDX-<version>.msi`
- `latest.json` — `{ "version", "url", "sha256", "signature" }` the self-updater
  polls.

It then copies `latest.json`, the MSI (as `OpenIDX.msi`) and the stamped
install script onto **`agent-latest`**, a release that never moves and whose
assets each agent release replaces. That is the release channel:
```
update_manifest_url = https://github.com/mhmtgngr/openidx/releases/download/agent-latest/latest.json
```
Not `releases/latest/download/…`: GitHub's "latest" is the newest release of any
kind, and the server is released far more often than the agent, so that URL
names a server release with no `latest.json` and no MSI. Agent releases are
published with `make_latest: false` so they never take "latest" from the server.

A release build carries the channel as its default: the MSI's
`UPDATE_MANIFEST_URL` defaults to it, and `openidx-agent enroll` records it when
no `--manifest-url` is given, which covers a device enrolled from the console's
link. Enrolling again keeps the channel the device already had. To turn
self-update off, install with `UPDATE_MANIFEST_URL=""` (or enrol with
`--manifest-url ""`). To point at a mirror, pass its URL. The service checks every 6h
and applies newer signed MSIs. Manual: `openidx-agent update --apply`.

A device enrolled before this keeps the empty `update_manifest_url` it was
enrolled with. To turn self-update on for it, set
`update_manifest_url` in `%ProgramData%\OpenIDX\agent\agent.json` (as an
administrator) or enrol it again.

### The manifest is signed, and the release fails if it cannot be
`latest.json` is what tells an installed agent which MSI to fetch and run as
SYSTEM. Its `sha256` proves the download arrived intact and nothing more — the
same file supplies the URL and the digest that matches it — so the manifest
carries a `signature` over its own fields, made with the **same code-signing key
as the MSI** and verified by every agent against the copy of
`openidx-codesign.cer` pinned at `agent/internal/updater/release-publisher.cer`.

Consequences worth knowing before you tag:
- **`WINDOWS_CERT_PFX_BASE64` and `WINDOWS_CERT_PASSWORD` are required for an
  `agent-v*` release.** Without them the job fails rather than publishing an
  unsigned manifest, which every agent would refuse anyway.
- **Rotating the signing key means updating three things together**: the two
  secrets, `agent/packaging/openidx-codesign.cer`, and its byte copy at
  `agent/internal/updater/release-publisher.cer` (a test compares them and fails
  the build if they differ). Agents must be running a build that carries the new
  certificate *before* the first release signed with the new key, or they will
  refuse it — ship the new agent first, then rotate.
- **Publishing your own builds** (an on-premise release channel) means signing
  the manifest with your own key and setting `update_trusted_cert` in the
  agent's `agent.json` to that certificate in PEM. It *replaces* the pinned
  OpenIDX publisher, so such an agent accepts your releases and only yours.

## winget
`packaging/winget/` holds the three-file manifest (version + installer + en-US
locale), filled for the current signed release (`InstallerUrl` → the release MSI,
`InstallerSha256` → the hash from that release's `latest.json`). Submit it to
`microsoft/winget-pkgs` (public) or host a private source. Install:
```
winget install OpenIDX.Agent
# Zero-touch fleet enroll — pass MSI properties through --override:
winget install OpenIDX.Agent --override "SERVER_URL=https://openidx.example.com ENROLL_TOKEN=<REUSABLE>"
```
Upgrades are detected via the fixed `UpgradeCode` (the MSI ProductCode changes
per build). On each release: bump `PackageVersion` in all three files, repoint
`InstallerUrl` to the new tag, and replace `InstallerSha256` from the new
`latest.json`.
