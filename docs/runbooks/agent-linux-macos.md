# OpenIDX agent on Linux and macOS

## Linux (.deb / .rpm)

The package installs:

| path | purpose |
|---|---|
| `/usr/local/bin/openidx-agent` | agent |
| `/usr/lib/systemd/system/openidx-agent.service` | service (user `openidx-agent`) |
| `/usr/lib/systemd/system/openidx-agent-update.{service,timer}` | update check every 6h (`update --apply`) |
| `/etc/openidx-agent/agent.env` | environment, conffile (kept on upgrade). Put `HTTPS_PROXY`/`NO_PROXY` here. |
| `/var/lib/openidx-agent/` | config dir (`agent.json`, identity), 0700 |

`postinstall` creates the system user, copies a legacy
`/etc/openidx-agent/agent.json` into `/var/lib/openidx-agent` once, enables the
timer and (re)starts the service. `preremove` stops and disables units on
removal only, never on upgrade. For one release the agent itself also reads
`/etc/openidx-agent` when only it holds an enrolled `agent.json`.

### One-line install

```sh
curl -fsSL https://<server>/downloads/install.sh | sh -s -- \
  --server https://<server> --code <code> [--pubkey publisher.pem] [--format deb|rpm|pkg|bin]
```

The script reads `/downloads/agent-manifest.json`, prefers deb (apt systems),
rpm (dnf/yum/zypper) or pkg (macOS), falls back to the bare binary, and refuses
any download whose sha256 differs from the manifest. With `--pubkey` it also
verifies the manifest signature (needs `openssl`).

### Signed downloads manifest

Set `AGENT_MANIFEST_SIGNING_KEY` on the access service to the PEM RSA private
key (or a path to it) that signs `latest.json`. The manifest response then
carries `X-OpenIDX-Manifest-Signature`: base64 RSASSA-PKCS1-v1_5/SHA-256 over

```
openidx-agent-downloads-manifest/v1
<key>.filename=...
<key>.sha256=...
<key>.url=...
```

for every top-level key, sorted. An unparsable key makes the endpoint answer
500 rather than serve an unsigned manifest.

## macOS (.pkg, unsigned)

`make package-macos` (CI job `macos-pkg` on `macos-15`) builds a universal
binary and an **unsigned** pkg with `/Library/LaunchDaemons/com.openidx.agent.plist`
(config dir `/var/lib/openidx-agent`). No Apple Developer ID yet: install via
MDM or right-click Open. Tunnel and tray on macOS are a later slice.

## CI smoke

- `nfpm-smoke`: `dpkg -i`/reinstall/`dpkg -r` on `debian:bookworm`, `rpm` on `rockylinux:9`.
- `msi-smoke` (windows-latest): `/i /qn /l*v` → service Running, registry
  Version, no token in the log; upgrade to version+0.0.1 keeps config; `/x`
  removes service, ProgramData and any Wintun adapter.
- `scripts/check-agent-release.sh --manifest latest.json --version X.Y.Z`
  validates each published `latest.json`.
