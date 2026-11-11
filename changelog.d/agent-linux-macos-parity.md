### Added
- **Linux and macOS agent packaging parity (Faz B8.8).** The deb/rpm ship the
  systemd service, an update timer and a kept `agent.env`; postinstall creates
  the `openidx-agent` user and enables them. The config dir is unified at
  `/var/lib/openidx-agent` (legacy `/etc/openidx-agent` still read for one
  release). `install.sh` verifies sha256 against the downloads manifest and
  prefers deb/rpm/pkg. The manifest is signed when `AGENT_MANIFEST_SIGNING_KEY`
  is set. New unsigned universal macOS pkg with the LaunchDaemon.
- **Install/upgrade/uninstall smoke in CI (Faz B8.10).** `msi-smoke` on
  windows-latest, `nfpm-smoke` on debian:bookworm and rockylinux:9, and
  `check-agent-release.sh --manifest` for each published `latest.json`.
