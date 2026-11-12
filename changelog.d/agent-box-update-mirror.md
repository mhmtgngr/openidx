### Added
- **Agent updates from the box.** `GET /downloads/agent/<stable|beta>/latest.json` and the MSI it names are served
  from `<AGENT_DOWNLOADS_DIR>/agent/<channel>/`, with `url` rewritten to the box and re-signed with
  `AGENT_MANIFEST_SIGNING_KEY` (the pinned release publisher). When the box mirrors a channel, `/agent/config` names
  the box URL (from `PUBLIC_BASE_URL`, else the `OAUTH_ISSUER` origin); GitHub stays only as a fallback.
  `scripts/agent-mirror.sh agent-vX.Y.Z` mirrors a release after checking its signature and sha256
  (`box-deploy.sh agent-mirror` with `AGENT_MIRROR_TAG`). Release builds stamp repo variable
  `AGENT_CHANNEL_MANIFEST` as `DefaultManifestURL` when set.
- **Second pinned publisher for a key switch.** The agent also trusts `release-publisher-next.cer` (embedded, empty
  means none), so the move to an OV/EV certificate needs an overlap release, not a flag day.
- Runbooks: `docs/runbooks/agent-updates.md`, `docs/runbooks/agent-code-signing.md`.
