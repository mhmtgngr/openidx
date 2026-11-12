# Agent updates

How OpenIDX desktop agents find, verify and install new builds, and how an
operator controls it. Windows endpoints get updates **only from the OpenIDX
box**: no endpoint needs to reach github.com.

## How an update reaches a device

1. CI (`windows-client-build.yml`) builds an `agent-v*` tag, signs the MSI
   (Authenticode) and writes a `latest.json` whose `version`, `url` and
   `sha256` are signed with the release publisher key
   (`WINDOWS_CERT_PFX_BASE64`). It publishes both on the GitHub release and on
   the channel release (`agent-latest` for stable, `agent-beta` for
   `agent-v*-beta.*`).
2. On the box, `scripts/agent-mirror.sh agent-vX.Y.Z` downloads that
   release's `latest.json` and MSI, verifies the signature against the pinned
   `release-publisher.cer` (and `release-publisher-next.cer` when set) and the
   MSI against the signed sha256, and installs them into
   `<AGENT_DOWNLOADS_DIR>/agent/<channel>/`.
3. The access service serves `GET /downloads/agent/<channel>/latest.json` with
   `url` rewritten to `https://<box>/downloads/agent/<channel>/<msi>` and
   **re-signed** with `AGENT_MANIFEST_SIGNING_KEY` (the same publisher key, so
   the agent's pin still verifies it). The MSI is served beside it.
4. `GET /agent/config` gives every device an `update` block. When the box
   mirrors the device's channel, `manifest_url` is the box URL; otherwise it
   falls back to `AGENT_UPDATE_MANIFEST_STABLE` / `_BETA`, then to the GitHub
   channel.
5. The agent service checks 5 to 15 minutes after start, then every 6h±30m,
   verifies the manifest signature against its pinned publisher, downloads the
   MSI, checks the sha256 and runs `msiexec`. It reports the outcome as
   `update_state`.

The box URL is derived from `PUBLIC_BASE_URL`, else the origin of
`OAUTH_ISSUER`. The mirror is only advertised when the box has both a public
URL and `AGENT_MANIFEST_SIGNING_KEY`, and the mirrored MSI is present.

## Channels

| Channel | Fed by | Box path |
|---|---|---|
| `stable` | `agent-vX.Y.Z` | `/downloads/agent/stable/latest.json` |
| `beta` | `agent-vX.Y.Z-beta.N` | `/downloads/agent/beta/latest.json` |

An organization picks its channel in **Agent Fleet > Updates**
(`update_channel`). Any other channel name is a 404.

## Rings: pause, pin, rollout

Set per organization in the Updates card or `PUT /api/v1/access/agent/settings`:

- `update_paused: true` holds the whole fleet. Devices keep their version.
- `update_rollout_percent: N` lets only devices with
  `fnv32a(agent_id) % 100 < N` move. A device's slot never changes, so raising
  N only adds devices. A staged rollout: 5, then 25, then 100.
- `update_pin_version: X.Y.Z` aims the fleet at one version, and allows a
  downgrade to it (`REINSTALLMODE=vomus`). Clear it to follow the channel again.

## Box mirror setup

One time:

1. Set `AGENT_MANIFEST_SIGNING_KEY` on the access service to the release
   publisher's private key (PEM, or a path to it; the key from
   `WINDOWS_CERT_PFX_BASE64`). Without it the mirror is not advertised and
   `latest.json` answers 503.
2. Make sure `PUBLIC_BASE_URL` (or `OAUTH_ISSUER`) is the public origin, e.g.
   `https://openidx.tdv.org`, and that the edge forwards `/downloads/` to the
   access service.
3. Set the repository variable `AGENT_CHANNEL_MANIFEST` to
   `https://openidx.tdv.org/downloads/agent/stable/latest.json`
   (Settings > Secrets and variables > Actions > Variables). Release builds then
   stamp that URL as `DefaultManifestURL` in the exe, the MSI and the install
   script, so even a device that has never fetched `/agent/config` updates from
   the box. Unset, builds stamp the GitHub channel.

Per agent release:

```bash
scripts/agent-mirror.sh agent-v1.2.3          # into stable
scripts/agent-mirror.sh agent-v1.3.0-beta.1   # into beta (from the tag)
# or as part of a box deploy:
AGENT_MIRROR_TAG=agent-v1.2.3 scripts/box-deploy.sh agent-mirror
```

`DEST` (default `AGENT_DOWNLOADS_DIR` from the env file, else
`deployments/downloads`) and `CHANNEL` override the defaults. The script keeps
the newest three MSIs per channel.

Check:

```bash
curl -s https://openidx.tdv.org/downloads/agent/stable/latest.json | jq .
```

`url` must name the box, and the agent's `/agent/config` `update.manifest_url`
must be the box URL.

## Rollback

- **Stop the bleeding:** set `update_paused: true`. Nothing more installs.
- **Go back:** pin the previous version (`update_pin_version`) and mirror that
  release again (`scripts/agent-mirror.sh agent-v<previous>`), so the box's
  `latest.json` names it. Devices downgrade on their next check. Unpause.
- **Fix forward:** release a new `agent-v*`, mirror it, clear the pin.

## Troubleshooting `update_state`

The Agent Fleet page shows each device's last `update_state`
(`ok`, `applying`, `held`, `failed`, with an error). The alert
`OpenIDXAgentUpdateFailing` fires on `openidx_agents_update_failing`.

| Symptom | Cause and fix |
|---|---|
| `failed`: "not signed by pinned release publisher" | The box key is not the publisher key, or the agent pins another cert. Check `AGENT_MANIFEST_SIGNING_KEY` matches `release-publisher.cer`. During a key switch see the code signing runbook. |
| `failed`: "carries no signature" | Something other than the access service answered the manifest URL (edge rewrite, stale static file). |
| `failed`: sha256 mismatch | The mirrored MSI was replaced by hand. Run `agent-mirror.sh` again. |
| `failed`: publisher certificate expired | The pinned certificate is past its validity. Rotate it (code signing runbook). |
| `held` | Paused, outside the rollout percentage, or pinned to the running version. Expected. |
| Stays on the old version, no state | The device does not reach the box, or its config has no update block. Run `openidx-agent update` (check only, no `--apply`) on it and read the log. |
| `latest.json` is 404 | The channel is not mirrored yet, or the MSI it names is missing. |
| `latest.json` is 503 | No signing key or no public URL on the access service. |
