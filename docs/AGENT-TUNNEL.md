# The agent's network tunnel (OpenZiti ziti-edge-tunnel)

The OpenIDX agent can give every application on a device the overlay services
that device may reach, the way a VPN client does, without a VPN. It does this by
running the official OpenZiti tunneler, `ziti-edge-tunnel`, with the device's
own overlay identity. This page says what is bundled, how to turn it on, and how
to find out why it is not working.

## What it does

Since v1.42.0 every enrolled agent has an OpenZiti identity of its own,
`dev-<agent_id>`, whose attributes the server keeps in step with the person's
groups and applications and with the device's own compliance (see
`internal/access/device_identity.go`). The agent stores that identity at
enrolment as `ziti-identity.json` in its config directory.

When the tunnel is on, the agent:

1. finds the tunneler binary: `tunnel.binary_path` if set (an absolute path),
   otherwise the one installed beside the agent or in
   `/usr/local/lib/openidx-agent/`. `PATH` is never searched: the agent runs as
   LocalSystem or root, and a PATH lookup with those privileges runs whatever an
   ordinary account managed to put in a PATH directory. Whichever file is found
   must pass a trust check, or it is not run (see "Who can choose the binary");
2. copies the device identity into `<config dir>/tunnel/identities/dev-<agent_id>.json`
   (owner-only permissions; any other `dev-*.json` there, left by an earlier
   enrolment, is removed);
3. runs `ziti-edge-tunnel run --identity-dir <that directory> -P openidx` and
   restarts it when it exits, waiting 2 s after the first exit and doubling the
   wait for each exit in a row, up to 2 minutes; a run that lasted 2 minutes
   resets the count;
4. every 15 seconds asks it how it is doing with
   `ziti-edge-tunnel tunnel_status -P openidx`, and, when that does not answer,
   dials `tunnel.probe_address` if one is configured;
5. reports the result to the server in every posture report and shows it in
   the tray.

`-P openidx` gives the tunneler's command socket a name of its own, so a second
tunneler on the machine (Ziti Desktop Edge, for example) is never mistaken for
the agent's, and the status command never stops to ask which one was meant.

When the tunnel is turned off, the agent stops the tunneler and deletes the
identity copy.

## What is bundled

| Package | Tunneler | Where it goes |
|---|---|---|
| Windows MSI | `ziti-edge-tunnel.exe` and `wintun.dll` (the Wintun driver it creates its adapter with) | `%ProgramFiles%\OpenIDX\`, beside `openidx-agent.exe` |
| deb / rpm (amd64, arm64) | `ziti-edge-tunnel` | `/usr/local/lib/openidx-agent/ziti-edge-tunnel`, plus the unit `/usr/lib/systemd/system/openidx-tunnel.service` (not enabled) |
| macOS | not bundled yet | the agent reports `not_installed` |

The version is pinned in `.github/workflows/windows-client-build.yml` (top-level
`env:`): `ziti-edge-tunnel` v1.18.7, the latest stable release of
`openziti/ziti-tunnel-sdk-c` when this was written, with the SHA-256 of each
release asset. The build downloads the assets, checks each against its pinned
SHA-256, and bundles them only when they match. A release build that cannot
verify them fails; any other build is packaged without the tunneler, with a
warning, as builds were before. The `bundle_tunneler` input of a dispatched
run turns bundling off. To move the pin, change the version and all three
hashes together; `gh release view <tag> -R openziti/ziti-tunnel-sdk-c --json assets`
lists the digests.

On Windows the MSI does not register the tunneler as a service. It runs as a
child of the OpenIDX Agent service, which runs as LocalSystem. A child in a job
object that kills it with its parent was the simplest arrangement that is also
robust: one code path starts, restarts and stops it; it lives exactly as long as
the agent; the agent service's own restart-on-failure covers both; and an agent
that crashes cannot leave a tunneler behind holding the adapter and the command
pipe for the next one to collide with.

## Turning it on

The tunnel is off by default. Either of these turns it on:

- **For an organization:** the server sends `org_network_policy.always_on: true`
  in the agent's config (`/agent/config`) or in the response to a posture report.
  The agent honours the field when the server sends it and ignores its absence,
  so an older server leaves the device's own setting in charge. `always_on: false`
  does not turn off a device whose own setting is on.
- **For a device:** in `agent.json` (`%ProgramData%\OpenIDX\agent\agent.json` on
  Windows, the agent's `--config-dir` elsewhere):

  ```json
  "tunnel": {
    "enabled": true
  }
  ```

  and restart the agent service.

Other settings in the same object:

| Setting | Meaning |
|---|---|
| `binary_path` | Run this tunneler instead of the bundled one. |
| `mode` | `child` (the agent runs the tunneler), `external` (systemd runs it; the agent only writes the identity and reads the status) or `auto` (the default: `child` when the agent runs as LocalSystem or root, `external` otherwise). |
| `probe_address` | A `host:port` reachable only through the tunnel. When the tunneler's command socket does not answer, a TCP connection to it counts as healthy. |

### Who can choose the binary

The agent runs the tunneler with LocalSystem or root privileges, so:

- **The `tunnel` object is obeyed only from a trusted `agent.json`.** The file
  must pass the check `plugin_dir` passes (`ConfigTrusted`: on Unix not writable
  by group or others; on Windows owned by, and writable only by, SYSTEM,
  Administrators or TrustedInstaller), and so must the directory that holds it.
  If either fails, the whole object, `enabled` included, is ignored, and the
  agent logs why.
- **The binary must be one only an administrator could have put there.** On
  Linux the file and every directory above it must be owned by root (or by the
  account the agent runs as) and not writable by group or others; symlinks are
  resolved first. On Windows it must be under Program Files, and the file, its
  folder and that folder's parent must pass the same owner and permission check
  as a plugin. A binary that fails is reported and not run; the agent does not
  try the next location instead.
- **The server cannot choose a binary or an argument.** `org_network_policy`
  turns the tunnel on or off and nothing else. The arguments
  (`run --identity-dir <dir> -P openidx`) and the identity directory are fixed.
- **The identity file name comes from the agent id**, which the server issued,
  so the id must match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`; the agent refuses to
  write the identity otherwise, and it refuses an identity directory that is a
  symlink.

### Linux

The agent needs root (CAP_NET_ADMIN) to open a TUN device. When it runs as root
it runs the tunneler itself, as on Windows. `deploy/openidx-agent.service`
runs the agent as the unprivileged `openidx-agent` user, so there the agent
runs in `external` mode and the tunneler runs from the packaged unit:

```sh
sudo systemctl enable --now openidx-tunnel.service
```

The unit loads identities from `/var/lib/openidx-agent/tunnel/identities`, the
directory an agent with `--config-dir /var/lib/openidx-agent` writes to. If the
agent uses another config directory, edit both. The unit does not start while
that directory is empty.

In `external` mode the agent reads the tunneler's status through its command
socket under `/tmp/.ziti`, which the tunneler creates as root, owned by group `ziti` when that group exists.
An agent with `PrivateTmp=true` (as in `deploy/openidx-agent.service`) cannot
see that directory, and one outside the `ziti` group cannot open the socket.
Either run the agent with `PrivateTmp=false` and in the `ziti` group, or set
`tunnel.probe_address`; otherwise the agent reports `degraded` even when the
tunnel works.

## What the server and the tray see

Each posture report carries:

```json
"tunnel_status": {
  "state": "connected",
  "version": "v1.18.7",
  "last_seen": "2026-10-10T12:00:00Z",
  "services": ["erp-web", "rdp-finance"]
}
```

| `state` | Meaning |
|---|---|
| `connected` | The tunneler runs and the device identity is active on the overlay (or the probe connected). |
| `degraded` | The tunnel should be on and is not fully working: starting, restarting after an exit, the identity not loaded or waiting for authentication, the command socket not answering, or no device identity to give it. |
| `off` | The tunnel is not enabled for this device. |
| `not_installed` | The tunnel is enabled and no tunneler binary was found. |

`last_seen` is when the tunneler last answered (`null` if it never has).
`services` are the services the identity may dial, sorted. An agent that
supervises no tunnel (one older than this feature) sends no `tunnel_status`.

On Windows the tray shows **Network: Connected · N services**, **Degraded**,
**Off** or **Not installed**. Its submenu lists the intercepted services, and,
when the tunnel is not connected, the reason first.

## Troubleshooting

- **Logs.** The agent logs every state change with its reason (logger
  `tunnel`). In `child` mode the tunneler's own output goes to
  `<config dir>/tunnel/ziti-edge-tunnel.log`, moved to `.log.1` at 10 MB. In
  `external` mode: `journalctl -u openidx-tunnel`.
- **Ask the tunneler directly.** As an administrator / root:
  `ziti-edge-tunnel tunnel_status -P openidx` prints the same answer the agent
  reads.
- **`not_installed`.** The package was built without the tunneler, the binary
  was removed, or `tunnel.binary_path` names a file that is not there or not
  executable. The agent does not fall back from a `binary_path` that is wrong.
- **"the tunneler binary is not safe to run".** The file or a directory above it
  can be written by an account other than root/Administrators; the message
  names which. Fix the permissions (`chmod go-w`, or `icacls`).
- **`degraded`, "this device has no enrolled Ziti identity".** The device
  enrolled without an overlay identity (the server issued no Ziti enrolment, or
  enrolling it failed). Enrol the device again.
- **`degraded`, "identity … is waiting for authentication".** The identity
  needs MFA or an external sign-in on the overlay; the tunneler cannot complete
  it unattended.
- **`degraded`, "the tunneler exited …; waiting to restart it".** It is
  crash-looping; its log says why. A common cause on Windows is another
  program holding a Wintun adapter of the same name; on Linux, no root.
- **Two tunnelers.** The agent's runs with `-P openidx`; anything else on the
  machine uses its own socket and is left alone. Both may intercept the same
  addresses if they are given overlapping identities.

## Not yet verified

These parts were built from the tunneler's source and its documentation and
tested with a stand-in binary, not against a live controller:

- the exact `tunnel_status` JSON a running v1.18.7 tunneler returns (read from
  `programs/ziti-edge-tunnel/include/model/dtos.h` at that tag);
- the MSI with the tunneler on a Windows machine (the CI build checks that the
  files are in the MSI and that `ziti-edge-tunnel.exe version` runs from it, not
  that it opens an adapter);
- whether the Wintun adapter and DNS (NRPT) rules are cleaned up when the agent
  stops the tunneler on Windows, where it can only be killed, not asked to stop.
