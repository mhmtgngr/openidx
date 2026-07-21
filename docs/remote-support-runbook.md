# Remote Support — operator runbook (test on a real Windows device)

End-to-end procedure to verify OpenIDX remote support on a real Windows machine:
deploy the agent, start a session, confirm the on-device banner, see the screen,
and take control. Covers both unattended (servers) and attended (a person's PC,
with Allow/Deny consent).

> Architecture: the **device** captures its screen and creates a WebRTC offer;
> the **admin browser** answers; the server only relays signaling. Input and the
> "being controlled" banner ride the same peer connection. See
> `docs/OPENIDX_ZITI_ARCHITECTURE.md` and `internal/access/remote_support_api.go`.

## 0. Prerequisites

- An OpenIDX deployment reachable from the Windows device (e.g.
  `https://openidx.example.com`).
- The **screen-share** agent build. The CI job `Windows Client Build` produces
  `OpenIDX-<ver>.msi` with real capture (libvpx bundled). The default cross-build
  has **no video** — it negotiates + accepts control but streams nothing, so use
  the CI/`build-screenshare` MSI for a video test. (See
  `agent/packaging/wix/README.md`.)
- An admin/operator console login (role `operator`+ for Remote Support).

## 1. Deploy the agent to the Windows device

Silent install + enroll in one command (reusable bootstrap token; mint via
`POST /api/v1/access/agent/tokens {"reusable":true}`):

```powershell
msiexec /i OpenIDX-<ver>.msi /qn `
  SERVER_URL=https://openidx.example.com `
  ENROLL_TOKEN=<REUSABLE_TOKEN>
```

Verify:
- `services.msc` → **OpenIDX Agent** is Running.
- The **OpenIDX tray icon** appears for the logged-in user (it launches at login;
  to start it now: `"C:\Program Files\OpenIDX\openidx-agent.exe" tray`).
- Get the device's agent id (needed to target it):
  ```powershell
  Get-Content "$env:ProgramData\OpenIDX\agent\config.json" | ConvertFrom-Json | Select agent_id
  ```
  or list enrolled agents in the console (**IAM → Devices / Agent Fleet**) or DB:
  `SELECT agent_id, status, platform FROM enrolled_agents WHERE status='active';`

## 2. Start a session (admin console)

1. Console → **Remote Support** (under PAM/Ziti; `minRole: operator`).
2. **Start session** →
   - **Target agent ID:** the device's `agent-xxxxxxxx`.
   - **Mode:** `interactive` (view + control) or `view` (watch only).
   - **Require device consent:** check it for a person's machine (attended). Leave
     unchecked for an unattended server.
   - Optionally **Record session**.
3. **Start.**

## 3. What the user sees on the device

- **Tray banner (always, while the session is live):**
  *"🔴 An OpenIDX admin can see this device"* — and *"…can see and CONTROL this
  device"* the moment the admin takes control. It clears when the session ends.
- **If consent was required:** the session is **blocked** until the device grants
  it. The managed agent auto-grants by default (policy); to require a human click,
  install a `ConsentDecider` that shows a native Allow/Deny prompt (see
  `agent/internal/agent/agent.go` — `ConsentDecider`, and the mobile-guide hook
  note). Server-side, the admin WebSocket returns **403 "awaiting device consent"**
  until `consent_status=granted`.

## 4. What the admin sees (console)

- The viewer opens and shows the device screen within a few seconds (offer →
  answer → ICE → streaming).
- **Take control / Release control** button toggles input dispatch live; the
  device banner updates to match. In `view` mode, input is disabled.
- Move the mouse / type: on the screen-share build the device cursor moves and
  text is typed (Win32 SendInput). Global buttons: Back=Esc, Home=Win,
  Recents=Win+Tab.

## 5. End + audit

- **End session** (admin) or close the viewer. The banner clears on the device.
- Audit: `remote_support.session_started` / `consent_granted|denied` /
  `session_ended` land in `unified_audit_events` (Console → **Audit Logs**).
- If **Record** was on: the recording finalizes server-side; download it from the
  session row (subject to any legal hold).

## 6. Fast verification without a Windows box

Two automated proofs that don't need a device:

```bash
# Backend + gate + Quick Links + SSH relay (through the edge):
bash scripts/test-new-features.sh          # 10/10 PASS

# Device WebRTC pipeline against the live broker (offer→answer→connected):
#   (enroll a throwaway agent, start a session, then)
go run ./agent/cmd/e2e-screenshare -host 127.0.0.1:8007 \
  -agent <agent-id> -token <agent-token> -session <session-id>
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Viewer connects but **no video** | The deployed agent is the pure-Go build (no capture). Deploy the `screenshare` MSI. |
| Admin WS returns **403 "awaiting device consent"** | Consent required and not yet granted — the device must Allow (or the auto-grant policy hasn't run its next config poll, ~interval). |
| Session starts but device **never joins** (no `HandleAgentWS` in logs) | Old agent without the WebRTC peer (pre-`feat(agent): device-side WebRTC screen-share`). Update the agent. |
| Control does nothing | `view` mode, or control not taken (click **Take control**), or a non-Windows agent (input injector is Windows-only). |
| `unified_audit_events` FK error | Fixed in `fix(access): agent-lifecycle audit events dropped by users FK`; ensure the access-service is current. |

## Process model & operational invariants

The Windows client is **two cooperating processes**, deliberately split:

| Process | Runs in | Responsibilities |
|---|---|---|
| **Service** (`OpenIDXAgent`, `service run`) | Session 0 (no desktop) | Posture reporting, enrollment, self-update. `DisableRemoteSupport=true` — it never captures the screen (session 0 has no interactive desktop, so capture would be black and input would go nowhere). |
| **Tray** (`openidx-agent tray`) | The interactive user session | Owns remote support: screen capture + input + the "being controlled" banner. Auto-starts at login (HKMU Run key) and immediately post-install (MSI `LaunchTray`). Its remote-support agent loop auto-restarts on any failure. |

`openidx-agent run` (foreground) is a **dev/debug escape hatch** that does
everything in one process (posture + remote support). Not used in production.

Invariants a change must preserve:

- **One identity per device.** Enrollment sends a hashed `device_fingerprint`
  (Windows MachineGuid + hostname); `issueAgentCredentials` upserts by it, so a
  re-install reuses the same `agent_id`/`device_id` and only rotates the auth
  token. Never mint a new agent per process/install. (migration v92)
- **Poll cadences.** `/agent/config` returns `report_interval` = 5s while a
  remote-support session is attached, 30s baseline otherwise. The 30s baseline
  is what lets a *new* session connect without restarting the client.
- **Keyframes.** VP8 `KeyFrameInterval = 2*fps`; the device forces keyframes on
  peer-connect and on RTCP PLI, so a joining viewer paints within ~1s (no
  close/reopen). The viewer also auto-reconnects if no track arrives in 4s.
- **Teardown ordering.** The frame pump goroutine is joined (bounded 2s) BEFORE
  the libvpx encoder is closed — closing the encoder mid-read deadlocks the
  process ("client hangs on session end, must Ctrl+C").
- **Signaling / SDP.** The DEVICE creates both the video track and the
  `openidx-input` data channel BEFORE its offer (an SDP answer cannot add an
  m-line the offer omitted, or input silently never negotiates). The broker
  echoes the browser's `Sec-WebSocket-Protocol` (bearer subprotocol) or the
  admin WS is rejected. The broker replays only the agent's CURRENT offer to a
  late-joining admin — never a stale answer (old ICE ufrag → ICE never
  completes).
- **ICE.** Default is public STUN (same-LAN / VPN). Cross-internet needs a real
  TURN server (the minter is wired but unprovisioned here).

## Remote support over Ziti (device-leg zero-trust)

Signaling can ride the OpenZiti overlay instead of a public WSS, so the DEVICE
reaches the broker with no inbound port and enforced device-trust. Opt-in.

Enable (access-service env):

```
ZITI_ENABLED=true
ZITI_AGENT_OVERLAY_ENABLED=true    # issue Ziti identities to agents at enroll
REMOTE_SUPPORT_OVER_ZITI=true      # provision the openidx-access dial + advertise it
```

How it works:

- Reconciler ensures a Ziti service `openidx-access` (host.v1 → 127.0.0.1:8007)
  bound by the routers, with a Dial policy `openidx-access-dial-openidx-agent`
  granting the `#openidx-agent` role. (`internal/access/ziti_reconciler.go` →
  `reconcileRemoteSupportZiti`.)
- Enroll issues each device a Ziti identity tagged `openidx-agent`
  (`issueAgentCredentials`, gated by ZITI_AGENT_OVERLAY_ENABLED).
- `/agent/config`'s remote_support block carries `ziti_service: "openidx-access"`
  for agents that have a Ziti identity (`zitiServiceForAgent`).
- The device dials the signaling WebSocket over the overlay:
  `zitiCtx.Dial("openidx-access")` → net.Conn → gorilla websocket handshake
  (`agent/internal/agent/remote_support.go` → `dialSignaling`). Any Ziti failure
  or a device without an identity falls back to the public WSS — so same-LAN /
  edge deployments are unchanged.

Scope: this is the DEVICE leg only (Option B). The admin browser still reaches
the broker via the edge (a browser can't dial Ziti natively without BrowZer).
The WebRTC MEDIA remains peer-to-peer over STUN (same-LAN / VPN); routing media
over the overlay or a TURN server is a future step.

Verify: after enabling, a device that re-enrolls gets a `ziti_identity_id`, and
its agent log shows `remote-support: signaling over Ziti overlay` when a session
starts. `openidx-access` appears in `ziti edge list services` with the
`openidx-access-dial-openidx-agent` Dial policy.
