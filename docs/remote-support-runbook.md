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
