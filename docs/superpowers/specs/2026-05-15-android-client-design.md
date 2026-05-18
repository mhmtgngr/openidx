# Android Unified Agent — Design

**Status:** Phase 1 in implementation. Phases 3 (kiosk) and 4 (remote control) sketched.
**Date:** 2026-05-15
**Related:**
- [2026-03-29 Endpoint Agent (Go) design](2026-03-29-endpoint-agent-design.md)
- [2026-03-29 Agent server completion design](2026-03-29-agent-server-completion-design.md)

## Why this exists

OpenIDX shipped a Go endpoint agent for Linux / macOS / Windows in March 2026 (enrollment, posture, Ziti zero-trust transport, lifecycle management, audit). Android cannot reuse that binary — Android MDM requires native APIs (`DevicePolicyManager`, Android Enterprise provisioning, `MediaProjection` for screen capture, etc.).

The user wants a **single Android APK** that bundles what is normally three separate products: an MDM/UEM, a kiosk solution, and a remote-support tool — all governed by OpenIDX as the identity / posture authority and connected over Ziti. This document covers Phase 1 (foundation + enrollment) in detail and the later phases as roadmap.

## Scope (Phase 1)

A single APK (`com.openidx.agent`) that:

- Enrolls via **two** paths sharing the same `enrolled_agents` table:
  1. Android Enterprise QR provisioning — factory-reset device, scan QR, app installs as Device Owner.
  2. Email/OAuth (OIDC PKCE) — user installs the APK and signs in; the device is enrolled to that user.
- Reports **Android-native posture** (10 built-in checks) to `/agent/report` using the existing protocol.
- Establishes a Ziti tunnel after enrollment; all post-enrollment traffic flows through Ziti.
- Survives reboot via a foreground service + WorkManager periodic work.
- Registers a `DeviceAdminReceiver` so Phase 3 (kiosk) and Phase 4 (remote control) drop in without manifest churn.

Out of scope for Phase 1: kiosk lockdown, remote control, app catalog, BYOD work-profile mode.

## Architecture

```
┌────────────────────────── Android client (APK) ──────────────────────────┐
│                                                                          │
│  app/      EnrollmentActivity ──▶  OAuthEnrollmentFlow ─┐                │
│            OpenIDXDeviceAdminReceiver ─▶ QrEnrollmentBootstrapper ─┐     │
│            OpenIDXAgentService (foreground, owns Ziti tunnel)       │    │
│            PostureWorker (WorkManager periodic)                     │    │
│                                                                     ▼    │
│  core/     ServerApi  ◀──────── ZitiClient (SocketFactory)               │
│            IdentityStore (EncryptedSharedPreferences)                    │
│            PostureScheduler                                              │
│                                                                          │
│  posture-android/  10 PostureCheck implementations                       │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │  Ziti tunnel (post-enrollment)
                                   ▼
            ┌────────────── OpenIDX access service ──────────────┐
            │ POST /agent/enroll               (token, public)   │
            │ POST /agent/enroll/oauth         (JWT,   admin)    │
            │ POST /agent/report               (X-Agent-ID, pub) │
            │ GET  /agent/config               (X-Agent-ID, pub) │
            │ POST /api/v1/access/agent/qr     (JWT, admin)      │
            │ GET  /api/v1/access/agent/apk-info (JWT, admin)    │
            │ GET  /downloads/openidx-agent.apk (public)         │
            └────────────────────────────────────────────────────┘
```

### Modules

| Module | Purpose |
|---|---|
| `app/` | UI (Compose), `DeviceAdminReceiver`, `BootReceiver`, foreground service, `PostureWorker` |
| `core/` | `IdentityStore`, `ServerApi`, `ZitiClient`, `PostureScheduler`, `PostureCheck` interface |
| `posture-android/` | 10 concrete `PostureCheck` implementations + `PostureRunner` |

Each module is independently buildable; `app` depends on `core` + `posture-android`, `posture-android` depends on `core` only. This keeps server-protocol code (`core`) test-isolated from Android UI concerns.

## Enrollment flows

### QR / Device Owner

1. Admin clicks "Generate Android enrollment QR" in the OpenIDX admin console.
2. Server: `POST /api/v1/access/agent/qr` mints a fresh one-shot enrollment token, computes the APK's SHA-256 (URL-safe base64, no padding — the format Android Enterprise expects), and returns the provisioning JSON payload.
3. Admin console renders the JSON as a QR (client-side React).
4. User factory-resets the device, taps the setup-wizard welcome screen 6×, scans the QR.
5. Android downloads the APK from `/downloads/openidx-agent.apk`, verifies the checksum, installs the app as **Device Owner**.
6. `OpenIDXDeviceAdminReceiver.onProfileProvisioningComplete` fires with the extras bundle containing the server URL and enrollment token. `QrEnrollmentBootstrapper.kickOff` posts to `/agent/enroll`, persists the returned identity, bootstraps Ziti from the returned JWT, and starts `OpenIDXAgentService`.

### Email / OAuth

1. User installs the APK normally (Play Store / sideload / managed Play).
2. Opens the app → enters OpenIDX server URL → taps "Sign in with OpenIDX".
3. AppAuth-Android opens a Chrome Custom Tab to `<server>/oauth/authorize` with PKCE.
4. After consent, the redirect (`com.openidx.agent://oauth/redirect`) carries the auth code back.
5. App exchanges the code for an access token, POSTs to `/agent/enroll/oauth` with `Authorization: Bearer <access_token>`.
6. Server resolves the user from the JWT (`middleware.Auth` already sets `user_id`), creates an `enrolled_agents` row with `enrolled_by_user_id`, returns the same response shape as token-based enrollment.

Both paths converge on `IdentityStore.save(AgentIdentity)`, which is the only place identity material is persisted.

## Posture checks

| `check_type` | Implementation | Default severity |
|---|---|---|
| `os_version` | `Build.VERSION.SDK_INT` vs server minimum | medium |
| `disk_encryption` | `DevicePolicyManager.storageEncryptionStatus` | high |
| `screen_lock` | `KeyguardManager.isKeyguardSecure` + password quality | high |
| `patch_level` | `Build.VERSION.SECURITY_PATCH` age vs 90d default | high |
| `play_integrity` | Play Integrity API (token forwarded raw for server-side verification) | critical |
| `enterprise_managed` | `isDeviceOwnerApp` / `isProfileOwnerApp` | medium |
| `developer_options` | `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` + `ADB_ENABLED` | medium |
| `unknown_sources` | Audit packages with `REQUEST_INSTALL_PACKAGES` | high |
| `accessibility_audit` | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` vs allow-list | medium |
| `agent_version` | `BuildConfig.VERSION_NAME` / `VERSION_CODE` (always pass; server decides) | low |

`PostureRunner.runAll(configs)` resolves the list received from `/agent/config` against the built-in map and returns wire-shaped `PostureCheckResult` records ready for `/agent/report`. Unknown check types are silently dropped — the server may include checks that don't have an Android implementation yet, and that's not fatal.

## Server-side changes

### Migrations
- `202605150001_agent_platform.up.sql` — adds `platform`, `form_factor`, `is_device_owner`, `enrollment_method`, `enrolled_by_user_id` to `enrolled_agents`. Backfills `platform` from `metadata`.
- `202605150002_posture_checks_platforms.up.sql` — adds `platforms` JSONB array to `posture_checks`, tags existing seeds, inserts six Android-specific check rows.

### `internal/access/agent_api.go`
- Extracted `issueAgentCredentials` — the credential-minting half of enrollment shared by all paths.
- Refactored `HandleEnroll` to call the helper.
- New `HandleEnrollOAuth` — reads `user_id` from the gin context (set by `middleware.Auth`), enrolls with `enrollment_method='oauth'`.
- New `HandleGenerateQR` — mints a one-shot token, computes APK checksum, assembles the Android Enterprise provisioning payload.
- New `HandleAPKInfo`, `HandleAPKDownload`.
- Split route registration into `RegisterAgentPublicRoutes` (enroll/report/config — public) and `RegisterAgentAdminRoutes` (tokens, agent list/approve/revoke, OAuth enrollment, QR generator — auth-protected).
- `HandleConfig` now reads the agent's `platform` and filters `posture_checks` via `platforms ? $1`.

### `internal/access/service.go`
- Public agent surface mounted on a no-auth subgroup so agents can reach `/agent/enroll` without a JWT (this also fixes a pre-existing inconsistency where the public enrollment endpoint sat behind JWT auth).
- Admin agent surface mounted on the auth-protected `api`.
- `/downloads/openidx-agent.apk` mounted at the router level (no auth) for Android Enterprise provisioning.

## Verification

1. `go build ./...` — clean (verified during implementation).
2. `go test ./internal/access -run TestRegisterAgentRoutes` — passes (verified).
3. `cd agent-android && ./gradlew :app:assembleDebug` — needs Android SDK; will be exercised in CI follow-up.
4. End-to-end checklist in `/home/cmit/.claude/plans/iterative-whistling-shell.md` § Verification.

## Phase 3: kiosk mode (implemented)

### Data model

- `kiosk_policies` — `mode` ∈ {`single_app`, `multi_app`, `off`}, `allowed_packages` (JSONB array), `primary_activity` (component name), `lock_task_features` (JSONB array of feature names — translated to `LOCK_TASK_FEATURE_*` int constants on the client), `branding` (JSONB passthrough), `exit_pin_hash` (optional SHA-256 of the on-site exit PIN), `enabled`.
- `kiosk_policy_assignments` — maps a policy to a target. `target_kind` ∈ {`agent`, `group`, `tag`}, `target_id` is the kind-specific identifier, `priority` defaults to 300/200/100 respectively. Higher priority wins.

Policy resolution (`resolveEffectiveKioskPolicy` in `internal/access/kiosk_api.go`) walks direct agent assignments and tag-based assignments (against `enrolled_agents.metadata->'tags'`) in one query and returns the highest-priority enabled policy. Group support is reserved for future identity-service integration.

### Server endpoints (admin)

All mounted on the auth-protected `api` group:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/access/kiosk/policies` | List all policies |
| `POST` | `/api/v1/access/kiosk/policies` | Create policy |
| `GET` | `/api/v1/access/kiosk/policies/:id` | Get one |
| `PUT` | `/api/v1/access/kiosk/policies/:id` | Update (fields are COALESCEd — omitted fields preserved) |
| `DELETE` | `/api/v1/access/kiosk/policies/:id` | Delete (cascades to assignments) |
| `GET` | `/api/v1/access/kiosk/policies/:id/assignments` | List assignments for a policy |
| `POST` | `/api/v1/access/kiosk/policies/:id/assignments` | Assign to agent/group/tag |
| `DELETE` | `/api/v1/access/kiosk/assignments/:assignment_id` | Remove an assignment |

### `/agent/config` integration

`agentConfigResponse` gains an optional `kiosk_policy` field that's populated from `resolveEffectiveKioskPolicy` for active agents. Legacy Go agents that don't know about the field simply ignore it (JSON omit-empty semantics).

### Android client

| Component | File | Role |
|---|---|---|
| `KioskPolicy` | `core/ServerApi.kt` | Wire model (kotlinx.serialization with `ignoreUnknownKeys`) |
| `KioskController` | `core/KioskController.kt` | Applies policy via `DevicePolicyManager.setLockTaskPackages` / `setLockTaskFeatures`; no-op when not Device Owner |
| `KioskState` | `core/KioskState.kt` | Caches the most-recently-applied policy in `EncryptedSharedPreferences`. Reapplied on service start; used to detect transitions for audit |
| `KioskLauncherActivity` | `app/ui/KioskLauncherActivity.kt` | Multi-app launcher; registered as `category.HOME` so DPM can promote it to the system launcher |
| `OpenIDXAgentService` | `app/service/OpenIDXAgentService.kt` | Applies cached policy on start; reapplies after every `/agent/config` cycle |

### Behaviour matrix

| Server says `mode=` | KioskController action | UX |
|---|---|---|
| `off` or `enabled=false` | Clear lock-task whitelist, stop lock-task if active | Device behaves normally |
| `single_app` | Whitelist `primary_activity`'s package + agent; launch the activity | One app pinned full-screen |
| `multi_app` | Whitelist `allowed_packages` + agent; let HOME route to `KioskLauncherActivity` | Curated grid of allowed apps |

### Edge cases handled

- **Not Device Owner** — `KioskController.apply` early-returns and logs. Posture report's `enterprise_managed` check already surfaces this to admins.
- **Network loss** — `KioskState` survives offline cycles; service replays cached policy on every start. Devices stay in kiosk even when /agent/config is unreachable.
- **Policy churn** — `setLockTaskPackages` is set-replace, so reapplying the same policy is a no-op. `KioskState.differsFromCached` is used to suppress redundant audit events.

### Audit events

Emitted via the agent handler's existing pipeline:

- `kiosk.policy_created`
- `kiosk.policy_changed`
- `kiosk.policy_deleted`
- `kiosk.policy_assigned`
- `kiosk.policy_unassigned`

Client-side `kiosk.entered` / `kiosk.exited` transitions are surfaced through the next posture report's details (no separate endpoint) — keeps the wire surface flat for Phase 3.

### Out of scope (deferred)

- Admin-console UI for the kiosk policy editor (server endpoints are ready; React side lands in a follow-up).
- Exit-PIN UX on the device — server stores the hash, client lookup wiring is in `KioskPolicy.has_exit_pin` but the modal lives in a Phase-3.1 task.
- Group-based assignment (depends on identity-service group exposure).
- Managed Google Play catalog binding so `allowed_packages` can be picked from a real list.

## Phase 4: remote control (implemented)

### Data model

- `remote_support_sessions` — one row per attempt to remote-control an agent.
  Columns: `id`, `agent_id`, `admin_user_id`, `status` (`pending` / `active` /
  `ended` / `expired` / `declined`), `mode` (`interactive` / `view`),
  `ice_servers` JSONB, `end_reason`, `recording_url` (reserved), `started_at`,
  `accepted_at`, `ended_at`, `notes`, `last_activity_at`.

### Signaling broker

`internal/access/remote_support_api.go` runs an in-memory broker that relays
WebRTC offer / answer / ICE candidates between exactly two peers per session
(admin browser + agent). Sessions persist in Postgres so reconnects work, but
signaling messages themselves are ephemeral — when both peers drop the broker
slot is freed.

A background janitor (`StartJanitor`, every minute) ages out pending / active
sessions whose `last_activity_at` is older than 5 minutes, flipping their
status to `expired`.

### Endpoints

| Method | Path | Surface | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/access/remote-support/sessions` | admin | Start session (returns `id`, `admin_ws`, `agent_ws`, `ice_servers`) |
| `GET` | `/api/v1/access/remote-support/sessions` | admin | List recent sessions |
| `GET` | `/api/v1/access/remote-support/sessions/:id` | admin | Get one session |
| `POST` | `/api/v1/access/remote-support/sessions/:id/end` | admin | Explicit end with reason |
| `GET` | `/api/v1/access/remote-support/sessions/:id/ws` | admin | Signaling WebSocket (browser viewer) |
| `GET` | `/api/v1/access/agent/remote-support/sessions/:id/ws` | public (agent-auth) | Signaling WebSocket (device side) |

The agent-side WebSocket authenticates with `X-Agent-ID` + `X-Auth-Token`
(same pattern as `/agent/report`), verified against
`enrolled_agents.auth_token_hash`.

### `/agent/config` integration

`agentConfigResponse.remote_support` is populated by
`findActiveSessionForAgent` whenever a pending / active session targets the
agent. The agent's heartbeat picks this up within 60 seconds and launches the
consent prompt.

### Android client

| Component | File | Role |
|---|---|---|
| `SignalingClient` | `core/SignalingClient.kt` | OkHttp WebSocket, exposes incoming as a SharedFlow |
| `RemoteSupportEngine` | `app/remote/RemoteSupportEngine.kt` | PeerConnection lifecycle, screen capture, data channel |
| `OpenIDXAccessibilityService` | `app/remote/OpenIDXAccessibilityService.kt` | `dispatchGesture` + `performGlobalAction` injector |
| `InputInjector` | `app/remote/InputInjector.kt` | Routes data-channel events; prefers Device Owner, falls back to Accessibility |
| `RemoteSupportService` | `app/remote/RemoteSupportService.kt` | Foreground service hosting the engine; non-suppressible banner |
| `RemoteSupportTriggerActivity` | `app/remote/RemoteSupportTriggerActivity.kt` | Transparent activity prompting for `MediaProjection` consent |
| Heartbeat hook | `app/service/OpenIDXAgentService.kt` | Reads `remote_support` from `/agent/config`, fires the trigger once per session |

Screen capture uses `ScreenCapturerAndroid` from the `io.getstream:stream-webrtc-android`
artifact, fed at 1280×720@15fps; bitrate and resolution adapt via WebRTC
congestion control, so admins on a slow link still get a usable stream.

### Signaling protocol

All messages share a `{type, payload}` envelope:

| `type` | `payload` shape | Direction |
|---|---|---|
| `control` | `{action, reason}` (`accept` / `decline` / `end` / `ping`) | both |
| `sdp` | `{sdp, type}` (`offer` / `answer`) | both |
| `ice` | `{candidate, sdp_mid, sdp_m_line_index}` | both |
| input | `{event, x, y, x_end, y_end, duration_ms, key_code, text, action}` | admin → agent only |

Input events ride a WebRTC data channel inside the same PeerConnection rather
than going over signaling — keeps the broker stateless and gives end-to-end
encryption for free.

### Input injection paths

| Device state | Path | Notes |
|---|---|---|
| Device Owner (QR provisioning) | Accessibility Service (system-pre-granted on DO devices) | No user toggle needed; we still use the AS API so the same code path serves both |
| BYOD / sideloaded | Accessibility Service (user-toggled) | Requires the user to enable the service in Settings. `accessibility_audit` posture check surfaces non-OpenIDX accessibility services to admins |
| Text + named keys (Backspace / Enter / Tab) | Accessibility Service via `ACTION_SET_TEXT` + `ACTION_IME_ENTER` | Writes into the currently input-focused editable node. See "Text + named-key injection" below |
| Arbitrary KeyCode injection | Not implemented | Would require a custom `InputMethodService`. Deferred — see "Future work" below |

### Text + named-key injection (wired)

The admin viewer carries a text input below the video; whatever the admin
types and submits with Enter (or "Send text" button) is sent over the
`openidx-input` data channel as a single `{event: "text", text: "…"}`
frame. The Android `OpenIDXAccessibilityService` walks the active-window
node tree, finds the input-focused editable node, and calls
`AccessibilityNodeInfo.performAction(ACTION_SET_TEXT, …)` to append (or
replace, via `replace: true`) the supplied string.

The same overlay forwards three named keys without consuming individual
character presses:

| Browser key | Wire event | Android impl |
|---|---|---|
| Backspace | `{event: "key", key_name: "backspace"}` | re-set existing text minus last char |
| Enter | `{event: "key", key_name: "enter"}` | `performAction(ACTION_IME_ENTER)`; falls back to appending `\n` |
| Tab | `{event: "key", key_name: "tab"}` | `ACTION_ACCESSIBILITY_FOCUS` + `ACTION_FOCUS` (moves accessibility focus) |

Caveats:
- `ACTION_SET_TEXT` bypasses the device IME's composition pipeline, so
  autocomplete / suggestions don't fire. For a "help the user fill out a
  form" use case this is the right behavior — predictable, atomic.
- WebViews and some custom views silently no-op on `ACTION_SET_TEXT`
  even with a visible caret. The injector returns `false` from
  `injectText` and the admin sees a "no focused editable" log; reflecting
  that to the viewer UI is on the deferred list.
- The accessibility config now declares `canRetrieveWindowContent="true"`
  (previously `"false"`); without it, `findFocus(FOCUS_INPUT)` returns
  null and ACTION_SET_TEXT has no target.

### Future work

- **Custom InputMethodService** for arbitrary KeyCode injection. Would
  give the admin a full hardware-keyboard equivalent (modifier keys,
  arrow keys, function keys). Requires the user (or DPM, on Device
  Owner devices) to pick it as the default keyboard, which is a
  significant UX shift — defer until a concrete use case demands it.
- Reflect `injectText` failures back to the admin viewer so the operator
  knows when the field they expected isn't actually focused.

### Consent and audit

- The Phase-4 foreground service banner ("Remote support session active — An
  OpenIDX admin can see and control this device") is at `IMPORTANCE_HIGH`
  with an action button to end the session locally.
- Audit events: `remote_support.session_started`, `..._active` (both peers
  connected), `..._ended`, `..._expired`. Each logs the session ID + admin
  user + reason.

### Distribution caveat

The agent registers an Accessibility Service. Google Play restricts apps that
do so. Distribution remains via `/downloads/openidx-agent.apk` (sideload) or
managed Google Play for Device-Owner devices — already the chosen channel.

### TURN credential minting (wired)

OpenIDX now mints short-lived TURN credentials per session, so admins
don't have to manage long-lived shared secrets or paste ICE-server
config into every start-session request.

**Pattern**: coturn's `use-auth-secret` mode (also
`draft-uberti-rtcweb-turn-rest-00`). OpenIDX and the TURN server share a
static secret. For each session:

```
username   = "<expiry_unix_ts>:<session_id>"
credential = base64(HMAC-SHA1(static_secret, username))
```

The TURN server validates by computing the same HMAC; expired usernames
are rejected by comparing the embedded timestamp against `now`. No
shared state, no credential rotation infrastructure — every credential
is intrinsically short-lived (default TTL 2 h, configurable).

**Code**:
- `internal/access/turn_credentials.go` — `TurnConfig`, `TurnMinter`,
  `Mint` / `MintAsRawJSON` (returns the ICE-servers JSON shape both
  the browser viewer and Android client already consume).
- `internal/access/remote_support_api.go` — `HandleStartSession`
  resolves `ice_servers` in priority order:
    1. Admin-supplied JSON (verbatim, back-compat).
    2. Minted per-session TURN credentials when the minter is configured.
    3. Empty array (LAN / Ziti-overlay-only mode).
  Audits `turn=minted` in the `remote_support.session_started` event
  when minting fires.
- `internal/access/service.go` — constructs the minter from config at
  startup. Soft-disabled when uris/secret are unset; logs at INFO when
  enabled.

**Configuration**:

| Setting | Env var | Notes |
|---|---|---|
| `turn_uris` | `TURN_URIS` | Comma-separated `turn:` / `turns:` URIs |
| `turn_static_secret` | `TURN_STATIC_SECRET` | Must match TURN server's `static-auth-secret` |
| `turn_realm` | `TURN_REALM` | Optional |
| `turn_credential_ttl_seconds` | `TURN_CREDENTIAL_TTL_SECONDS` | Default 7200 (2 h) |

**Threat model**:

| Threat | Mitigation |
|---|---|
| TURN credentials reused across sessions / leaked | Each session gets a unique HMAC; credentials expire on schedule |
| Long-lived shared password copy-pasted into admin requests | Removed — minter is the default path, admin override is back-compat only |
| Static-secret leak letting an attacker mint creds | Same impact as before this change; rotation is the same operational gesture (update both sides). Future work: per-tenant secrets in DB |
| Admin starts session with malicious ICE servers | Admin path is still an authenticated endpoint behind JWT; minting doesn't widen the attack surface, just removes the operational toil |

**Deferred**:
- Per-tenant TURN config in DB (currently global at the access-service
  instance level). Multi-tenant deployments share one TURN server today.
- STUN-only fallback when TURN isn't configured.

### Session recording (wired)

The admin browser uses `MediaRecorder` to capture the inbound WebRTC
video stream and streams chunks to OpenIDX every 5 seconds. Each chunk
is appended byte-for-byte to a per-session WebM file; MediaRecorder's
timeslice output is a standalone WebM segment, so simple concatenation
yields a playable file with no remuxing.

**Data model** (migration `202605180001_remote_support_recording`):
- `recording_enabled` — admin opt-in flag captured at session start
- `recording_storage_key` — filesystem path (or future object-store key)
- `recording_size_bytes` — running tally, updated on each chunk
- `recording_chunk_count` — monotonically increasing chunk index
- `recording_finalized_at` — set when the recorder stops

`recording_url` (already existing) is set on finalize to the public
download path.

**Endpoints**:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/access/remote-support/sessions/:id/recording/chunk` | Append one MediaRecorder chunk. `X-Chunk-Index` header carries ordering metadata. 50 MiB body cap per chunk. |
| `POST` | `/api/v1/access/remote-support/sessions/:id/recording/finalize` | Stamp `recording_finalized_at` and set `recording_url`. |
| `GET` | `/api/v1/access/remote-support/sessions/:id/recording` | Stream the assembled WebM back to the admin. |

**Code paths**:
- `internal/access/remote_support_recording.go` — `recordingStore`
  interface + filesystem implementation, chunk / finalize / download
  handlers.
- `internal/access/remote_support_api.go` —
  `RemoteSupportHandler.recordingStore` field, registered routes,
  `record` flag plumbed through `HandleStartSession`. Audits
  `recording=on` on the session-started event and
  `remote_support.recording_finalized` on stop.
- `internal/access/service.go` — constructs the filesystem store from
  `RecordingsStoragePath` config; soft-disabled when unset.
- `web/admin-console/src/components/remote-support/remote-support-viewer.tsx`
  — `MediaRecorder` attached to the inbound stream when
  `recordingEnabled` is true; `ondataavailable` POSTs each blob;
  `onstop` calls finalize. Red "recording" badge in the viewer header.
- `web/admin-console/src/pages/remote-support.tsx` — "Record session"
  checkbox in start-session, "Download recording" button on rows with
  a `recording_url`. Click → fetches the blob with bearer auth and
  triggers a browser download.

**Configuration**:

| Setting | Env var | Notes |
|---|---|---|
| `recordings_storage_path` | `RECORDINGS_STORAGE_PATH` | Local directory root. Per-session subdir + `recording.webm`. |
| `recordings_s3_endpoint` | `RECORDINGS_S3_ENDPOINT` | S3 host (e.g. `s3.amazonaws.com`, `play.min.io`, custom MinIO host:port). When set with bucket, S3 backend wins over filesystem. |
| `recordings_s3_bucket` | `RECORDINGS_S3_BUCKET` | Bucket name. Must exist; we don't create it. |
| `recordings_s3_region` | `RECORDINGS_S3_REGION` | Region for AWS S3 / required for some compatible providers. |
| `recordings_s3_prefix` | `RECORDINGS_S3_PREFIX` | Optional key prefix inside the bucket (e.g. `openidx/recordings`). |
| `recordings_s3_access_key` | `RECORDINGS_S3_ACCESS_KEY` | Static IAM credential. |
| `recordings_s3_secret_key` | `RECORDINGS_S3_SECRET_KEY` | Static IAM credential. |
| `recordings_s3_use_ssl` | `RECORDINGS_S3_USE_SSL` | Default true; set false for local MinIO over plain HTTP. |

**Storage backend abstraction**: handlers talk through a
`recordingStore` interface (`Append` / `Open` / `Key`). Two
implementations ship:

- **Filesystem** — single per-session `recording.webm` file with
  append-mode writes. Best for single-instance deployments and dev.
- **S3 / S3-compatible** (Phase 4 follow-up) — each chunk is its own
  S3 object under `<prefix>/<session>/<NNNNNN>.webm`. `Open` lists
  the chunks, sorts by their zero-padded numeric prefix, and returns
  a sequential reader that concatenates them. Targets: AWS S3,
  MinIO, Cloudflare R2, Wasabi, Backblaze B2, GCS-via-interop (any
  S3 v4-compatible endpoint). Built on `github.com/minio/minio-go/v7`
  for a small dep footprint.

`service.go` picks S3 when configured, falls back to filesystem, and
disables recording when neither is set. Per-chunk-object layout was
chosen over multipart upload because the chunks WebRTC produces (~300
KB – 1.25 MB at typical screen-recording bitrates) are below S3's 5
MB minimum part size; buffering to hit that minimum would add
server-side memory pressure with no downstream benefit.

**Codec**: viewer probes `video/webm;codecs=vp8`, `vp9`, plain `webm`,
then `video/mp4`. Safari (no MediaRecorder VP8 support) falls back to
mp4; everything else lands on VP8 by default.

**Threat model**:

| Threat | Mitigation |
|---|---|
| Recording leaks PII (user's screen) | Recording is opt-in per session; admin must explicitly check the box. Audit records `recording=on`. Future: per-tenant policy that requires recording for compliance flows. |
| Storage tampering | Filesystem chunks are append-only by API contract but not append-only at the OS level. Object-storage backend with versioning + immutability is the production path. |
| Admin downloads someone else's recording | Endpoint is behind `middleware.Auth`. Downstream: tenant-scoped check once tenant boundaries are enforced on this surface. |
| Disk fill / DoS | 50 MiB cap per chunk request, surfaced as `http.MaxBytesReader`. No global cap yet — flagged as deferred work. |

**Retention policy + auto-purge (wired)**: recordings have a four-layer
retention resolution chain and a background sweeper that purges expired
blobs.

Resolution priority (`resolveEffectiveRetention` in
`remote_support_retention.go`):

1. `recording_retention_days` on the session row — admin can override
   per-session at start (`record: true` + `recording_retention_days: 30`).
2. `retention_days` on `recording_retention_policies` for the session's
   org — per-tenant policy.
3. `RecordingsDefaultRetentionDays` config — global default.
4. Hard fallback (90 days) — last-ditch so a misconfigured deployment
   doesn't accumulate blobs forever.

A retention value of `0` anywhere means "infinite" — useful for
compliance regimes that need indefinite hold under a separate legal-hold
process. The sweeper skips those rows.

**Sweeper** (`StartRecordingRetentionEnforcer`): runs hourly, selects
finalized-but-not-purged recordings via the predicate index from
migration 202605180001, resolves each session's retention, and for
expired ones calls `recordingStore.Delete` + stamps
`recording_purged_at` + nulls `recording_storage_key` / `recording_url`.
The session row itself stays so audit history survives the purge.

**Per-tenant policy endpoints**:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/access/recording-retention-policy` | Read the caller's org policy; falls back to the configured default with `source: "default"` when no row exists. |
| `PUT` | `/api/v1/access/recording-retention-policy` | Upsert the policy for the caller's org. `retention_days >= 0`; 0 = infinite. |

**Storage interface gains `Delete(sessionID)`**: implemented on both
backends — filesystem rms the per-session directory; S3 does a parallel
bulk-remove via `minio-go`'s `RemoveObjects` channel. Both are
idempotent on missing sessions so the sweeper can safely retry.

**Audit events**: `remote_support.retention_policy_set`,
`remote_support.recording_purged` (one per session purged).

**Tests** (`remote_support_retention_test.go`): unit tests for the
four-layer resolution chain (override / 0 = infinite / default
fallback / hard fallback) and `Append` → `Open` → `Delete` round-trip
on the filesystem store including the idempotent-delete contract.

**Device-side banner reflects recording state**: `/agent/config`'s
`remote_support` block carries a `recording: bool` field. When true,
the agent's `RemoteSupportService` swaps its foreground-notification
text from "An OpenIDX admin can see and control this device" to "An
OpenIDX admin is recording this device's screen". Flag is latched
before `startForeground` so the first display already reflects the
right state — no banner-text flicker. Wire path:
`HandleConfig → activeSessionInfo.Recording → agentRemoteSupportInfo
→ RemoteSupportInfo.recording → service intent extra → buildBanner`.

**Admin console**: a `RetentionPolicyCard` lives at the top of
`/remote-support`. It reads the policy via the GET endpoint, surfaces
the source as a badge (`org policy` vs `server default`), and exposes
a number input + "Set to infinite" affordance for editing. Optimistic
update via React Query's `setQueryData` so the card reflects the new
value immediately on save.

**Deferred**:
- Legal-hold workflow that exempts specific sessions from sweep when
  the org policy is non-infinite.
- Encryption at rest for the filesystem backend (S3 backend inherits
  bucket-level SSE-S3 / SSE-KMS when the bucket policy enables it).
- Global disk-usage quota check before each chunk append.

### Out of scope (deferred)

- Clipboard sync between admin and device.

## Ziti zero-trust transport (wired)

The Phase 1 design described a fallback to direct HTTPS while the Ziti
Android SDK coordinates were being settled. The agent now wires the real
SDK:

- **Artifact**: `org.openziti:ziti-android:0.30.0` on Maven Central
  (Apache 2.0, published from `openziti/ziti-sdk-android` via Sonatype).
- **Repository config**: already satisfied by `mavenCentral()` in
  `agent-android/settings.gradle.kts` — no extra auth or repo entries.

### Bootstrap

1. `OpenIDXAgentApplication.onCreate` calls `ZitiClient(this).initializeFromStored()`
   which invokes `org.openziti.android.Ziti.init(applicationContext, seamless = true)`.
   `init` is idempotent and process-global; calling it twice is a no-op.
2. `seamless = true` replaces the JVM default `SocketFactory` after init
   so any unmodified OkHttp client routes through the overlay for hosts
   the network advertises. Vanilla HTTPS continues to work for everything
   else.
3. After `/agent/enroll` returns a `ziti_jwt`, `ZitiClient.enrollWithJwt`
   calls `Ziti.enrollZiti(jwt.toByteArray())`. The SDK provisions the
   identity on a background thread and stores keys in the
   AndroidKeyStore + sharedPrefs (`ziti` file) keyed by the SDK's internal
   `"ziti-sdk"` alias. We listen on `Ziti.identityEvents()` for the
   completion signal if a caller needs to block on enrollment finishing.

### Lifecycle reentry

- **Reboot**: `BootReceiver` runs `OpenIDXAgentService.start(context)`,
  which calls `ZitiClient(this).initializeFromStored()` on service
  `onCreate`. `Ziti.init` rehydrates identities from sharedPrefs +
  AndroidKeyStore.
- **Process death**: same path — Android restarts the foreground service
  due to `START_STICKY`, and Ziti reinitializes from stored identities.
- **Revocation**: when the server marks an agent revoked, the agent
  receives a 403 from `/agent/config` and clears its identity store. We
  rely on the SDK's own posture / token failure detection for graceful
  shutdown of in-flight connections.

### Known follow-ups

- The SDK posts a "Application is not enrolled with Ziti Network" system
  notification on init when no identities exist. For the OpenIDX agent
  this fires briefly during first-time enrollment. A custom notification
  channel / suppression is tracked separately; current UX is acceptable.
- The SDK pulls in `com.goterl:lazysodium-android` + JNA which ships
  native libraries (~3–4 MB across ABIs). Acceptable for an enterprise
  agent; revisit if APK size becomes a constraint.

## Play Integrity server-side verification (implemented)

The Android agent forwards the Play Integrity token raw inside its
posture-report payload. The access service now verifies the token via
Google's `decodeIntegrityToken` API before persisting the result.

### Flow

1. Agent runs `IntegrityCheck` (Phase 1), gets a signed integrity token,
   posts it as `details.token` in the `play_integrity` posture result.
2. Access service's `HandleReport` detects `check_type=play_integrity`
   and calls `verifyPlayIntegrityResult` for that single result.
3. `PlayIntegrityVerifier.Verify` POSTs the token to
   `https://playintegrity.googleapis.com/v1/<package>:decodeIntegrityToken`
   with a service-account-derived bearer; Google returns the decoded
   `TokenPayloadExternal`.
4. Server-side validations:
   - **Package match** — the verdict's `requestPackageName` must equal
     the configured expected package (rejects token-replay across apps).
   - **Freshness** — `requestTimestampMillis` within ±30 s of "now",
     and within `maxTokenAge` (10 min default) of arrival (rejects
     replayed tokens past their useful window).
5. Policy evaluation: parameters stored in `posture_checks` for the
   `play_integrity` row are parsed as an `IntegrityPolicy`:
   - `require_meets_device_integrity`
   - `require_meets_basic_integrity`
   - `require_meets_strong_integrity`
   - `require_play_recognized`
   A failed policy flips the result to `status=fail` regardless of
   what the agent reported.
6. The raw token is **stripped** from the persisted details (it's
   one-shot bearer credential material, no audit value). The decoded
   verdict fields go in instead so admins can query history.

### Configuration

| Setting | Env var | Meaning |
|---|---|---|
| `play_integrity_service_account_json` | `PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` | Service-account JSON for the Google Cloud project linked to the Play Integrity API |
| `play_integrity_package_name` | `PLAY_INTEGRITY_PACKAGE_NAME` | Package name of the OpenIDX Android agent — must match the verdict's `requestPackageName` |

When **both** values are set, server-side verification is active. When
either is empty the verifier is disabled, agent-supplied tokens are
persisted with `verified=false` and `verifier_status=disabled` in their
details, and every report emits an `agent.play_integrity.unverified`
audit so admins can see they're trusting unverified attestations.

### Audit events

- `agent.play_integrity.unverified` — verifier disabled, token recorded
  but not validated.
- `agent.play_integrity.rejected` — Google returned an error, or the
  decoded verdict failed package-match or freshness checks.
- `agent.play_integrity.policy_failed` — verdict decoded successfully
  but didn't satisfy the configured `IntegrityPolicy`.

### Threat model

| Threat | Mitigation |
|---|---|
| Replay of a known-good token across many devices | Token is one-shot against Google; `decodeIntegrityToken` rejects reuse |
| Replay across apps (sideloaded malicious app forwards real token) | Server-side package-name match against the configured expected package |
| Stale token from a previously-compromised state | `requestTimestampMillis` freshness window |
| Agent lying about its own check status | Server overrides `status` based on verifier output, not the agent's claim |
| Verifier outage masking failures | When verification fails, status flips to `fail` rather than passing through the agent claim |

### Deferred

- **Nonce binding** — the agent currently sends Google a freshly-generated
  nonce, but the server doesn't track expected nonces. Adding a
  server-issued nonce (delivered via `/agent/config`) would close the
  remaining replay-during-window window.
- **Strong device integrity** — `MEETS_STRONG_INTEGRITY` (hardware-backed
  attestation) is available in the verdict; we just don't enforce it yet.
  Will be tightened as a policy default once hardware test coverage is in.

## Open items

- Push notifications (FCM) so the server can wake the agent on policy changes without polling.
- iOS / Windows / macOS / Linux unified clients — extend after Android stabilizes.
- BYOD work-profile mode (Profile Owner instead of Device Owner) — Phase 3 follow-up.
