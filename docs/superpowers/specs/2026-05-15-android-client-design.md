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

## Phase 3 (sketch): kiosk mode

- `DevicePolicyManager.setLockTaskPackages` + `startLockTask` + `setLockTaskFeatures`.
- New tables: `kiosk_policies`, `kiosk_policy_assignments`.
- `/agent/config` extended with optional `kiosk_policy` block; agent applies on receipt.
- Admin UI: kiosk policy editor (allowed apps, lock-task features, branding, exit PIN).
- Audit: `kiosk.entered`, `kiosk.exited`, `kiosk.policy_changed`.

## Phase 4 (sketch): remote control

- WebRTC signaling over Ziti.
- `MediaProjection` for screen capture; H.264 via `MediaCodec`.
- Input injection: Device Owner privileges where available; Accessibility Service fallback (requires user-toggle prompt).
- Admin viewer in the OpenIDX web console.
- Non-suppressible foreground-service banner when a remote session is live.
- Session row + optional recording in `remote_support_sessions`.
- Play Store caveat: Accessibility-Service apps are restricted; distribute via `/downloads/...` or managed Google Play. Already the chosen channel.

## Open items

- Server-side Play Integrity decode + verdict policy (Phase 1 just stores the token).
- Push notifications (FCM) so the server can wake the agent on policy changes without polling.
- iOS / Windows / macOS / Linux unified clients — extend after Android stabilizes.
- BYOD work-profile mode (Profile Owner instead of Device Owner) — Phase 3 follow-up.
