# OpenIDX Mobile Authenticator — Developer Guide

**Audience:** a mobile developer building the OpenIDX authenticator app (OAuth/OIDC
login, TOTP, push-approval MFA, passkeys) **and** the "connect to applications"
experience (zero-trust access to internal apps).

**TL;DR:** most of this already exists. There is a **feature-complete React Native +
Expo app in [`mobile/`](../mobile)** that is `tsc`-clean and wired to the live
backend. Your job is mostly to (1) finish two backend-adjacent gaps (real push
delivery, native Ziti `dial()`), (2) do the build/release plumbing (EAS, real bundle
ids, domain-association files), and (3) extend UX. This guide is the single source of
truth for the API contract and the app's current state, with exact `file:line`
citations into the backend so you can verify everything yourself.

> Companion docs already in the repo:
> - [`mobile/HANDOFF.md`](../mobile/HANDOFF.md) — accounts/secrets/build handoff.
> - [`docs/remote-access-lifecycle-scenarios.md`](./remote-access-lifecycle-scenarios.md) — the zero-trust access model.
> - [`mobile/modules/ziti/README.md`](../mobile/modules/ziti/README.md) — the native OpenZiti module.

Everything below marked **[verified]** was exercised live against
`https://openidx.tdv.org` while writing this guide.

---

## 0. What "an authenticator that also connects apps" means here

OpenIDX splits into three planes; the mobile app touches all three but is only ever a
**client + a factor**, never an admin console:

| Plane | The app's role | Backend service |
|---|---|---|
| **Identity (IAM)** | Log the user in (OIDC/PKCE); be the second factor (TOTP, push approve, passkey) | `oauth-service` (:8006), `identity-service` (:8001) |
| **MFA / authenticator** | Enroll + present factors; approve push challenges by number-match | `identity-service` `/api/v1/identity/mfa/*` |
| **Access (ZTNA/PAM)** | Enroll the device, report posture, list + open connectable apps | `access-service` `/api/v1/access/*` |

All traffic goes through the gateway host (`https://openidx.tdv.org` on the reference
box); the app never talks to a service port directly.

Three build tiers (from `docs/remote-access-lifecycle-scenarios.md:167-199`):
- **MVP** — login + push approvals + TOTP + "My Access". No Ziti SDK. **(built)**
- **Phase 2** — browse/request PAM connections; open brokered Guacamole/BrowZer
  sessions in an in-app WebView. **(built)**
- **Phase 3** — embed the mobile Ziti SDK so the phone is a first-class overlay
  endpoint; native SSH/RDP clients dial over the overlay. **(scaffolded — the one real
  code TODO)**

---

## 1. Current state of the app (start here, don't rebuild)

Stack: **React Native 0.86 + Expo SDK 57, TypeScript (strict), expo-router**, TanStack
Query, axios. Routes live under **`mobile/src/app/`** (not `mobile/app`).

**Already complete and `tsc`-clean** (see `mobile/HANDOFF.md`):

| Area | Files | Status |
|---|---|---|
| OAuth PKCE login (browser) | `mobile/src/lib/auth.tsx`, `oauth.ts`, `pkce.ts` | ✅ |
| Native passkey login (usernameless) | `mobile/src/features/mfa/passkey.ts` | ✅ (needs domain-assoc files) |
| Token storage / refresh / 401 interceptor | `mobile/src/lib/{secureStore.ts,api.ts,auth.tsx}` | ✅ |
| TOTP enroll/verify/disable | `mobile/src/features/mfa/totp.ts`, `app/(app)/security/totp.tsx` | ✅ |
| **Push MFA approve (number-match)** | `mobile/src/features/mfa/push.ts`, `app/(app)/approve/[challengeId].tsx` | ✅ poll-based (real push = TODO) |
| Step-up re-auth | `mobile/src/features/mfa/stepup.ts` | ✅ (API layer) |
| Approvals inbox | `mobile/src/features/approvals/`, `app/(app)/approvals/*` | ✅ |
| My Access | `mobile/src/features/myaccess/`, `app/(app)/my-access.tsx` | ✅ |
| Notifications | `mobile/src/features/notifications/`, `app/(app)/notifications.tsx` | ✅ |
| Biometric app-lock | `mobile/src/app/(app)/_layout.tsx` | ✅ |
| PAM browse/request/launch (Guacamole WebView) | `mobile/src/features/pam/`, `app/(app)/pam/*` | ✅ |
| Device enrollment + posture | `mobile/src/features/ziti/{device,posture}.ts`, `app/(app)/security/device.tsx` | ✅ |
| **OpenZiti native `dial()` loopback proxy** | `mobile/modules/ziti/*`, `src/features/ziti/native.ts` | 🚧 **scaffolded** |

**Not done (your work):**
1. **OpenZiti native `dial()`** — `mobile/modules/ziti/ios/OidxZitiModule.swift` and
   `.../android/.../OidxZitiModule.kt` both `reject("not_implemented")` on `dial()`.
   `enroll()/status()/serviceAvailable()` are written. See §7.
2. **Real push delivery** — currently poll-based; backend FCM/APNs senders need work
   (§4.4). Not blocking for dev.
3. **Build/release plumbing** — `eas init`, real `ios.bundleIdentifier` /
   `android.package` (placeholder `com.anonymous.openidxmobile`), domain-association
   files for passkeys (§8).

Run it: `cd mobile && npm install && npx expo start` — but passkeys and the Ziti module
need a **dev-client / EAS build** (Expo Go can't load native modules).

---

## 2. Configuration & the seeded mobile OAuth client

The backend ships a public PKCE client for exactly this app
(`internal/migrations/sql_v84.go:10-18`):

| Field | Value |
|---|---|
| `client_id` | `openidx-mobile` |
| `client_secret` | none (public client) |
| `redirect_uri` | `openidx://oauth-callback` |
| `grant_types` | `authorization_code`, `refresh_token` |
| `scopes` | `openid profile email offline_access` |
| `pkce_required` | `true` (S256) |
| access-token TTL | `3600` s (1 h) |
| refresh-token TTL | `2592000` s (30 d) |

App-side config resolves from `expo-constants` `extra` (per EAS profile) with
reference-box defaults (`mobile/src/config.ts`):
```ts
API_BASE_URL       = extra.apiBaseUrl   ?? 'https://openidx.tdv.org'
OAUTH_BASE_URL     = `${API_BASE_URL}/oauth`
OAUTH_CLIENT_ID    = extra.oauthClientId ?? 'openidx-mobile'
OAUTH_REDIRECT_URI = 'openidx://oauth-callback'    // must match app.json `scheme: openidx`
OAUTH_SCOPES       = 'openid profile email offline_access'
```
To point at your own backend, override `extra.apiBaseUrl` / `oauthClientId` in
`app.json` (or per-profile in `eas.json`), and seed an equivalent client there.

---

## 3. Login (OAuth 2.0 Authorization Code + PKCE)

Two paths ship; **the native path is recommended** because the browser `/oauth/authorize`
flow server-renders HTML that a native app can't cleanly intercept
(`internal/oauth/service.go:1322-1325`).

### 3.1 Native login (JSON, no browser hop) — recommended

This is what `mobile/src/features/mfa/passkey.ts` + `mobile/src/lib/oauth.ts` implement.

**Step 1 — mint a login session.** `POST /oauth/native/login-init`
(`internal/oauth/handlers_passwordless.go:160`):
```jsonc
// request
{
  "client_id": "openidx-mobile",
  "redirect_uri": "openidx://oauth-callback",
  "scope": "openid profile email offline_access",
  "code_challenge": "<base64url(S256(verifier))>",
  "code_challenge_method": "S256",
  "state": "<random>",         // optional
  "nonce": "<random>"          // optional
}
// 200
{ "login_session": "<token>" }
```
**[verified]** returns `{"login_session":"…"}`.

**Step 2 — authenticate.** Either password or passkey, both consuming `login_session`:

*Password* — `POST /oauth/login` (`internal/oauth/service.go:1636`):
```jsonc
// request
{ "username": "alice", "password": "…", "login_session": "<from step 1>" }
// 200 — success (no MFA): parse `code` out of redirect_url
{ "redirect_url": "openidx://oauth-callback?code=<code>&state=<state>" }
// 200 — MFA required (go to §4)
{ "mfa_required": true, "mfa_session": "<token>",
  "mfa_methods": ["totp","push","webauthn","sms","email","backup"],
  "risk_score": 42, "risk_level": "medium", "device_trusted": false, "can_trust_browser": true }
```
**[verified]** end-to-end: `login-init → login → token` yields a working access token.

*Passkey (usernameless)* — the app's default when supported:
- `POST /oauth/passkey-begin` `{ "login_session": "…" }` → `{ publicKey: {…assertion options…} }`
  (`internal/oauth/handlers_passwordless.go:221`)
- run `react-native-passkeys` `get(publicKey)`
- `POST /oauth/passkey-finish` `{ "login_session": "…", "credential": <assertion> }` →
  `{ "redirect_url": "openidx://oauth-callback?code=…&state=…" }`
  (`internal/oauth/handlers_passwordless.go:273`)

**Step 3 — exchange the code for tokens.** `POST /oauth/token`
(**form-encoded**, `internal/oauth/service.go:2796`):
```
grant_type=authorization_code
code=<code>                     ← URL-DECODE it first (see gotcha below)
redirect_uri=openidx://oauth-callback
client_id=openidx-mobile
code_verifier=<the PKCE verifier>
```
```jsonc
// 200
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 3600,
  "id_token": "<jwt>", "refresh_token": "<opaque>", "scope": "openid profile email offline_access" }
```
**[verified]** returns access + `refresh_token` + `id_token`, `expires_in: 3600`.

> **Gotcha (verified live):** the `code` inside `redirect_url` is URL-encoded (it ends
> with `%3D` for `=`). You **must URL-decode** it before sending to `/oauth/token`, or
> you get `{"error":"invalid_grant"}`. The app already handles this
> (`mobile/src/features/mfa/passkey.ts` parses with a regex then decodes).

### 3.2 Browser login (fallback)
`mobile/src/lib/auth.tsx` `loginWithBrowser` uses `expo-auth-session` against
`authorizationEndpoint = ${OAUTH_BASE_URL}/authorize/v2` and
`tokenEndpoint = ${OAUTH_BASE_URL}/token`, with `usePKCE: true`. Used automatically when
passkeys aren't supported.

### 3.3 Tokens, refresh, revoke, logout
- **Access token**: RS256 JWT, verify against `GET /.well-known/jwks.json`. Claims:
  `sub, aud, client_id, scope, iss, iat, exp, email, name, roles[], groups[],
  permissions[], sid` (`internal/oauth/service.go:840-858`).
- **Refresh**: `POST /oauth/token` form `grant_type=refresh_token&refresh_token=…&client_id=openidx-mobile`.
  Refresh tokens **rotate** — persist the new one each time
  (`internal/oauth/service.go:3047-3068`). The grant re-checks the user is still enabled
  and the session isn't revoked (kill-switch, `service.go:2995-3017`).
- **Store tokens in the OS keystore** (`expo-secure-store`) as the app does
  (`mobile/src/lib/secureStore.ts`: `oidx.access_token`, `oidx.refresh_token`,
  `oidx.token_exp`).
- **Revoke**: `POST /oauth/revoke` form `token=…`. **Logout**: `POST /oauth/logout`
  (Bearer or `id_token_hint`); **logout everywhere**: `POST /oauth/logout-all`.
- `.well-known/openid-configuration` **[verified]** returns
  `issuer=https://openidx.tdv.org`, `code_challenge_methods_supported=["S256","plain"]`
  (use **S256**; `plain` is rejected in production, `service.go:2853-2856`).

---

## 4. The authenticator: MFA factors

All MFA endpoints are under `/api/v1/identity/mfa/*`, **self-service** (any authenticated
user manages their own factors, `internal/identity/service.go:433`), authorized with the
user's own `Authorization: Bearer <access_token>`.

### 4.1 TOTP (the classic authenticator app feature)

Algorithm is **explicit in the emitted URI [verified]**:
`otpauth://totp/OpenIDX:<email>?algorithm=SHA1&digits=6&issuer=OpenIDX&period=30&secret=<BASE32>`.

- **Enroll (get secret + QR)** — `POST /api/v1/identity/mfa/totp/setup`
  (`internal/identity/service.go:3942`). No body. **[verified]** →
  ```jsonc
  { "secret": "<base32>", "qr_code_url": "otpauth://totp/OpenIDX:alice@…?algorithm=SHA1&digits=6&period=30&secret=…&issuer=OpenIDX", "manual_key": "<base32>" }
  ```
  Render `qr_code_url` as a QR **or** store the `secret` and generate codes locally
  (the app is the authenticator). Setup does not persist yet — enroll does.
- **Activate** — `POST /api/v1/identity/mfa/totp/enroll`
  `{ "secret": "<from setup>", "code": "123456" }` → `{ "status": "enrolled" }`
  (`service.go:3959`).
- **Verify** — `POST /api/v1/identity/mfa/totp/verify` `{ "code": "123456" }` →
  `{ "valid": true }` (`service.go:3985`).
- **Status** — `GET .../mfa/totp/status`; **Disable** — `DELETE .../mfa/totp`.
- App code: `mobile/src/features/mfa/totp.ts`, UI `app/(app)/security/totp.tsx`.

### 4.2 Push approval (number-match) — the flagship authenticator feature

The number is **2 digits (10–99)**; the challenge times out after
`PushMFA.ChallengeTimeout` (default 60 s) (`internal/identity/pushmfa.go:161-176`).

**Register this phone as an authenticator** — `POST /api/v1/identity/mfa/push/register`
(`internal/identity/handlers_mfa.go:170`). **[verified]**:
```jsonc
// request
{ "device_token": "<FCM/APNs token>", "platform": "ios", // ios|android|web
  "device_name": "Alice's iPhone", "device_model": "iPhone15,2", "os_version": "17.5" }
// 201 — the stored device (device_token omitted)
{ "id": "<uuid>", "platform": "ios", "device_name": "…", "enabled": true, "trusted": false, "created_at": "…" }
```
Re-registering the same `device_token` updates the row (idempotent). Until real push is
wired, the app registers a stable per-install UUID as `device_token`
(`mobile/src/features/mfa/push.ts`).

**Approve/deny a challenge (number-match)** —
`POST /api/v1/identity/mfa/push/verify` (`handlers_mfa.go:272`):
```jsonc
// request — challenge_code is the 2-digit number the user reads off the OTHER device
{ "challenge_id": "<uuid>", "challenge_code": "42", "approved": true }
// 200 approved
{ "verified": true, "method": "push_mfa" }
// 401 when approved:false
{ "verified": false, "message": "Challenge denied by user" }
```

**Poll a challenge** — `GET /api/v1/identity/mfa/push/challenge/:challenge_id`
(`handlers_mfa.go:309`; the `challenge_code` is blanked in this response for security) →
`{ "id","user_id","device_id","status","created_at","expires_at","responded_at" }`,
`status ∈ pending|approved|denied|expired`.

List/remove devices: `GET .../mfa/push/devices`, `DELETE .../mfa/push/devices/:id`.

App code: `mobile/src/features/mfa/push.ts`; approve screen
`app/(app)/approve/[challengeId].tsx`; deep link **`openidx://approve/<challengeId>`**
(the shape a real push notification will carry).

### 4.3 Passkeys (WebAuthn) — enroll + manage
Self-service registration/assertion for managing credentials:
`POST /api/v1/identity/mfa/webauthn/register/begin|finish`,
`.../authenticate/begin|finish`, `GET .../credentials`,
`DELETE .../credentials/:id` (`internal/identity/service.go:3126-3131`). Options are
standard `go-webauthn` JSON — pass straight to the platform WebAuthn API.
**For sign-in use the OAuth `/oauth/passkey-*` endpoints (§3.1), not the identity
`authenticate/finish`** which returns a bare success object, not a token.
RP config: `OPENIDX_WEBAUTHN_RP_ID` (must be your associated domain, e.g.
`openidx.tdv.org`), `OPENIDX_WEBAUTHN_RP_ORIGINS`
(`internal/common/config/config.go:350-355`). App code:
`mobile/src/features/mfa/passkey.ts`, UI `app/(app)/security/passkeys.tsx`.

### 4.4 MFA at login (step-up) & how the app drives it
When `/oauth/login` returns `mfa_required:true` + `mfa_session` (§3.1), call one of:
- **TOTP/backup** — `POST /oauth/mfa-verify`
  `{ "mfa_session","code":"123456","method":"totp" }` →
  `{ "code":"<authcode>","state":"…" }` then exchange at `/oauth/token`
  (`internal/oauth/service.go:2055`).
- **Push (number-match at login)** — `POST /oauth/mfa-push-begin` `{ "mfa_session" }` →
  `{ "challenge_id","challenge_code":"42","expires_at" }` (show the number), poll
  `GET /oauth/mfa-push-status/:challenge_id`, then `POST /oauth/mfa-verify`
  `{ "mfa_session","method":"push","code":"<challenge_id>" }`
  (`service.go:2274,2321`).
- **Passkey** — `POST /oauth/mfa-webauthn-begin` → assert → `/oauth/mfa-verify`
  `method:"webauthn"`.
- **SMS/email** — `POST /oauth/mfa-send-otp` `{ "mfa_session","method":"sms" }` then
  `/oauth/mfa-verify`.

App code: `mobile/src/features/mfa/stepup.ts`.

`GET /api/v1/identity/mfa/methods` **[verified]** returns which factors a user has
enabled, e.g. `{"enabled_count":1,"methods":{"push":true,"totp":false,…},"mfa_enabled":true}`.

### 4.5 ⚠️ Push delivery is the one MFA gap
The challenge lifecycle (create/verify/poll) is fully implemented, but **actual push
delivery needs work** before it works unattended in prod:
- **FCM** uses Google's **deprecated legacy `fcm/send` + server-key API**
  (`internal/identity/pushmfa.go:523-552`) — must migrate to **FCM HTTP v1**
  (OAuth2 + service account).
- **APNs** posts to the right URL but **attaches no provider auth JWT**
  (`pushmfa.go:575-611`) — will 403 in prod; the provider-token signing is unimplemented.
- For dev/testing: set `PushMFA.AutoApprove` (dev only) or just **poll the challenge and
  approve via `/mfa/push/verify` directly** (which the app already does).

**Recommended first backend task for the mobile effort:** rewrite the FCM path to HTTP
v1 and add APNs provider-token auth, then wire `expo-notifications` on the app side so
`openidx://approve/<challengeId>` arrives as a real notification.

---

## 5. Connecting to applications (zero-trust access)

Model (`docs/remote-access-lifecycle-scenarios.md:16-53`): **Identity says who you are;
Ziti decides whether your device may reach the target's network path; PAM decides whether
you may open a privileged session with which hidden credential, and records it.** Each IAM
user is auto-mirrored to a Ziti identity (`internal/access/ziti_user_sync.go:69-150`).

The app has **three ways to reach an app**, in increasing integration cost:

### 5.1 Brokered PAM / Guacamole session in a WebView — ✅ implemented, best first target
Credentials are injected **server-side** and never touch the phone
(`internal/access/pam_launch.go:150-344`). Flow:
1. **List** — `GET /api/v1/access/pam/entries` (ACL-filtered) and/or
   `GET /api/v1/access/guacamole/my-connections`. Launchable types: `rdp, ssh, vnc,
   telnet, website`.
2. **Request access** if required — `POST /api/v1/access/pam/entries/:id/request`
   `{ "reason": "…" }` → `{ "request_id": "…" }` (single-use grant, 1 h). An admin/
   approver approves via `POST .../pam/entry-requests/:id/approve` — **this is what a
   push-approval flow drives.**
3. **Launch** — `POST /api/v1/access/pam/entries/:id/connect`:
   ```jsonc
   // brokered — open connect_url in a WebView
   { "launch_type": "guacamole", "connect_url": "https://guac…/#/client/…?token=…",
     "session_id": "…", "credential_injected": true, "recorded": true, "reach_mode": "ziti" }
   // website — just a URL
   { "launch_type": "url", "url": "https://intranet.example.com" }
   ```
   Handle `403 {"approval_required": true}` (do step 2 first) and
   `503 {"code":"ziti_broker_unconfigured"|"ziti_unavailable"}`.
4. **End** — `POST /api/v1/access/pam/sessions/:id/end`.

App code: `mobile/src/features/pam/api.ts`, screens `app/(app)/pam/*` (session rendered
in a `react-native-webview`).

### 5.2 BrowZer clientless (browser) access — ✅ implemented, zero native integration
BrowZer runs the Ziti SDK **in the browser**; the user's OIDC login (which the app
already does) authorizes the overlay dial (`internal/access/apisix_routes.go:52-108`,
`ziti_user_sync.go:275-300`). For an HTTP app, just open its BrowZer URL
(`browzer_domain`/`browzer_path` on a service row, §5.3) in a WebView. A **login-time
device-trust gate** may apply when `OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS=true`
(`internal/oauth/service.go:1624-1634`) — an untrusted device is refused and a
device-trust request is filed.

### 5.3 List connectable services — ✅ implemented
`GET /api/v1/access/ziti/services` **[verified]** (returns 3 on the ref box):
```jsonc
{ "services": [
  { "id":"…","ziti_id":"…","name":"acme-server1-ssh","protocol":"tcp",
    "host":"10.0.5.20","port":22,"enabled":true,
    "browzer_path":"/apisix","browzer_domain":"apisix.localtest.me" } ] }
```
`name` is the Ziti service a native SDK dials; `browzer_*` gives the clientless URL.

### 5.4 Native overlay dial (Phase 3) — 🚧 scaffolded, the one real code TODO
Goal: the phone becomes a first-class Ziti endpoint so a native SSH/RDP client (or the
WebView) connects to `127.0.0.1:<port>` and the app bridges that over the overlay — no
VPN, posture-bound. The exact pattern is already implemented in Go for the desktop agent
(`agent/internal/ziti/dialer.go:47-85` `Bridge()`: listen on `127.0.0.1:0`, accept, dial
the Ziti service, pipe both ways) — port that behavior into the mobile native module.

**Enroll the device's Ziti identity:**
- Self-service: `GET /api/v1/access/ziti/sync/my-identity` → `{ "linked":true,
  "ziti_id","name","enrolled":false,"attributes":[…],"enrollment_jwt":"…" }` (the JWT is
  present only while unenrolled) (`internal/access/ziti_sync_handlers.go:124-184`).
- Or at device enrollment: `POST /api/v1/access/agent/enroll/oauth` returns `ziti_jwt`
  in its response (`internal/access/agent_api.go:423-508`).
Feed that JWT to `OidxZiti.enroll(jwt)` (already wired), then implement `dial(service)`.

---

## 6. Device enrollment & posture (device trust)

The phone can enroll as a managed device and report posture, which drives device-trust
(and thus the clientless gate + Ziti `#device-trusted` attribute).

- **BYOD enroll (logged-in user)** — `POST /api/v1/access/agent/enroll/oauth` →
  `{ "agent_id","device_id","auth_token","status","ziti_jwt?" }`
  (`internal/access/agent_api.go:423-508`). Upserts a `known_devices` row
  (`trusted=false` until an admin approves).
- **Report posture** — `POST /api/v1/access/ziti/posture/device`
  `{ "identity_id":"<ziti_id>", "posture": {…screen-lock, root/jailbreak, os_version…} }`
  → health report `{ overall_passed, score, … }` (`ziti_fabric_handlers.go:427-457`).
  The app collects signals in `mobile/src/features/ziti/posture.ts`.
- **My devices** — `GET /api/v1/access/my-devices`.
- Trust is granted admin-side; it flips `known_devices.trusted=true` and re-adds the
  `#device-trusted` Ziti attribute on the next sync
  (`internal/access/device_trust.go:14-40`).

App code: `mobile/src/features/ziti/device.ts`, UI `app/(app)/security/device.tsx`.

---

## 7. The native OpenZiti module (`mobile/modules/ziti/`)

A local Expo native module (`OidxZiti`) autolinked at prebuild. iOS wraps **CZiti**
(`ios/OidxZitiModule.swift`), Android wraps **ziti-android**
(`android/.../OidxZitiModule.kt`). TS surface in `modules/ziti/index.ts`, optional
wrapper in `src/features/ziti/native.ts` (app runs fine when the module is absent).

**Done:** `enroll(jwt)`, `status()`, `serviceAvailable(name)` + keychain/keystore
identity persistence.

**TODO (the single real code gap):** `dial(service)` on **both** platforms currently
`reject("not_implemented")`. It must open a Ziti connection to the named service and
**bridge it to a `127.0.0.1:<port>` loopback socket** the WebView/SSH client connects to
(mirror `agent/internal/ziti/dialer.go` `Bridge()`), returning `host:port`.

**Before first build:** pin exact `CZiti` (iOS, `~> 1.4` placeholder) and `ziti-android`
(`0.30.+`) versions, verify the `// MARK: SDK` / `// SDK:` calls, then
`npx expo prebuild` + `eas build --profile development`. See
[`mobile/modules/ziti/README.md`](../mobile/modules/ziti/README.md).

---

## 8. Build & release (from `mobile/HANDOFF.md`)

**This repo's build host is a headless Linux VM** — no macOS (no iOS builds) and no KVM
(no Android emulator). All real builds go through **EAS cloud** (CI workflow
`.github/workflows/mobile-eas-build.yml`) or your own Mac / KVM machine. Expo Go **cannot**
load `react-native-passkeys` or `OidxZiti` — you need a **dev-client / EAS build**.

Checklist:
1. Accounts: Expo (+`EXPO_TOKEN` GitHub secret), Apple Developer ($99/yr, iOS),
   Google Play ($25, store), Firebase FCM project + APNs `.p8` key (real push).
2. `cd mobile && npx eas init` (writes a real `extra.eas.projectId` — commit it).
3. Set real `ios.bundleIdentifier` / `android.package` in `app.json` (replace
   `com.anonymous.openidxmobile`).
4. **Domain-association files** for native passkeys (host at your RP domain, e.g.
   `openidx.tdv.org`):
   - iOS `/.well-known/apple-app-site-association` (`webcredentials: <TEAMID>.<bundleid>`)
     + `associatedDomains` in app config.
   - Android `/.well-known/assetlinks.json` (package + signing-cert SHA-256).
5. Verify deep links resolve on device: `openidx://oauth-callback` (OAuth),
   `openidx://approve/<id>` (push approve).
6. Trigger the "Mobile EAS Build" GitHub Action, or
   `eas build -p android --profile preview`.

---

## 9. Quick reference — endpoint index

**OAuth (`/oauth`, oauth-service):**
`GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json` ·
`POST /oauth/native/login-init` · `POST /oauth/login` · `POST /oauth/passkey-begin|finish` ·
`POST /oauth/token` (authorization_code / refresh_token, form-encoded) ·
`GET|POST /oauth/userinfo` · `POST /oauth/mfa-verify` · `POST /oauth/mfa-push-begin` ·
`GET /oauth/mfa-push-status/:id` · `POST /oauth/mfa-webauthn-begin` ·
`POST /oauth/mfa-send-otp` · `POST /oauth/stepup-challenge|verify` ·
`POST /oauth/revoke` · `POST /oauth/logout` · `POST /oauth/logout-all`.

**MFA (`/api/v1/identity/mfa`, identity-service, self-service Bearer):**
`totp/setup|enroll|verify|status` + `DELETE totp` ·
`push/register|devices|verify` + `GET push/challenge/:id` ·
`webauthn/register/begin|finish` · `webauthn/authenticate/begin|finish` ·
`webauthn/credentials` · `backup/generate|verify|count` · `sms/*` · `email/*` ·
`GET /api/v1/identity/mfa/methods`.

**Access (`/api/v1/access`, access-service, Bearer):**
`GET ziti/services` · `GET ziti/sync/my-identity` ·
`POST agent/enroll/oauth` · `POST ziti/posture/device` · `GET my-devices` ·
`GET pam/entries` · `POST pam/entries/:id/request` · `POST pam/entries/:id/connect` ·
`POST pam/sessions/:id/end` · `GET guacamole/my-connections`.

---

## 10. Recommended path for the new developer

1. **Run the app** against `https://openidx.tdv.org` with a test user; log in, enroll
   TOTP, register the push device, approve a challenge (poll-based). Everything above is
   already wired — confirm it end to end first.
2. **Ship the MVP**: EAS init, real bundle ids, domain-association files → a dev-client
   build that does login + push approve + TOTP + My Access.
3. **Close the push gap**: FCM HTTP v1 + APNs provider-token on the backend
   (`internal/identity/pushmfa.go`), then `expo-notifications` on the app so
   `openidx://approve/<id>` arrives as a real notification.
4. **Phase 2 app-connect**: the PAM/Guacamole WebView + BrowZer URL paths already work —
   polish the UX.
5. **Phase 3 native overlay**: implement `OidxZiti.dial()` (loopback bridge, mirror
   `agent/internal/ziti/dialer.go`), pin SDK versions, ship native SSH/RDP over Ziti.

---

*Backend citations verified against the repo at `/home/cmit/openidx`. Flows marked
**[verified]** were exercised live against `https://openidx.tdv.org` on
2026-07-17. Known backend gaps to plan around: real push delivery (FCM v1 + APNs
provider-token) and the native Ziti `dial()` loopback bridge.*
