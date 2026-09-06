# OpenIDX Mobile Authenticator — Developer Guide

> **The React Native / Expo app this guide was written against has been
> deleted.** The mobile client is the Flutter app in [`client/`](../client),
> which drives the same Go engine as the desktop agent (`agent/mobile`), so
> posture and OpenZiti are one implementation rather than two. Every API
> contract, endpoint, payload and sequence below is still current — that is why
> this document is kept — and the file citations now point into `client/`,
> `agent/` or the backend rather than at the deleted Expo tree.

**Audience:** a mobile developer building the OpenIDX authenticator app (OAuth/OIDC
login, TOTP, push-approval MFA, passkeys) **and** the "connect to applications"
experience (zero-trust access to internal apps).

**TL;DR:** most of this already exists. The shipping client is the **Flutter app in
[`client/`](../client)**, which drives the Go engine (`agent/mobile`) through the
`openidx_engine` plugin — so login, enrolment, posture and OpenZiti are the desktop
agent's implementation, not a parallel one. Your job is UX and the release plumbing
(§8), not a rebuild. This guide is the single source of truth for the **API
contract**, with exact `file:line` citations into the backend so you can verify
everything yourself; §1 says what the app does today.

> Companion docs already in the repo:
> - [`client/README.md`](../client/README.md) — the app's own architecture notes.
> - [`docs/remote-access-lifecycle-scenarios.md`](./remote-access-lifecycle-scenarios.md) — the zero-trust access model.
> - [`docs/mobile/push-mfa-delivery.md`](./mobile/push-mfa-delivery.md) — how push MFA reaches the phone, and what re-adding a provider SDK would take.

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
- **Phase 3** — the phone is a first-class overlay endpoint; native SSH/RDP clients
  dial over the overlay. **(built — the Go engine's Ziti stack, the same one the
  desktop agent runs; see §7)**

---

## 1. Current state of the app (start here, don't rebuild)

Stack: **Flutter (Dart), Riverpod, dio**, over the **Go engine** — `agent/mobile`
bound with `gomobile` and consumed through the `openidx_engine` plugin. That is the
architectural fact everything else follows from: posture, enrolment, OpenZiti and the
OAuth session are the *same implementation the desktop agent runs*, not a second one
written in Dart. Code lives under `client/lib/`; see [`client/README.md`](../client/README.md).

| Area | Where | Status |
|---|---|---|
| OAuth login | `lib/ui/screens/login_screen.dart` → engine `loginStart` / `login` | ✅ |
| Deep-link callback (`openidx://oauth-callback`) | `lib/mobile/{deep_links,oauth_login_handler}.dart` | ✅ |
| Token storage / refresh / 401 | engine-owned; `lib/api/api_client.dart` sources the bearer from it | ✅ |
| TOTP codes (offline) | `lib/features/totp.dart`, `lib/ui/screens/mobile/authenticator_screen.dart` | ✅ RFC 6238, tested |
| Push MFA approve (number-match) | `lib/ui/screens/mobile/push_approve_screen.dart`, `lib/mobile/push_token_service.dart` | ✅ over ntfy |
| QR login approval | `lib/ui/screens/mobile/qr_login_approve_screen.dart` | ✅ |
| Approvals inbox | `lib/ui/screens/mobile/approvals_screen.dart`, `lib/api/governance.dart` | ✅ |
| My Access | `lib/ui/screens/my_access_screen.dart`, `lib/api/{access,portal}.dart` | ✅ |
| Notifications | `lib/ui/screens/mobile/notifications_screen.dart`, `lib/api/notifications.dart` | ✅ |
| Biometric app-lock | `lib/mobile/app_lock.dart` | ✅ tested |
| Device enrolment + posture | engine (`agent/mobile`), `lib/ui/screens/enroll_screen.dart` | ✅ |
| OpenZiti overlay | engine — the same Ziti SDK the desktop agent uses | ✅ |

**Passkeys are not a Dart code path and should not become one.** On mobile the engine
hands the authorize URL to the system browser, so passkeys, MFA and step-up run in the
browser against the same server flow the console uses. A Dart re-implementation
(`lib/api/auth.dart`) existed until v1.34.0 with its two platform seams left as stubs
that threw, no test and no caller; it was deleted rather than finished, because two
credential pipelines that can disagree is the hazard, not the missing feature.

**Known gaps:**
1. **Push delivery is ntfy-only on the client.** The backend also carries FCM HTTP v1
   and APNs senders (`internal/identity/pushmfa_providers.go`) for operators who
   provision one; the client half is deliberately not shipped. See §4.5 and
   [`docs/mobile/push-mfa-delivery.md`](./mobile/push-mfa-delivery.md).
2. **iOS ships unsigned.** CI builds and packages an `.ipa`; signing needs an Apple
   distribution certificate and provisioning profile — maintainer credentials. See §8.
3. **The Android release APK is debug-signed until an upload keystore is configured**
   in CI, and its filename says `-debugsigned` while that is true. See §8.

Run it: `cd client && flutter pub get && flutter run`. The engine has to be built
first — `client-mobile-build.yml` shows the `gomobile bind` invocation for each
platform.

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

There is no compiled-in backend URL. The app learns it from **enrolment**: the
engine reports `server_url` in its status, and `backendBaseUrlProvider`
(`client/lib/state/api_providers.dart:33`) reads it, so the HTTP journeys are empty
until the device is enrolled and point at whatever deployment enrolled it. The engine
owns the client id, the redirect and the PKCE exchange:

```
backend base URL  = the engine's status.server_url (set at enrolment)
client_id         = openidx-mobile        (seeded by migration v84)
redirect_uri      = openidx://oauth-callback   (must match the app's URL scheme)
scopes            = openid profile email offline_access
```

Seed an equivalent client on your own backend if you change `client_id`.

---

## 3. Login (OAuth 2.0 Authorization Code + PKCE)

Two paths are contracted, and **the Flutter client takes the browser one**: the
engine mints the authorize URL and hands it to the system browser, so MFA, step-up and
passkeys run in the server's own flow rather than a second implementation on the
phone.

> A note on an earlier version of this section: it recommended the native path
> because `/oauth/authorize` "server-renders HTML a native app can't cleanly
> intercept". That page was deleted in v1.34.0 — `/oauth/authorize` redirects to the
> SPA login now, and there is no server-rendered credential form left to intercept.
> The native path below is still contracted and still works; it is documented as the
> contract a fully native client would meet, not as what this client does.

### 3.1 Native login (JSON, no browser hop) — recommended

The Flutter client does not implement this natively: the engine opens the system
browser, so the server's own passkey flow runs there. The sequence is documented
because it is the contract a native client would have to meet.

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
> (a native client must parse and base64url-decode the challenge itself).

### 3.2 Browser login (fallback)
`client/lib/ui/screens/login_screen.dart` opens the engine's authorize URL with
`url_launcher` against
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
- **Store tokens in the OS keystore.** On mobile the engine owns them; the Dart
  side keeps a `flutter_secure_storage` store (`client/lib/api/token_store.dart`)
  used on desktop and as the fallback.
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
- App code: `client/lib/features/totp.dart` (RFC 6238, unit-tested against the RFC
  vectors in `client/test/totp_test.dart`), UI
  `client/lib/ui/screens/mobile/authenticator_screen.dart`.

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
(`client/lib/mobile/push_token_service.dart`).

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

App code: `client/lib/mobile/push_token_service.dart`; approve screen
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
not implemented in the client — passkey enrolment and management happen in the
console or in the browser the engine opens.

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

App code: server-side; the browser the engine opens drives step-up.

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

**Where this stands:** the FCM HTTP v1 and APNs provider-token senders exist
(`internal/identity/pushmfa_providers.go`); the client half is deliberately not
shipped, and the phone subscribes to its per-user ntfy topic instead. Adding a
provider SDK on the app side would
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

App code: `client/lib/api/access.dart`, `client/lib/ui/screens/my_access_screen.dart` (session rendered
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
  The engine collects the signals (`agent/internal/checks`, surfaced through `agent/mobile/mobile.go`'s `Posture()`), shared with desktop.
- **My devices** — `GET /api/v1/access/my-devices`.
- Trust is granted admin-side; it flips `known_devices.trusted=true` and re-adds the
  `#device-trusted` Ziti attribute on the next sync
  (`internal/access/device_trust.go:14-40`).

App code: the engine (`agent/mobile`), UI `client/lib/ui/screens/enroll_screen.dart`.

---

## 7. OpenZiti on the phone — the engine, not a second SDK

There is no separate mobile Ziti module to finish. The overlay is the Go engine's:
`agent/mobile` is bound with `gomobile` (an `.aar` for Android, an `.xcframework`
for iOS) and exposed to Dart through `client/plugins/openidx_engine`. It is the same
`agent/internal/ziti` the desktop agent runs, including `dialer.go`'s `Bridge()` —
so a service dialled on the phone and a service dialled on a laptop go through one
implementation, and a fix to either is a fix to both.

That is the whole argument for the Flutter-over-Go shape. The alternative that used
to be scaffolded here — a Swift `CZiti` wrapper and a Kotlin `ziti-android` wrapper,
both with `dial()` returning `reject("not_implemented")` — would have been a third
Ziti client to keep in step with the other two.

The bind commands live in `.github/workflows/client-mobile-build.yml`
(`gomobile bind -target=android …` / `-target=ios …`); reproduce them locally to
build the engine before `flutter run`.

---

## 8. Build & release

CI builds both platforms on every change to `client/**`
(`.github/workflows/client-mobile-build.yml`: `flutter analyze`, `flutter test`, an
Android APK and an unsigned iOS build) and publishes release artifacts on a `v*` tag
(`.github/workflows/client-mobile-release.yml`).

**What ships today, and under what name:**

| Artifact | Signed with | Name |
|---|---|---|
| Android APK | the upload keystore, when `ANDROID_KEYSTORE_BASE64` and its three companions are set | `openidx-agent-android-<tag>.apk` |
| Android APK | Flutter's debug key, when they are not | `openidx-agent-android-<tag>-debugsigned.apk` |
| iOS archive | nothing — unsigned | `openidx-agent-ios-<tag>-unsigned.ipa` |

The suffix is not cosmetic. A debug-signed APK is rejected by the Play Store, and
every device that installs one must uninstall before a properly signed build can
replace it, because the signing key changed. `scripts/check-release-signing.sh` (run
in CI, self-tested by `check-release-signing.test.sh`) fails the build if the
artifact name and the key that signed it can ever come apart — including if the
`apksigner` verification that rejects `CN=Android Debug` is removed.

**Maintainer actions to get a store-ready build:**
1. **Android upload keystore.** Generate one
   (`keytool -genkey -v -keystore upload-keystore.jks -keyalg RSA -keysize 2048
   -validity 10000 -alias upload`), then set four repository secrets:
   `ANDROID_KEYSTORE_BASE64` (`base64 -w0 upload-keystore.jks`),
   `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. The
   release job signs and drops the suffix on the next tag; set all four or none —
   a partial set fails the job rather than quietly debug-signing.
2. **iOS signing.** An Apple Developer account, a distribution certificate and a
   provisioning profile. Re-sign `openidx-agent-ios-<tag>-unsigned.ipa` and upload
   with `xcrun altool` / Transporter. Keep the bundle identifier stable across
   releases.
3. **Domain-association files**, if you want passkeys usable from the phone's
   browser without a redirect: host `/.well-known/apple-app-site-association`
   (`webcredentials: <TEAMID>.<bundleid>`) and `/.well-known/assetlinks.json`
   (package + signing-cert SHA-256) at your issuer's domain. Both are already
   served by `oauth-service` — see §9.
4. **Verify deep links on device:** `openidx://oauth-callback` (OAuth) and
   `openidx://approve/<id>` (push approve).

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
2. **Get a distributable build**: the Android upload keystore and the Apple signing
   material (§8). Until they exist CI still publishes both artifacts — named for what
   they are — so nothing is blocked on them but store distribution.
3. **Decide the push transport**: ntfy is the shipped one and needs nothing; if you
   want FCM/APNs, the backend senders are written
   (`internal/identity/pushmfa_providers.go`) and the app side is the work —
   see [`docs/mobile/push-mfa-delivery.md`](./mobile/push-mfa-delivery.md).
4. **Phase 2 app-connect**: the PAM/Guacamole WebView + BrowZer URL paths already work —
   polish the UX.
5. **Native overlay** is already the engine's (`agent/internal/ziti`, §7); what is
   left there is UX — surfacing dialled services and their health in the app.

---

*Backend citations verified against the repo at `/home/cmit/openidx`. Flows marked
**[verified]** were exercised live against `https://openidx.tdv.org` on
2026-07-17. Known backend gaps to plan around: real push delivery (FCM v1 + APNs
provider-token) and the native Ziti `dial()` loopback bridge.*

---

## Remote-support & clientless access — device-side hooks (remaining native work)

The server, admin console, and Go agent are complete for these flows. Two hooks
remain, both inside the not-yet-compiled native WebRTC/screen module:

1. **`control_state` receiver.** The admin viewer sends
   `{event:"control_state", active:<bool>}` over the `openidx-input` WebRTC data
   channel when it takes or releases control (see
   `web/admin-console/src/components/remote-support/remote-support-viewer.tsx`).
   The device receiver should show/hide a "being controlled" banner accordingly.
   Input events (`event:"global_action"`, pointer, keyboard) already flow on the
   same channel — only honor them while control is active.

2. **Attended consent prompt (optional upgrade).** The device already answers
   consent automatically via the Go agent's `ConsentDecider` (default: grant for
   a managed device). For a real Allow/Deny dialog, install a decider that shows
   a native prompt and returns `"grant"`, `"deny"`, or `""` (defer — keep the
   dialog open, decided on a later `/agent/config` poll). Contract:
   `POST /api/v1/access/agent/remote-support/sessions/:id/consent {"decision":"grant|deny"}`
   with `X-Agent-ID` + `X-Auth-Token`. Until the device grants, the admin
   WebSocket is refused server-side (403 "awaiting device consent").

Everything else — session start, ICE/TURN, signaling, recording, the view<->control
toggle, and the consent gate — is implemented and live-verified.
