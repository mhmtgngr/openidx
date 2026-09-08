# Client access design — registration, MFA, ZTNA, permissions

> **Status:** design, 2026-09-08. Android and Windows first. Every "today"
> statement below was read from the file it names, not assumed. Items marked
> **DECISION** need the maintainer's word; everything else is engineering.

## The one rule

**A device starts with the minimum and earns more by proving things.** Enrolling
proves the device exists and who owns it (Tier 1). Posture proves it is healthy
(Tier 2). MFA proves the person is present. Revoking any of those must take back
*everything* it unlocked, at once. The user always sees which of the three they
have and which they lack.

## The three clients

| | What it is | Enrolls? | Posture? | Tier it can reach |
|---|---|---|---|---|
| **Windows agent** (`agent/`, MSI) | SYSTEM service + per-user tray. Enrollment, posture loop, Ziti tunnel, PAM launch | yes | yes — `agent/internal/checks/` (AV, disk encryption, firewall, domain join, patch level, OS version, integrity, screen lock, agent version) | **Tier 2** |
| **Android agent** (`agent-android/`, APK `com.openidx.agent`) | Native endpoint agent: enrollment, posture, kiosk, remote support. Work-profile / device-owner / unmanaged | yes | yes — `posture-android/` (screen lock, encryption, Play Integrity, developer options, unknown sources, enterprise-managed, patch level, OS version, agent version) | **Tier 2** |
| **Companion app** (`client/`, Flutter, iOS + Android) | End-user app over the gomobile engine: authenticator (TOTP), push number-match, approvals, My Access, QR sign-in | yes, as a *device of the user* | no meaningful posture — the Go engine's checks are desktop checks | **Tier 1** |

Two consequences worth saying out loud:

- **iOS is Tier 1 by design.** There is no native iOS agent and the companion
  cannot prove posture. Under `POSTURE_DEVICE_TRUST_GATE=enforce` an iPhone
  never earns `device-trusted`. That is correct, and the UI must say so rather
  than show a spinner. **DECISION:** confirm iOS stays Tier 1 for this release.
- **The Windows MSI ships the agent and the tray only** (`agent/packaging/wix`
  installs `openidx-agent.exe` and two DLLs). The Flutter desktop shell is a
  separate, undistributed artifact. Windows' user surface *is* the tray: Sign
  in, Sign out, My Connections, Quit.

## 1. Registration (enrollment)

### What exists today

| Path | Who presents what | Starts as |
|---|---|---|
| `POST /agent/enroll` with an **admin/MDM token** (`agent_enrollment_tokens`: expiry, revocable, single-use unless `reusable`) | an installer, MDM, or a user pasting a token / scanning a QR | pending admin approval — unless the token came from an **enrollment session** created in an MFA-verified console session, in which case `DEVICE_AUTOTRUST_MODE` may auto-trust |
| `POST /agent/enroll/oauth` with a **bearer carrying `agent.enroll`** | a signed-in user enrolling their own device from a native enrolment client | same auto-trust decision as the session path (was: always pending — the handler passed a literal `trusted=false`; and any console session token was accepted — fixed with v184) |
| `POST /api/v1/access/enroll` (Tier-0 dark front door) | session, or admin token | trades entitlement for a one-time Ziti JWT; audited; the only public route when the platform goes dark |

### Findings

1. **The Android agent's first screen cannot enroll.** `EnrollmentActivity.kt`
   shows "Sign in with your work email to enroll this device" and runs
   `OAuthEnrollmentFlow` with `client_id=openidx-agent-android` and scope
   `agent.enroll`. Neither exists on the server: the seeded native clients are
   `openidx-mobile` and `openidx-desktop` (migrations v84/v85), and
   `validateScope` (`internal/oauth/authorize.go`) rejects a scope the client
   is not allowed. The button every Android user sees first returns
   `invalid_client`. The QR/token path works. **Android priority one.**
2. **The no-database fallback in `HandleEnroll`** ("Dev mode: no DB, accept any
   non-empty token") has no environment gate. It is unreachable in the shipped
   binary — `cmd/access-service` fatals without `database_url` — but a refactor
   that makes the pool optional arms it silently. Gate it on
   `APP_ENV=development` and test that production refuses.
3. **A device waiting for approval is invisible to its user.** The client has
   no "pending admin approval" state (`client/lib/ui/screens/` shows PAM
   request/approve, nothing about device trust). Controlled access that the
   user cannot see reads as "broken".

### The policy

- **Anyone may enroll their own device** (OAuth path) and it lands **pending**.
  Self-service without the wait needs the console-issued enrollment session
  (MFA-verified) *and* `DEVICE_AUTOTRUST_MODE=enforce`, optionally
  `DEVICE_AUTOTRUST_REQUIRE_POSTURE=true` so trust always implies a compliant
  report. Fleet/MDM enrollment uses reusable admin tokens.
- **The OAuth path gets the same auto-trust decision as the session path** —
  today's `trusted=false` is a safe inconsistency, not a policy. Pass the
  session's `amr` (MFA-verified or not) into `decideAutoTrust` like the session
  path does.
- **Seed `openidx-agent-android`** as a public PKCE client with redirect
  `com.openidx.agent://oauth/redirect` (the intent-filter in
  `agent-android/app/src/main/AndroidManifest.xml`), scopes `openid profile
  offline_access agent.enroll`, and make `/agent/enroll/oauth` **require
  `agent.enroll`** in the token's scope. That closes the gap the other way too: a console session
  token (no `agent.enroll`) can no longer enroll a device by accident.
- **The client shows three states**: *Enrolled — waiting for approval*,
  *Enrolled — Tier 1*, *Trusted — Tier 2*, each with one line on what unlocks
  the next.

## 2. Access (ZTNA)

### What exists today — and it is sound

`internal/access/ziti_reconciler.go`:

- **Tier 0**: only `/api/v1/access/enroll`.
- **Tier 1** (`#enrolled-users`): every enrolled identity — self-service and the
  console shell.
- **Tier 2** (`#device-trusted`): admin-api, governance, audit, provisioning,
  SCIM, access. Granted and **removed** by posture (`applyPostureDeviceTrust`,
  under `POSTURE_DEVICE_TRUST_GATE`).
- **Per application**: a route's Dial policy is scoped to `#app-<uuid>` (its
  assignees) when `ACCESS_ASSIGNMENT_ENFORCE=true`; otherwise the blanket
  `#access-proxy-clients`.
- The `#all` grants in `ziti.go` are edge-router and service-edge-router
  policies (which routers carry which services), not identity reachability.

### What each role sees on a client

| Role | Companion app | Windows / Android agent |
|---|---|---|
| `user` | own codes, own approvals, own apps (Tier 1) | own apps; PAM entries assigned to them |
| `operator` | same + PAM launch for assigned entries (Tier 2 device required) | same |
| `auditor`, `compliance_reader` | same as user | same as user — audit is a console surface |
| `admin`, `super_admin` | **no admin actions from the companion** | admin surfaces reachable over the overlay only from a Tier-2 device |

**DECISION:** keep the companion app free of admin actions (recommended: a phone
that approves its own device is a phone that cannot be revoked by a phone).

### The finding that mattered most — fixed on this branch (item 2)

**Revoking a device did not revoke its tokens.** `executeDeviceRevoke`
(`internal/access/user_devices.go`) deleted the Ziti identity, terminated Ziti
sessions and resynced the trust attribute — and touched no OAuth session or
refresh token. The native clients hold a **30-day** refresh token
(`refresh_token_lifetime = 2592000`, v84/v85; the console's is one day). After
an admin revoked a phone, that phone could not dial the overlay but could still
act as the user on every HTTP surface for up to a month — including **approving
push-MFA challenges**. `Logout()` in the client was local only; nothing called
`/oauth/revoke`.

All three parts have landed:

1. **The session names its device.** Migration **v185** adds
   `oauth_refresh_tokens.agent_id`. A native client sends `agent_id` with its
   code exchange (`agent/internal/sso/sso.go`); the server binds it only if the
   agent is one it records as enrolled by that same user and not revoked
   (`internal/oauth/device_binding.go`). Rotation carries the binding forward
   like `family_id`, so a chain that has refreshed is still findable.
   `/agent/enroll/oauth` binds the enrolling bearer's own session to the agent
   it has just issued, which is the Android path and needs no client claim.
2. **The revoke follows it.** `executeDeviceRevoke` revokes every bound
   refresh-token family, marks the sessions those families ran under revoked,
   and publishes the `revoked_session:<id>` markers the refresh grant honours.
   The result reports both counts, and the console says so.
3. **Logout revokes.** `Engine.Logout`, the tray's Sign out and
   `openidx-agent logout` call `/oauth/revoke` (RFC 7009) before clearing local
   state. The local session is cleared either way — a user who signs out must
   not stay signed in because the network was down — and a failed revocation is
   reported rather than swallowed.

**What this does not do, deliberately.** An access token already minted to the
device keeps working until it expires, because nothing on the request path
consults the session marker — only the refresh grant does. That window is the
client's `access_token_lifetime`: one hour for the native clients, against the
thirty days it was before. Closing it means the auth middleware reading the
marker on every request, which is a per-request cost and a change of its own.

**And what the binding is not.** `agent_id` arrives as a form field, so a client
can omit it and be handed an unbound token — the pre-v185 state. No check here
could close that: an attacker replaying a stolen refresh token would simply not
send it. The binding is a routing key for revocation; the device's
authentication is the agent credential on `/agent/*` and the Ziti identity on
the overlay.

**DECISION:** native refresh-token lifetime. 30 days on a phone is long;
recommended **14 days, sliding on use**, hard cap 90. Windows agent may keep
30 (it re-attests posture continuously).

## 3. MFA

### What exists today

- Factors: TOTP, WebAuthn/passkeys, push number-match (over ntfy), SMS, email,
  backup codes (`internal/identity/`).
- **Policy engine**: org-scoped `mfa_policies` with conditions on groups, IP
  ranges, time windows and user attributes, `required_methods`, a grace period;
  evaluated at login for every client including native ones, since
  `openidx-mobile` / `openidx-desktop` go through the SPA login
  (`internal/oauth/mfa_policy.go` → `IsMFARequired`).
- **Adaptive**: new device +30, new location +20, impossible travel +50, blocked
  IP +40, failed login +10; ≥ 70 requires MFA (`adaptive_mfa.*`).
- **Step-up** endpoints exist (`/oauth/stepup-challenge`, `-verify`, `-status`).
- `push_mfa.auto_approve` (default false) does **not** do what its name says.
  *Corrected here after reading it again:* the flag only makes
  `sendPushNotification` return early, skipping the FCM/APNs hop and logging
  "Auto-approving push challenge". No challenge is approved — the prompt is
  still delivered over ntfy and still needs a tap and the right number. The
  log line was the lie, and it is now fixed; the flag's real effect is
  "skip the provider send", which matters only for availability (a deployment
  with neither a provider nor ntfy would deliver nothing). Left in place rather
  than deleted: three shipped documents describe it, and its effect is real,
  just smaller than its name.

### The policy

- **Login**: MFA per org policy; phones and laptops are not exempt. A
  **trusted browser** skips MFA (`BrowserTrusted`) — on a phone that is the
  system browser's cookie, so document that "trusted browser" is not "trusted
  device", and never let browser trust substitute for Tier 2.
- **Step-up for the two things that matter**: launching a PAM session and any
  admin write, on any client, if the session's last MFA is older than the org's
  step-up window (recommended 15 minutes; `PAM_SESSION_RISK_GATE` already
  carries the PAM half).
- **Push number-match is the phone's job, not its right.** ✅ *Item 3, landed.*
  A device that is pending approval or revoked cannot approve a challenge:
  `VerifyPushMFAChallenge` checks the approving device's state server-side (the
  push registration must be enabled, and the enrolled agent behind it — the
  v135 linkage — must be active). A **deny** is never refused on device
  grounds: a revoked phone saying "this wasn't me" is a signal worth keeping.

  Two things found while implementing it, both worse than the item as written,
  both fixed with it:

  - **Anyone could answer anyone's prompt.** `/mfa/push/verify` is on the
    authenticated identity group and `isIdentitySelfService` admits every
    authenticated user to anything under `/mfa/` — "the caller's own MFA
    verification". The handler passed `challenge_id` and the number straight
    through and never compared the challenge's user to the caller. It does now.
  - **The number match had unlimited attempts.** A wrong code returned an error
    and left the challenge pending, so all ninety two-digit values could be
    tried. Three wrong answers now deny the challenge; with no Redis counter
    available the first wrong answer is final, because "no counter" must never
    mean "no limit".
  - **A prompt could be raised for someone else.** `POST /mfa/push/challenge`
    took `user_id` from the request body on that same open route, so one
    account could make another account's phone buzz at will. It is now raised
    for the caller only; the login flow does not use this route (it calls
    `CreatePushMFAChallenge` in-process).
- **Recommended defaults for a new org**: MFA required for `operator` and
  above always; for `user` on new device / new location (adaptive); backup
  codes issued at first MFA enrollment; SMS off unless a real provider is
  configured (the mock is already refused in production).

## 4. Secrets at rest, per platform

| Platform | Today | Required |
|---|---|---|
| **Android agent** | `EncryptedSharedPreferences` (AES-256-GCM); Ziti identity in the KeyStore (`agent-android/core/`) | as is |
| **Companion app** | Ziti identity via the engine; tokens in the engine's config dir | use the platform keystore through the engine (Keychain / KeyStore) — verify, do not assume |
| **Windows agent** | `%ProgramData%\OpenIDX\agent\user-tokens.json` (access **and 30-day refresh** token) and `control-endpoint.json` (the bearer that fully drives the engine, including minting access tokens for the GUI), written with Unix mode `0600` — **which Windows ignores**; the directory inherits ProgramData's ACL. No DPAPI or ACL code anywhere in `agent/` (`authstore.go` itself says "hardening follow-up: DPAPI") | **DPAPI** (`CryptProtectData`, per-user scope) for both files, and an explicit ACL on `%ProgramData%\OpenIDX\agent` (SYSTEM + Administrators + the enrolled user). **Windows priority one.** |

## 5. Production gate additions

`ValidateProduction` errors:

- `HandleEnroll` no-DB fallback reachable outside `APP_ENV=development`

(`push_mfa.auto_approve` was listed here on the strength of its name; §3 records
what it actually does. It is an availability setting, not an MFA bypass, so it
belongs in `ProductionWarnings` at most.)

`ProductionWarnings` (report mode is allowed, but visible):

- `DEVICE_AUTOTRUST_MODE=enforce` without `DEVICE_AUTOTRUST_REQUIRE_POSTURE`
- native refresh lifetime above the recommended cap

## 6. Implementation order — Android and Windows first

| # | Item | Where | Size |
|---|---|---|---|
| 1 | ✅ Seed `openidx-agent-android` + `agent.enroll` scope; require the scope on `/agent/enroll/oauth`; make the OAuth path use `decideAutoTrust`; derive a census of every shipped client's id/redirect/scopes against the seeds | v184, `internal/common/middleware`, `internal/access/agent_api.go`, `internal/migrations/v184_test.go` | small — done |
| 2 | ✅ Device revoke revokes bound tokens: `agent_id` at token exchange → stored on the refresh family (v185) and carried through rotation → `executeDeviceRevoke` revokes the families, the sessions and publishes the markers; `Logout()` calls `/oauth/revoke` | v185, `internal/oauth`, `internal/access`, `agent/internal/sso`, `agent/internal/control`, `agent/internal/tray` | medium — done |
| 3 | ✅ Push approval checks who is answering, how often they may guess, and whether the approving device may still approve | `internal/identity/pushmfa.go`, `pushmfa_approval_gate.go`, `handlers_mfa.go` | small — done |
| 4 | Windows: DPAPI for `user-tokens.json` and `control-endpoint.json`; ACL on the agent directory | `agent/internal/authstore`, `agent/internal/control/listener_windows.go` | medium |
| 5 | `ValidateProduction`: reject `push_mfa.auto_approve`; gate the no-DB enroll fallback | `internal/common/config`, `internal/access` | small |
| 6 | Client shows the three enrollment states; iOS says "Tier 1" plainly | `client/lib/ui/screens/` | small |
| 7 | Step-up on PAM launch and admin writes when last MFA is older than the window | `internal/oauth`, `internal/access` | medium |
| 8 | Refresh-token lifetime per client (after DECISION) | migration | small |

Each item ships with the same discipline as the rest of this programme: a
derived guard where a list would drift, a red-proof, and a CHANGELOG entry.

## 7. Operator rollout (after merge, in this order, observe before enforce)

1. `ACCESS_ASSIGNMENT_ENFORCE=true` — apps and overlay routes scoped to assignees
2. `DEVICE_AUTOTRUST_MODE=observe` → `enforce` with `DEVICE_AUTOTRUST_REQUIRE_POSTURE=true`
3. `POSTURE_DEVICE_TRUST_GATE=observe` → `enforce` — Tier 2 follows posture
4. `PAM_SESSION_RISK_GATE`, then `ABAC_ENFORCE`, then `ENABLE_OPA_AUTHZ`

Merging turns none of these on. `ProductionWarnings` lists whichever are still
off at startup.

---

*Supersedes, for the Flutter client and the native agents,
[mobile-mfa-and-ziti-posture-access.md](./mobile-mfa-and-ziti-posture-access.md),
which was written against the deleted Expo app and is kept as history.*
