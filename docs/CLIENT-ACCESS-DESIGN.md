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
| **Companion app** (`client/`, Flutter, iOS + Android) | End-user app over the gomobile engine: authenticator (TOTP), push number-match, approvals, My Access, QR sign-in | yes, as a *device of the user* | ✅ none, and it now says so — the Go engine's checks are desktop checks and decline on mobile rather than warning | **Tier 1** |

Two consequences worth saying out loud:

- **iOS is Tier 1 by design.** There is no native iOS agent and the companion
  cannot prove posture. Under `POSTURE_DEVICE_TRUST_GATE=enforce` an iPhone
  never earns `device-trusted`. That is correct, and the UI must say so rather
  than show a spinner. **DECISION:** confirm iOS stays Tier 1 for this release.
- **The companion app used to call that "Compliant".** This document has said
  from the start that the Flutter client has no meaningful posture, because the
  Go engine's checks are desktop checks. The code did not say it. Seven of the
  ten dispatch on `runtime.GOOS` with cases for linux, darwin and windows and
  answer anything else with a warning — and `Engine.Posture()` computed
  compliance as "nothing failed and nothing errored", which warnings do not
  affect. So on the gomobile builds the summary came out compliant on the
  strength of seven checks that never ran, and the home screen drew it green.
  Fixed in v1.34.0: a check that has no implementation for the running OS marks
  its result `Unsupported`, compliance is withheld whenever anything was
  unsupported, and the card says which checks could not run and that a managed
  device reports posture through the device agent instead. `tools/posturevocab`
  holds each check next to the platforms it can examine, across both clients,
  and fails the build when two clients claim one check on one platform.

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
  the next. ✅ *Item 6, landed.* `GET /agent/config` now states
  `enrollment_status` and `device_trusted` — the server always knew both and
  never said either — the engine's `DeviceState()` asks with the device's own
  credential, and the companion app renders it as a banner above everything
  else. Five states, not three: *revoked* is named rather than left to look
  like a network error, and *cannot check with the server* is kept distinct
  from a refusal, because a phone in a lift must not be told it has been
  revoked.

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

**DECISION — taken, item 8 landed.** Native refresh-token lifetime. 30 days on a
phone is long; the recommendation was **14 days, sliding on use**, hard cap 90,
with the Windows agent keeping 30 because it re-attests posture continuously.
Taken as written rather than left open; migration **v187** carries it, and an
operator who has already retuned `refresh_token_lifetime` keeps their value
(the UPDATE matches only the seeded `2592000`).

**And the finding that came with it, which was bigger than the numbers.**
`refresh_token_lifetime` is enforced — `GetRefreshToken` refuses a token past its
`expires_at` — but rotation issues each successor with `now + lifetime`, so the
window restarts on every use. Every native client refreshes far more often than
the window: the desktop agent hourly, the phone whenever it opens. **So the
thirty days bound only on a device that went DARK for thirty days**, which is the
opposite of the case the number exists for. A phone taken while unlocked, or an
agent on a machine that changed hands, held a working chain for as long as it
kept refreshing.

v187 gives the family an end: `oauth_refresh_tokens.family_started_at` (copied
forward by rotation, backfilled from each family's `MIN(created_at)`) and
`oauth_clients.refresh_token_max_lifetime`. The grant refuses and revokes the
whole family past the cap, before an access token is minted. A stored column
rather than a `MIN()` at read time because rows age out with their own
`expires_at`, so a computed origin would recede ahead of the client forever — the
same never-binding failure one level down.

Browser clients (`admin-console`, `access-proxy`, the playground) stay uncapped
on purpose: their refresh token lives in a browser rather than at rest on a
device someone can pick up, and capping the console would sign administrators out
on a schedule nobody asked for. `TestEveryNativeClientHasAFamilyCap` derives the
native set from the clients' own source, so a fourth one that ships without a cap
fails the build.

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
  step-up window (15 minutes by default). ✅ *Item 7, landed.*

  The step-up endpoints had shipped long before this and asked nothing of
  anyone: `/oauth/stepup-verify` minted a `step_up` JWT that no handler, no
  middleware and no gate in the product has ever read, so completing a
  challenge left the caller exactly as permitted, or refused, as before. What
  was missing was not a mechanism but a fact — `sessions.auth_methods` (v133)
  says a session used MFA and never says *when*, so a ten-hour-old factor and a
  ten-second-old one are the same row.

  `sessions.mfa_verified_at` (v186) is that fact. It is stamped at login,
  derived from the auth methods the login already records so a fourth login
  path cannot record `mfa` and forget the timestamp, and stamped again by
  `/oauth/stepup-verify` — which is what finally gives step-up an effect.
  Refreshing an access token deliberately does not refresh it: the refresh
  grant carries `session_id` forward, so a native client cannot refresh its way
  out of proving who is holding the laptop.

  The gate reads server state rather than a bearer the client presents. Three
  carve-outs, each pinned by a test: reads are never gated, machine identities
  (API keys, service accounts, client-credentials tokens) are never gated
  because step-up asks a person to touch a key and there is nobody to ask, and
  a person whose freshness cannot be established at all — no session on the
  token, or a lookup that failed — is refused under `enforce` and recorded
  under `observe`. A refusal is `403 step_up_required` naming
  `/oauth/stepup-challenge`, so the client has somewhere to go.

  The admin-write half hangs off the role gate (`requireAdminRole` in the
  access service, an `/api/v1` middleware in the admin API) rather than a list
  of sensitive endpoints, because a list is what lets the next endpoint escape.
  For the PAM half, where a list is unavoidable, a census requires every
  mutating `/pam/` route to carry a gate or a written reason — which is what
  found `POST /pam/apps/:id/launch`, a brokered Windows session the first pass
  had missed.
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
| **Companion app** | ✅ *Both halves landed (backup: item 4b; keystore: item 9).* The engine's config dir is `getFilesDir()` on Android and `Library/Application Support` on iOS, and it holds **three** credentials, not the two Windows has: `agent.json` (the agent's `auth_token`), `user-tokens.json` (access **and 30-day refresh** token) and `ziti-identity.json` (the **private key** that puts the device on the overlay). The Go code wrote all three `0600`. In an app sandbox that mode is not protection that was added — every file there is already private to the app's UID — and it answers neither of the two ways those bytes get out: **the platform backup**, and **anything reading the file system**. The Flutter client's manifest carried no `android:allowBackup`, whose default is `true`, so all three were in the user's Google Drive and extractable with `adb backup`; iOS had no `isExcludedFromBackup`, so they were in iCloud and in every unencrypted iTunes backup. And both platforms decrypt app storage at the **first unlock after boot** and leave it decrypted while the device is on, so on a rooted or jailbroken phone — or one merely unlocked and imaged — "at rest" meant readable | **Backup, landed:** `android:allowBackup="false"` **plus** `dataExtractionRules` excluding every domain from cloud backup *and* device-to-device transfer (from API 31 D2D is a separate channel, allowed by default whatever `allowBackup` says, so one without the other still hands the identity to the next phone); `isExcludedFromBackup` set on the config directory in the iOS plugin **before** `MobileStart`. `scripts/check-mobile-secrets-at-rest.sh` fails the build on either half. **Keystore, landed:** `agent/mobile.Keystore` is a gomobile **reverse** binding — a Go interface the host implements — so Go calls out to `AndroidKeystoreSealer` (AES-256-GCM under a non-exportable `AndroidKeyStore` key, StrongBox where the hardware has it) and `KeychainSealer` (AES-GCM under a Keychain key marked `…AfterFirstUnlockThisDeviceOnly`). The **key** never crosses: an `AndroidKeyStore` key cannot be exported at all, so a boundary that carried key material could not use one. `Start` takes the keystore as a parameter with no overload that omits it, and `secretfile.SelfTest` refuses to start unless the host's seal differs from the plaintext, does **not contain** it, opens back to it, and differs again on a second wrap — the four ways a "keystore" that compiles and runs can still leave the credential readable. On upgrade `Start` re-seals the files an earlier build left in the clear rather than waiting for the next write. `scripts/check-mobile-keystore.sh` covers the one thing no runtime check can: that the key comes from the OS and is not a constant in the source |
| **Windows agent** | ✅ *Item 4, landed.* `user-tokens.json` (access **and 30-day refresh** token) and `control-endpoint.json` (the bearer that fully drives the engine) were written with Unix mode `0600` — **which Windows ignores** — so both inherited `%ProgramData%`'s ACL, where `BUILTIN\Users` can read | `agent/internal/secretfile`: **DPAPI** (`CryptProtectData`, per-user scope) plus an explicit **file** DACL — SYSTEM, Administrators, and the writing user, inheritance switched off. A per-file DACL rather than a directory one: the SYSTEM service creates the directory before any user has signed in, so there is no "enrolled user" to name at that moment, and a file's own DACL is what Windows checks. `agent.json` (the agent's `auth_token`) is **not** covered — the service and the user's tray both read it, so a per-user blob would break one of them; that one needs the directory decision and is still open |

### What the keystore does **not** cover, on either platform

Two files, and both are said here rather than left to be discovered:

- **`ziti-identity.json`** — the private key that puts the device on the
  overlay. The OpenZiti SDK writes it during enrolment and reads it back itself
  through `ZitiIdentityFile`; neither call goes through `agent/internal/secretfile`.
  Sealing it would hand the SDK ciphertext, and unsealing it to a temporary file
  to hand over would put the private key back on disk for no gain. It needs an
  SDK-side change — an identity loaded from bytes rather than from a path — and
  is deliberately not half-done. On the phone it is still covered by the backup
  rules and the sandbox; what it lacks is the key-in-the-OS layer the other two
  now have.
- **`agent.json` on Windows** — unchanged, and for the reason it always had:
  both the SYSTEM service and the user's tray read it, so the per-user DPAPI
  blob and the writer-named DACL that protect `user-tokens.json` would lock one
  of the two out. It now goes through `secretfile.WriteShared`, which takes the
  keystore seal (a phone has one identity, so nothing to lock out) and skips the
  per-user layer — so the mobile half is closed and the Windows half still wants
  a directory-ACL decision: which account is "the enrolled user" when the
  service writes first?

## 4b. PAM travels the overlay, or it does not travel

A brokered privileged session has **two legs**, and before v1.34.0 each could
leave the overlay on its own — one of them by default.

| Leg | What it is | Before | Now |
|---|---|---|---|
| **user → broker** | the connect URL the console opens: `{public base}/#/client/{id}?token={t}` | A bearer URL. Minting it is gated hard (fresh MFA, entry ACL, approval, moderation, checkout); **using** it was gated by possession alone — any browser, any network, no client, no device. | Under `PAM_REQUIRE_ZTNA=enforce` every allowed launch is routed through the **overlay broker**, whose browser-facing base must be its own address (`GUACAMOLE_ZITI_PUBLIC_URL`, distinct from the direct broker's) or the service refuses to start. |
| **broker → target** | guacd's dial to the machine being administered | `pam_entries.reach_mode`, which migration v82 created `NOT NULL DEFAULT 'direct'`. An entry created without a deliberate choice opened a socket to the target's real address from the broker's network. | Under `enforce`, a launch whose reach mode is not `ziti` is **refused before any credential is resolved**, and audited. A website entry — which returns a URL and brokers nothing — is refused outright. |

**What the code decides, and what it cannot.** The target hop is this
process's decision and it is made completely. The user→broker leg is not:
nothing in an HTTP request proves the caller reached the service over the
overlay, and a header claiming it is set by whoever is calling — a control the
checked input switches off. That leg is closed by **deployment**: the broker
published as a Ziti service and at no other address, so the connect URL's host
routes for a machine running the client and for nothing else. What the code does
about it is refuse to start without the configuration that property requires,
and route every enforced launch through that broker. Saying which half is which
beats implying the flag delivers both.

**Operator verification** (the check the flag cannot make for you) — from a host
with no OpenIDX client and no overlay membership:

```bash
curl -sS --max-time 5 "$GUACAMOLE_ZITI_PUBLIC_URL/" -o /dev/null -w '%{http_code}\n'
```

Anything other than a connection failure means the overlay broker is reachable
without the client, and the first leg is open however the flag reads.

**What the console shows.** A gate that refuses on the server and nowhere else
is the branch's defect class inverted: instead of a control that displays
without enforcing, a control that enforces without displaying. `GET
/pam/broker/status` — which already exists so the launcher can explain a missing
broker rather than dead-end on a `503` — therefore reports the mode as
`require_ztna`, and the console uses it for two things: the Connect button on an
entry `enforce` would refuse is disabled with the reason on hover, and the
connection-path diagram draws that entry's network hop as a **refusal** rather
than as a working direct route. The mode reported is what the service will *do*,
not the raw setting: an unrecognised value reads `off` in both places, so the
console cannot show "enforce" over a gate that is not enforcing. When the field
is absent — an older service, or the probe has not resolved yet — nothing is
refused in the UI, because guessing `enforce` would grey out a button that
works. `observe` refuses nothing on the server, so it refuses nothing in the
console either; greying out what the server would still allow is the same lie in
the other direction.

**Rollout.** `observe` first: it refuses nothing and audits every launch
`enforce` would refuse (`pam.ztna.would_deny`), which is how you get the list of
entries still on `direct` and the count of website entries, before they stop
working.

## 5. Production gate additions

`ValidateProduction` errors:

- ✅ *Item 5, landed.* The `HandleEnroll` no-database fallback — the branch that
  accepts any non-empty token and mints a working agent credential — is refused
  outside `APP_ENV=development`, **including when no config is present at all**:
  a gate whose safe state depends on someone having wired configuration is not a
  gate. It answers `503` and audits the refusal. The branch was latent (the
  binary fatals without `database_url`), which is why it needed a gate rather
  than a comment: what kept it unreachable was a startup check in another
  package.

(`push_mfa.auto_approve` was listed here on the strength of its name; §3 records
what it actually does. It is an availability setting, not an MFA bypass, so it
belongs in `ProductionWarnings` at most.

**Corrected in v1.34.0.** This paragraph used to end "the report-mode warnings
themselves — `ACCESS_ASSIGNMENT_ENFORCE`, `ABAC_ENFORCE`, `ENABLE_OPA_AUTHZ`,
`PAM_SESSION_RISK_GATE`, `POSTURE_DEVICE_TRUST_GATE` — already ship in
`ProductionWarnings`". They do not and never did. `ProductionWarnings` covers
configuration hygiene — secrets, TLS, CORS, CSRF — and names no gate.
The gates are in `Config.ReportModeGates`, which until v1.34.0 **had no caller
outside its own test**: the right list, with a test proving it named every open
control, that no running process ever asked for. That test could not notice,
because a test that calls the function is itself a caller, so the list looked
read.

It now has one reader, and the reader is what the tests pin:
`ValidateProductionConfig` — the function every `cmd/*/main.go` already calls —
logs one line per open control plus a summary carrying the count, **before** the
production branch can abort, so an operator fixing a validation error sees which
controls are open while they are in there. Every environment, not only
production: development is where someone writes a deny policy, watches it permit
the request, and has nothing to read. `Warn` in production, `Info` elsewhere,
because report mode is the designed default there and a warning nobody can act
on is one people learn to skip.

Still not done, and said rather than implied: no console surface renders this.
The startup log reaches whoever runs the stack, which is the operator the
rollout in §7 is written for, and that is the whole of the claim.)

`ProductionWarnings` (report mode is allowed, but visible):

- `DEVICE_AUTOTRUST_MODE=enforce` without `DEVICE_AUTOTRUST_REQUIRE_POSTURE`
- native refresh lifetime above the recommended cap

## 6. Implementation order — Android and Windows first

| # | Item | Where | Size |
|---|---|---|---|
| 1 | ✅ Seed `openidx-agent-android` + `agent.enroll` scope; require the scope on `/agent/enroll/oauth`; make the OAuth path use `decideAutoTrust`; derive a census of every shipped client's id/redirect/scopes against the seeds | v184, `internal/common/middleware`, `internal/access/agent_api.go`, `internal/migrations/v184_test.go` | small — done |
| 2 | ✅ Device revoke revokes bound tokens: `agent_id` at token exchange → stored on the refresh family (v185) and carried through rotation → `executeDeviceRevoke` revokes the families, the sessions and publishes the markers; `Logout()` calls `/oauth/revoke` | v185, `internal/oauth`, `internal/access`, `agent/internal/sso`, `agent/internal/control`, `agent/internal/tray` | medium — done |
| 3 | ✅ Push approval checks who is answering, how often they may guess, and whether the approving device may still approve | `internal/identity/pushmfa.go`, `pushmfa_approval_gate.go`, `handlers_mfa.go` | small — done |
| 4 | ✅ Windows: DPAPI + an explicit file DACL for `user-tokens.json` and `control-endpoint.json`; the Windows-only tests now run on a Windows runner | `agent/internal/secretfile`, `agent/internal/authstore`, `agent/internal/control/listener_windows.go`, `windows-client-build.yml` | medium — done |
| 5 | ✅ Gate the no-DB enroll fallback on `APP_ENV=development`, refusing when no config is present. (`push_mfa.auto_approve` needed a correction, not a rejection — see §3) | `internal/access/agent_api.go` | small — done |
| 6 | ✅ The client shows what the server allows: `enrollment_status` + `device_trusted` on `/agent/config`, `DeviceState()` on the engine (+ gomobile and all three plugin bridges), a banner on the home screen | `internal/access`, `agent/internal/control`, `agent/mobile`, `client/plugins/openidx_engine`, `client/lib` | small — done |
| 7 | ✅ Step-up when the last factor is stale: `sessions.mfa_verified_at` (v186) stamped at login and by `/oauth/stepup-verify`; `STEPUP_GATE` off\|observe\|enforce at the PAM launch/reveal routes and at every write made with admin authority; a route census keeps the launch set from drifting | v186, `internal/stepup`, `internal/oauth`, `internal/access`, `internal/common/middleware` | medium — done |
| 8 | ✅ Refresh-token lifetime per client — and the family cap that makes it bind. `refresh_token_lifetime` was enforced per token and reset by every rotation, so on a client that refreshes hourly it bounded how long the device could be OFFLINE and nothing else. v187 adds `family_started_at` (carried through rotation, backfilled per family) and `refresh_token_max_lifetime`; the grant revokes a family past its cap before minting anything. 14 days / 90-day cap for the two mobile clients, 30 / 90 for the Windows agent. A derived test fails the build on a native client shipped without a cap | v187, `internal/oauth`, `internal/migrations` | small — done |

Each item ships with the same discipline as the rest of this programme: a
derived guard where a list would drift, a red-proof, and a CHANGELOG entry.

## 7. Operator rollout (after merge, in this order, observe before enforce)

1. `ACCESS_ASSIGNMENT_ENFORCE=true` — apps and overlay routes scoped to assignees
2. `DEVICE_AUTOTRUST_MODE=observe` → `enforce` with `DEVICE_AUTOTRUST_REQUIRE_POSTURE=true`
3. `POSTURE_DEVICE_TRUST_GATE=observe` → `enforce` — Tier 2 follows posture
4. `STEPUP_GATE=observe` → `enforce` — read the `access.stepup.would_require`
   rows first: they carry the factor's age and the window, so the number an
   operator is really choosing (`STEPUP_MAX_AGE`, or the console's
   re-authentication interval) can be chosen from evidence
5. `PAM_SESSION_RISK_GATE`, then `ABAC_ENFORCE`, then `ENABLE_OPA_AUTHZ`

Merging turns none of these on. `ProductionWarnings` lists whichever are still
off at startup.

---

*Supersedes, for the Flutter client and the native agents,
[mobile-mfa-and-ziti-posture-access.md](./mobile-mfa-and-ziti-posture-access.md),
which was written against the deleted Expo app and is kept as history.*
