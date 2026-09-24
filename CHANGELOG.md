# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- **`oauth_clients.front_channel_logout_uri` is dropped (v202).** v63 added it
  next to the back-channel logout URI. The back-channel column became a
  feature — stored, registered, edited in the console, advertised in
  discovery and delivered. The front-channel column did none of that: a
  search of the whole tree finds it in exactly one place, the `ALTER TABLE`
  that created it, and discovery never claimed
  `frontchannel_logout_supported`, so this is a dead column rather than an
  advertised lie. Every row has always held `NULL`; nothing is lost. A test
  pins the premise — no non-test Go file outside the migrations may mention
  the column — so a reader added later reconsiders the drop instead of
  reading a column that is gone. Front-Channel Logout 1.0, if it is added,
  arrives with its reader, writer, discovery claim and delivery in the
  migration that adds the column back.

### Changed
- **MFA policies enforce what they show (#990).** The login path used to
  discard the policy it matched, so a policy that listed WebAuthn was
  satisfied by SMS or email OTP, and nothing read the grace period. The API
  accepted three conditions (`factor_enrolled`, `min_risk_score`,
  `client_ids`) that no code reads, and refused the four the evaluator reads.
  So every policy applied to every user with an enrolled factor.
  - **Required methods are enforced** at password sign-in. A policy that
    requires methods offers only those, and no other factor satisfies it, nor
    does a remembered browser. An administrator's bypass code still works, as
    the way back in. Backup codes do not satisfy it.
  - **The grace period is enforced, per user.** A user with none of the
    required methods gets the grace period, from their first sign-in under
    the policy, to add one (`mfa_policy_grace`, v203). Until then they sign
    in as before, and the sign-in page shows them the deadline. After it,
    sign-in is refused with `403 mfa_enrollment_required` unless they have a
    bypass code, which is then the only method offered. The start and the
    refusal are audited (`mfa_grace_started`, `mfa_enrollment_required`).
    Raising the grace period extends every running window. Changing the
    method list starts every window again. 0 hours refuses at once, and the
    most is 720 (30 days).
  - **Policies are tried in the order the console lists them**, lowest
    priority number first, then by name. The login used to try the highest
    first, which did not matter while every policy did the same thing.
  - **Conditions are still refused**, and the console flags an older policy
    that stores some: nothing enforces them yet.
  - **API:** methods must come from `totp`, `webauthn`, `push`, `sms` and
    `email`, with no duplicates. A grace period needs at least one method and
    must be 0 to 720 hours. Anything else answers 400.
  - **Console:** the method checkboxes and the grace field are back, with what
    each does, and the table lists both. The toggle sends only `enabled`.
  - **Scope:** a policy governs sign-in with a password, as before this
    release.
  - **Tests:** each rule has two sides, at the login decision, at
    `POST /oauth/login` and in the admin API, against a migrated Postgres.

  **Upgrade: v203 clears the required methods and grace periods stored on
  existing policies**, and the column default drops from 24 hours to 0. No
  code enforced them. Enforcing them on upgrade would start windows nobody
  chose, and refuse sign-ins a day later. So every existing policy keeps
  doing what it did: challenge every user who has a factor enrolled. To
  require methods, set them again in MFA Management. A rollback drops the
  grace table, and cannot restore the cleared values.
- **The Helm chart ships the OPA policy** (#980). The OPA pods used to run
  empty unless an operator created a ConfigMap, so every decision was
  undefined. They now load the policy the chart carries, or the ConfigMap
  `opa.policyConfigMap` names, and a new policy rolls the pods. OPA runs with
  `--ignore=.*`, in the chart and in `dev-kube/opa.yaml`. A ConfigMap mount
  also holds each file in a hidden directory, and without the flag OPA loaded
  the policy twice and would not start ("multiple default rules"). A test
  fails any manifest that mounts a ConfigMap at `/policies` without it.
- **Fresh installs enforce application assignment and run ABAC in `observe`**
  (#956). `scripts/generate-secrets.sh` and the Helm chart write these
  values. An existing install keeps its values until the operator changes
  them; the order to do that in is in the configuration reference.
- **An `off`/`observe`/`enforce` setting with an unknown value now stops the
  service at startup** and names the setting. Check the values of
  `ABAC_ENFORCE`, `STEPUP_GATE`, `BOT_GATE`, `PAM_SESSION_RISK_GATE`,
  `PAM_REQUIRE_ZTNA`, `POSTURE_DEVICE_TRUST_GATE`, `DEVICE_AUTOTRUST_MODE` and
  `RATELIMIT_COST_MODE` before upgrading.
- **A delegation can only be scoped to the organization** (#956). Group, Role
  and Application scopes were stored and shown but never enforced, so the
  delegated permissions applied across the whole organization. `POST` and `PUT
  /api/v1/delegations` now refuse them with a 400, and the console no longer
  offers them. `scope_id` may be left out for the organization scope. Existing
  delegations keep their scope, keep working and stay editable.
- **Decided: the event bus is not a hard dependency.** Two open plan items
  asked whether the audit indexer should move onto the outbox/NATS path with
  `StartESReconciler` retired, and whether the SSF transmitter and the
  cross-binary seams (`ssf_pending_events`, `backchannel_logout_pending`)
  should become NATS consumers. Both stay PostgreSQL-backed: in the default
  install `elasticsearch.enabled` is true and `nats.enabled` is false, so a
  pure move would silently stop the Elasticsearch backfill, SSF delivery and
  back-channel logout for every existing deployment, and the outbox is
  single-consumer by construction. No "events" mode switch was added — a
  switch to a mode that does not exist is the declared-but-nonexistent
  capability this programme hunts. Measured: the code already agrees; the
  reconciler starts only behind `if es != nil` and the three drainers start
  unconditionally, with no reference to `NATSURL` in either binary. Two
  starter guards now pin that shape: any condition naming the broker around
  those calls fails the build. Six mutations red, no-op control green. The
  event path returns, if it returns, as a measured optimisation gated on
  `nats.enabled` — not as a default.

### Security
- **A sign-in link no longer skips the second factor.** A magic link proves
  the mailbox, which is one factor, and its redirect cannot ask for a second.
  It issued an authorization code to whoever it was sent to, including a user
  with a second factor enrolled and a user an MFA policy covers. It now signs
  in only a user whom the password login would let in without a second factor,
  because it asks the password login's own decision (`evaluateMFA`). Anyone
  else goes back to the login page, for the same pending request, with the
  reason: a second factor is needed, or a policy's grace period is over. The
  link is spent either way, and the refusal is audited (`magic_link_login`,
  failure). The login page now shows why a sign-in link was sent back; it used
  to ignore the reason.
- **A tenant may mint at most 100 device-enrolment tokens an hour.** Three
  handlers mint `agent_enrollment_tokens` rows — the admin token endpoint,
  the Android QR and the onboarding wizard's session — and none asked how
  many the tenant had already minted, so a console credential that could
  mint one could mint without limit. The plan left the number open as a
  product decision after v197 made the table per-tenant; it is decided at
  **100 an hour** (`AGENT_ENROLLMENT_QUOTA_PER_HOUR`,
  `config.agentEnrollmentQuotaPerHour`): a tenant provisioning a fleet mints
  one reusable token, not one per device, so 100 is far above any legitimate
  rate and far below what an unlimited endpoint allows. The rule lives in
  `internal/access/enrollment_quota.go`, every mint site calls it before its
  INSERT, and an AST census fails the build if a fourth appears without it.
  The (N+1)th request in a rolling hour is refused with `429` and a
  `Retry-After` naming when the oldest in-window token ages out; the count is
  the tenant's alone, and tokens older than the window do not count. `0`
  turns the quota off, deliberately, and startup then reports it with the
  other report-mode gates. Migration v201 indexes `(org_id, created_at)`,
  which the count needs and v197's single-column index answered by scanning
  the tenant's whole history. Measured against the full migrated schema at
  all three doors. **One chart defect found by rendering, not by reading:**
  `AGENT_ENROLLMENT_QUOTA_PER_HOUR: {{ … | default 100 }}` turned an
  operator's explicit `0` back into `100`, because Helm's `default` treats
  zero as empty — the "0 = off" promise was false until the template was
  changed to fall back only on an absent value. Ten mutations red, no-op
  control green.
- **The external identity links are per-tenant (v200), and orgscope's
  needsScoping register is empty.** `user_identity_links` and
  `social_account_links` were the last two tables in the product outside the
  tenant belt, parked on a question the lint could not answer: may one
  external account link to a user in two tenants at once, and which tenant
  owns the row? Decided: a link belongs to the tenant of the identity provider
  it was made through. `identity_providers` has carried `org_id` since v155,
  so `provider_id` already names exactly one tenant, and a consultant with an
  account in two organizations signs in through two different provider rows
  and holds two links, one in each, neither visible from the other.
  Uniqueness stays `(provider_id, external_id)` for the same reason; what is
  added is the belt: `org_id NOT NULL` with a foreign key, an index, the
  standard policy and FORCE ROW LEVEL SECURITY. Measured before the change:
  both admin list handlers filtered the tenant on a `LEFT JOIN` (`... AND
  ip.org_id = $2`), which keeps every row of the left table and filters
  nothing, so a user's links were returned regardless of which tenant asked;
  both DELETEs addressed a link by bare id. Nine queries across three packages
  now carry the tenant on the link row itself, and a cross-tenant upsert that
  PostgreSQL would have applied as a silent `INSERT 0 0` under RLS now fails
  with a named error — no product path reaches it, since the provider lookup
  is tenant-scoped, but a write that silently did not happen is the shape
  this repository's `silentwrite` lint exists to refuse. Measured as the
  unprivileged application role: a tenant sees only its own links on both
  tables, cannot read, delete or forge another tenant's row, and the same
  external subject links once in each tenant. Backfill: the provider's
  organization, then the user's, then the oldest; no column DEFAULT. Ten
  mutations red, no-op control green.
- **PKCE is now enforced at the authorization endpoint every browser client
  actually reaches.** `/oauth/authorize` is served by `handleAuthorize`, and
  that handler enforced no part of RFC 7636: measured against the live
  endpoint, a **public** client with no `code_challenge` at all was carried
  straight to the login page, an unsupported `code_challenge_method` was
  accepted, and a `code_challenge` that is not base64url was accepted. The
  code minted at the end of such a flow carried an empty challenge, which
  makes the token endpoint's `if authCode.CodeChallenge != ""` verification
  vacuous — so the protection public clients depend on was, in practice,
  optional for whoever omitted it. `/oauth/authorize/v2` did check the
  public-client half, and is not the route the console, the reference compose
  stack or the mobile fallback use. This is the third control to go missing
  from this handler in the same shape, after scope and `response_type`.
- **`pkce_required` now decides something.** The flag is stored on the client,
  served by the admin API and editable in the console's Applications editor,
  and no code read it: an operator who ticked the box for a confidential
  client was told PKCE was required and it was required of nobody. A
  confidential client marked `pkce_required` is now held to a challenge on
  every authorization path. Confidential clients that are *not* marked are
  unchanged, since turning it on for every existing registration would reject
  the next request from clients that work today.
  The rule itself moved to one place, `internal/oauth/pkce_policy.go`, and the
  five request paths that accept a client-supplied `code_challenge` — the live
  authorize endpoint, `/oauth/authorize/v2`, the `idp_hint` SSO hop, the
  consent POST and the native login-init endpoint — all call it. An AST census
  fails the build if a sixth appears that neither calls the rule nor records
  why it is exempt. The console's "sign in with an external IdP" button built
  its own authorize URL without a challenge and now mints and stores one like
  the primary login button, so the code it comes back with is verified rather
  than merely accepted. Ten mutations red, no-op control green.
- **Introspection and revocation now answer only for the caller's own tokens.**
  Both endpoints already required client authentication, and neither looked at
  which client had authenticated. Measured with two registered clients in one
  tenant and a refresh token issued to the second: `POST /oauth/introspect`
  from the **first** client answered `active: true` together with the second
  client's id, the **end user's subject** and the granted scope, so one
  application in a tenant could learn who was using another; and `POST
  /oauth/revoke` from the first client **revoked the second's token**, which
  RFC 7009 §2.1 requires be prevented in as many words. A token that is not
  the caller's now gets the answer a token that does not exist gets:
  `active: false` from introspection (RFC 7662 §2.2) and a 200 that does
  nothing from revocation. An error was the other option and was not taken,
  because it would distinguish "exists but is not yours" from "does not
  exist" and hand a registered client an existence oracle over the tenant.
  The two halves are different kinds of decision and the code says so: the
  revocation check is a specification MUST with no legitimate caller on the
  other side, while the introspection rule is a deliberate closed default that
  also forecloses a separate resource server introspecting another client's
  token — nothing in this tree does that, and re-opening it should mean an
  explicit per-client permission rather than a return to "any authenticated
  client may introspect anything". One asymmetry is deliberate: a token naming
  no client at all is refused by introspection but still revocable, because
  failing toward "it still works" is the wrong direction for a kill switch.
  The server's own severing paths, logout and reuse detection among them, do
  not go through these endpoints and are unchanged. Eight mutations red,
  no-op control green.
- **A scope is a whole scope, not a substring.** Five decisions asked whether a
  grant carried a scope with `strings.Contains`, and two of them decide what a
  client receives. Measured at the real token endpoint: a code granted the
  scope `openidx` — the name of this product, so not a contrived value — was
  answered with an **ID token**, although `openid` was never requested; and a
  code granted `openid offline_access_reports` was answered with a **refresh
  token**, although `offline_access` was never requested. The second hands a
  long-lived credential to a client that did not ask for one. Any custom scope
  that happens to contain either name as a substring did the same, in the
  authorization-code grant, the refresh grant and the device-code flow alike.
  RFC 6749 §3.3 makes the scope string a space-delimited list of whole scopes,
  and all five decisions now go through the one splitter this package already
  had. A census refuses the shape, so a sixth cannot appear. Six mutations red,
  no-op control green.
- **A granted scope now actually restricts what a token carries.** A token
  whose granted scope was the bare `openid` came back carrying `email` and
  `name`, and `GET /oauth/userinfo` presented with that same token answered
  with `email`, `name`, `given_name`, `family_name` and `preferred_username`.
  The scope was recorded, shown on the consent screen and written into the
  token's own `scope` claim, and then read by nothing. The cause was
  structural rather than a missed branch: of the three emitters of identity
  claims, `GenerateIDToken` and `GetUserInfo` did not take a scope at all, so
  the grant could not reach them even in principle, and `GenerateJWT` took one
  only to copy it into a claim. Per OpenID Connect Core §5.4, `profile` now
  carries `name`, `given_name`, `family_name` and `preferred_username`, and
  `email` carries `email` and `email_verified`; a claim whose scope was not
  granted is absent rather than empty, so a relying party cannot mistake "you
  did not ask" for "the user has no name". An empty scope grants none of them,
  because reading it as "everything" would leave a client that omits the
  parameter better off than one that asks honestly.

  `email_verified` is now read from the user record rather than asserted true,
  and it carries three answers: absent (the `email` scope was not granted),
  false (granted, address not verified) and true. As a plain bool with
  `omitempty` the first two were the same bytes on the wire, which matters
  because this claim is what a relying party uses to decide whether it may
  match an identity onto an existing local account by address.

  `roles`, `groups` and `permissions` are deliberately NOT gated: they are not
  claims about the end user but the authorization facts the resource servers
  read, and gating them on `profile` would silently turn authorization off for
  a client that asked for `openid` alone. The discovery document's
  `claims_supported` now lists them, along with `preferred_username`, all four
  of which were emitted and none advertised.

  **Behaviour change.** A client that requested only `openid`, or no scope at
  all, and relied on receiving identity claims anyway must now ask for
  `profile` and/or `email`. The token response's own `scope` field already
  reports exactly what was granted.

  Measured with a real PostgreSQL and httptest across all three emitters, the
  token endpoint end to end, and the discovery document. Eleven mutations red,
  no-op control green.

### Added
- **The post-logout allowlist can be registered from the console.** The
  RP-Initiated Logout list added below was reachable only through dynamic
  client registration and the OAuth client API. The applications editor —
  the only interface the product ships for managing an application — had no
  field for it, `PUT /api/v1/applications/{id}` refused the key outright
  ("no valid fields to update"), and the application read never returned it.
  So every console-managed installation stayed on the origin fallback for
  good, while the OAuth service logged advice to "register
  post_logout_redirect_uris to tighten it" — advice the shipped interface
  could not take. Both dialogs now carry a **Post-logout redirect URIs** box,
  one URI per line, and the admin API reads and writes the column on the
  backing OAuth client. The read tells three states apart: a registered list,
  an empty array for a client that registered nothing (the client still on
  the loose rule, and the one that most needs the field shown), and an
  omitted key for a tile with no OAuth client behind it. A key absent from
  the payload leaves the registration alone, so renaming an application
  cannot widen it back to the fallback by omission; an empty list clears it,
  which is how an operator deliberately returns to the fallback. The rule
  itself moved to `internal/common/validation` so its three writers — the
  client store, dynamic registration and this editor — cannot drift. Measured
  against a real PostgreSQL and in the console's own suite: write, clear,
  leave-alone, blank-line trimming, refusal of an entry that could never be
  matched, tenant scoping, and the three read states. Eight mutations red,
  no-op control green.

- **RP-Initiated Logout 1.0: `state` comes back, `client_id` identifies the
  relying party, and `post_logout_redirect_uris` is a registered list
  (migration v199).** Three gaps, all in `/oauth/logout` and all measured:
  the handler never read `state`, so a relying party that uses it to tell its
  own logout callback from a forged one could not — §2 makes returning it a
  MUST; the caller's client was known only from the `id_token_hint`
  audience, so the `client_id` the spec provides for a relying party that no
  longer holds the ID token (expired, discarded at sign-out, never stored)
  was ignored and its registered landing page refused; and "registered" was
  derived from `redirect_uris` by comparing ORIGIN and ignoring the path, a
  rule whose own comment asked to be tightened. Origin matching says yes to
  every path on the relying party's host — an open redirector, a
  user-content page, a half-finished route — so a client that registered two
  callbacks got its whole site as logout destinations. Now: `state` is
  appended to the destination (alongside a query the registered value
  already carries, and nothing is appended when no state is sent);
  `client_id` identifies the caller, and a `client_id` that disagrees with
  the `id_token_hint` audience is refused with `400` rather than resolved in
  either direction; and a client with a registered list is matched EXACTLY,
  path and query included. **A client with no registered list keeps the
  origin rule**, because unconditional exact-match would refuse the logout
  redirect of every client in every existing install on the upgrade that
  adds the column — the default has to stay installable, registration is
  what tightens it, and each fallback logs the client so an operator can see
  who is still on the loose rule. The field is first-class: stored on the
  client, accepted and echoed at `POST /oauth/register`, and documented on
  the OAuth clients API. Measured with httptest and a real PostgreSQL: the
  state returns and rides alongside an existing query; a registered page is
  followed and a sibling path on the same host is refused; a client that
  registered nothing still reaches its page and still cannot be sent to
  another host; a mismatched `client_id` is refused while a matching one
  goes through; the store round-trips the list including clearing it; and
  registration refuses an entry that could never be matched. Eleven
  mutations red, no-op control green.
- **A session ended by another binary is announced to its relying parties
  too (`backchannel_logout_pending`, migration v198).** Back-channel logout
  fired from oauth-service's one revocation funnel and nowhere else could:
  sixteen paths in five other binaries — the identity service's session
  pages, password change, offboarding, lifecycle actions and deprovisioning;
  the admin console's revoke-session and revoke-all, the breach responder,
  the DSAR delete and restrict; risk remediation; device revoke and the
  kill switch; SCIM deprovisioning — end sessions with a raw `UPDATE` or
  `DELETE` and hold no signing key, and six of them delete the row, so no
  later sweep could even find the session. Each of them now captures the
  session first — tenant, user, id and every client it reached (the login
  client and every client holding a refresh token bound to it) — into
  `backchannel_logout_pending` through `internal/common/sessionend`, on the
  handle it already holds (the offboarding transaction included) and before
  its own statement; only live sessions some client reached are captured,
  so a session oauth-service already announced is not announced twice and
  a session nobody reached writes nothing. oauth-service's drainer claims
  the rows with `SKIP LOCKED` (the SSF signal drainer's shape), resolves
  the captured clients against the tenant's registered URIs and delivers
  through the same code the funnel uses, recording `delivered`/`failed` so
  "no relying party registered" and "every relying party refused" stay
  distinguishable. A census in `sessionend` reads every function under
  `internal/` that revokes or deletes `sessions` rows and fails when one
  lacks the capture; the funnel is its one named exemption. Measured
  against a real PostgreSQL and a real HTTP receiver: a session deleted the
  identity service's way is announced to its login client and its
  refresh-token client with the right `sid`, `aud` and `sub`; a named
  capture takes only the named live session; nobody-reached sessions are
  not captured; candidates resolve in the capture's tenant only; a refusing
  relying party is counted failed and the row is done; a stale claim is
  handed back and a poisoned row left alone; a failed offboarding captures
  nothing. Ten mutations red, no-op control green.
- **OpenID Connect Back-Channel Logout 1.0 is implemented, not only
  advertised.** The discovery document has said
  `backchannel_logout_supported: true` and
  `backchannel_logout_session_supported: true` since it was written, the
  `oauth_clients` table has carried `back_channel_logout_uri` since v63, and
  nothing read that column or sent a logout token: a relying party that
  registered its endpoint and trusted the advertisement kept its own session
  open after the user signed out here. Now, from the one place a session
  stops being live (`revokeSessionWithRedis`: `/oauth/logout` with a cookie,
  an `id_token_hint` or a bearer, `/oauth/logout-all`, an SSF receiver
  acting on an upstream signal, concurrent-session eviction, force-login
  termination, and the inactivity and absolute-timeout sweeps), every
  relying party the session reached — the client it was created for and
  every client holding a refresh token bound to it — that registered a URI
  in the session's tenant is POSTed a logout token: RS256 with the ID-token
  key, `typ` `logout+jwt`, `iss`, `sub` as the RP saw it (pairwise or
  public), `aud`, `iat`, `exp` (two minutes), `jti`, the `events` claim
  naming `http://schemas.openid.net/event/backchannel-logout`, `sid`, and
  never a `nonce`. Delivery is asynchronous and best-effort (one attempt,
  audited as `backchannel_logout` delivered/failed); it never delays or
  fails the revocation. The URI is now a first-class client field:
  `back_channel_logout_uri` on `POST/PUT /api/v1/oauth/clients`,
  `backchannel_logout_uri` at `POST /oauth/register` (echoed in the
  response), validated as https (http only on localhost), and on the
  console's application editor (below). A session another binary ends is
  announced through the seam below. Measured against a real
  PostgreSQL and a real HTTP receiver: token shape and signature, one
  message per relying party per session, cookie-only logout, per-session
  announcements for a user-wide revocation, a failing relying party, tenant
  scoping, store round-trip, DCR. Twelve mutations red, no-op control green.
- **A browser session reaches the consent screen without a password:
  `POST /oauth/login/resume`.** Single sign-on stopped one screen short. A
  live `openidx_sso` session that reached an application still needing
  consent, or a request with `prompt=consent`, was sent to the login page,
  and the login page knew one way to the consent screen: a password. The
  person retyped, minutes later, the password they had typed for another
  application. `/oauth/authorize` (and `/oauth/authorize/v2`) now put
  `resume=1` on the login URL when the cookie named a live session that
  could not be carried straight to a code because the page has a screen to
  show; the pending request's `prompt` and `max_age` travel in the
  `login_session` stash. The login page, seeing the hint, posts the
  `login_session` to `/oauth/login/resume`, which resolves the cookie again
  (tenant-scoped, live, unrevoked), refuses with `401 login_required` when
  the request asked for the form itself (`prompt=login`, `select_account`),
  when the session is older than `max_age`, or when no usable session exists
  (a stale cookie is cleared), and otherwise consumes the `login_session`
  and completes through the same code issuance as a credential login:
  assignment gate, consent challenge (always for `prompt=consent`), code
  bound to the session, cookie refreshed. A 401 leaves the login form as it
  was. Measured against a real PostgreSQL: the hint appears exactly when a
  session can carry the user (never without a cookie, for a revoked
  session, or for `prompt=login`/`select_account`); the resume answers the
  consent challenge whose stash names the session's user, the ordinary
  decision then mints a code bound to that session, and a second resume of
  the consumed `login_session` is refused. Seven mutations red, no-op
  control green.
- **`/oauth/authorize` reads an existing browser session: single sign-on.**
  The docs have promised "users log in once and access all connected
  applications" since they were written, and nothing implemented it: every
  `/oauth/authorize` minted a fresh `login_session` and sent the browser to
  the login page, so the second application asked for the password again.
  The login flow's code issuance now sets an `openidx_sso` cookie (HttpOnly,
  SameSite=Lax, Secure, 24h) holding a random token that the
  session Redis maps to the identity session; `/oauth/authorize`, after the
  existing client/redirect_uri/scope/response_type validation, resolves it
  and — for a live, unrevoked, unexpired session of the request's tenant,
  through the same assignment/ABAC and consent gates — redirects to the
  client with a code. Anything less (no cookie, forgotten token, revoked /
  expired / deleted / other-tenant session, `prompt=login`, older than
  `max_age`) falls through to the login flow, and a cookie that resolves to
  nothing is cleared. `prompt` and `max_age` (OIDC Core §3.1.2.1) are read
  for the first time: `prompt=none` never shows UI and answers
  `login_required` / `consent_required` at the redirect_uri (§3.1.2.6);
  `none` combined with another value, an unknown value, or a malformed
  `max_age` is `invalid_request`. `/oauth/logout` ends the browser session
  too (revoke + marker, mapping deleted, cookie cleared). The new mint site
  is registered in both mint-site guards. Measured against a real PostgreSQL
  and miniredis: live session → code; each stale shape → login with the
  cookie cleared and nothing minted; fourteen mutations (revoked / expiry /
  tenant check dropped, max_age ignored, prompt guard dropped, consent
  skipped, HttpOnly dropped, stale cookie kept, logout keeps the session,
  issuance sets no cookie, assignment gate skipped — caught by the source
  guard and by a behavioural test, prompt=none without a cookie not
  answered, authcode session binding dropped) each turn a test red; a
  log-text control stays green.
  Same-origin only, and documented as such: the cookie is set on the login
  page's request to `/oauth/login`, which is same-origin in the production
  layout and cross-origin (no credentials, no cookie) in the compose stack.

- **The ID token carries `auth_time`, from the session the code was bound
  to.** `GenerateIDToken` already read the session row for `sid` and `amr`
  and emitted no `auth_time`; the only `auth_time` in the codebase was the
  social/SAML immediate-issue path's, which is `now` because there the token
  is minted the instant the assertion is consumed. Single sign-on made the
  gap live: a token minted from a two-hour-old browser session said nothing
  about those two hours, and OIDC Core §3.1.2.1 requires `auth_time`
  whenever the client asked with `max_age`. The session read now returns
  `auth_methods` and `started_at` in one org-scoped query; `auth_time` is
  `started_at`, and is omitted — never guessed from `iat` — when no session
  row is bound, the id is unknown, or the row belongs to another tenant.
  `claims_supported` in the discovery document now lists `auth_time` and
  `amr`, both of which the token has carried without saying so. Measured
  against a real PostgreSQL: a session started two hours ago yields
  `auth_time` equal to its start and about two hours before `iat`; six
  mutations (auth_time from `iat`, auth_time never emitted, `started_at`
  not read, tenant filter dropped, `auth_time` or `amr` dropped from
  `claims_supported`) each turn a test red; a comment-text control stays
  green.

- **`/oauth/authorize/v2` reads the browser session too.** The v2
  authorization endpoint — the one the mobile authenticator's browser-login
  fallback opens — carried the comment "would be from session cookie / for
  now, redirect to login" and did exactly that for every request, while the
  login it redirected to set the `openidx_sso` cookie through the shared
  `/oauth/login` path: the cookie was issued to these browsers and never
  read. After its client, redirect_uri, response_type, scope and PKCE
  validation it now parses `prompt` / `max_age` and runs the same SSO fast
  path as `/oauth/authorize` (same gates, same code table, no new mint
  site); a live session is redirected with a code and no `login_session` is
  started, anything less takes the login path, and `prompt=none` answers at
  the client. The v2 consent POST deliberately does not bind a cookie to the
  client-supplied `session_id` it accepts. Measured against a real
  PostgreSQL: live session → code with the PKCE challenge carried; no
  cookie, revoked session, `prompt=login`, `max_age` older → login UI with
  nothing minted; `prompt=none` → `login_required`; malformed values →
  `invalid_request`. Three mutations (fast path never consulted, `prompt`
  errors swallowed, `max_age` errors swallowed) each turn a test red; a
  comment-text control stays green.

- **NOTICE, THIRD_PARTY_NOTICES.md, SUPPORT.md, and a Developer Certificate
  of Origin that is checked.** The repository shipped an Apache-2.0 LICENSE
  and nothing that named a single third-party licence. `NOTICE` now points
  at `THIRD_PARTY_NOTICES.md`, which is generated from the Go module graph
  by `scripts/check-third-party-notices.sh --write` (198 modules and
  packages, 91 Apache-2.0, 63 MIT, 32 BSD-3-Clause, one MPL-2.0, one
  BSL-1.0, two Unlicense) and checked by the same script in the License
  Compliance job: a dependency added, removed or relicensed without
  regenerating the file is a red job. Versions are left out so a bump does
  not stale it. `SUPPORT.md` says where to ask, what to expect (best
  effort, no service level, the 1.x line, Compose and the Helm chart) and
  what is not on offer. `CONTRIBUTING.md` asks for `git commit -s`, and a
  new CI job, `Every commit is signed off` (`scripts/check-dco.sh`), walks
  every non-merge commit a pull request adds and fails on the first one
  without a `Signed-off-by`; merge commits and commits merged in from the
  base are not the branch's to sign. Both guards ship with self-tests that
  drive them red: a stale, hand-edited or missing notices file, a tool that
  reports no modules, an unsigned commit, a sign-off without an address.

- **The chart refuses to install a placeholder.** `values-prod.yaml` ships
  `edge.originVerify.value` as `REPLACE-WITH-FRONT-DOOR-PROFILE-GUID`, and
  nothing could tell that string from a real profile GUID: `required` only
  asks whether a value is empty. Measured on 2026-09-19, `helm template`
  with `values-prod.yaml` plus `deployments/kubernetes/cells/eu-1.yaml`,
  which is what `rollout-cell.yml` installs, rendered an Ingress whose
  snippet compares `X-Azure-FDID` against the literal placeholder, so every
  request arriving through the edge would have been answered 403, and the
  render reported success. A new interlock (`templates/no-placeholders.yaml`,
  `openidx.rejectPlaceholders`) walks every value, lists and subchart values
  included, and fails the render on the first string that still carries
  `REPLACE-WITH`, naming its path. The marker is the shape, so a placeholder
  added anywhere later is refused too. Renders that never reach a cluster
  (the lint job, the static chaos drill, the image check) override it on the
  command line, never in a values file. The three cell files say the value
  is theirs to supply. Verified by mutation: the shipped file and the
  prod-plus-cell render are red; a placeholder inside a list is red and
  named; the override, the default values and a look-alike lowercase string
  are green; with the template emptied the shipped file renders again.
- **`values-prod.yaml` says what it leaves off.** Scraping
  (`monitoring.serviceMonitor`), alert delivery (`monitoring.alerting`) and
  scheduled backups (`backup`) were off by inheritance from `values.yaml`
  and the production file never mentioned them, so a production install
  had alert rules that nothing scraped for, no route for anything that
  fired, and no backup, with the only word of it in a file the operator
  does not edit. They are now written out as `enabled: false` with the
  fact each one needs before it can be turned on.
- **The docs site carries the guides it used to leave in the repository.**
  Seventy-one of the hundred and seven documents under `docs/` never
  rendered on the published site, among them the MFA, passwordless and
  push, SSF/CAEP, SCIM, OAuth/OIDC, token exchange and DCR, tenancy,
  hardening, threat model, compliance mapping, disaster recovery,
  releasing, HR-driven JML, EDR/MDM posture, getting started and user
  guides. A new **Guides** section in `docs/mkdocs.yml` shows eighteen of
  them without copying: each page under `docs/docs/guides/` is a stub that
  includes the source document at build time (`pymdownx.snippets`, which
  the site already used, now with `docs/` as a second base path and
  `check_paths: true`, so a renamed or missing source fails the build
  instead of publishing an empty page). The stubs keep the source files'
  names, so the relative links between those documents resolve on the
  site exactly as on GitHub; the eleven links that pointed at documents
  not on the site, in `GETTING-STARTED.md` and
  `PROJECT-READINESS-GUIDE.md`, are now absolute GitHub URLs. Measured with
  `mkdocs build --strict`: nine warnings before the link rewrite, none
  after; a stub naming a missing source turns the build red.

### Fixed
- **The sign-in page could not take a backup or bypass code.** Its code field
  took six digits and dropped every other character. Backup codes are eight
  letters and digits, and an administrator's bypass codes are sixteen. The
  field now takes them as typed when the method is a backup or bypass code.
- **`PAM_SESSION_RISK_GATE` terminated sessions on "Off" or "OBSERVE".** It
  compared the raw value, so any spelling other than exactly `off` or
  `observe` enforced. It now reads the value the way every other gate does.
- **Editing a delegation wrote its scope unchecked.** `PUT
  /api/v1/delegations/{id}` stored any `scope_type` and `scope_id` it was
  sent, including another tenant's group or organization, or a scope type that
  does not exist. A scope change must now leave the delegation scoped to the
  caller's organization.

- **With application assignment enforced, the access proxy could not dial an
  identity-mode Ziti route that has an application behind it** (#984). The
  Dial policy dropped `#access-proxy-clients` for the application's marker.
  That cut the unassigned tunnelers enrolled with that attribute, and it also
  cut the proxy, whose identity carries the same attribute. Every proxied
  request to such an application failed, including an assigned user's. The
  proxy is now named in that policy by id, so it keeps its dial and the
  tunnelers stay cut.

- **A session a user ended from their Sessions page kept refreshing (#992).**
  Ending a session from Profile → Sessions, or from the Sessions page
  without the admin role, calls `DELETE /api/v1/identity/sessions/:id`.
  That deleted the session row and nothing else. The refresh grant does not
  read that row: it decides on the refresh token's own row and on the
  `revoked_session:<id>` marker. So the signed-out device kept getting new
  access tokens, and a new rotated refresh token with each one. The admin
  path, password change, the kill switch and deprovisioning all published the
  marker or removed the tokens; this path did neither.

  Ending a session now revokes its refresh tokens in the database, which holds
  with Redis down, and publishes the marker, and only then deletes the row. A
  new test on the migrated schema covers four cases:
  - a live session refreshes;
  - an ended one does not;
  - it still does not with Redis down;
  - the user's other session keeps working.

  Four mutations turn it red: no database revocation, no marker, neither, and
  revoking every session's tokens.

- **User Access 360 answered 500 for every user from v1.35.0.** When the
  access map's elevation list moved from `jit_grants` to `access_requests`, it
  took `COALESCE(resource_name, resource_id)`. On the migrated schema
  `resource_id` is a UUID and `resource_name` a VARCHAR, and Postgres refuses
  that COALESCE when it plans the query, whatever the rows hold. So
  `GET /api/v1/access/users/:id/access-map` failed for every user, elevated or
  not. The access map's tests create their tables by hand and had declared the
  column VARCHAR, so they stayed green. The query now casts the id to text, the
  hand-written column is a UUID as in the product, and a new test builds the
  map on the migrated schema. Removing the cast turns both tests red. Found
  while writing the JIT row's end-to-end test for #957.

- **The OPA policy did not parse** (#980). A brace left over from trimming the
  role table made `authz.rego`, and its copy in `dev-kube/opa.yaml`, a parse
  error. OPA therefore served no `openidx.authz` rules, and
  `ENABLE_OPA_AUTHZ=true` would have refused every guarded request. It parses
  now. CI checks it and runs tests that hold both halves of each rule.
- **provisioning-service had no `OPA_URL` in compose.** It wires OPA like
  admin-api and governance-service, so with OPA on it would have asked
  `localhost:8281`, where nothing listens.

- **User Access 360 answered 500 for every user from v1.35.0.** When the
  access map's elevation list moved from `jit_grants` to `access_requests`, it
  took `COALESCE(resource_name, resource_id)`. On the migrated schema
  `resource_id` is a UUID and `resource_name` a VARCHAR, and Postgres refuses
  that COALESCE when it plans the query, whatever the rows hold. So
  `GET /api/v1/access/users/:id/access-map` failed for every user, elevated or
  not. The access map's tests create their tables by hand and had declared the
  column VARCHAR, so they stayed green. The query now casts the id to text, the
  hand-written column is a UUID as in the product, and a new test builds the
  map on the migrated schema. Removing the cast turns both tests red. Found
  while writing the JIT row's end-to-end test for #957.

- **The Applications editor's "Require PKCE" box displayed a default and
  enforced nothing; it and the back-channel logout URI now read from and
  write to the backing OAuth client.** The console's edit dialog showed a
  "Require PKCE" checkbox for every application and sent `pkce_required` on
  save. Nothing read it: `GET /api/v1/applications` and its list never
  returned the field, so the box always showed its default (checked).
  Nothing wrote it: the admin update path's allowlist ignored the key and
  its sync to the backing `oauth_clients` row did not carry it. An
  administrator who unchecked the box saw it come back checked, and a
  client registered without PKCE stayed without it whatever the box said —
  a control that displays without enforcing. The applications GET and list
  now join the backing OAuth client (on `client_id` within the tenant) and
  return `pkce_required` and `back_channel_logout_uri`, omitting both for a
  tile with no client behind it (a proxy-app tile); `PUT
  /api/v1/applications/{id}` accepts both and writes them to the OAuth
  client, validating the URI with the same rule as the OAuth store and
  dynamic registration (https, or http on localhost; `400` and nothing
  written otherwise), and a payload naming only these two fields is a
  valid update. The edit dialog gains the back-channel logout URI field and
  initialises both from the application; the register dialog offers the
  URI too. English and Turkish strings added. Measured against a migrated
  PostgreSQL: the detail and list report each tenant's own client row and
  omit the keys for a tile; an update lands on the backing client and only
  there, clearing persists, an unrelated edit disturbs neither, a
  client-only payload is accepted; an insecure URI is refused before any
  row is written and the handler answers 400. Seven server mutations and
  three console mutations red, no-op controls green.
- **The login page renders the consent challenge; before, consent dead-ended
  every login.** `application_sso_settings.require_consent` has been enforced
  server-side since #513: when an application requires approval and none is
  on record, `/oauth/login` (and every other completion endpoint) answers
  `200 {consent_required, consent_session, client_name, scopes}` instead of a
  `redirect_url`, and the decision is expected at `POST /oauth/consent`. No
  client of that endpoint existed. The admin console's login page handled
  `mfa_required`, `concurrent_limit_reached` and `redirect_url` and nothing
  else, so the consent answer left it silent: no error, no redirect, no
  screen, and the person stayed on the login form with a spent
  `login_session`. Turning "Require consent" on for an application made it
  unreachable through the browser. The page now hands every completion
  response (password, MFA verify, WebAuthn, push, passkey, QR poll,
  force-login) to one `finishAuth` helper that renders a consent screen
  (application name, requested scopes, Allow / Deny) for a challenge and
  follows `redirect_url` otherwise; the decision is posted to
  `/oauth/consent` and its `redirect_url` (the code on Allow, `access_denied`
  at the client on Deny) is followed the same way. A source census in the
  page's tests fails if any completion path follows `redirect_url` on its
  own again. English and Turkish strings added. Five mutations (challenge
  ignored, decision always Allow, `consent_session` omitted, MFA path
  bypassing the helper, spent challenge kept after a refusal) each red with
  the new tests; a no-op control green.
- **The v2 consent POST binds only the caller's own live session.**
  `POST /oauth/authorize/v2` accepts a client-supplied `session_id` "for
  linkage" and bound it to the code unverified; the token endpoint then read
  `sid`, `amr` and `auth_time` from whatever session row it named, scoped to
  the tenant but not to the user. The access service trusts `amr` to decide
  whether MFA happened (device auto-trust, enrollment sessions), so an
  authenticated user who knew another user's session id could mint tokens
  for themselves that carried the other user's `amr`, `sid` and `auth_time`.
  This was the only place a client-supplied session id reached a code; the
  login flows bind server-created sessions. The handler now requires the id
  to be a live, unrevoked, unexpired session of the authenticated user in
  the request's tenant and answers `400 invalid_request` otherwise — a
  mismatch is a client bug or an attempt, and both should be visible rather
  than silently dropped. Measured against a real PostgreSQL: another user's
  session, the caller's revoked session, an unknown id and a malformed id
  are all refused with nothing minted and no binding written; the caller's
  live session binds as before and an omitted `session_id` is unchanged.
  Writing that last test found a second defect in the same handler: after
  minting it re-read the stored authorization request to build the redirect,
  but the mint had just consumed (deleted) that request, so every successful
  consent answered `500 server_error` — the endpoint's success path had
  never completed. The redirect is now built from the request read before
  the mint. Five mutations (ownership check removed, `user_id` filter
  dropped from the query, liveness filter dropped, tenant filter dropped,
  redirect built from the post-mint re-read) each turn a test red; a
  comment-text control stays green. The tenant-filter mutation stayed green
  on the first pass — no test exercised a session of the same user in
  another tenant — and that branch now has one.
- **A role-assignment review shows what the assignment grants.**
  `populateRoleAssignmentItems` was `return s.populateUserAccessItems(...)`
  under the comment "Same as user access for now", so the `role_assignment`
  and `user_access` review types produced identical rows. It now walks
  `composite_roles` (the edges `internal/access/privgraph.go` already uses
  to decide who can reach a resource) and names each direct assignment with
  its effective reach: `platform_admin (also grants: auditor, reader)`. One
  item per direct assignment remains, because removing that row is the only
  lever a revoke has; the type is `role_assignment`, which
  `jitgrant.Revoke` now maps to the same `user_roles` delete as `role`.
  Disabled users are left out, the walk is bounded and a cycle terminates,
  and the root role is not listed in its own reach. Measured against
  PostgreSQL: with a composite `platform_admin → auditor → reader` and a
  cycle back to the root, the review names the reach, the user-access
  review of the same data names only `platform_admin`, and revoking the
  item removes the assignment. The governance guide's review-type table
  described items the code never produced (user access "to one
  application", application access as "one application's set of users",
  no `privileged_access`); it now says what each type populates.
- **A real super admin is treated as one by every identity handler.** The
  elevated role is spelled `super_admin` (`auth.RoleSuperAdmin`, the SQL
  seed, the console, the route gate), but ten inline checks in
  `internal/identity`, in the login-history, device-trust-request,
  bypass-code list, bypass-code revoke-all and bypass audit-log handlers
  and the lifecycle-execution list, compared roles against `superadmin`.
  A super admin passed the route gate and then got 403 on another user's
  records, or was silently narrowed to their own when they asked for all.
  Measured with the handler: `super_admin` asking for another user's login
  history was 403. The ten checks now call the one helper,
  `identityCallerIsAdmin`, which accepts `admin` and `super_admin` and
  refuses the look-alike; the portal's helper does the same. A test drives
  the login-history handler both ways, and an AST guard fails the package
  when any Go file under `internal/` or `cmd/` compares against the legacy
  literal again (the privileged-account discovery list, which names other
  systems' spellings, is the one exception).
- **The License Compliance job said what it intended, not what it did.**
  Its npm half ran `license-reporter` without a subcommand, which printed
  usage and wrote no file, behind `|| true`; its summary then wrote
  "License reports generated for Go and NPM dependencies". The npm report
  is now produced by `license-checker-rseidelsohn` (432 production
  packages when run here), the Go steps no longer hide their exit code
  behind `|| echo` (the job stays informational through
  `continue-on-error`, but a failed step shows as one), `go-licenses` is
  pinned to v1.6.0, and the summary reports each artifact's presence.
  `CONTRIBUTING.md` sent bug reports to an issue tracker under an
  organisation that does not host this repository.

- **The console's API-docs page shows the API, not a stale copy of it.**
  `web/admin-console/public/api-specs/` held ten hand-written OpenAPI files
  that a comment called "copied from `api/openapi/` by the build". Nothing
  copied them: they were stamped 0.1.0, last touched 2026-08-24, and each
  held a fraction of the canonical spec's routes (access: 49 paths against
  267); three of the ten were listed nowhere on the page, and their routes
  already live in the canonical identity and admin-api specs. The ten files
  are deleted. A vite plugin serves `api/openapi/*.yaml` at `/api-specs/` in
  development and copies them into `dist/api-specs/` at build time, and
  refuses to build without the directory rather than publish an empty
  list; the console image copies `api/openapi/` to where the plugin looks.
  `api-specs.test.ts` holds the page's list and the directory to each other
  in both directions. `RELEASING.md` said "all ten OpenAPI specs"; there are
  seven, and now the sync guard, the page and the document agree.

- **A dispatched release attaches the mobile artifacts.** `release.yml`'s
  dispatch path handed off to `docker.yml` so the images got their version
  tags, and to nothing else. `client-mobile-release.yml` runs on a pushed
  tag, a token-created tag starts no workflow, and so v1.36.0 was published
  with eight binaries and a signed chart and no APK or IPA, while v1.34.0
  (pushed tag) and v1.35.0 (a maintainer dispatched the mobile workflow by
  hand) had both. The same job now dispatches `client-mobile-release.yml` on
  the tag it created; `scripts/check-release-dispatch.sh` holds that
  hand-off, the workflow's dispatchability and its tag-ref upload gates, with
  three red cases in its self-test. `RELEASING.md` names the second run to
  check before announcing. v1.36.0's artifacts were attached by a manual
  dispatch on the tag on 2026-09-19.

## [1.36.0] - 2026-09-18

### Fixed

- **The mobile engine builds again.** `client-mobile-build.yml` and
  `client-mobile-release.yml` called `android-actions/setup-android@v3`
  with no package list; v3's default asks sdkmanager for the legacy
  `tools` package, which the SDK repository stopped offering, so the
  gomobile Android job died in setup ("Failed to find package 'tools'")
  on a commit that changed only a version number. Both now use v4 with an
  explicit list (`platform-tools`, the pinned NDK), the shape
  `ci-android.yml` already had.

### Added

- **The docs say what CI proves, and CI proves what the docs say.** Three
  claims measured on 2026-09-18 and made true rather than deleted. (1) The
  global-scale plan has said since 2026-09-13 that the static chaos drill
  (`make k8s-chaos`) runs on every PR; no workflow ran it, and run for the
  first time it was red: the OPA Deployment lacked `preStop`,
  `terminationGracePeriodSeconds`, `topologySpreadConstraints` and a
  `rollingUpdate` strategy, the one Deployment of eleven the always-on
  profile did not cover. The chart now gives it all four (the preStop is the
  Kubernetes sleep handler, because the OPA image has no shell), and the
  Helm lint job runs the drill with kubeconform and promtool installed, so
  "not measured" cannot read as a pass. (2) `terraform.yml` validated five
  of ten Terraform directories. The Azure root and the rds, elasticache,
  openziti and audit-service modules join the matrix; validated standalone,
  two were broken — the openziti and audit-service modules write helm 2.x
  `set {}` blocks and pinned no provider, so alone they pulled 3.x and
  failed on the first block; audit-service also defined the
  `production_safe` output twice and wrote its ConfigMap label keys
  unquoted, which HCL reads as a resource reference, and no root calls
  that module, so nothing had ever parsed it. All fixed. (3) Four documents said
  things the tree did not: `PROJECT-STATUS.md` was a May snapshot calling
  Helm and Terraform incomplete (rewritten as a one-page current snapshot
  that points at the authorities); `evidence/release-gate.md` recorded
  v1.34.0 as "not cut" after v1.34.0 and v1.35.0 had both shipped signed
  (rows written from the releases and runs, dated as written after the
  fact); the operator guide asked operators to confirm "digests pinned"
  when nothing in the repository pins a digest, and said Terraform covers
  only AWS when an Azure root exists; migration 042's comment called three
  tables unimplemented that migration 043 creates.

- **A condensed operator guide** (`docs/docs/deployment/operator-guide.md`,
  in the docs nav and linked from both READMEs): the fourteen sections an
  operator reads instead of six thousand lines of readiness notes. What you
  run, the install paths, the secrets and the production gate, the first
  install and its verification, what is enforced and how to check it in a
  minute, upgrade and rollback, the scale knobs in the order to turn them
  on, cells and the release wave, backup and the drills, the alerts that
  matter, the recurring controls, the six failures you will actually hit,
  and what is not done and not claimed. Writing it caught a stale claim in
  the chart's own values file: the two-pass fresh install was documented as
  "zero only the pooler", which stopped being a first pass when every pooled
  service gained the `wait-for-pooler` init container (finding 6 below); with
  the pooler at zero the services sit in Init forever and `--wait` deadlocks
  the same way. Measured by render: the three running services in the cell
  overlay each carry the init container while the pooler has zero replicas.
  The values file and the guide now say `--set pgcat.enabled=false` for the
  first pass (services on the direct DSN, no init containers, hooks run; the
  bootstrap hook is pre-upgrade too and sets the pooler's credential before
  pgcat starts), and name the kind-cell job's shape (pooler and every pooled
  service at zero) as the other one that works. The `enabled=false` pass is
  reasoned from the hook phases and checked by render, not run live.

- **The cell shape, installed and driven on kind** (global-scale plan 4.2/4.3,
  the half a build environment can measure). Every switch the plan added was
  a switch the lint job could only prove RENDERS: the transaction pooler with
  `RLS_MODE=local`, the read replica, the identity plane split, the cell id
  and the guard that reads it. A new `values-ci-cell.yaml` layers all of them
  over `values-ci.yaml`, and a new `kind-cell` job in `helm.yml` installs it
  with this tree's `identity-service` and `oauth-service` behind them and
  asserts against the live cluster: migrations landed through the direct DSN
  and replicated to the streaming replica while the services connect through
  pgcat; the tenant belt holds THROUGH the pooler as `openidx_app` (no scope,
  zero rows; a transaction-local bypass, the seeded rows; the statement after
  COMMIT, zero again); two identity Deployments each serve only their plane
  (`/users` is 401 on the admin half and 404 on the auth half, the WebAuthn
  credential list the mirror image), both healthy through the pooler and
  reading the replica; a `client_credentials` token carries `cell: canary-1`
  and a live admin pod serves it; and once the tenant directory places that
  tenant in `eu-1`, the issuer stamps `eu-1` and the same pod answers
  `421 Misdirected Request` with `X-OpenIDX-Cell: canary-1`, then serves
  again when the placement moves back. No forged token: only the placement
  changed. Two helm passes on purpose, because `--wait` holds post-install
  hooks until every Deployment is Ready and a service that needs the schema
  would deadlock the migration that provides it. **Measured while building
  it, and fixed in the chart:** (1) `postgresql.architecture=replication`
  renames the primary's Service to `-postgresql-primary`, and every DSN the
  chart built spelled the standalone name, so turning replication on broke
  every connection string at once; one `openidx.postgresHost` helper now
  feeds the DSN Secret, the plane DSNs, the bootstrap hook, the migration
  Job's wait and pgcat's upstream. (2) pgcat authenticates upstream as
  `openidx_app` with `pgcat.password`, and migration v53 creates that role
  passwordless, so with the bundled PostgreSQL the pooler could never log in
  and every service behind it was down with the install green; the bootstrap
  hook now sets the role's password from the same value, via psql variable
  quoting. (3) The bundled database had no read-replica wiring at all
  (`DATABASE_READ_URL` existed only in external-secrets mode); new
  `database.bundledReadReplica` points it at `-postgresql-read`, refuses to
  render without the replication architecture, and the Postgres
  NetworkPolicy now admits traffic to the read pods too, which it did not.
  (4) Measured by the job's own first run: a FRESH `helm install --wait`
  with pgcat and the bundled database deadlocks, because the role pgcat logs
  in as is created by a post-install hook that `--wait` holds until every
  Deployment is Ready, and pgcat exits at startup when the login is refused.
  Twelve minutes of `Role "openidx_app" does not exist` and a
  CrashLoopBackOff with the hooks never created. The job's first pass now
  keeps the pooler at zero too, and `values.yaml` says why an operator has
  to do the same on a fresh cell. (5) Measured by its third run: the pooler
  had no NetworkPolicy of its own, its pods carry the label the chart's
  default-deny selects, and kind enforces policies, so a healthy pooler
  holding upstream connections was unreachable by every service for twelve
  minutes. `-pgcat-allow` now admits exactly the eight services the DSN is
  repointed for, and the lint job asserts the two sets agree. (6) Measured
  by its fourth run: the upgrade that turns the pooler on rolls it and the
  eight services together; the services dial first, fail fast by design,
  and CrashLoopBackOff's growing delay put convergence ten minutes out, past
  `--wait` and past what an `--atomic` upgrade would tolerate. Each pooled
  service now carries a `wait-for-pooler` init container, and the lint job
  asserts every repointed Deployment has it. (7) Measured by its sixth run,
  once everything before it held: the issuer's NetworkPolicy admitted only
  the gateway and the admin console, but seven services verify bearer
  tokens by fetching `/.well-known/jwks.json` from the oauth-service
  directly, so on an enforcing CNI the hardened profile answered 401 to a
  token the issuer had minted seconds earlier (`failed to fetch JWKS:
  context deadline exceeded`) with every health check green. Latent in every
  install with `networkPolicy.enabled` on a CNI that enforces it; the plain
  kind job could not see it because it never presents a token, and to its
  plane-split step a 401 is the expected answer. `-oauth-service-allow` now
  admits the token verifiers, and the lint job derives that set from the
  rendered manifests (who carries `OAUTH_JWKS_URL`, directly or through the
  ConfigMap) and asserts each one is admitted. **Not proved, and said so in
  the values file:** load and failover timing,
  three Redis roles on three instances, `database.planeRoles` (interlocked
  with the pooler by design), ingress and external secrets. Those wait for a
  real cell.

- **The device fleet is one tenant's** (migration v197; global-scale plan 4.5
  and the last product decision the orgscope register was waiting on).
  `enrolled_agents`, `agent_posture_results` and `agent_enrollment_tokens`
  had no `org_id` for 196 migrations, on a decision three comments in
  `internal/access` asserted and v159 already found wanting: a kiosk policy
  could be aimed at a device another tenant managed, because "somebody else's
  device" was not a thing the schema could express. Measured first, against
  the real schema: the admin fleet list, revoke and approve were the
  installation's, not the organization's; a token minted in one tenant
  enrolled a device that every tenant's console then listed; and the
  per-tenant enrolment quota the plan asks for had no column to count on.
  **Decided per-tenant**, because the fleet is administered, revoked, listed
  and locked down from one organization's console, and every other
  per-organization table in the product is belted the same way. v197 adds
  `org_id` to the three tables, backfills most-exact-first (a token from the
  user who minted it; a device from the user who enrolled it, then from the
  token that admitted it, then from the known device it is linked to; posture
  from its agent; the rest to the oldest organization), makes it NOT NULL with
  a cascade to `organizations`, replaces v93's install-wide device-fingerprint
  key with a per-tenant one so one physical machine may be managed by two
  tenants, and puts all three under `FORCE ROW LEVEL SECURITY`. Every fleet
  query in `internal/access`, `internal/portal`, `internal/identity` and
  `internal/oauth` now carries the tenant; the admin handlers refuse a request
  with no organization on its context (403) and answer 404, not 200, when a
  revoke or approve matches no row of the caller's. **The two pre-tenant
  doors stay open and are said to be open:** an agent redeeming an enrolment
  token or presenting its credential arrives with no tenant, so those two
  lookups run under an explicit RLS bypass keyed by the token's SHA-256 or the
  agent id, and the row's own `org_id` is put on the request context so
  everything after them is scoped — an agent's report lands in its tenant
  and nowhere else. The kiosk resolver additionally requires the device to be
  enrolled in the policy's organization, which closes the v159 finding. The
  `needsScoping` register goes 5 → 2 (the two external-identity-link tables,
  which wait on a different decision); the compliance grace sweep is the one
  deliberate install-wide reader left and carries its reason. Two PostgreSQL
  suites: the belt as `openidx_app` (cross-tenant rows invisible, cross-tenant
  writes refused, both public doors open, a report lands in its own tenant),
  and the migration end to end (backfill source by source, the fingerprint
  key, list, revoke, approve, mint-and-enrol). Seven mutations red — the
  redeemer's bypass removed, the list's predicate dropped, one backfill step
  removed, the install-wide key kept, ENABLE removed, FORCE removed, the agent
  auth no longer putting the row's tenant on the context — and the no-op
  control green. FORCE was expected to be latent (the runtime role is not the
  owner) and was live in both suites: the belt fixture's role owns the table
  it builds, which is exactly the single-role install where FORCE is what
  belts it.

- **The global-scale plan says where it stops** — a closing section in
  `docs/plans/2026-09-13-global-scale-cell-architecture-plan.md` lists every
  item still open after this run (live k6 game day, pgcat and the read
  replica in `values-prod.yaml`, the remaining `Reader()` batches, sweepers
  into worker binaries, per-plane APISIX upstreams, the Terraform cell
  module, the second region and canary cell, per-cell KMS, the Ziti
  controller's L4 exposure and per-tenant enrolment quota, and the quarterly
  cadence) and for each says what remains, why it cannot be measured in a
  build environment (no cell, no cloud account, no load, or a product
  decision not yet taken), and what unblocks it. Measured where a number
  belongs: nine `internal/admin` files read from the replica today and 57
  still read the primary, which is why the next `Reader()` batch is a
  screen-by-screen decision and not a rule. Nothing is checked off by this
  entry; the acceptance rule (measured, not done) is restated, and the
  decisions the plan cannot take on its own (K2, K5, whether the device
  fleet is per-tenant) are named as decisions.

- **The release wave: canary-1, then eu-1, then us-1, and it stops at the
  first cell that does not come up** (global-scale plan 4.3, the workflow
  half). Measured first: `release.yml` built binaries, published and signed a
  chart, and deployed nothing anywhere; there was no place a cell-sequenced
  rollout could attach. There is now a reusable
  `.github/workflows/rollout-cell.yml` — one cell per call, in the GitHub
  environment `cell-<id>` (where that cell's `KUBECONFIG` and a required
  reviewer live), `helm upgrade --install --atomic` layering `values-prod.yaml`
  and the cell's own `deployments/kubernetes/cells/<id>.yaml`, and a
  post-deploy read of `CELL_ID` from the deployed ConfigMap that refuses a
  cell answering as another cell — and three jobs in `release.yml` that
  `need` each other in wave order. **Off by default:** the wave runs only
  where the repository variable `CELL_ROLLOUT` is `"true"`, so a release on
  an install with no cells is exactly the release it was. A new guard,
  `scripts/check-release-rollout.sh`, pins the shape (order, no
  `always()` on a later cell, gate, `secrets: inherit`, `--atomic`,
  environment, identity check, each values file naming itself) and its
  self-test goes red on ten bent shapes. **Not measured, not claimed:** a
  live rollout — there is no cell to roll out to in this environment — and
  the bake between cells (whether canary-1 is healthy rather than merely
  up), which is the required reviewer on `cell-eu-1` until it is automated.

- **Each identity half can be pinned to its own node pool** (global-scale
  plan 3.4, the placement half of "APISIX upstreams per plane;
  `nodeSelector: plane=issue` separate node pool"). Measured first: the chart
  had no `nodeSelector` or `tolerations` anywhere, so `identityService.planeSplit`
  produced two Deployments that still shared every node, and ADMIN load could
  still take ISSUE's CPU. `planeSplit.auth` and `planeSplit.admin` now each
  take `nodeSelector` (the pool's label) and `tolerations` (its taint), both
  empty by default and rendered only when set, so an install that never named
  a pool schedules exactly as before, and that absence is asserted (a rendered
  `nodeSelector: {}` is not none). Own step in the Helm workflow renders both
  modes. Four mutations red (selector never rendered, both halves given the
  auth pool, tolerations dropped, empty selector rendered anyway), no-op
  control green. **Not done, and said so:** per-plane APISIX upstreams. The
  Docker edge runs one `identity-service` container, so a per-plane upstream
  has nothing to point at until that stack also runs two profiles, and its
  routes are hand-written rather than generated from `identity-planes.json`
  the way the Ingress rules are; both are the same decision and it is not
  taken here.

- **A signing key names the cell that minted it, and a token names the key
  that signed it** (global-scale plan 4.4, code half). `signingkeys.NewStore`
  takes the cell id: every kid the store generates or rotates is now
  `<cell>-key-<hex>` (`openidx-key-<hex>` on a single-cell install, so nothing
  changes where `CELL_ID` is unset), and the legacy import keeps
  `openidx-key-1` in any cell because pre-upgrade tokens carry that name. The
  `<n>` is random hex rather than a counter: nothing coordinates a counter
  across replicas and the kid only has to be unique and legible. **This is
  attribution, not isolation:** a cell refuses another cell's token because
  its own JWKS does not hold the kid, whatever it is called (pinned by a
  cross-cell verification test: another cell's token is refused naming the
  foreign kid, a leaked foreign key wearing this cell's kid fails on
  signature, this cell's own token verifies); the prefix is what makes that
  refusal readable in a log. **Found while measuring:** the step-up JWT
  (`generateStepUpToken`) stamped the literal kid `openidx-key-1` while
  signing with whatever key was active, so on every fresh install (whose
  first key is generated, not imported) and every install after its first
  rotation the token named a key that had not signed it. Latent, since
  nothing in the tree verifies that token; fixed anyway, since it is a token
  the product hands out. It now carries the signer's kid, and an AST census
  refuses any kid header in `internal/oauth` set from a string literal. Five
  mutations red (prefix ignores the cell, store drops the cell, rotation
  keeps the single-cell prefix, legacy import renamed into the cell, literal
  kid restored), no-op control green. Own CI step. **Not done:** OpenBao/KMS
  per cell is infrastructure; `cmd/rekey` needs no cell scope because it
  re-encrypts one database and a cell is one database.

- **One redeemer for the enrollment token, and the spend is a claim** — an
  admin/MDM enrollment token (`agent_enrollment_tokens`) admits a device on two
  public routes, the agent's `POST /agent/enroll` and the dark-mode
  `POST /api/v1/access/enroll`, and each carried its own copy of the check.
  Measured against the real table: the dark-mode copy read `expires_at` and
  never compared it, so a token issued for 24 hours admitted a device for ever
  (live defect); the agent copy compared it but marked `used_at` with a warning
  on failure, so a single-use token that could not be spent was accepted and
  stayed spendable (latent: needs the UPDATE to fail); and neither made the
  spend a claim: with the old SELECT-then-UPDATE shape reproduced, twenty
  concurrent redemptions of one single-use token admitted 12, 20, 12, 7 and 12
  devices in five rounds, and 19 through the agent route (live, measured). Both routes now call
  `redeemEnrollmentToken`: unknown, revoked and expired tokens are refused on
  both, a single-use token is spent by
  `UPDATE ... SET used_at = NOW() WHERE id = $1 AND used_at IS NULL` and zero
  rows is a refusal, a spend that fails returns the failure (the agent route
  answers 503 and mints nothing) and a reusable fleet token is never spent but
  still expires. Seven tests against PostgreSQL (fixture DDL taken from the
  registered v43 and v86 migrations, twenty racers on one row, a trigger that
  makes the spend fail) and a shape census that every non-test file in the
  package satisfies: a lookup of the token table by the presented `token_hash`
  and any `SET used_at` live only in the redeemer, and both redemption
  functions call it. Seven mutations red (expiry dropped, claim predicate
  dropped, row count ignored, failed spend tolerated, reusable waiving expiry,
  a private copy of the lookup, a second spend site), one no-op control green.
  Own CI step with named pass checks. **Not done, and said so:** the plan's
  "N enrolments per tenant per hour" cannot be enforced on this table, which
  carries no `org_id` (it is on the needs-scoping register behind the
  is-the-fleet-per-tenant decision); the Ziti controller's own L4 exposure is
  infrastructure. The `used_at IS NULL` claim also closes the window between a
  session cancel's `revoked = true` and a spend already in flight only for the
  spend; a revoke racing the SELECT is still admitted once, by design of the
  two-statement shape, and the token was valid at the moment it was read.

- **Four open plan items closed by decision, not by code** — the event path
  is an accelerator, never the only route for a security-critical outcome, and
  that decision now settles the items that were waiting on it. Migrating the
  SSF and SCIM outbound queues onto the shared outbox: **won't do** (both are
  durable, claim-based PostgreSQL queues already; the move would put two
  security-critical deliveries behind a broker whose chart default is off).
  Making the webhook deliverer an outbox consumer: **won't do** (v194 made
  delivery a claimed row; the remaining step would only have changed the
  carrier). The "nothing writes to the outbox and nothing runs the relay" note:
  **closed** by `cmd/event-relay` and the producers census. The kill-switch
  event to a Ziti reconciler: **superseded** by the synchronous sever
  `executeKillSwitch` already performs in-request (Ziti sessions terminated and
  identity deleted on the controller, Guacamole sessions closed, PAM leases and
  tokens revoked, every step reported by name in `warnings`). Not measured and
  not claimed: the controller call's own latency.

- **An SSF stream configuration now says what the stream will get** —
  `events_delivered`, computed from the one list the discovery document
  advertises, and a stream that could never deliver is refused instead of
  created enabled and left silent.

  The discovery document was made honest earlier: `events_supported` names
  what this transmitter emits and nothing else. This is the same honesty one
  step later. A receiver posts `events_requested`; the Shared Signals
  Framework answers with `events_delivered`, the intersection with what is
  supported, and OpenIDX answered with the request echoed back and an enabled
  stream. A receiver that asked for `credential-change` — never sent — was told
  nothing and waited. The stream configuration and the discovery document were
  two places that could disagree, and the receiver only ever reads the second.

  - `ssfEventsSupported` is now **one variable** in `ssf_handlers.go`: the
    handler advertises it and `ssfEventsDelivered` intersects against it, in
    the advertised order. An empty request means everything — the reading the
    emit side (`streamWantsEvent`) already gives it, and a test holds the two
    sides to the same answer.
  - `SSFStream` carries `events_delivered` on every read.
  - `CreateSSFStream` refuses a request whose intersection is empty, **before
    the INSERT**, with the offered list in the error where the receiver's
    operator is looking.
  - The advertised-events census reads the variable and additionally holds the
    handler's `events_supported` key to *that* variable, so a literal list
    growing back in the handler is a census failure, not a second truth.

  **Five mutations red against a green no-op control:** `events_delivered`
  echoing the request; the refusal removed (the stream is created); the read
  path echoing the request (the CRUD test against a live database catches it);
  the handler growing its own literal list (the census pin); and an empty
  request meaning nothing on the configuration side while the emit side
  delivers everything.

  Not measured: no receiver-facing HTTP round trip is driven here; the handler
  maps the create error to 400 as before, unchanged.

- **A severed account now reaches the SSF receivers that subscribed to
  `account-disabled`** — the RISC event the product advertised for months and
  never sent once, with the seam built in the place the measurement said it had
  to be.

  **The problem was structural, not an oversight.** The SSF transmitter
  (`EmitCAEPEvent`) is a method on oauth-service: it reads the tenant's streams,
  signs a SET with the issuer's key and enqueues it on `ssf_stream_delivery`,
  whose `set_jwt` column is `NOT NULL`. The paths that disable or delete a user
  live in identity, directory, admin, access, risk and provisioning — other
  binaries, no signing key, no way to call it. The earlier recorded direction
  ("a shared writer into `ssf_stream_delivery` inside the severing transaction")
  was measured against that column and does not work: a producer without the
  key has no SET to write. So the seam sits one step earlier.

  - **Migration v196, `ssf_pending_events`:** a row per signal, org-scoped
    with forced RLS, claimed with `FOR UPDATE SKIP LOCKED`, `published_at` as
    the done marker, `attempts` as the poison guard, a partial backlog index.
    The outbox's shape on purpose, and **not the outbox itself**, for two
    measured reasons: the outbox has one consumer by construction (the relay
    claims and deletes, so a second drainer would split the rows), and its
    sink is NATS, whose chart default is off — a security signal behind a
    broker the default install does not run is a signal the default install
    never sends.
  - **`internal/common/ssfsignal`:** the producer half. `Enqueue(ctx, exec,
    Signal)` takes any `Exec`-shaped handle — the pool, or the severing
    transaction — and refuses a signal with no tenant or no subject.
  - **The drainer, in oauth-service:** `StartSSFSignalDrainer` claims a batch
    under bypass-RLS, resolves the row's event type through an allow-list to
    the package's own constant (so a poisoned row cannot make the issuer sign
    an event nobody advertised), calls the same `EmitCAEPEvent` the in-process
    callers use, and marks the row published with how many streams it reached
    — so "drained into zero streams" is readable on the row and distinct from
    lost. At-least-once, in the stated direction: mark-after-emit, so a crash
    re-emits rather than loses; RFC 8935 receivers already de-duplicate on
    `jti`. Stalled claims are handed back after five minutes. The sweeps
    census in `internal/common/leader` records the drainer as claim-coordinated
    — the row lock is the coordination, so any number of replicas drain
    safely and no leader is needed.
  - **Fifteen producers wired.** `Delete` in the user repository; both HRIS
    deprovision branches; four directory-sync branches (LDAP/Azure AD
    deleted/disabled); IBDR quarantine; every admin sever (`signalAfterSever`
    beside `revokeAfterSever`: stale-account cleanup, bulk disable/delete,
    lifecycle-policy disable/delete, ISPM remediation, DSAR erasure and
    restrict); the kill switch; anomaly auto-remediation; lifecycle
    `disable_user`; inbound SCIM delete; and **offboarding, where the enqueue
    rides the severing transaction** — the one path that holds one, so the
    one where "disabled here AND the partners will be told, or neither" is
    free. Every other producer is best-effort after the sever, loud on
    failure, on the same contract as token revocation.
  - **`events_supported` grows to two**, and the advertised-events census
    (which reads the constant passed to `EmitCAEPEvent`) sees the drainer's
    call because the allow-list resolves to a constant, not a variable.

  **The sever census now asks a second question.** Beside "does every path
  that disables or deletes a user also revoke its tokens", it asks "does a
  path from it enqueue the account-disabled signal", transitively, with a
  register for the ones that must not. One entry: `applyCAEPEvent` in the SSF
  *receiver* — it applies a partner-originated disable locally, and
  re-emitting it would echo the event back to every stream, including the
  partner that sent it; two OpenIDX deployments subscribed to each other
  would loop. A receiver applies; it does not originate.

  **Measured against a live PostgreSQL, as `openidx_app` so the RLS belt is in
  force, with the v196 DDL the loader ships:** one signed SET on the tenant's
  subscribing stream, none on the tenant's stream that asked only for
  session-revoked, none on the other tenant's stream that asked for
  everything; the SET's `events` carry the RISC URI, the producer's claims and
  the email subject; a second drain does nothing. An unknown event type is
  retired with zero streams and never signed. A stalled claim is handed back,
  a row over the attempt cap is left alone, a fresh claim inside the grace is
  still the other drainer's. A tenant sees only its own pending rows and
  cannot write a row into another tenant. CI runs the four by name.

  **Nine mutations red against a green no-op control:** the drainer never
  emitting; stale claims never handed back; the attempt cap never biting; the
  fan-out crossing tenants (the `OR $1<>''` shape this transmitter once had);
  another drainer's fresh claim stolen; zero-stream rows never retired; one
  producer dropped (the census names it); the register entry misspelled (the
  census refuses an entry it cannot find); and the offboarding enqueue moved
  after the commit — `TestOffboardingIsAllOrNothing` gained a third case, a
  signal that cannot be written, and under that mutation it reports the
  leaver disabled, the operator told "offboarded", and the partners never
  told, which is the exact shape this item removes.

  **Not measured, and not claimed:** the ten-second ticker and the process
  wiring in `cmd/oauth-service` are read, not driven; the drainer's core is
  driven directly. Whether a real receiver accepts these SETs is the push
  worker's existing contract, unchanged here.

- **Placing and releasing a legal hold on a session recording now requires admin
  authority** — a decision the step-up census had recorded as undecided, made.

  `POST` and `DELETE /remote-support/sessions/:id/legal-hold` were open to any
  authenticated caller in the tenant: the group they mount on carries
  authentication and nothing else, and the handlers gate on session visibility,
  not on role. Neither opens a host nor reveals a credential, so the freshness
  gate the PAM launches carry was the wrong control — but **releasing a hold is
  what lets the retention sweep purge the recording it protected.** Both writes
  now take `requireAdminRole()`; under `STEPUP_GATE` that gate already asks an
  admin *write* for a fresh second factor, so release inherits it. The list
  (`GET .../legal-holds`) stays open: reading which holds exist grants nothing.

  `RegisterRemoteSupportAdminRoutes` now takes two named gates, `stepUp` and
  `admin`, and hands `admin` to `RegisterLegalHoldAdminRoutes`; the mount site
  in `service.go` supplies `requireFreshMFA(...)` and `requireAdminRole()`.

  **The census had to learn to follow a parameter more than one frame.** Its
  gate resolution accepted a gate passed by name and looked at the enclosing
  function's callers — one level. `RegisterLegalHoldAdminRoutes(r, admin)` is
  called from inside `RegisterRemoteSupportAdminRoutes` with the *parameter*,
  and the literal gate is one frame further up in `service.go`. On the day the
  writes were gated, the census called them ungated — correctly refusing to
  trust the spelling `admin`, wrongly stopping before the frame that spelled the
  gate. Resolution is now transitive with a depth bound of three; a caller that
  passes nothing is still an open mount. The two "undecided" register entries
  are gone — a gated route cannot sit in the register, and the test enforces it.

  A behavioural pair measures what the text-reading census cannot:
  `requireAdminRole` refuses `user`/no roles and admits `admin`/`super_admin`;
  and the legal-hold registration puts a gate in front of both writes and not
  the read, observed with a sentinel gate rather than a database.

  **Eight mutations against a green no-op control — and two of them stayed
  green on the first run, each exposing a limit in the census that was then
  closed:**

  - the mount site passing `nil` for the admin gate stayed **green**: the
    census's caller resolution accepted *any* literal gate anywhere on the
    caller's line, so the freshness gate going to a *different* parameter
    counted for the legal-hold writes. A control reporting success while the
    thing it exists to make true is not true — the fourth time this tree has
    found that shape inside a census. Resolution now follows the **parameter
    position**: which parameter the route's chain names, which argument that is
    at each call site, and what sits there (a literal gate; another parameter,
    recurse; anything else, an open mount). Red after the fix.
  - the two gates **swapped** at the mount site stayed **green by the census's
    own rule** — it accepts either gate as a classification — while letting any
    user with a fresh second factor release a litigation hold.
    `TestTheLegalHoldGateIsTheAdminGateNotTheFreshnessGate` pins the mount line
    to *which* gate goes *where*, the same shape as
    `TestTheLaunchRoutesActuallyCarryTheGate`. Red after the pin.
  - red first time: the registration ignoring the parameter (census and
    behaviour); `withGate` dropping the gate — **text unchanged, so the census
    stays green and only the behavioural test goes red**, which is why it
    exists; `requireAdminRole` admitting everyone; the caller resolution made
    non-transitive; and the read gated too (the positive-path control).

- **A privileged-session recording could be sealed twice and stop decrypting**
  — a race in the Guacamole recording sealer, measured, root-caused, and closed
  by construction.

  `TestTwoConcurrentSealersAnnounceTheSealOnce` failed on `main` in **1 of 60
  runs** with "got 32801 bytes, want 32768": `32801 − 32768 = 33`, exactly one
  seal envelope. The recording on disk was `seal(seal(plaintext))`, and one
  decrypt pass returned ciphertext. On a product that records privileged
  sessions for compliance, that is evidence an auditor cannot read by the
  documented path — and nothing on the row said so.

  **Root cause.** `sealOneGuacRecording` asked "is this path plaintext?" and
  then opened the path: **two `open(2)` calls on one name.** When the other
  replica's `rename` landed between them, the second call resolved the *new*
  inode — the other replica's ciphertext — while the sealer still held a
  "plaintext" answer about an inode no longer behind the name. It encrypted
  ciphertext. A second, independent race sat beside it: every sealer used the
  **same** temp name, `path + ".sealing"`, with `O_TRUNC`, so two concurrent
  sealers wiped each other's frames mid-write.

  **Fix, by construction rather than by lock.** `openUnsealedRecording` opens
  once and proves plaintext **on that descriptor** (`sealedFile` takes the
  `*os.File`, not the path; the probe's AES-GCM authentication is now about the
  inode that will be encrypted), seeks back to zero, and `sealFrom` encrypts
  from it into a **private** `os.CreateTemp` beside the recording. If the other
  replica renames after this open, this sealer encrypts the old plaintext inode
  and its rename replaces one valid single envelope with another of the same
  plaintext — same digest, different nonces; the row claim (`recordGuacSeal`)
  decides who announces, and the file is sound either way. `alreadySealed(path)`
  stays as a path-form wrapper for callers that only want the answer; the
  sealer itself may not use it.

  **Measured after the fix: 0 failures in 60 runs** of the racing test.

  **Driven deterministically, not by racing** (`guac_recording_seal_interleaving_test.go`):
  replica B opens plaintext and is held; A seals to completion; B seals from the
  descriptor it held → one envelope, and B's digest is the plaintext's. The
  window itself is shown as two facts — a path answer of "plaintext", then a
  fresh open yielding ciphertext — and the new API refuses in that position.
  Two sealers never receive the same temp file. The CI step
  `A recording is sealed once, and announced once` names all three, so a rename
  cannot skip them silently.

  **Four mutations red against a green no-op control:** `sealFrom` re-opening by
  path (the old TOCTOU); the temp name reverted to the shared
  `path+".sealing"`; the seek back to zero dropped (the recording loses its
  head — two tests catch it); `sealedFile` always answering plaintext.

- **The outbox has no producer, and the guard written to catch exactly that was
  watching the other end** — plus the decision it forces.

  Measured by shape, not spelling: `NewOutboxBus` has no caller outside
  `internal/common/events`; `events.Event{}` is constructed nowhere outside it;
  the only `INSERT INTO outbox` in production code is inside
  `OutboxBus.Publish` itself. **`cmd/event-relay` drains a table that nothing
  writes to.** The plan already said so, honestly, and kept the item open.
  What nothing did was *measure* it: `TestSomeBinaryRunsTheOutboxRelay`'s own
  doc said it would fail "when the answer to 'does anything actually publish
  these events' becomes no" — and it measures the drain (`NewRelay`,
  `NewNATSSink` in `cmd/`), which cannot see a producer. The answer was no and
  it was green. The defect shape this tree keeps finding, inside the guard
  written to prevent it.

  `outbox_has_producer_test.go` measures the producer end: every function under
  `internal/` and `cmd/` that constructs an `OutboxBus`, by AST. With none, the
  `noProducerYet` statement must say why; with one, that statement must be
  empty and the producer must be in the `producers` register **naming the
  completion guarantee it keeps when the broker is absent** — `nats.enabled`
  defaults false, so in the default install a publish reaches nobody. A ghost
  register entry fails; a vacuous scan fails; the consumer guard's doc now
  states its one-end scope and a test keeps the over-claim from growing back.

  **The decision this encodes — the event path is an accelerator, not a
  dependency.** The two paths proposed as first producers each already have a
  broker-free completion guarantee: the audit indexer reconciles against
  `indexed_at IS NULL` in PostgreSQL (`StartESReconciler`, leader-gated); SSF
  posts to partner endpoints over HTTP with its own durable retry queue. Moving
  either onto the bus would replace a guarantee that self-heals from durable
  state with a delivery that, in the default install, never happens — with
  `elasticsearch.enabled: true` by default, an operator would get the
  Elasticsearch they provisioned, silently empty. So: `StartESReconciler` is
  **not** retired; the audit-indexer migration item is closed as *won't do*,
  with the measurement that closed it; and the earlier proposal of a chart
  interlock is withdrawn — it would have broken the default render rather than
  fixing the dependency direction. For SSF's `account-disabled`, the seam
  problem is real (sever paths live in other services) and the decided
  direction is a shared writer into the existing `ssf_stream_delivery` queue,
  inside the severing transaction — broker-free.

  **Seven mutations against a green no-op control:** six red (statement emptied
  with no producer; a producer with an empty register; a producer registered
  but the statement left stale; a ghost register entry; the consumer guard's
  over-claim restored; the census pointed at an empty tree) and one
  **deliberately green** — producer + register + statement cleared, the
  legitimate future state, which is the positive path's control.

- **Security: any authenticated user could take interactive control of any
  enrolled device in their tenant** — and the census written to catch exactly
  this could not see the route, three times over.

  `POST /api/v1/access/remote-support/sessions` starts a remote-control session
  on a named agent. Its default mode is `interactive`, not `view`. It carried
  **no authorization gate at all**: the group it is mounted on has
  `promoteWebSocketBearer` and the authentication middleware and nothing else,
  `HandleStartSession` checks tenancy and request shape but neither role nor MFA
  freshness, and the device-side consent that looks like a second control is
  **chosen by the caller** — `consent_required` is a field in the start request
  body and it defaults to `false`. Measured, not inferred, from the route table,
  the group's middleware chain and the handler.

  It now carries `requireFreshMFA("remote_support.start_session")` at the same
  enforcement point as `POST /pam/apps/:id/launch`, because taking interactive
  control of a device is that same act. The gate is passed into
  `RegisterRemoteSupportAdminRoutes` as a parameter: it is a method on `Service`
  and that handler has none.

  **Why the step-up census missed it.** `stepup_route_census_test.go` read one
  file (`service.go`), matched one group name (`api`), and looked at one path
  prefix (`/pam/`). Measured: `internal/access` registers **23 mutating routes
  in five other files**, on the receivers `r`, `router` and `publicAgent` — any
  one of the three limits was enough to hide this route. A guard keyed on a
  spelling cannot see work that uses none of them. The file and the receiver are
  gone as limits: the census now reads every non-test file in the package and
  accepts any receiver. The **path prefix cannot go**, because nothing in the
  tree says which routes open privileged access — that is the judgement the
  census exists to make somebody write down. So it stays and is named as a
  `privilegedSurfaces` **vocabulary** rather than left to look like a census,
  each entry is checked to still match a route, and the residual blind spot — a
  privileged surface under a fourth prefix — is stated rather than left to be
  discovered.

  The newly visible remote-support routes are classified: session start gated;
  ending a session, the recording upload pair and the device's own consent
  callback registered with reasons. Two entries record something **undecided
  rather than settled**: placing and releasing a legal hold on a session
  recording grants no host access, so the freshness gate is the wrong control —
  but they are governance actions open to any authenticated caller in the
  tenant, and whether they should take `requireAdminRole()` is a decision nobody
  has made. Written down so it gets made rather than inherited.

  **The first version of this census's own gate check was wrong in the way this
  file exists to catch, and a mutation is what found it.** It accepted the
  literal `privileged...` in a registration line as proof of a gate — so
  deleting `svc.requireFreshMFA(...)` from the mount site left the census
  **green**: a control reporting success while the thing it exists to make true
  is not true. A variadic gate is now *resolved*: the parameter proves nothing,
  and the census reads every call of the enclosing function and requires a real
  gate in the arguments of **all** of them. One gated caller out of two is a
  service guarded on one port and open on another.

  **Seven mutations red against a green no-op control** run either side: the
  gate dropped at the mount site (the one that initially stayed green, and the
  reason `gatedBy` exists); `/remote-support/` deleted from the vocabulary; a
  prefix that matches no route; the scan narrowed back to `service.go`; the
  receiver narrowed back to `api`; a register entry deleted; and a second,
  ungated mount of the same helper.

  What is measured here is the *registration*: that the route carries the gate.
  That the gate itself refuses — fails closed on an unreadable session, honours
  the console window, lets machine callers through — is measured where it lives,
  in `stepup_gate_test.go`, and is unchanged.

- **The cell guard's blind spot: the mount was measured, what could reach it was
  not** — two registers that said what they covered and nothing about what they
  did not.

  `cmd/cell_guard_census_test.go` recorded which binaries mount `cell.Guard`,
  read off the text of `main.go`. It named **seven binaries; `cmd/` holds
  seventeen.** The other ten were not exempt and not deferred — they were
  *invisible*, which is worse than either, because nothing would ever have
  mentioned them. A list can be a vocabulary or a census; this one read as a
  census and behaved as a vocabulary. The universe is now derived from the tree:
  every directory under `cmd/` with a `main.go` must appear in exactly one of
  `mounts`, `unmounted` (request-serving, guard not mounted, **with the
  reason**) or `notRequestServing`. Closing it **found no defect** — all ten are
  legitimately out of scope, and their reasons are written down
  (`gateway-service` does not authenticate at all; `verify-service` serves only
  JWKS and has no caller identity; `event-relay`'s HTTP surface is `/health` and
  `/metrics`; `demo-app` is a demonstration relying party; six are CLIs or batch
  jobs). That is the honest result and it is worth what a defect would have
  been: the next one cannot be invisible.

  The classification is **checked rather than trusted**: a binary filed as
  answering no requests must not contain a listener, or the cheapest way to
  satisfy the census would be to file a new service under `notRequestServing`
  and never think about it again. An exemption that writes itself is the defect
  shape this branch keeps finding. A mirror check requires the listener
  spellings to still match the servers, because a guard keyed on a spelling that
  matches nothing passes forever.

  The second blind spot cannot be closed from `cmd/` at all, and it is the one
  that nearly shipped a defect: **mounting the guard says nothing about whether
  the authentication in front of it binds the claim the guard reads.**
  `identity-service` bound roles by hand and never bound the cell claim, so a
  guard mounted there would have answered 200 to every misdirected request while
  the census recorded it as guarded. That was fixed; the *property* was still
  not measured. `internal/common/middleware/cell_credential_census_test.go` now
  measures it as a census of **credential kinds** rather than of mounts — real
  RSA-signed tokens, a real JWKS endpoint, the real middleware, the guard
  mounted in the order every binary uses. Of the five ways a caller can
  authenticate here, three are refused with a 421 and **two cannot be refused at
  all**:

  - **an API key** carries no claims. `AuthWithAPIKey` looks it up by its
    globally-unique hash in *this* process's own database and binds `user_id`,
    `org_id`, `scopes` and `roles` from the row, returning before
    `BindSubjectClaims` is reached — measured: the cell key is left unset and
    the guard serves. That is **correct**: a key that validated here is a row
    this cell holds, so there is nothing misdirected to refuse. The cost is on
    the other side and is **not fixable here** — a valid key belonging to a
    tenant in another cell is simply absent from this database, so it comes back
    `401 invalid API key`, a credential error for what is really a routing
    error. Telling those apart needs the tenant directory, and `cell.Guard`
    deliberately has no database dependency.
  - **an anonymous request** under `SoftAuth` names no caller and therefore no
    tenant, so there is no cell it could have been misdirected from.

  **Nothing here is a live defect.** Both exemptions are correct today for the
  reasons recorded against them. What was live is only the silence: an operator
  reading "access-service mounts cell.Guard" had no way to learn that one of its
  two authenticated paths can never produce a 421. The exemptions are now
  measured, so a change that makes one of them false fails the build instead of
  shipping — and a control asserts the same credential naming the *serving* cell
  is served, without which a middleware that rejected everything would satisfy
  the census.

  **Ten mutations red against a green no-op control**, run either side:
  `BindSubjectClaims` no longer binding the cell claim; the guard calling
  `c.Next()` instead of refusing; the guard refusing *everything* (caught by the
  control, which is the point of it); `api_key` deleted from the blind-spot
  register; the API-key branch binding the claim after all; the register naming
  a credential kind nothing produces; a binary dropped from every register; a
  binary filed in two; a CLI growing a listener; and the mirror check looking
  for a spelling nothing uses.

- **A test that reported on the scheduler rather than on the code** — `Go CI`
  went red on `main` at `323f692` in
  `TestOnlyOneReplicaClaimsACertificateRotation`, and the honest answer was
  neither "flake" nor a defect in the rotation.

  The test raced two replicas at one certificate and asserted that **exactly
  one** stood down. Measured here: **6 failures in 20 runs.** The cause is
  structural. `RotateCertificate` claims with
  `UPDATE ... SET status='rotating' WHERE id=$1 AND status='active'`, and that
  claim is exclusive — but the CA path, which the test uses because it completes
  without a Ziti controller, refuses the certificate and calls
  `revertCertStatus`, putting the row straight back to `active`. The claim lasts
  microseconds. Whether the second replica stood down depended on whether its
  `UPDATE` landed inside that window, so **"exactly one of two concurrent
  replicas stands down" was never a property of the code** — it was a property
  of the scheduler.

  Replaced with the three things that are true:

  - **A held claim excludes everyone else**, asserted with the claim held
    outright rather than raced for, so there is no window to lose. It also
    requires the stand-down to be `errRotationNotClaimed` and not a bare error,
    because the expiry monitor's log level is chosen from exactly that
    distinction — an operator who watches a security-relevant rotation "fail"
    every hour learns to skip the line.
  - **A released claim is taken again**, which is *why* the old assertion could
    not hold: two sequential claims on a CA certificate are two no-ops, not a
    duplicated rotation.
  - **Under any interleaving**, each racer either stood down or took the claim
    and refused the CA certificate — no third outcome — and the row is left
    `active` either way, because a certificate parked in `rotating` is one no
    replica will ever pick up again.

  0 failures in 30 runs, against 6 in 20 before. Four mutations red against a
  green no-op control: the claim losing `AND status='active'`; the refusal
  parking the certificate in `rotating`; the stand-down no longer wrapping
  `errRotationNotClaimed`; and a CA certificate reported as successfully
  rotated. The CI step's named `--- PASS:` checks were updated with it — a
  renamed test that nothing looks for is the silent skip those checks exist to
  prevent.

- **The scope lint now sees the connections it could not, and a rekey that could
  have silently rewritten nothing now refuses to start.**

  `tools/orgscope`'s `Raw()` rules both begin from a `ScopedPool`, because that
  is the type task 2.1b put the tenant scope into. **A connection opened with
  `pgx.Connect` or `pgxpool.New` never becomes one** — it is not `Raw()`, it is
  not `Pool`, it is a different object — so neither question is ever asked about
  it. The lint was watching the marked door and not the wall beside it. Measured
  on this tree: six non-test files under `internal/` and `cmd/` open a
  connection that way. Each is now registered with the reason its work has no
  tenant to carry, and a new one is a blocking finding until somebody writes
  that sentence.

  **The register caught its author on its first run.** Three of the entries I
  wrote from memory rather than from the measurement — `cmd/migrate/main.go`
  (which reaches the database through `Raw()`, not a direct connection) and two
  files under `internal/common/database` (which the rule skips by design, since
  that package *builds* the scope) — and `TestTheDirectConnRegisterDoesNotRot`
  named all three. An entry for code that does not do what it says reads as a
  reviewed decision and is not one.

  **And the live defect the census led to.** `cmd/rekey` rewrites every tenant's
  encrypted columns, so it takes the cross-tenant bypass — with a single
  `pool.Exec`, best-effort, error discarded. `set_config(..., false)` is
  SESSION-scoped: it belongs to one backend, and a pool is many. Probed against
  a real server: after that one `Exec`, the connection that served it reported
  `app.bypass_rls = "on"` and a second connection from the same pool reported
  `""`. Any query landing on a later connection runs unbypassed, and under
  `FORCE ROW LEVEL SECURITY` that is not an error — it is **zero rows**. A rekey
  that sees nothing rewrites nothing, prints `0 rekeyed`, exits 0, and the next
  KEK rotation retires a key that is still decrypting live data.

  Whether it bit on a given run depended on whether the pool happened to hand
  back the same connection, which it usually does for this binary's sequential
  work and stops doing the moment a connection ages out or anything runs
  concurrently. The bypass is now set in `AfterConnect`, so every connection the
  pool opens carries it, and the binary refuses to start at all if it still
  cannot read across tenants — asking the database what is true rather than
  whether a statement returned no error, because the owner of these tables may
  be exempt from RLS without any setting.

  Six mutations red against a green baseline: the bypass taken once on the pool
  instead of per connection (which reproduces the bug and fails the new test);
  the see-everything check hardwired to yes; a new unregistered direct
  connection; a register entry naming a file that no longer opens one; a reason
  thinned out; and the lint blinded to `pgx.Connect`. A seventh **did not apply
  at all** — the edit missed and the suite stayed green, which is not a signal
  and is recorded as one that was redone. Blinding `pgxpool.New` then proved
  nothing either, for a measured reason: `cmd/rekey` had moved to
  `NewWithConfig` in this very change, so no file on this tree uses that
  spelling. The constructor list is a vocabulary, not a census, and now says so.

  The rekey checks have their own CI step with named `--- PASS:` checks — and
  adding them made a second guard fire: `tools/testmatrix` carried `cmd/rekey`
  on its register with the reason that the package's only test file sat behind
  the `integration` build tag, so the matrix's `./cmd/...` entry "looked like
  coverage and compiled zero tests". Untagged tests in that package make the
  line excuse nothing, and `TestTheRegisterCarriesNothingTheMatrixAlreadyRuns`
  said so on the first run. The entry is gone, with why it went.

- **`openidx cell place|show` — the tenant directory's write path, which did not
  exist** (global-scale plan task 4.1). `internal/common/celldir` has held a
  `Place` since the directory landed, and the package's own comment calls
  `Execer` "the write surface, for the placement tool". Measured across
  `internal/` and `cmd/`: **nothing called it.** The read half was live — the
  issuer looks up a tenant's home cell to stamp a token with it — so the
  directory was a table that could only ever answer "not placed", and every
  token fell back to whichever cell minted it. A capability that is declared and
  cannot be exercised is the shape this branch keeps finding; this is that shape
  with the tool missing rather than the claim wrong.

  **A command, not an endpoint.** Placing a tenant is a control-plane act and
  the control plane is not inside a cell: an admin-api in `eu-1` deciding that a
  tenant lives in `us-1` is one cell's view of a directory spanning all of them,
  and every cell would need the same write. A command run against the directory
  database by whoever is moving the tenant is also the only thing that can run
  before any cell serves that tenant at all.

  **What the belt costs the tool, measured rather than assumed.** `org_cells` is
  org-scoped and FORCE-belted, so a connection carrying no tenant scope writes
  nothing — including this one. The placement runs in a transaction that sets
  `app.bypass_rls` locally, the same door the outbox relay and the SSF
  transmitter go through, named at the call site rather than granted to
  everybody by leaving the table unbelted.
  `TestWithoutTheControlPlaneBypassTheBeltRefusesTheWrite` drives the same
  `INSERT` without it and requires the policy to refuse — against a real
  PostgreSQL, as the role that OWNS the table, which is what makes `FORCE`
  observable at all.

  Six mutations red against a green baseline: the command dropping the bypass
  (the write is refused); the empty-cell refusal removed; the upsert no longer
  moving a placed tenant; a move rewriting `created_at`, which is when the
  tenant was *first* placed; `show` treating an unplaced org as a failure rather
  than as the answer it is for every install today; and `FORCE` deleted from
  v195, which turns the belt's refusal into an acceptance.

  The suite has its own CI step with named `--- PASS:` checks, because a
  database test in a job that sets no DSN skips silently — a guard that never
  fires being the shape this branch keeps finding one step before production.

  **Not built, and not claimed:** a cross-tenant `list`. It needs a read surface
  `celldir` does not have, and adding one is a decision about the control
  plane's read path rather than part of making the write path exist.

- **A third coordination census, this one finding periodic work by SHAPE rather
  than by name** (`internal/common/leader/periodic_shape_census_test.go`). The
  two that existed are each keyed on a spelling: the sweeps census walks only
  files containing `time.NewTicker`, and `cmd`'s background-work census derives
  the `Start<Name>(` calls a `main.go` makes. A loop that repeats on a timer
  using neither spelling is invisible to both.

  **One exists on this tree, and it was found by measuring rather than
  guessing.** `internal/common/events.Relay.Run` is the outbox poller: it loops
  forever on `case <-time.After(PollInterval)`, its file holds zero
  `time.NewTicker`, and `cmd/event-relay` starts it as `go relay.Run(ctx)` —
  not a `Start`-anything name. So the sweeps census never opens the file and
  `cmd`'s census never names the entry point. Both guards pass, and neither is
  looking at it.

  **Latent, not live.** The relay claims each batch `FOR UPDATE SKIP LOCKED`, so
  two relays are correct rather than merely tolerated — the lock *is* the
  coordination. That is now written down, together with the thing that makes it
  worth writing: a future poller copied from this one **without** the
  `SKIP LOCKED` claim would be the defect the other two censuses exist to catch,
  arriving in the one spelling neither of them reads.

  Derived: every loop that repeats without a counter and waits on `time.After`,
  `Tick`, `Sleep`, `NewTimer` or `NewTicker` inside. **Five on this tree**, each
  either leader-gated or registered with why every replica running it is
  correct: the relay (the row lock), the email queue consumer (Redis `BRPop`
  distributes, and its `Sleep` is an error backoff rather than the period), the
  migration lock wait (the lock is the point, and it ends at a deadline), the
  Ziti hosted-service listener (one terminator per pod IS the intent — one in
  total would send every dial to a single pod), and the CLI's status poll (there
  are no replicas of a command somebody typed).

  The "unbounded" test admits `for {}` **and** `for cond {}` with no post
  statement. The second shape matches nothing today — measured — and is included
  so the derivation cannot be accused of being fitted to this tree; a bounded
  `for i := 0; i < n; i++` retry with a sleep is deliberately out, because
  retrying eight times is not periodic work.

  Six mutations red against a green no-op control: a new `runEvery`-shaped loop
  appearing undeclared; the relay's file starting to name a leader gate (which
  makes its register entry stale); a register entry naming a loop that moved; a
  reason thinned out; the derivation blinded to `time.After` — the very spelling
  that hid the relay; and the pinned count drifting from the tree.

- **The login page can now actually present the bot gate's challenge** — and
  getting there meant fixing two things that made the instruction impossible to
  follow (global-scale plan task 1.4, the open half).

  **What shipped before.** `internal/botgate` refuses a login with
  `403 challenge_required` once an account name has collected enough failures
  from anywhere, and the body said *"Complete the verification challenge and try
  again."* Nothing in that response named a challenge or carried a site key, and
  a Turnstile widget cannot be rendered without one — the public key was not in
  the configuration at all, only the secret. So the page had exactly one move:
  print the sentence. The person read an instruction, found nothing to do, and
  retried into the counter that had just refused them. **A control that tells
  someone to do something it gives them no way to do is the same defect as one
  that reports success without doing its job; it just fails in the user's
  direction.**

  **The site key travels with the refusal.** New `TURNSTILE_SITE_KEY`
  (`config.turnstileSiteKey` in the chart, beside the secret rather than in the
  secret store — it is served to every browser that is challenged). The gate
  answers `ChallengeSiteKey()` only when a verifier is configured too, because
  each half alone is a dead end: a verifier with no site key is what shipped,
  and a site key with no verifier is worse — the widget renders, the person
  solves it, and `Check` ignores the token and falls through to the same
  counter, which is a loop with no exit and reads as a broken login rather than
  a lockout. The wording follows the key: with one, "complete the challenge";
  without one, "wait a few minutes", which is what a soft lockout actually is.

  **And the layer under that: the challenge the browser is not allowed to
  load.** Turnstile is a script from `challenges.cloudflare.com` that draws
  itself in an iframe from the same origin, so `script-src 'self'` with no
  `frame-src` blocks both halves — silently, in the browser, long after every
  test here has passed. Measured across the three nginx configs:
  `nginx/admin-console.conf`, which the shipped console image uses, sets no CSP
  and would have worked; `oidx-nginx/nginx.conf` (which serves the SPA itself)
  and `conf.d/openidx.tdv.org.conf` both set one that blocks it. **Live, not
  latent, in two of three.** One pinned origin is now allowed in the directives
  Turnstile needs, in the blocks that serve the login *document* — the
  static-asset block keeps the narrow policy, and a test holds it there.

  The console half is `TurnstileChallenge` plus the login page's handling:
  solving the widget resubmits the credentials the person already typed with
  `challenge_token` — the gate refused before the password was checked, so
  nothing about them was wrong, and retyping would punish them for someone
  else's guessing.

  Ten mutations red against two green no-op controls, across three suites: the
  refusal dropping the site key; the old sentence returning where no challenge
  can be rendered; the gate offering a key with no verifier; the page ignoring
  the key, rendering a widget without one, dropping `challenge_token`, and
  rendering on any failure; `frame-src` dropped; the origin landing in the
  static-asset block instead; and one of the two document configs left out. The
  CSP guard is derived in both directions, so removing the widget makes it
  report the allowance as a widening with no user.

- **Two more admin reads moved to the read replica, and two measured holes in
  the census that licensed them closed** (global-scale plan task 2.3, batch 5).
  `mfa_management.go handleListUserMFAStatus` and
  `notification_management.go handleNotificationStats` now read through
  `Reader()`, declared one handler at a time in `offloadedHandlers` with the
  console evidence that nothing refetches them.

  **The first hole, found by deriving what the census never derived.** The
  handler tier checks that the declared query KEY is declared in exactly one
  console file and invalidated by nothing. That is an argument about a TILE.
  What moves to the replica is a HANDLER, and a handler answers a ROUTE, which
  more than one tile may fetch under more than one key. Deriving every
  `useQuery` that fetches an `internal/admin` route:
  `/api/v1/security-alerts` is fetched under `['ops-security-alerts']` on the
  ops cockpit, which nothing invalidates, and under `['security-alerts']` on two
  other screens, which a mutation does. `handleListSecurityAlerts` could
  therefore have been declared with an entirely true sentence about the cockpit
  and passed every test in the file, while the other screens read after their
  own writes. **Latent, not live**: neither handler declared before this change
  shares its route. It would have gone live on this very batch, because
  `/security-alerts` is one of the candidates the console criterion alone marks
  safe. `TestOffloadedHandlerRoutesAreFetchedOnlyUnderTheDeclaredKey` now
  requires every key that fetches a declared handler's route to be the declared
  one.

  **The second hole: `invalidateQueries` is not the only way a tile is
  refetched.** `useQuery` returns `refetch()`, which refetches that component's
  query without invalidating anything, so "no mutation invalidates this key" is
  necessary and not sufficient. Measured: seven `refetch()` call sites in the
  console, six wired to a Refresh button's `onClick` — an operator asking for
  fresh data is not a read-after-write — and none in a file that declares an
  offloaded key. Latent too, and guarded rather than noted, because the file is
  the unit and `refetch()` binds to the `useQuery` instance in that component.

  **Batch 5, with the console evidence.** `mfa-user-status` is the per-user
  enrolment table on the same screen as the already-offloaded enrolment tile;
  the screen's only three mutations are policy create, update and delete and all
  three invalidate `['mfa-policies']`. `notification-stats` is the notification
  overview; the screen holds seven mutations and every one invalidates
  `['routing-rules']` or `['broadcasts']`. The stats tile carries a preview of
  the last five broadcasts, which is the sharp edge and the reason it is safe
  rather than despite it: sending a broadcast already does not refresh this
  tile, so it is stale until remount, and a second of replication lag is not
  visible inside a staleness that already lasts that long.

  The key matcher now accepts a PREFIX key, because `mfa-user-status` is
  paginated (`['mfa-user-status', page]`) and TanStack invalidates by prefix —
  matching only the single-element form made this tier unable to say anything
  about a paginated screen, which is most of them.

  Both handlers were added to the read-only-replica path test, which drives them
  against a real PostgreSQL session with `default_transaction_read_only=on`:
  they answer, they stay tenant-scoped, and the pool they read from still
  refuses a write with SQLSTATE 25006.

  Eight mutations red against two green no-op controls (one per round). The one
  that survived is worth recording: dropping the correlation from the
  backup-code subquery left `ada`'s count unchanged, because she holds all of
  the tenant's unused codes — the assertion was reading the one row where both
  branches agree. It now asserts on `grace` as well, who holds none, and the
  mutation goes red. **A mutation that survives is sometimes a fact about the
  assertion rather than about the query.**

- **identity-service refuses a token minted in another cell** — and the reason
  it could not before was not the one written down. `cell.Guard` now rides
  behind identity-service's authentication, mounted through a new variadic
  parameter on `RegisterRoutesForProfile` and passed from `cmd/identity-service`
  the way the other five services pass it.

  **The registered obstacle was the cheap half.** `cmd/cell_guard_census_test.go`
  had carried identity-service as a backlog of one, with the reason that mounting
  the guard meant changing the route registrar's signature. It did, and that took
  one variadic parameter: `Service` already held `cfg` and `logger`, so nothing
  had to be threaded through. What actually stood in the way was invisible from
  that register: `openIDXAuthMiddleware` extracted `roles` by hand and bound
  nothing else, so `c.Get(cell.Claim)` was unset on every request. A guard
  mounted on top of that would have answered 200 to every misdirected request
  while two censuses recorded the service as guarded — a control reporting
  success while the thing it exists to make true is not true.

  So the middleware now calls `middleware.BindSubjectClaims`, and
  `internal/common/middleware`'s subject register — which had listed this
  middleware with the reason that binding the subject here "would be a no-op that
  looks like a fix" — is empty. That reason was true of roles and groups and
  stopped being true when `BindSubjectClaims` took on a third key. **An exemption
  is a claim about a moment, not a property**: what the register said had not
  changed; what the function did had.

  **The guard runs before anything that costs a query**, ahead of
  `PermissionResolver`: a request this cell should not be answering has no
  business first resolving the caller's permissions out of PostgreSQL and Redis.

  Measured end to end in `internal/identity/cell_guard_test.go` with nothing
  stubbed: a real RSA key signs a real token, a real JWKS endpoint serves the
  public half, the real middleware verifies it, and `GET /users` — administrative
  tenant data — answers 421 with `X-OpenIDX-Cell`. A test that handed the guard a
  claims map would have passed against the defect above; this one cannot, because
  the only thing that puts the claim in the gin context is the middleware under
  test. Five mutations red against a green no-op control: dropping the guard from
  `main.go` (census red), restoring the hand-rolled roles block (the 421 red, and
  the misdirected request reaches the nil pool), mounting the guard after
  `PermissionResolver` (the same nil pool, which is how the ordering is measured
  rather than read), dropping the `X-OpenIDX-Cell` header, and mounting the extra
  middleware on the public group instead of the authenticated one.

  `oauth-service` remains the one unmounted entry, with its reason unchanged: it
  mints tokens rather than serving tenant records, and whether the guard belongs
  there is a decision, not a backlog item.

- **A census joining every binary's background starters to a coordination
  answer** (`cmd/background_work_census_test.go`). Two censuses already existed
  and neither made this join: `internal/common/leader`'s classifies the
  coordination of every file containing `time.NewTicker`, and
  `cmd/identity-service`'s asks whether a starter belongs to the plane the
  process serves. What was missing is which *binaries* call which starters, and
  whether every one of those calls reaches an answer at all.

  **The hole that makes it worth having, measured on this tree.** The sweeps
  census finds work by looking for `time.NewTicker` in a file. Ten of the
  starters here have no ticker in their own file — they hand the interval to
  `leader.RunPeriodic`, which owns the ticker and the gate together. That is
  correct, and it is exactly why the census cannot see them: **the ticker moved
  into a helper.** The shape this guard exists for is the same move *without*
  the gate — a `runEvery(d, fn)` in a util package, called from eight services,
  where the sweeps census sees one file while eight sweeps run once per replica.
  Nothing in the tree would have said so.

  Measured split: **14 leader-gated, 11 with a ticker in their own file, 1 not
  periodic** (`cmd/profiler`'s pprof listener, registered with its reason). The
  14 is pinned, because every entry in it is a sweep that would otherwise run
  once per replica and `access-service` autoscales to eight.

  **What this does not measure, and does not claim.** Whether these starters
  would be better off in their own `cmd/<svc>-worker` binaries is a question
  about load — how much of a request-serving pod's CPU and pool budget the
  sweeps take. That needs a staging cell under load. The classification is
  measurable and is what this does; the benefit of splitting is not.

- **The tenant directory: which cell serves which org** (migration `v195`,
  `internal/common/celldir`). `org → {cell_id, region, residency, status}`,
  with `Lookup`, `HomeCell` and an upsert `Place`.

  **This is the routing decision; the 421 is the backstop behind it.** The two
  halves of the cell model are easy to conflate. `cell.Guard` answers 421
  Misdirected Request to a token stamped with another cell — what happens when
  a routing decision was already made and was wrong. This table *is* the
  decision, the record the edge reads to send a request to the right cell in
  the first place. Neither substitutes for the other.

- **The issuer now stamps the tenant's home cell, not its own.** This closes a
  gap in the guard shipped alongside it. The stamp used to be `CELL_ID` — the
  cell that *minted* the token — which catches a token carried from one cell to
  another and **cannot catch a login that reached the wrong cell**: an `eu-1`
  issuer serving a `us-1` tenant stamped `cell=eu-1`, every `eu-1` guard
  compared `eu-1` against `eu-1` and agreed, and the request was served from a
  database that does not hold that tenant. That is the confident 404 the 421
  exists to replace, arriving through the one door the guard cannot watch. All
  three access-token mint paths now resolve the home cell, including RFC 8693
  token exchange — where it matters most, because `oauth-service` mounts no
  guard, so a subject token from another cell can be exchanged there and would
  otherwise be laundered into one this cell accepts.

  **Both fallbacks land on today's behaviour, deliberately.** An uncelled
  install (`CELL_ID` empty — every install today) does no lookup at all. A
  celled install whose directory is *unreachable* stamps the serving cell and
  logs, rather than refusing to mint: an issuer that failed closed here would
  turn a control-plane outage into an authentication outage, which is the
  failure the plan's own acceptance criterion budgets against.

  **No foreign key to `organizations`, and that is the point.** In a celled
  deployment the directory is global and `organizations` is per-cell, so the
  row saying "org X lives in us-1" is precisely a row about an org this cell's
  database does not have. A foreign key would make the table unable to record
  the only fact it exists for. The cost — nothing cleans up a placement when an
  org is deleted — is stated rather than discovered. `cell_id` is `CHECK`ed
  non-empty because `cell.Misdirected` reads an empty cell as "this token
  predates the claim" and *serves* the request: a placement naming no cell
  would be a tenant placed nowhere and refused by nobody.

  The table is `org_id`-scoped under forced RLS from creation; the readers that
  legitimately cross tenants use `orgctx.WithBypassRLS`, as the outbox relay and
  SSF transmitter already do.

### Fixed

- **`X-OpenIDX-Cell` names the cell that answered, not the one that should
  have.** The `cell` package doc claimed the opposite while the code did the
  former. The guard holds no directory and cannot know where a tenant lives —
  that is `celldir`'s job, and keeping the database dependency out of the guard
  is deliberate. RFC 9110 defines no "go there instead" header for 421 either.

### Added

- **A request that reached the wrong cell now says so, instead of answering a
  confident 404 from a database that does not hold the tenant.** `CELL_ID`
  (`config.cellId`) names the cell a process serves. Empty — every install
  today — changes nothing. Set, the issuer stamps the cell into a `cell` claim
  on every access token it mints, and `cell.Guard` answers **421 Misdirected
  Request** with `X-OpenIDX-Cell` naming the cell that should have served the
  request, so a caller can correct its routing without a directory lookup and
  an operator can tell a misroute from a genuinely missing tenant. Without it
  those two are the same 404.

  **This is the backstop, not the routing.** The edge decides which cell serves
  a tenant, from the tenant directory; this is what happens when that decision
  was stale. The two are easy to conflate and neither substitutes for the
  other — the directory makes the common case right, and this makes the
  uncommon case legible.

  **Three flows mint an access token, and stamping one of them would have been
  worse than stamping none.** `GenerateJWT`, the SAML flow's
  `generateTokensForUser` and RFC 8693's `issueExchangedToken` all produce a
  bearer an API is handed; only the first was stamped when this was written.
  A guard that refuses tokens from one login flow and serves tokens from
  another makes the behaviour depend on how the caller signed in, which is the
  hardest kind of failure to report. All three are stamped now, and a census
  derives every `jwt.MapClaims` the package mints from the source: each one is
  either registered as a stamped bearer or carries a written reason it is not.
  ID tokens (both of them) are not stamped — an ID token is handed to the
  client to read, never presented back as a bearer, so the guard never sees it.

  **An unstamped token is served, deliberately.** Requiring the claim would
  make setting `CELL_ID` a flag day: every token outstanding at that moment
  would start failing, including ones minted seconds earlier by the same
  process. During the rollout window a misrouted request carrying an old token
  gets the 404 it would have got anyway. The cost is written down rather than
  discovered.

  The guard is mounted in `access-service`, `admin-api`, `audit-service`,
  `governance-service` and `provisioning-service`. `identity-service` and
  `oauth-service` are not mounted and a register in `cmd/` names why, so the
  gap is a backlog entry rather than something a second cell discovers.
  `CELL_ID` reaches all of them plus the issuer through the shared ConfigMap,
  and the chart render asserts which containers actually consume it: every
  service in one cell must agree on which cell it is, because a cell where one
  service refuses a foreign token and another serves it is worse than one where
  none do.

### Fixed

- **A guard documented a class it did not check.** `internal/common/logsafe`'s
  package comment names the request target as attacker-controlled text — "a
  percent-encoded `%0A` in a request target arrives in `c.Request.URL.Path` as
  a real newline" — but `no_tainted_field_test.go` only tracked values assigned
  to a local from `c.Param`/`c.Query`/`c.GetHeader`. A function that logs
  `c.Request.URL.Path` inline has no tainted local at all, so it was skipped
  entirely: the guard's first act was `if len(tainted) == 0 { return }`.
  CodeQL reported one such site; four more had the same shape in
  `internal/common/handlers/decorator.go`. All five now go through
  `logsafe.String`, and the guard reads `c.Request.URL.{Path,RawPath,RawQuery,
  Fragment}` wherever they appear rather than only through a local.

  `c.Request.RemoteAddr` is deliberately left alone: net/http writes it from the
  accepted connection, it is bounded by an address and a port, and a guard that
  reports noise is a guard somebody turns off. The three sites logging it stay
  as they are, and the exclusion is a test case rather than an omission.

- **The identity plane split reached the routes and not the background work.**
  `cmd/identity-service/main.go` started its sweeps without ever consulting
  `serviceProfile`, so `SERVICE_PROFILE=auth` — the ISSUE half, which registers
  login and MFA routes only — also ran `StartRoleExpirationChecker`. That sweep
  deletes expired time-bound role assignments across every org and revokes the
  tokens still carrying them; nothing about it belongs to a login. It now sits
  behind `serviceProfile.ServesAdmin()`, and since the unsplit process is
  `ProfileAll` (which serves ADMIN), **a default install is unchanged**.

  **The reason is latent rather than live, and saying which is the point.** The
  sweep is leader-gated, so the cost was already one replica per minute
  cluster-wide, and an auth pod winning that election is harmless today:
  `values.yaml` gives *both* halves the `admin` database role. What makes it
  matter is the move that file already names as next — the auth half to the
  `issue` role, whose `statement_timeout` is sized for a login query rather than
  a `DELETE` across every org. Elected onto an ISSUE pod after that move, this
  sweep would fail every tick it won. Gating it now keeps that move a
  configuration change instead of an incident.

  **The SMS config watcher is deliberately not gated.** It reads one
  `system_settings` row and writes nothing: the tick swaps *this process's own*
  SMS provider, so a pod skipping it would keep sending codes through a provider
  an admin has already replaced — and the auth half is the one sending MFA codes
  during login. The sweeps census in `internal/common/leader` already records it
  as per-process for that reason, and gating it was one of the mutations.

  A register in `cmd/identity-service` now requires every background starter to
  declare its plane: ADMIN-plane work behind the profile check, per-process work
  outside it with the reason a pod skipping it would be wrong. An unclassified
  starter fails the build, and so does a register entry for a starter `main.go`
  no longer calls. Four mutations red; a fifth did not compile, so it was not
  treated as a signal and was redone in a form that did.

  **A measurement in the plan is corrected alongside it:** an earlier paragraph
  said eleven tickers stood "undecided" in the sweeps census. The register
  carries **one** today (`internal/access/ziti_reconciler.go`, parked for want of
  a Ziti controller to measure against), and a test pins that count. The
  coordination question is closed; the open one is which sweeps run *inside*
  request-serving processes — seven binaries start more than twenty between
  them, ten in `access-service` alone.

### Changed

- **The Redis half moved to `internal/common/redisclient`, and a claim about
  `cmd/gateway-service` is corrected.** `internal/common/database/database.go`
  was three packages in one file — Postgres, Redis, Elasticsearch — so every
  binary wanting a Redis client linked a PostgreSQL driver with it. The Redis
  half now stands alone, the same way `jwksverify` came out of `middleware`:
  nothing copied, `database` keeps the old spellings as aliases, **no call site
  changed**.

  **The correction.** An earlier entry said gateway-service links a driver "for
  no reason but `database.NewRedisFromConfig` sharing a package with the
  Postgres half". That was written from reading one import in one `main.go`, and
  it was wrong: the binary reaches `pgx` through **five** independent routes —
  `internal/common/middleware`, `internal/metrics`,
  `internal/common/syssettings`, `internal/appaccess` and `internal/stepup`. The
  split removed one of five, and the binary still links the driver. Reading an
  import list is not measuring an import graph — a conclusion drawn one frame
  too low, which is the mistake this work keeps finding in the product.

  So the split's justification is the honest one: a PG-free binary *can* now
  hold a Redis client. Nothing needs that today — `verify-service` wants no
  Redis — and that the gain is latent is written down too. Making gateway-service
  database-free is a much larger job than one import and is not obviously worth
  doing: auth, pool metrics, settings, app-access and step-up all read
  tenant-scoped tables.

### Added

- **`tools/planecensus` derives the plane map instead of asserting it.** A
  register names the binaries whose value depends on holding no database
  (`verify-service` today); one of them gaining a driver fails the build. A
  second register records the binaries that *do* reach it and why, and fails
  when one of them becomes clean — the explanation would then be wrong and the
  binary has earned the stronger guarantee. Entries naming a binary that no
  longer exists fail too. Everything else is deliberately unpoliced: most
  services are supposed to reach the database, and a gate that complains about
  them is a gate somebody turns off. Three mutations red.

### Fixed

- **The SSF transmitter advertised seven event types and sent one.**
  `/.well-known/ssf-configuration` listed all seven CAEP/RISC events the package
  defines under `events_supported`. `EmitCAEPEvent` has one production caller,
  inside `revokeAllUserSessions`, and it emits `session-revoked`. Nothing has
  ever sent `account-disabled`, `account-purged`, `credential-change`,
  `assurance-level-change`, `token-claims-change` or `device-compliance-change`.

  A receiver reads that document, subscribes to `account-disabled` so its apps
  drop a disabled user immediately, gets an enabled stream back, and waits
  forever — with nothing misconfigured on either side and nothing to debug. It
  asked for what it was offered. That is this branch's recurring shape one layer
  up: not a control reporting success while the thing it was meant to make true
  is not true, but a capability document describing a product that does not
  exist.

  **The cause is structural rather than an oversight**, and it explains why the
  plan asks for an outbox migration here. `EmitCAEPEvent` is a method on the
  oauth service, so the paths that cause those events cannot call it: accounts
  are disabled in identity, access, admin, directory and provisioning, and none
  of the nine sever paths fixed earlier on this branch can reach it. The outbox
  is the seam — the severing path writes the event in its own transaction and a
  consumer in oauth-service turns it into a SET for the existing delivery queue.
  SSF's own queue (`ssf_stream_delivery`) is already durable, with retry,
  backoff, stall-requeue and dead-lettering, so moving it for its own sake would
  close no defect; reaching the other services is the whole point.

  `events_supported` now names only `session-revoked`. The six that left are not
  abandoned, they are unbuilt, and the difference is written down.
  `CreateSSFStream` never validated `events_requested` against the advertised
  list, so no existing stream changes behaviour — only the document stops being
  untrue.

  **A census holds both directions.** It reads the constants from `ssf.go`, the
  advertisement from `ssf_handlers.go` and the emitters from the `EmitCAEPEvent`
  call sites — nothing is hand-listed, and an empty read fails rather than
  passing vacuously. Advertising an event nothing emits fails the build, and so
  does emitting one nothing advertises, which would be a SET no receiver could
  have subscribed to. The list can grow again exactly when an emitter appears.
  Four mutations red.

### Added

- **A verification tier that cannot reach the database.** `cmd/verify-service`
  serves `/.well-known/jwks.json` and nothing else, from a process with no
  connection pool. `cmd/verify-service/main_test.go` walks its transitive import
  graph and fails the build if `github.com/jackc/pgx` or
  `internal/common/database` ever appears in it, which is the whole point: the
  claim is not that this binary happens not to open a connection today, it is
  that it *cannot*, so it can be deployed with no egress to PostgreSQL and run
  at a replica count the database could never support.

  **It serves only JWKS, and the plan records why.** ADR-2 asks for a tier
  serving "JWKS, introspection and forward-auth, with no PostgreSQL dependency".
  Measured against the code, two of those three cannot be served without
  PostgreSQL, for reasons that are not incidental. Introspection is protected by
  client authentication — RFC 7662 §2.1 requires it, and
  `requireTokenEndpointClientAuth` exists because this endpoint was once open —
  and authenticating the *caller* means reading `oauth_clients`; a tier that
  skipped the check to stay database-free would reopen the hole that middleware
  was added to close, and one that cached the registry would hold client secrets
  in a tier whose whole claim is that it holds nothing. A refresh token, in any
  case, is a row with no signature to check offline. `/access/.auth/*` is a
  login flow rather than a verification: `/login` and `/callback` run the OIDC
  exchange and `/idps` reads `identity_providers` and `proxy_routes`. Only
  `/session` is database-free, and one session-info endpoint is not forward-auth.

  What is left is still worth its own process. JWKS is the highest-fanout
  endpoint in the product — every relying party and every sidecar verifier polls
  it — and it is answered today by the same pod that mints tokens and holds the
  write pool.

  **The chart ships it, off by default**, and with the flag off the render is
  byte-identical to before. Turned on it gets a Deployment, a Service, a
  PodDisruptionBudget, and — with `networkPolicy.enabled` — the only policy in
  the chart that has an Egress section: DNS and the issuer, nothing else. The
  build guard and the network policy assert the same claim at two layers,
  because a claim with one enforcement point survives exactly one refactor.

  **It mounts no platform Secret and no database URL.** Every other service
  takes both through `envFrom`; this one takes three plain environment
  variables. The binary is built for that — it skips the platform production
  validator, which in production demands an encryption key, a vault KEK and an
  audit chain secret from a process that encrypts nothing, has no vault and
  seals no chain. Mounting them so it could serve a public document would hand
  the most sensitive material in the install to the one pod whose claim is that
  it carries none of it.

  Two policies can be individually correct and jointly broken: the tier's egress
  rule permits the connection to the issuer, and the issuer's own ingress policy
  did not admit it — a tier that renders perfectly, passes its health check and
  answers 503 forever. The issuer's policy gained the rule and the CI assertion
  reads both sides. One chart mutation stayed green and the reason is recorded:
  hardcoding the JWKS URL was byte-identical to the derived value because the
  CI render's release name is `openidx`, so the step now renders under a name
  that cannot collide.

  **The edge sends it the key set, and only the key set.** `/.well-known` was
  one Prefix rule to the issuer; behind the same flag there is now an Exact
  rule for `/.well-known/jwks.json`. Kubernetes gives Exact precedence over
  Prefix whatever order they appear in, so `openid-configuration`, the SSF
  metadata and the mobile app-association files keep going to the issuer —
  each is built from the database or from config, and this tier could not
  answer any of them. `jwks_uri` in the discovery document needs no change: it
  names the same public URL, and what moved is which pod answers.

  The assertion drives requests through the same Exact-then-longest-Prefix
  matcher the plane-split step uses, rather than checking that a rule exists —
  what matters is where a request lands. One mutation there stayed green and
  the reason was the test: turning `Exact` into `Prefix` changed nothing,
  because `/.well-known/jwks.json` beats `/.well-known` as a longest prefix
  too. The two match types diverge only on sub-paths, which nothing was
  driving, so `/.well-known/jwks.json/anything` is now one of the cases. A
  mutation that survives is sometimes evidence about the test rather than
  about the code.

  **An unreachable issuer with nothing cached answers 503, not an empty key
  set.** `{"keys":[]}` with a 200 tells a relying party, authoritatively, that
  this issuer signs nothing, and the correct thing to do with that answer is to
  reject every token it holds — including the valid ones. The tier also
  publishes only keys it would itself verify with (RSA, `use=sig`, parseable),
  because a document advertising a key the product will not accept is the same
  kind of lie in the other direction.

### Changed

- **The JWKS cache moved out of `internal/common/middleware` into
  `internal/common/jwksverify`.** Verification needs a public key and a
  signature, not a database — but the package holding it also holds
  `PermissionResolver` and `RequireFreshMFA`, which read tenant-scoped tables,
  so `pgx` sat in the import graph of *every* binary that merely validated a
  bearer. Nothing was copied: `middleware` calls the new package and keeps its
  old spellings as aliases, so there is still one key cache, one serve-stale
  window and one algorithm pin in the tree, and no call site changed.

  This is the same mixed-plane shape in three places, and only one of them is
  fixed here. `internal/metrics` reaches `pgx` for its pool collector, so the
  verify tier serves `/metrics` from `promhttp` directly. `cmd/gateway-service`
  also links a PostgreSQL driver — see the correction below, which measured that
  claim and found it wrong.

- **The access-token blacklist key and the revocation check moved to
  `internal/revocation`.** That package exists because this product once had two
  spellings of the per-user revocation marker, one of which nothing read, so an
  access review could revoke somebody and their session kept working. The
  blacklist key was private to `internal/oauth`, which was correct while the
  revoking endpoint and the enforcement point were one process. They are not any
  more. `internal/oauth` now calls the shared check inside its own circuit
  breaker — the breaker is that service's policy for a Redis brownout, not part
  of the answer.

  An unreadable marker is now an error rather than "no marker": somebody
  revoked, and the record of it cannot be interpreted, so the token is refused
  rather than served.

### Fixed

- **`/access/.auth/session` reported an expiry it had never read.**
  `getSessionFromRequest` consumed the session blob's `expires` field to decide
  whether the session was still alive and then dropped it, while
  `handleSessionInfo` reports `session.ExpiresAt` — so every live session
  answered with the zero time. A consumer honouring that value re-authenticates
  on every request; one ignoring it never learns the session is about to end.
  The absolute expiry was always enforced (the check above the drop), so what
  was wrong was only the answer — which is the same shape as the rest of this
  work: a report that reads as authoritative while the value it names was never
  filled in. Measured over the real route against a real Redis; two mutations
  red, including setting a plausible-but-wrong `time.Now()`.

- **The event relay is deployable.** A Dockerfile, an image in the build matrix,
  a Helm Deployment with its Service and PodDisruptionBudget, and an
  `eventRelay` values block — off by default. Port 8009 carries `/health` and
  `/metrics` only: the relay serves no requests, so there is no Ingress and the
  Service exists to give Prometheus a target.

  More than one replica is safe and is the point. The drain claims rows with
  `FOR UPDATE SKIP LOCKED`, so a row one relay holds is invisible to the others
  — no leader, no lease, and the replicas are capacity rather than a quorum.
  Hence `minAvailable: 1`: one relay drains the whole table, and the budget only
  keeps the backlog from going unattended.

  **The chart refuses to render a relay with no broker.** The binary refuses to
  start without `NATS_URL`, deliberately — a relay that starts and fails every
  publish looks healthy while the backlog grows where nobody looks — and that
  refusal is also a CrashLoopBackOff. The chart answers the same question one
  layer earlier, where it costs nothing. An external broker
  (`eventRelay.natsUrl`) is an equally valid answer: the interlock is about
  *having* one, not about the chart owning it.

  Its wiring is derived from the broker rather than repeated beside it:
  `NATS_URL` from the **client** Service (not the headless one, which is how
  peers find each other), the password from the broker's own Secret, the subject
  prefix from `nats.subjectPrefix`. A wrong host, a wrong password or a prefix
  outside the relay's permissions is refused by the server on *every event*, and
  a values file is where that divergence would be invisible.

  Four mutations red: turning the interlock into a silent default, pointing
  `NATS_URL` at the headless Service, hardcoding the prefix, and removing the
  default-off gate.

  Two shell traps were measured while writing the CI step, not reasoned about.
  `render | grep -q` reports a **successful** match as a failed step: `grep -q`
  closes the pipe on its first match, helm dies of SIGPIPE, and `pipefail` turns
  that into a non-zero exit. And a failed render with an unmatched grep is the
  same answer to a pipeline as a clean render with nothing to find. Both are now
  rendered to a file first.


- **`cmd/event-relay`: the process that makes the outbox live.** Tasks 3.1a and
  3.1b built the outbox table, the publisher and the relay; 3.2 built the sink.
  None of it ran anywhere, and the plan said so rather than letting it pass as
  finished — a table nothing writes to differs from a package nothing imports
  only by intention. This binary composes them: Postgres, NATS, the sink, the
  drain, and a leader-gated retention sweep (a sweep is not a claim, so every
  replica would otherwise delete its own batch of the same rows). The drain
  itself elects no leader, and that is not an omission: `FOR UPDATE SKIP LOCKED`
  is the coordination.

  **It refuses to start without a broker.** A relay with no sink looks healthy
  from outside: it claims rows, cannot deliver them, rolls back, claims them
  again. Nothing is lost — the outbox is built for that — but nothing is
  delivered either, and the only place the failure shows is the table, which is
  the last place anyone looks. Measured: `NATS_URL` empty exits 1 and says why,
  and CI runs that every time.

  `TestSomeBinaryRunsTheOutboxRelay` is the guard against this package becoming
  what it replaced. Its own doc records why the in-memory bus was deleted —
  nothing in the tree imported it — and the outbox spent two tasks in exactly
  that position. The guard looks for a binary calling **both** `NewRelay` and
  `NewNATSSink`: a relay wired to a stub satisfies "the relay runs" and delivers
  nothing, which is the failure it is really about.

### Added

- **A census that every binary holding an Elasticsearch client also runs the
  audit reconciler.** `LogEvent` indexes fire-and-forget and its comment says
  the reconciler backfills whatever the index dropped, "guaranteeing ES search
  completeness". That is a claim about the whole deployment, not about the
  function: `StartESReconciler` runs in one binary, the ES client is built in
  one binary, and they happen to be the same one.

  Nothing made them the same one. A second service given an ES client would
  index fire-and-forget with no reconciler behind it, and every write
  Elasticsearch dropped there would be lost silently — `indexed_at` NULL
  forever, the row in PostgreSQL, and the console's audit search simply never
  showing it.

  The test finds the binaries itself rather than trusting a list, and checks
  both directions: a client with no reconciler, and a reconciler with no client
  (which returns immediately when `es` is nil, so it reads as coverage while
  being a no-op). Three mutations red.

### Fixed

- **The OPA policy was written against a caller the middleware never supplied.**
  `OPAAuthz` builds its authorization input from `c.Get("roles")` and
  `c.Get("groups")`, and `authz.rego` opens with `default allow := false` and
  grants by role. **Nothing anywhere called `c.Set("groups")`** — not in
  production, not in tests — although the issuer mints a `groups` claim onto
  every token beside `roles`. Worse, two of the three services that mount
  `OPAAuthz` authenticate with their own middleware
  (`governance-service`, `provisioning-service`), and those bound `user_id`,
  `email` and `name` and **neither `roles` nor `groups`**.

  So with `ENABLE_OPA_AUTHZ` on, every role-based rule in the policy was decided
  against an empty list. That is not a silent hole: against
  `default allow := false` it is a service that denies nearly everything except
  the two path-scoped rules, which is presumably why nobody had switched it on.
  The separation-of-duties `deny` failed the other way — it looks for
  conflicting roles held together, so an empty list satisfies nothing and that
  rule has never produced a message.

  `opa.ResourceContext`'s own doc already records this shape twice, for `owner`
  and for the resource `tenant_id`, and both were deleted because nothing could
  ever fill them. These two are the opposite case: the claims were minted all
  along and simply were not passed on. So they are bound — in one place,
  `middleware.BindSubjectClaims`, called by `AuthWithAPIKey`, `SoftAuth`, and
  governance's and provisioning's own middlewares, because four copies of this
  is how the four drifted apart.

  **A census now finds the authentication middlewares itself** — a function that
  reads token claims and writes the caller's id — and fails the build when one
  binds no subject. `internal/identity` is on its register with a reason: it
  mounts neither `OPAAuthz` nor `RequireRole`. The register only shrinks.

  **This changes behaviour where OPA is enabled.** Governance and provisioning
  go from denying nearly everything to letting the policy decide, and on all
  three services `authz.rego`'s `admin-group` rule starts firing for members of
  that group. That is what the policy says; it had simply never been given the
  input to say it. Anyone running with `ENABLE_OPA_AUTHZ=true` should read
  `deployments/docker/opa/policies/authz.rego` before taking this upgrade.

  Four mutations red: dropping the groups binding, binding a malformed claim
  instead of rejecting it, removing governance's call to the binder (caught by
  the census, which is the defect that existed), and loosening the census's own
  detector. A fifth was a real find rather than a mutation: the census's first
  run accused this package's own middlewares, because it matched only the
  qualified `middleware.BindSubjectClaims` and not the bare identifier used
  inside the package.


- **The census found the last two grant paths, and looking for them found a
  third shape it could not see at all.** `directory`'s
  `replaceDirectoryMemberships` and `provisioning`'s `UpdateSCIMGroup` both
  clear every membership and re-insert the current ones in one transaction, so
  most of what they remove they put straight back. Cutting on the delete would
  log out every member of every synced group on every sync, for nothing — a
  grant that has not reached the token permits nothing it should not. Both now
  `DELETE ... RETURNING user_id`, subtract the members they re-insert, and cut
  only the difference, after the commit.

  **`group_memberships.group_id` and `user_roles.role_id` carry
  `ON DELETE CASCADE`**, so deleting the parent takes every assignment with it
  and the statement never names the child table. Three live paths were in
  exactly that position and the census — which reads SQL — reported the set
  closed: SCIM group deletion, and the LDAP and Azure AD syncs dropping a group
  the directory no longer has. Each silently removed a claim from every member
  while their tokens kept asserting it. A cascade returns nothing, so these
  cannot use `RETURNING`: they read the members before the delete and cut them
  after.

  The census now recognises that third shape, so a new parent delete that
  severs by cascade fails the build. Both `unaudited` entries are gone from its
  register; the two directory paths remain listed as `revokes-indirectly`,
  because their cut goes through the injected `e.revoke` — a function-valued
  field that name-based reachability cannot follow, which `revoker_wiring_test.go`
  covers instead.

  Six mutations red, measured against a real PostgreSQL and a real Redis with
  the general and revocation roles on separate databases. **One stayed green
  and it was the same gap as the last round, which is why it is worth writing
  down twice:** moving the SCIM revoke from after the commit to inside the
  transaction passed, because no test forced a commit to fail — a failing
  DELETE returns before either placement runs. A `DEFERRABLE` constraint
  trigger now forces it: the DELETE succeeds, the COMMIT does not, both
  memberships come back, and a marker written inside the transaction would have
  survived that rollback.

  Installs with no Redis, and installs that never wired the directory revoker,
  still sync: refusing would leave the membership live in the database as well
  as the token.


- **Taking a role away and cutting the token that names it were two things, and
  the census could not see the difference.** The sever census guards one shape:
  an account disabled or deleted. Removing a role or a group does not touch the
  user row, so it never looked — while the token carries both, because the
  issuer builds `roles` from `user_roles` and `groups` from `group_memberships`
  and the enforcement point resolves the role claim's permissions on every
  request.

  Four paths closed: an access certification refusing someone's access
  (`admin/attestation.go`, which had its own hand-rolled DELETEs rather than the
  shared revoke), a bulk `remove_role` and a bulk `remove_from_group` (one
  operator action, one live credential per user — the same switch's
  `disable_users` and `delete_users` branches already knew this), and
  `identity.RemoveGroupMember`. Deleting a group is the mass case: the
  repository cut by predicate and reported nothing, so `DeleteGroup` had no
  identities to revoke — the fourth time in this programme that a sever path
  needed `RETURNING` for that reason.

  Removal only. A bulk `assign_role` cuts nobody, and neither removal cuts a
  user who did not hold what was removed (`RowsAffected` is 0): a grant that has
  not reached the token permits nothing it should not, so cutting there is an
  outage with no security gain.

  **The census now recognises the second shape**, so a new path that deletes
  from `user_roles` or `group_memberships` without revoking fails the build. It
  found four more the moment it could look: `jitgrant.Revoke` and
  `identity`'s group repository are `revoked-by-caller` (both verified by
  reading every caller — the revoke belongs in the caller because Redis cannot
  join a Postgres transaction), and `directory`'s `replaceDirectoryMemberships`
  and `provisioning`'s `UpdateSCIMGroup` are recorded OPEN with the fix named:
  both clear every membership and re-insert the current ones in one
  transaction, so only the DIFFERENCE is a revocation and cutting on the delete
  would log out every member of every synced group on every sync. The register
  only shrinks, so neither can be forgotten.

  Ten mutations red, measured against a real PostgreSQL and a real Redis with
  the general and revocation roles on separate databases. Two of them needed
  the tests fixed rather than excused. Moving the certification's revoke from
  after the commit to beside the DELETE stayed green, because the only failure
  the suite injected killed the DELETE itself and the handler returned before
  reaching either placement; a `DEFERRABLE` constraint trigger now forces the
  case that distinguishes them — the DELETE succeeds, the COMMIT does not, and
  a marker written inside the transaction would survive the rollback that gave
  the role back. And the two bulk mutations first "passed" against tests that
  had silently skipped, because one shell export derived a variable from
  another set in the same statement; the runs were repeated with the
  environment proven.


- **The lifecycle reconcile net caught the access and let the credential
  through.** The cross-pillar sweep exists for the disable paths that do NOT go
  through `deprovisionUser` -- SCIM deactivation, directory sync, a lifecycle
  policy, a direct database change -- and `deprovisionUser` is the path that
  cuts tokens. So for every path this sweep is the net for, the token was never
  cut: it removed the disabled user's time-bound elevation rows, logged how
  many, and the access token in their browser kept naming the role that the
  enforcement point resolves on every request.

  It was never a missing identity. `EndAllForDisabledUsers` selects
  `requester_id` to do its work, so the users were in hand the whole time and
  simply were not passed back, because the function returned a count -- and a
  count cannot be revoked. Its sibling `EndAllForUser` is *handed* the user,
  which is why that one's two callers already cut tokens and this one did not;
  the asymmetry is what hid the gap.

  It now returns the users to cut, deduplicated (one user holding three
  elevations is cut once) and filtered by `jitgrant.TokenCarries`, and the sweep
  cuts them after the rows are gone -- Redis cannot join those statements, so
  the revoke lives at the call site rather than inside the shared revoke.

  **The list is returned alongside the error, not instead of it.** A sweep that
  fails part way through has already removed real access, and those users are
  exactly the ones whose tokens must not outlive it; dropping them on the error
  path would make a partial failure the one case that severs access without
  severing the credential. The rows are ordered by expiry for the same reason:
  an abort leaves a prefix done, and without an order the next tick retries a
  differently-ordered set.

  Measured against a real PostgreSQL and a real Redis with the general and
  revocation roles on separate databases. Six mutations red: removing the
  revoke, writing to the general Redis, dropping the `TokenCarries` filter,
  dropping the deduplication, dropping the list on the error path, and removing
  the `ORDER BY`. The last one stayed green at first and the reason was worth
  the fix rather than the excuse: Postgres happened to return insertion order,
  which matched the order the test wanted, so the test was measuring luck. It
  now inserts the failing row first and expires it last, so physical order and
  expiry order disagree.

  An install with no Redis still reconciles: refusing to run would leave the
  elevation live in the database as well as the token.


- **A JIT elevation outlived the expiry that defines it.** "Admin until 15:00"
  is enforced by one piece of code, the JIT expiry sweep, and that sweep deleted
  the assignment row and stopped there. The access token minted at 14:00 still
  carried the role in its `roles` claim, and the enforcement point resolves that
  claim's permissions on every request -- so at 15:01 the row was gone, the
  audit said `jit_access_expired` / `success`, and the elevation kept working
  until the token expired on its own. An expiry sweep whose entire purpose is a
  deadline was the path that missed it.

  Two other severs sat right next to it and neither is this one: the DELETE
  removes what a *future* login would read, and `enqueueNetworkRevocation`
  closes Ziti circuits on the overlay. Reading a call site is not enough to tell
  -- the same sweep's sibling path, the access-review decision, does cut tokens,
  but one frame up from the shared revoke, after its transaction commits.

  Which resource types need the cut is now a single answered question,
  `jitgrant.TokenCarries`, next to the revoke itself. It is read off what the
  issuer puts in a token and what the enforcement point reads back: `role`,
  `privileged_role` and `group` are claims, so ending one leaves a live
  credential; `application` is in no claim -- access is read from the table at
  the moment it is used, so the row being gone *is* the enforcement, and cutting
  there would force a re-login that changes no decision. An unknown type answers
  yes, because a type nobody classified is likelier to be a forgotten claim than
  a live table read, and being wrong that way costs one re-authentication rather
  than access that outlives its own expiry.

  The marker is written only after the access is actually gone. A revoke that
  failed leaves the request `fulfilled` for the next tick and cuts nothing: a
  marker for a user whose access is still live is a re-login that fixes nothing
  while reading, in the log, as though the deadline had been enforced.

  `killUserSessions` now takes the reason it was called for, because the marker
  is one key and the log line is the only place the caller survives.

  Measured against a real PostgreSQL and a real Redis, with the general and
  revocation roles bound to separate Redis databases so a marker written to the
  wrong one is visible, and read back through the key the enforcement point
  reads. Five mutations red: removing the revoke, writing to the general Redis,
  making every resource type carry a token (which erases the `application`
  decision), cutting before the access is removed, and removing the missing-Redis
  guard. An install with no Redis still sweeps -- refusing to run would leave the
  elevation live in the database *and* the token.


- **Three admin-plane paths take a role away, and none of them cut the token.**
  `RemoveUserRole`, `UpdateUserRoles` and `DeleteRole` are each reached from an
  HTTP handler an administrator drives directly. None disables the account, so
  none was covered by the sever work, which revokes only where the account is
  being cut off entirely.

  The enforcement point reads the caller's roles from the JWT `roles` claim, so
  deleting the row changes nothing for a session already holding a token. The
  administrator sees 200 and an audit line recording success.

  **`DeleteRole` is the one whose own comment already said so.** Above the audit
  event sat *"Deleting a role silently revokes it from every user who held it,
  so the event is a mass revocation as much as a definition change"* — the code
  knew, and still left every holder's token naming the role. It also cut **by
  predicate** (`DELETE FROM user_roles WHERE role_id = $1`), so it had no
  identities to revoke: `RETURNING user_id` now, the third place in this series
  that needed the same correction.

  **A grant is not a revocation, and the fix does not treat them alike.**
  `UpdateUserRoles` replaces a whole set, which is both at once. Revoking on
  every role write would end a live session each time somebody was *granted* an
  extra role, for no security gain — a token that does not yet carry a new role
  permits nothing it should not. So only the difference (`lostRoles`) triggers a
  cut. Adding a role, and replacing a set with itself, leave the session alone.

  Measured against a real PostgreSQL and a real Redis, with general and
  revocation bound to two different databases, reading the marker back from the
  key the enforcement point reads.

  **Five mutations red:** dropping the revoke from `RemoveUserRole`, dropping it
  from `DeleteRole`, revoking unconditionally in `UpdateUserRoles` (which cuts
  grants), making `lostRoles` return everything rather than the difference, and
  removing `RETURNING` so `DeleteRole` has nobody to revoke. One of the five did
  not compile on the first attempt and was redone rather than counted.

  **Six of the ten role-reducing paths remain**, and are listed in the plan.

- **A time-bound role elevation outlived its own expiry.** `user_roles.expires_at`
  is this product's temporary elevation — somebody is made an admin until 15:00.
  At 15:00 the sweep deleted the row, logged a count, and stopped.

  The enforcement point never reads that row. `PermissionResolver` takes the
  caller's role list from the JWT `roles` claim, so the access token minted at
  14:00 kept saying "admin" and kept being believed until it expired on its own.
  The grant had a deadline; the credential carrying it did not.

  **Clearing the permission cache cannot fix this**, and the fix does not try.
  That cache is keyed on (org, *role set*), so the entry the stale token
  resolves to is the same entry every genuine holder of that role resolves to —
  it is correct for them and must not be deleted. What has to change is the
  token, and the per-user revocation marker is the one thing the enforcement
  point consults for that.

  The sweep also had nothing to revoke *with*: it cut by predicate
  (`WHERE expires_at < NOW()`) and reported `RowsAffected`, and a number cannot
  be revoked. It now uses `RETURNING user_id` — the same correction the stale
  account cleanup needed for the same reason. The marker goes to the
  **revocation** Redis, not the general one, and one user holding several
  assignments that expire on the same tick is revoked once.

  Measured against a real PostgreSQL and a real Redis, with the general and
  revocation roles bound to **two different Redis databases** so a marker
  written to the wrong one is visible rather than silently accepted. The marker
  is read back from the key the enforcement point reads.

  **Four mutations red:** dropping the revoke (the old behaviour), writing to
  the general Redis, dropping the `expires_at < NOW()` predicate so the sweep
  takes live elevations too, and dropping `RETURNING` to go back to a count. A
  fifth did not compile and was redone rather than counted.

  A deployment with no Redis still sweeps: refusing to run would leave the
  elevation in place, which is worse than removing it and saying in the log that
  the token was not cut.

  **This is one of ten paths that reduce a user's effective roles**, and the
  other nine are not fixed here. Each needs its caller read before it is decided
  — two of them already revoke because they also disable the account, and a
  blanket patch would add a second marker write there and nothing would go red.

- **Sixteen CI steps went silent at the only moment they mattered.** Each one
  exists to name which test ran and passed, and each was written as
  `out=$(go test ... 2>&1)` followed by `echo "$out"` under `set -euo pipefail`.
  When the test *failed*, the shell left the step at the assignment and never
  reached the echo — so the job reported `Process completed with exit code 1`
  and not one line of test output.

  A control that reports nothing when the thing it watches breaks is the same
  defect this series is about, this time in the harness rather than the product:
  the steps were added to make a skipped or renamed test impossible to miss, and
  they hid the failure they were built to surface.

  Found the hard way. The `rls-isolation` job went red on this branch's head in
  a step covering `internal/access` — a package this PR does not touch — and the
  reason was unrecoverable from the log, because there was no reason in the log.
  Every capture now ends `|| { echo "$out"; exit 1; }`.

  Verified rather than assumed: the old shape prints nothing and exits 1, the
  new one prints the detail and still exits 1. Every `run:` block in the file
  was re-parsed with `bash -n` after the change, and
  `check-workflows-parse.sh`, `check-race-timeout.sh` and
  `check-docs-drift.sh` all pass.

  **What this does not claim.** It does not fix the `internal/access` failure —
  all seven of that step's tests pass locally against a fresh database built the
  way CI builds one (`openidx_app`-owned, freshly created), so there is nothing
  yet to fix. It makes the next occurrence say what it is.

- **A revoke with no Redis crashed the request that was severing the account.**
  Every caller of `revocation.RevokeUserTokens` reaches it through
  `RedisClient.RevocationDB()`, whose contract is that it is nil-safe and
  returns a nil `*redis.Client` when the service has no Redis. That nil then
  crosses into a `redis.UniversalClient` parameter — and a nil pointer inside an
  interface is not a nil interface, so the `client == nil` guard let it through
  and the next line called `Set` on a nil receiver.

  A panic is the worst available outcome for a best-effort sever. The function
  exists so that a missing or unreachable Redis degrades into a logged error
  beside an account that is *already* disabled; taking the process down instead
  turns "the tokens were not cut" into "the sever never finished", leaving the
  account in whatever half-disabled state the panic interrupted.

  Guarded once, at the choke point both `RevokeUserTokens` and `Revoker` share,
  because every sever path in the product passes through them and the accessor
  they all use is the thing producing the typed nil. The guard checks `Kind`
  before `IsNil` — `IsNil` panics on a kind that cannot be nil, and a value type
  satisfying the interface is usable and must not be reported as absent.

  Found by CI, in a suite that has no opinion about Redis at all: the identity
  lifecycle tenant-isolation tests build a `Service` with a database and a
  logger and nothing else, so the `disable_user` branch of
  `executeLifecycleAction` reached the new revoke with no client and
  segfaulted. Mutation: restoring `client == nil` reproduces the CI panic in
  both that suite and the new unit tests.

- **A cache-key assertion still spelled out `perms:v2:`.** The permission cache
  key moved to `perms:v3:` with escaped role names in this same series, and the
  delegation cache-poisoning test built the key it read back by hand — so it
  asked Redis for a key nothing writes any more and failed on the cache read
  rather than on anything it was written to check. It now builds the key with
  `PermissionCacheKey`, the one constructor the enforcement point uses, so the
  two cannot drift again.

- **Most paths that sever a user's access never revoked their tokens.** The
  `internal/revocation` package doc records half of this defect and *names* the
  other half: "a path that severs a user's access and never writes the marker at
  all — and the sever paths were exactly that." `deprovisionUser` and the kill
  switch were fixed. Nobody counted the rest.

  Seventeen functions disable or delete a user row. Two wrote the marker.
  Everything else stops only the *next* login: `/oauth/userinfo` and
  `/oauth/introspect` read the per-user marker and the per-token blacklist and
  nothing else, so the access token already in that browser keeps answering
  until it expires on its own.

  Three are fixed here, and all three are compromise paths:

  - **The CAEP receiver.** A federated partner sends `session-revoked`,
    `account-disabled` or `credential-change`; the code revoked sessions and
    refresh tokens and disabled the account, and left the access token alone.
    That signal is the entire reason CAEP exists.
  - **Risk auto-remediation.** `RemediateAccountLock` locks an account on
    impossible travel, brute force or a blocked IP — the moment the product
    decides the account is compromised.
  - **Leaver offboarding.** The transaction disables the account, revokes the
    API keys, strips roles and groups and deletes the session rows. The marker
    is written after the commit, because it lives in Redis and cannot join the
    transaction, and writing it before would cut a user whose offboarding then
    rolled back.

  The remaining eleven are recorded in a register that only shrinks, not fixed
  in one sweep, and the reason is the finding. `user_repository.Delete` *looks*
  like a defect from the census and is not — its caller deprovisions first,
  deliberately, so a concurrent refresh cannot slip through against a
  still-present user. A mass patch would have added a second write there and
  nothing would have failed.

  The directory syncs were the last three, and the first reading of them was
  **wrong**: "`internal/directory` has no revocation client at all" was read off
  the `SyncEngine` struct — a database handle and a logger — and turned into a
  claim about the package, and from there into "only the event bus can fix
  this". Checking the call sites instead took two minutes and showed the
  opposite: `Service` already takes a `*redis.Client` through `SetRedis`, and
  both binaries that *start* the scheduler already pass one.

  So the plumbing was done rather than deferred to an architecture that does not
  exist yet. `SyncEngine` takes a revoke callback, `Service.SetRevoker` forwards
  it, and the two binaries wire `revocation.Revoker(redis.RevocationDB(), log)`.
  A separate method from `SetRedis` deliberately: that one takes the general
  client for the scheduler's leader gate, and this marker has to reach the
  *revocation* Redis — writing it to the wrong one is the defect this package
  was created to fix.

  The shape of the mistake is worth keeping: a two-field struct is evidence
  about that struct, not about what its callers can reach, and "this needs the
  bus" is the most expensive conclusion available from not looking.

  Ten of the remaining eleven were fixed in the same pass, once each had had
  its caller read: bulk disable and delete, the lifecycle policy, ISPM
  remediation, DSAR erasure and restriction, stale-account cleanup, the
  `disable_user` and `revoke_sessions` lifecycle actions, and the IBDR breach
  quarantine. Stale-account cleanup severs *by predicate* rather than by id, so
  it now uses `RETURNING id` — without the ids there is nothing to revoke.

  The quarantine service was given the revoke *function* rather than its own
  Redis client, because a second client is how this product ended up with
  several hand-rolled copies of one marker write. The field is nil-safe on
  purpose — containment must still run — which is exactly why nothing would
  notice it silently becoming nil. The census cannot see through a function
  field either (measured: removing the injection everywhere leaves it green),
  so the wiring is guarded next to the constructions, where the question is
  answerable, and the register records that limit as `revokes-indirectly`
  rather than claiming the path is covered.

  Five mutations red on the census, and the fixes are measured rather than only
  counted. The census is an AST guard: it proves a call *exists*, not that it
  fires for the right user on the path an operator takes. So stale-account
  cleanup — the one whose statement changed from `Exec` to
  `Query ... RETURNING id`, without which there were no ids to revoke at all —
  and the shared helper thirteen call sites now depend on are both driven
  against a real PostgreSQL and a real Redis, reading the marker back out by the
  key the enforcement point reads.

  Those tests wire **two different Redis databases** to the general and
  revocation roles, deliberately. With one client for both, "the marker went to
  the wrong role" would be invisible — and a marker written where nothing reads
  it is precisely the defect `internal/revocation` was created to fix. Measured:
  swapping `RevocationDB()` for the general client turns both tests red.

- **A revoked access token came back to life once its revocation record
  expired.** A revocation has to outlive what it revokes, and this package has
  two revocation mechanisms that answered that differently.

  The per-token blacklist gets it right: `MarkAccessTokenRevoked` derives its
  Redis TTL from the token's own expiry, so the entry dies exactly when the
  token does. The per-user marker — written by `/oauth/logout-all`, by an access
  review, by a leaver's deprovisioning and by the **kill switch** — uses the
  constant `revocation.MarkerTTL`, seven days, justified in its own comment as
  "comfortably longer than any access token this product mints (an hour by
  default)".

  An hour is the default, not the limit. `access_token_lifetime` is a per-client
  `INTEGER` column set through client registration and nothing capped it, so a
  client configured with thirty days minted thirty-day tokens while the marker
  revoking them expired after seven. `IsAccessTokenRevoked` reads a missing
  marker as "not revoked" — correctly, since it cannot tell never-revoked from
  expired — so on the eighth day the revoked token was accepted again. A
  revocation that un-revokes itself is worse than none, because an operator
  watched it succeed.

  The invariant is one sentence: no path mints an access token that outlives the
  marker able to revoke it. `maxAccessTokenLifetimeSeconds` is now *derived*
  from `revocation.MarkerTTL` rather than chosen,
  `OAuthClient.EffectiveAccessTokenLifetime()` clamps at mint, and client
  registration refuses anything longer outright.

  Clamping and refusing are not the same thing and both are needed. Clamping
  covers rows on installs that already set the column — refusing at mint would
  break a working client at the worst possible moment. Refusing is how whoever
  configures a *new* client finds out, instead of asking for thirty days, being
  handed seven, and believing the first number.

  Seven minting paths read the raw column. A census guards them, because a clamp
  only helps at the call sites that use it and a new grant type added next year
  is one field access away from minting a token nothing can revoke — and it
  would look exactly like the code beside it.

  Six mutations red.

- **A revoked permission could stay in effect, depending on what the role was
  called.** `PermissionResolver` caches a role set's effective permissions in
  Redis and `RequirePermission` decides from that cache;
  `invalidatePermissionCache` clears the entry when a role's permissions change.
  It did so with a `SCAN` over `perms:*<roleName>*` — interpolating the role
  name into a Redis MATCH pattern. **A role name is not a pattern.**

  Role names arrive in the request body of `POST /api/v1/identity/roles` and
  nothing validates them: the struct carries no binding tags. So a role named
  `ops[x]` made a glob character class — `perms:*ops[x]*` looks for `ops`
  followed by the single character `x`, while the key to delete contains a
  literal `[`. The `SCAN` matched **nothing**. The revoke committed, the API
  answered 200, and the enforcement point kept granting the permission until the
  entry expired on its own five minutes later. In a product whose subject is
  access control, a revoke that reports success and does not take effect is the
  defect; the cache is only where it lives. Measured against a real Redis for
  `ops[x]`, `team[a-z` and `back\slash`.

  Two more followed from the same line. `perms:*ops*` also deleted `devops`, a
  different role. And the pattern carried no tenant term, so it deleted every
  *other* organization's entry for a role of that name — role names are
  per-tenant, the same `admin` exists everywhere, so one tenant editing a role
  made every administrator on the install re-query at once.

  A fourth came from the key itself: v2 joined the sorted role names with `,`,
  so the role set `{reader, writer}` and a single role literally named
  `reader,writer` produced the same key. Two different permission sets, one
  entry, whichever filled it first.

  The key is now built and parsed in one place
  (`internal/common/middleware/permcachekey.go`), which is the point: the two
  halves were written separately and drifted — one joined, the other guessed.
  The names stay *in* the key, because invalidation has to find entries by role
  and a hash would hide that, but each is escaped so the separator means one
  thing and a name cannot carry structure. Invalidation scans only its own
  organization's entries and decides membership by string equality over the
  decoded names.

  The `v3:` segment retires the old keys. During a rolling deploy old pods read
  and write v2 while new ones use v3; each is correct in itself, but a revoke
  through a new pod does not clear a v2 entry an old pod is still serving — a
  five-minute window, stated rather than hidden. A partial scan is no longer
  silent either: `iter.Err()` is checked and logged, because a scan that stopped
  early leaves exactly the stale grants this function exists to prevent.

  Six mutations red.

- **The webhook retry sweep multiplied the backlog instead of draining it, and
  the delivery backoff was written down and then defeated one line later.** The
  queue is a Redis list and the record is PostgreSQL, and nothing wrote down
  which deliveries were already on the queue.

  `Publish` inserts a delivery as `pending` and nudges Redis; `processRetryBatch`
  scans for pending rows and pushes them back, so a nudge lost to a Redis blip
  still gets delivered. That backstop is right. What it could not tell apart was
  a delivery nobody has queued and one the consumer simply has not reached yet —
  a row stays `pending` for its whole life in the queue *and* for the whole HTTP
  call. So every thirty seconds the entire undrained backlog was enqueued again.
  Measured: four entries for one event after three ticks, and eighty entries for
  twenty deliveries when four sweeps ran at once, which is what a Redis outage
  does to the leader gate that was the only thing holding it to one.

  That is not at-least-once delivery. At-least-once is a delivery that may
  repeat; this was a feedback loop whose output grew with how far behind the
  consumer already was, so it grew fastest exactly when the consumer was already
  struggling.

  `scheduleRetry` stored a one, five and thirty minute `next_retry_at` and then
  pushed the delivery id straight back onto the queue, where a consumer blocked
  on `BRPop` took it within milliseconds — nothing on the consumer side read
  `next_retry_at` at all. The effect was not a hammered endpoint (the attempt cap
  is three) but something worse: all three attempts were spent in under a second
  and the delivery was marked `failed`, so a retry policy meant to ride out a
  thirty-six minute outage rode out nothing, and a customer endpoint that
  restarted in ten seconds had already lost the event.

  And the idempotency guard — return early when the row already says
  `delivered` — is a read, not a claim. It absorbs a duplicate consumed *after*
  the first finished, which is why the amplification did not show up as
  duplicate POSTs in a single-consumer drain. It cannot absorb one consumed at
  the same time: measured, four consumers, four POSTs to the customer for one
  event.

  Migration v194 adds `webhook_deliveries.queued_at` to carry the claim. The
  sweep takes each row as it selects it, the consumer claims rather than reads,
  `scheduleRetry` releases the claim instead of re-nudging, and `Publish` records
  what it queued. A second column rather than reusing `next_retry_at`, and the
  first version of the fix proved why by breaking: `next_retry_at` is *when a
  delivery becomes due*, `queued_at` is *whether someone already has it*. Folding
  them together made the sweep's own claim look, to the consumer, like a delivery
  that was not due — so the customer's endpoint was called zero times.

  No new status value, so nothing can strand: whatever happens to the process
  holding a delivery, the row is claimable again after the claim window. The cost
  is that recovering a lost nudge now waits out that window rather than the old
  thirty-second grace — the sweep cannot tell a lost nudge from a slow consumer,
  and guessing the other way is what multiplied the queue.

  Measured against a real PostgreSQL, a real Redis and a real HTTP endpoint that
  counts what it was sent. Six mutations red.

- **The audit search index accepted events PostgreSQL had refused, including
  over another tenant's.** `audit.LogEvent` writes the event to `audit_events`
  and then dual-writes it to Elasticsearch — and it started that second write
  without looking at whether the first one succeeded.

  The audit trail has two stores and only one of them is the record.
  `audit_events` in PostgreSQL is the tamper-evident one: v181 gave it
  `chain_seq`, `prev_hash` and `event_hash`, and the sealer chains every row
  into a per-org sequence. Elasticsearch holds a copy for search, and the
  console reads *that* one. The lag between them has to run one way:
  PostgreSQL may be ahead of the index — the index write is fire-and-forget and
  the reconciler backfills — but the index may never be ahead of PostgreSQL. A
  document the record never accepted has no sequence number, no hash and no
  seal, and chain verification walks only the rows that exist, so it would keep
  reporting the chain intact while the console showed an event the chain says
  nothing about.

  The sharp edge is that `id` is also the Elasticsearch *document* id, and it
  arrives in the body of `POST /api/v1/audit/events`, which is deliberately
  unauthenticated (service-to-service, isolated by network rather than by a
  JWT). The `PRIMARY KEY` on `audit_events.id` is the only thing in the system
  making that document id unique. So a caller supplying another tenant's event
  id had the INSERT refused and the indexed document **overwritten** — measured:
  org A's refused event replaced org B's document while org B's row sat
  untouched in PostgreSQL, with nothing in the record saying so.

  No adversary is required for the same defect. `LogEvent`'s own comment records
  an era when every audit event access-service emitted was refused because the
  id was empty and the column is a `uuid`; seen from this side, that era shipped
  all of them to the index and none to the chain. The same shape today is a
  statement timeout — which the per-plane roles set, and which arrives under
  load.

  The fix is one early return, and the reverse direction is unchanged because it
  is the designed state. Measured against a real PostgreSQL and a real HTTP
  Elasticsearch (the product's own client, over the wire), since the question is
  about the ordering of two round trips. Five mutations red.

- **A 7.08 MB compiled binary was tracked in the repository, and its ignore line
  had been doing nothing for as long as it existed.** `.gitignore` carries a
  hand-written list of the binaries `go build ./cmd/<x>` drops into the working
  directory, and `/orgscope` was on it — but an ignore line does not untrack a
  file committed before it, so the build sat in the tree while the entry looked
  like it was working.

  Found by nearly repeating it: `cmd/event-relay` was new, the list was not
  updated, and a 42.8 MB binary went in with the commit that added the source.
  Checking the list against the tree then showed it had been drifting for a
  while — six of the sixteen commands and five of the tools were missing too.

  `tools/repohygiene` is the comparison, in two halves, because the list is
  necessary and not sufficient. One test asserts every `package main` under
  `cmd/` and `tools/` has a `/<name>` line. The other asks **git** what is
  tracked rather than guessing from what is on disk — a developer's own build at
  the root is the system working, and the only question that matters is whether
  a thing is committed. Both go red when reverted: re-tracking the binary, and
  removing a single line from the list.


- **The event sink refused this platform's own event types.** Every piece of the
  outbox had been measured alone; that the pieces *fit* had not. The first
  end-to-end test — a business transaction at one end, a real broker at the
  other — claimed three events and delivered **zero**: the sink's subject check
  rejected any value containing a dot, and this platform's event vocabulary is
  dotted (`user.created`, `session.revoked` in `event.go`). The rule looked
  principled and rejected what the rest of the package publishes. Every unit
  test passed, because the unit test encoded the same wrong rule the code did.

  The two halves of a subject are now checked differently, because they do
  different jobs. The **tenant** occupies one token — a dot there moves the
  event into another tenant's position, and a UUID is one token already. The
  **event type** may be a dotted hierarchy, which is what a consumer subscribes
  into with `<prefix>.<org>.user.>`. Both still refuse wildcards, whitespace,
  control characters and empty tokens.

  The lesson outlives the rule: a unit test that shares an assumption with the
  code it checks is green for the same reason the code is wrong. Only the
  composition could catch this one.


- **The outbox's sink, and the one publish call that satisfies its contract.**
  `NATSSink` implements `Sink` over JetStream. `Sink.Publish` promises the
  broker has accepted the event when it returns nil, and the relay deletes the
  outbox row on that nil — so the choice of publish call is the difference
  between at-least-once and at-most-once. Measured here, in this repository's
  own code: 200 synchronous publishes, all 200 in the stream at the instant the
  call returned, **233 µs each**. The mutation that swaps in `PublishAsync`
  drops it to **11 µs each** — a twentyfold speedup that loses events. A profile
  will point at that line one day; `no_async_publish_test.go` is what turns red
  when someone acts on it. AST and not grep, because the file's own comment
  names both forbidden calls in order to explain them, and a guard that cannot
  tell a call from a sentence gets worked around by not writing the sentence.

  The message id is a deduplication key rather than a trace field. The relay is
  at-least-once **by design** — publish, then commit the mark, and a crash
  between the two redelivers — which makes duplicates ordinary traffic. Stamping
  the event id means the broker drops that redelivery inside its duplicate
  window, so the consumer never sees it. The window outlasts a relay restart,
  which is the only length that buys anything.

  The subject is assembled and checked, not interpolated. `.` separates tokens
  and `*` and `>` are wildcards, so an event type of `user.>` would publish
  across a subtree a narrowly permitted subscriber was never meant to receive.
  Eight shapes are refused, and the refusal happens **before** the publish —
  measured against a real broker, which holds zero messages afterwards.

  Seven days of retention belongs to the stream and not to the server, so the
  sink creates the stream itself: one somebody else created with different
  settings would change what the relay guarantees without changing the relay.
  Read back and asserted. Five mutations red, and a CI step that starts a real
  `nats-server` and checks each of seven tests by name — without `TEST_NATS_URL`
  they all skip, and a skipped suite looks green.

  New dependency: `github.com/nats-io/nats.go` v1.53.1.


- **The chart can deploy NATS JetStream, and the broker's own parser is what
  says the config is valid.** Global-scale task 3.2's Helm half:
  `templates/nats.yaml` ships a StatefulSet (not a Deployment — each peer needs
  both a stable name for the route list and its *own* store), a headless and a
  client Service, a ConfigMap, a Secret, a quorum-shaped PodDisruptionBudget and
  its own ServiceMonitor. Default off, and with it off the render contains no
  `nats` line at all.

  **The interlocks refuse rather than render**, which is the lesson task 2.2
  wrote into pgcat.yaml. Seven refusals, each measured: `replicaCount` of 2, 4
  or 0 (Raft commits on a *majority*, so two peers still need two — losing one
  pod stops writes, strictly worse than the single node that never promised
  otherwise), either missing password, an empty `jetstream.size`, an empty
  subject prefix. 1, 3 and 5 render.

  Three things the earlier measurements decided outright. The store sits in a
  `volumeClaimTemplate` because the container securityContext sets
  `readOnlyRootFilesystem` and a store the server cannot use is
  `[FTL] Can't start JetStream` and exit 1, never a quiet fallback to memory.
  Both halves of the command line are spelled out even though the image carries
  an `ENTRYPOINT` (the inverse of pgcat, where `args` alone replaced the
  binary), so what the kubelet execs does not depend on a shell script this
  repository has never run. And the disruption budget is computed from the
  quorum, `(n-1)/2`, rather than being a round number.

  **Two findings came out of building it.** `1Gi`, `1GB` and `1073741824` parse
  to the same config in nats-server — verified by the checksum `-t` prints — so
  Kubernetes units pass through unconverted; `1G` does **not**, being decimal
  and 7% smaller while remaining silently valid. And the server answers a
  plaintext password with `[WRN] Plaintext passwords detected, use nkeys or
  bcrypt`: the value lives in a Secret and enters the config as `$VAR`, but the
  server sees it expanded. Helm has no bcrypt; nkeys will be weighed with task
  3.3, and until then the warning is **not** suppressed — a silenced warning
  looks like a decision that was made.

- **Subject permissions, and an explicit statement of what they are not.** Two
  users: the relay may publish under the platform prefix and to the JetStream
  API and may subscribe only to its own inbox; the consumer may read the prefix
  and may not write it. All five cases were measured against a real server
  started from the config **helm rendered**, not from one written for the test —
  a NATS permission violation is asynchronous, so each case flushes and reads
  what the error handler caught.

  What this does not do is isolate one tenant from another. Subjects are
  `<prefix>.<org_id>.<event>` and an allow-list cannot enumerate organizations
  created at runtime; tenant isolation on this path is the publisher stamping
  `org_id` and the consumer scoping its writes, the same belt the database
  carries. Saying so in the config is cheaper than someone later reading that
  block as a boundary it is not.

- **CI step "The broker is safe by construction".** Six properties, and the last
  is why the step exists rather than leaning on kubeconform: a chart can render
  a syntactically valid Kubernetes manifest whose ConfigMap holds a config the
  *server* refuses, and the first to find out is the kubelet. `nats-server -t`
  parses a config and exits, its parser is strict at every depth, and the step
  feeds it what the chart actually rendered. The binary comes from the module
  proxy — one static file, no container runtime, no trust anchor beyond the one
  Go already uses.

  Seven mutations. Six red on the first attempt, including a permission key
  misspelled as `alow`, which **only the real parser** catches. The seventh
  stayed green and found a hole in the guard itself: "default off" was written
  as `if render | grep -q ...`, and with the enabled gate removed the render
  failed on a missing password, grep saw nothing, and to a pipeline "no NATS in
  the output" and "no output" are the same answer — `set -e` does not apply
  inside an `if` condition. The render now goes to a file on its own line, where
  a failure is a failure, and the mutation is red.


### Changed

- **The admin plane's last two lag-tolerant reads moved to the replica, decided
  by evidence rather than by judgement.** Global-scale task 2.3 stopped at file
  granularity with a note saying the remainder — handlers over historical
  aggregates, like ISPM posture trends and MFA enrolment stats — could only be
  settled "one screen at a time, by someone who can say whether that tile is
  refetched after a mutation", and that more machinery would not help.

  Half of that was wrong. More machinery over the *Go* source would not help:
  "this function does not write" licenses exactly the moves that must not be
  made, because the write lives in `handleCreateX` and the relationship is the
  console's create-then-refetch across two handlers. But the console is in this
  repository, and in a TanStack Query application a tile is refetched after a
  mutation **iff some mutation invalidates its query key**. That is not a
  heuristic about source shape; it is the console's own definition of
  read-after-write, and it is greppable.

  Both keys — `ispm-trends` and `mfa-enrollment-stats` — appear exactly once in
  `web/admin-console`, at their own `useQuery`, and in no `invalidateQueries`
  call. The ISPM scan writes today's snapshot row and invalidates
  `['ispm-score']` and `['ispm-findings']` and not the chart, so the chart is
  not refetched after a scan at all; the MFA screen writes policies, never
  enrolments, and all three of its mutations invalidate `['mfa-policies']`.

  The new `offloadedHandlers` tier pins the whole chain — console query key →
  the URL its `queryFn` fetches → the route registration in `service.go` → the
  handler → the replica — so a console change that starts invalidating one of
  these keys turns the Go test red, in CI, in the same repository as the change.
  Inside a file that stays on the primary the guard **counts** rather than
  forbids: a second query quietly switched to `Reader()` raises the file's count
  above the declared bodies' and fails, even though the file is already allowed.
  An `invalidateQueries()` with no arguments (which refetches everything) now
  has to be declared too; the one that exists is the tenant switcher, and a
  context change is not a read-after-write.

- **Task 2.3's unmeasured assumption, measured.** A read through `Reader()` is
  not a bare `SELECT`: in `RLS_MODE=local` it is `BEGIN` +
  `select set_config('app.org_id', …, true)` + `SELECT`, and a replica answers
  SQLSTATE 25006 to anything it counts as a write. Nothing in the tree had asked
  a real server whether that shape survives. If the answer were no it would not
  be one handler that broke but all six already-offloaded files at once, on the
  day `values-prod.yaml` sets `readReplica: true`.

  Measured against a session with `default_transaction_read_only=on` — the same
  refusal, from the same server: both handlers answer, stay tenant-scoped, and
  the pool they read from really does reject a write with 25006. Eleven
  mutations red, including the two that keep the measurement honest (a replica
  pool that is not read-only, and no replica pool at all — which would leave
  `Reader()` handing back the primary while the test claimed to be reading a
  replica).

### Fixed

- **The certificate expiry monitor reported a failed rotation every hour, for a
  rotation that had succeeded.** The hourly monitor runs in every replica and
  every replica lists the same expiring certificates. `RotateCertificate` has
  always **claimed** — `UPDATE ziti_certificates SET status='rotating' WHERE
  id=$1 AND status='active'` — so exactly one replica rotates and the rest stand
  down; that part was right. What was wrong is what the rest then *said*:
  `Auto-rotation failed for certificate`, at Error, about a certificate another
  replica was rotating correctly.

  A certificate rotation is a security-relevant operation, and an operator who
  watches it fail every hour for a rotation that in fact succeeded learns to skip
  the line — the same defect the user-sync poller had, one alarm at a time.
  Losing the claim is now its own error (`errRotationNotClaimed`) and the monitor
  logs it as what it is. Two mutations red: dropping the claim's predicate, and
  making the stand-down indistinguishable from a failure again.

- **The Ziti user-sync poller reported a failure for every user it synced
  successfully.** `runAutoSync` selects up to ten users with no Ziti identity and
  every replica selects the same ten, so at the 30-second tick two replicas both
  ask the controller for an identity and both try to persist it. Nothing
  corrupts — two unique constraints sit on the same name, one in each system: the
  controller rejects a duplicate identity name (the loser adopts the winner's,
  which the create path already handles) and `ziti_identities.name` is UNIQUE
  with `name` = the user id.

  What did not converge was the **report**. The losing insert raised a unique
  violation and the poller logged `Auto-sync failed for user` — once per losing
  replica, per tick, for a user that had just been synced. An operator watching
  for sync failures saw one every thirty seconds that meant nothing, which is the
  kind of alarm that teaches people to ignore the channel. The insert is now the
  claim (`ON CONFLICT (name) DO NOTHING`): the caller that writes the row reports
  the creation, and the one that loses says so quietly.

  The controller half is **read from its contract, not measured** — there is no
  Ziti controller in reach, the same honesty the census applies to
  `ziti_reconciler.go`. The database half is measured against a real PostgreSQL,
  and the test also pins that the surviving row carries an enrolment token: a row
  written by the loser would hold the adopted identity's empty JWT, and that user
  could never enrol a device.

### Fixed

- **Two replicas sealing one recording destroyed it, and the row still read
  "sealed".** `sealOneGuacRecording` rewrites a guacd session recording in place
  as ciphertext, and the sweep's candidate query selected on
  `recording_sealed_at IS NULL` with no claim. Two replicas on the same tick both
  saw the same unsealed row, both stat'd the same file, and both sealed it — the
  second reading the first's ciphertext as though it were plaintext. What landed
  on disk was **doubly encrypted**, `recording_sha256` held the digest of the
  ciphertext the second sealer saw, and one decrypt pass returned ciphertext
  rather than the session. On a product that records privileged sessions for
  compliance, that is evidence destroyed silently: the row looks sealed, the file
  looks sealed, and playback is gone.

  The sweep's own comment had already named the same corruption on a different
  path — a crash between the rename and the metadata write leaves ciphertext with
  the row still unsealed, so the next tick re-seals it — and accepted it as
  something to reconcile by hand.

  **The sealer now refuses ciphertext, and the refusal is a proof rather than a
  guess**: the probe decrypts the first frame, so AES-GCM authenticates the
  answer. That makes the seal idempotent by construction at any replica count and
  closes the crash path with the same line. The announcement half is a claim
  (`recordGuacSeal`): the replica that records a seal is the one that announces
  it, because an auditor asking "when was this recording sealed, and under which
  key" must not get two answers.

- **A recording frame's length was four bytes from the file, and the reader
  believed them.** `nextFrame` read a `uint32` length and allocated it before
  authenticating anything — so a file whose header happened to say four gigabytes
  made the playback path allocate four gigabytes. The write side has always been
  bounded (`maxRecordingChunkBytes`, whose own comment says "so a runaway caller
  can't OOM us here either"); only the read side was not.

  **This was found by measurement, not review**: the new probe reads *plaintext*
  recordings, and a test that reads three small files took **12.7 seconds** —
  which is Go zeroing the allocations that line asked for. With the bound it is
  under a tenth of a second, and the mutation that disables the bound reproduces
  the 16-second stall.

### Added

- **The census guard learns what makes an `INSERT` idempotent.** Its rule was
  "an insert per pass is a row per replica", which is the shape that was actually
  wrong in this tree — but an `INSERT … ON CONFLICT (<column>) DO NOTHING` is a
  **claim**: the second replica's row is refused by a key rather than written.
  The guard now accepts that and only that.

  **The conflict target has to be named, and the Guacamole defect is why.** That
  sync also said `ON CONFLICT DO NOTHING` — and could never fire it, because the
  row it inserted carried a freshly generated uuid primary key, so no two
  attempts ever collided. A targetless `ON CONFLICT` is a statement about
  whatever unique index happens to exist; a named one is a statement about the
  key the claim rests on. Two mutations red: unnaming the target, and resolving
  the conflict by overwriting instead of standing down.

- **The sweeps census decides `remote_support_retention.go`, and its guard learns
  to follow a sweep into a sibling file.** One ticker drives five sweeps; the
  purges were already self-clearing (each candidate query filters on its own
  `purged_at`) and the sealer is the one that needed the work above. The census
  question had guessed "sealing is a chain-shaped write"; it was worse than that,
  and now it is idempotent by construction.

  The entry also forced a fix in the register itself. The census keys on the file
  that starts the **ticker**, which is the right key — that is where a new ticker
  appears — but the sealer lives in a sibling file because it is a subsystem of
  its own. An entry could therefore either name a function the guard could not
  find or name only the half that happened to share the file. The guard now looks
  in the entry's file first and then in its package, keeping what makes it a
  guard (the function must exist, and its body is what gets read) while dropping
  the assumption that a ticker and its sweeps share a file. The undecided backlog
  is down from four to three.


### Added

- **The agent grace-period enforcer decided: `idempotent`, and it is the first
  entry that also *emits*.** The census question was whether a pass pushes
  anything, and it does — every agent it suspends gets an `agent.suspended` row
  in the unified audit stream. That is exactly the shape the Guacamole external
  audit sync got wrong: one row per replica for a single recorded event, which on
  a compliance product is a wrong answer rather than waste.

  It is right here because **the claim and the work are the same statement**:
  `UPDATE … WHERE compliance_status = 'grace_period' … RETURNING`. A second
  replica blocks on the row lock, re-evaluates against the committed row, gets
  nothing back, and so never reaches the audit insert. Eight concurrent enforcers
  suspend two agents and announce each once; the agent still inside its grace
  period is untouched. Two mutations red: making the predicate non-self-clearing,
  and inverting the grace window so a device inside its grace period is
  suspended.

  **Each replica in that test gets its own connection pool, and that is not
  tidiness.** The sweep holds the `RETURNING` cursor on one connection while
  writing audit rows on another, so a replica needs two at once — eight
  goroutines sharing one pool is one process pretending to be eight, and it
  deadlocks on pool exhaustion the moment more than one gets rows back. Found the
  hard way: the first mutation run **hung instead of failing**. Backlog five to
  four.

- **The remote-support janitor decided: `idempotent`, measured.** It sets
  `status='expired'` on rows `WHERE status IN ('pending','active')` — the write
  makes the predicate false, so a second replica matches nothing. Eight
  concurrent janitors expire the two orphans once, leave the session with recent
  activity alone, and land settled.

  The test digests the **values** rather than counting rows, and here that is not
  a technicality: the failure mode is a sweep that re-applies itself and rewrites
  `ended_at` with a fresh `NOW()` on every tick, and on a product that records
  support sessions for compliance, an `ended_at` that drifts forward is a wrong
  answer to "when did this session end", not a wasted write. Two mutations red:
  dropping the self-clearing predicate, and inverting the idle window so live
  sessions are aged out from under their operator.

  The file's *other* ticker is not a sweep — `runPeer`'s is a per-websocket
  keepalive for one connected peer, per-process by definition, and gating it
  would mean a leader holding another pod's websocket open. Backlog six to five.

### Fixed

- **The stale Guacamole grant sweep never stopped, and its `LIMIT` was a ceiling
  rather than a batch size.** `sweepStaleGuacGrants` revokes the per-connection
  READ an ended PAM session left behind on a standing Guacamole account — the
  safety net for the browser-closed sessions nothing else cleans up. It wrote
  nothing, so the rows it had just handled matched its predicate again five
  minutes later, and again after that: a session that ended in March was still
  being revoked in June. Re-revoking an absent grant is a tolerated 404, which is
  why this was silent — **the sweep never failed, so it looked like it was
  working**.

  The wasted broker calls are not the part that matters. The query carries
  `LIMIT 200` with no progress marker, so once more than two hundred rows match —
  which grows as an install ages and never shrinks — the sweep revisits an
  arbitrary two hundred and the rest may never be reached. The grants that most
  need revoking are exactly the ones that can sit behind that limit
  indefinitely.

  **Migration v193** adds `pam_entry_sessions.guac_revoked_at` and a partial
  index on the sweep's own predicate, and the marker is written **only when the
  broker confirms** the revoke: a refused revoke leaves the row unmarked so the
  next tick retries, which is the same posture the lifecycle sweep takes with
  session termination and for the same reason — a grant recorded as revoked while
  the access survives is the silent hole this sweep exists to close.

  Measured against a real PostgreSQL and an HTTP broker: the first pass revokes
  the ended session and the twelve-hour-stale one and leaves the live one alone;
  **the second pass calls the broker zero times**. Three mutations red — dropping
  the marker from the predicate (which is the old sweep, and it revokes twice),
  recording a refused revoke as done, and collapsing the staleness window so live
  sessions are cut mid-use. The census entry for `guacamole_users.go` moves from
  undecided to `idempotent`, naming both of the ticker's sweeps; the backlog is
  down from seven to six.

- **The Ziti fabric health monitor wrote every fabric fact once per replica.**
  The 30-second tick is two kinds of work in one function, and the census
  question about it had both answers. The health check and the
  re-authentication are per-process and must run in **every** replica: each pod
  holds its own SDK session, and a pod that skipped its own re-auth because
  another pod was the leader would stay disconnected. The seven metrics it then
  wrote are the opposite — routers online, routers total, services, identities
  and policies count are properties of the **fabric**, not of the pod.

  So eight replicas wrote the same fact eight times, and the cost was not only
  storage: the fabric overview reads the most recent 50 rows of `ziti_metrics`,
  so that window fell from roughly three and a half minutes of history to
  twenty-six seconds of the same instant, eight times over. The metric half is
  now gated per tick with `leader.IsLeaderForTick`; the health check and re-auth
  are untouched.

  Measured both directions: eight replicas racing one bucket against a real
  Redis and a real database write **seven** rows (with the gate consulted but
  ignored they write **fifty-six**), and an install with no Redis still records
  its metrics, because one replica has no peer to coordinate with. The census
  entry moves from undecided to `leader`; the backlog is down from eight to
  seven.

- **The signing-key refresh raced every SAML signature.** `refreshSigner` swaps
  an immutable snapshot through an atomic pointer — the right shape — and then
  *also* assigned the plain fields `s.privateKey` and `s.publicKey` "for any
  direct readers". Those readers are the SAML paths: `signRedirectBinding`,
  `signAssertionEnveloped`, `samlSigningCertBase64` and the step-up token
  issuer all dereference `s.privateKey` **on request goroutines**, with no lock
  and no atomic. And it is not only the refresh ticker that writes:
  `verificationKeyfunc` refreshes inline when a token carries an unknown kid, so
  one request signing a SAML redirect could race another request verifying a
  token.

  `go test -race` reported it on the first attempt, against two objects: the
  pointer field, and the `rsa.PrivateKey` struct it pointed at. The refresh now
  writes nothing but the atomic pointer, and every reader goes through
  `activePrivateKey()` / `activePublicKey()`, which read the snapshot and fall
  back to the construction-time key (unit tests build a `Service` with no
  database behind it). The legacy fields are written once, in `NewService`, and
  never again.

  **The two halves of the fix are not interchangeable, and that was measured
  rather than assumed.** A race needs both the write and the unsynchronised
  read. The `-race` test covers the read half — put a field read back into a
  signing path and it goes red — while restoring only the write leaves it
  green, because nothing reads the field concurrently any more. So the write
  half has its own derived guard, which reads the package's own sources and
  fails on any assignment to those fields outside construction.

  Found while auditing `signer.go` for the sweeps census, where the entry is
  (correctly) `per-process`: gating the refresh behind a leader would leave
  eleven of twelve oauth-service replicas serving a stale JWKS.

### Added

- **The posture expiry sweep, decided — and the idempotence guard narrowed from
  the file to the function.** `internal/access/posture.go` starts a 15-minute
  ticker whose whole body is `DELETE FROM device_posture_results WHERE
  expires_at < NOW()`. Repetition is close to free there, so the half worth
  measuring was the other one: **the sweep decides nothing.**

  That mattered because the table it empties feeds the access proxy's posture
  enforcement, and a sweep that deletes a device's posture data could plausibly
  be the thing that moves that device from allowed to denied — a transition, on
  a Zero Trust enforcement path, running once per replica. It is not.
  `EvaluateIdentityPosture` fails a check whose result has **expired** and fails
  a check with **no result at all** in exactly the same way, so removing an
  already-expired row cannot change any decision. The new test asserts the
  decision itself, per check, across the sweep rather than the row count: a row
  count would pass for a sweep that also deleted live results, and that sweep
  would be a silent denial of service against every device whose posture was
  still valid. Three mutations turn it red — deleting the live rows instead of
  the expired ones, dropping the `WHERE` entirely, and deleting nothing at all.

  **The census guard was wrong about scope, and this entry is what exposed it.**
  It scanned the whole *file* for the two shapes that break idempotence, which
  worked for a 145-line file holding nothing but its sweep and fired a false
  positive on the second entry tried: `posture.go` is 1054 lines with five
  unrelated `INSERT`s on the request path. What the answer is about is the
  sweep, so an `idempotent` entry now names its function and the guard reads
  that function's body — and an entry that names no function, or names one that
  is not in the file, fails. The undecided backlog is down from ten to nine.

- **`sms_config_watcher.go` decided: per-process, and gating it would be the
  defect.** The tick reads one `system_settings` row and writes nothing — it
  swaps *this process's* SMS provider and OTP settings, and its `lastUpdatedAt`
  high-water mark is a local in the watcher's own goroutine. A leader-gated
  version would leave every non-leader pod sending codes through the provider an
  administrator had just replaced, for as long as that pod stayed up. Backlog
  nine to eight.


- **The sweeps census gains a fifth answer — "idempotent" — and the first entry
  measured rather than argued.** `internal/access/lifecycle_sweep.go` runs in
  every replica and its own comment said that was fine: "every statement only
  touches still-active rows, so repeat ticks (or replicas racing) are
  harmless." That is a claim about SQL under concurrency, which is exactly the
  kind this programme keeps finding true of one process and false of several.

  It holds, and now there is a measurement: **eight concurrent sweeps land on
  the same state as one, and land settled** — a further pass after them changes
  nothing. The reason is worth naming: the sweep's writes are `UPDATE … WHERE
  <still active>`, and under READ COMMITTED a second updater blocks on the row
  lock and then re-evaluates its predicate against the committed row, so it
  matches nothing. **The database does the coordinating**, which is why no
  leader and no claim is needed here.

  Four mutations turn it red: pushing the grant expiry into the future instead
  of to now, dropping the still-active predicate from the checkout revocation,
  revoking enabled users too, and dropping the id filter from the elevation
  marking.

  **The first draft of the test missed the second of those.** It counted rows —
  "how many checkouts carry a `returned_at`" — so a sweep rewriting that
  timestamp with a fresh `NOW()` on every pass moved no count. The predicate is
  precisely what makes the statement idempotent, so the test now digests the
  *values* it would rewrite rather than counting the rows that have one.

  The `idempotent` answer rests on its reason rather than on a mechanism, so
  the guard checks the two shapes that were actually wrong in this tree: an
  `INSERT` per pass (which wrote a duplicate audit row per replica) and a
  read-modify-write increment (which billed a customer once per replica).
  Neither proves idempotence; both catch its most common absence. The undecided
  backlog is down from eleven to ten.


- **Admission control: a bound on concurrency, which is not a rate limit.**
  `middleware.Admission` caps how many requests a process carries *at once* and
  refuses the rest with 503 and an honest `Retry-After`. The rate limiter
  already here bounds arrivals and cannot see what the process is already
  holding — 200 requests a second is fine at 5ms each and fatal at two seconds
  against a degraded database, and a per-minute counter cannot tell those
  apart.

  The failure it prevents is not "slow". Without a bound an overloaded service
  accepts everything: goroutines pile up, latency passes every client's
  timeout, the clients retry, and the process dies with a queue full of work
  nobody is waiting for. A bounded queue with a fast refusal turns that into
  degraded-but-alive. There is a queue at all because a 20ms burst is not
  overload; the queue's *timeout* is what stops it absorbing an outage.

  Off by default (`MaxInflight <= 0` is a pass-through): a limit guessed rather
  than measured against the pool behind the service is a self-inflicted outage.
  `/health`, `/ready` and `/metrics` are never gated — a gate that hides its own
  overload is worse than no gate. A client that hangs up while queued releases
  its place immediately, and `queue_wait_seconds` is observed for refused
  requests as well as admitted ones, because a queue measured only when it
  succeeds hides the overload it exists to report.

- **A per-tenant request-COST budget, which sheds by class rather than cutting
  a tenant off.** `middleware.TenantCostLimit` ranks routes into four classes
  and, once a tenant has spent its budget for the window, refuses the expensive
  ones while the cheap ones keep flowing.

  The limiter next door counts requests, and a request is not a unit of
  anything. Measured against this codebase's Argon2id parameters: a password
  verification is **37.3 ms and 19.9 MB**, a JWKS response **6 µs and 540
  bytes**. Six thousand times the CPU and thirty-seven thousand times the
  memory, on an axis a per-IP counter treats as one tick each — and the memory
  is the dangerous half, since a hundred concurrent logins hold two gigabytes
  of Argon2 scratch while the request rate still looks unremarkable.

  Those numbers are **not** the weights. A ratio-true table would spend the
  whole budget on one class and make this a login limiter with extra
  arithmetic, which the auth tier already is. The weights are ordinal — 1, 2,
  5, 10 — and the measurement decides the *order*, not the integers. What the
  budget buys is a shedding priority: a tenant flooding `/oauth/token` gets
  429s on `/oauth/token` while its relying parties still fetch JWKS and still
  verify the tokens they hold. Cutting the tenant off instead would turn one
  team's load test into an authentication outage for every application they
  run.

  Cost-1 routes are never shed **and never charged**: a Redis round trip on the
  JWKS path would cost more than serving it, and if a console's polling could
  spend the budget then a tenant's own dashboard could shed that tenant's
  logins. `RATELIMIT_COST_MODE=off` (default) accounts nothing; `observe`
  reports what enforcement *would* refuse, which is how a budget gets sized;
  `enforce` refuses. An unrecognised mode is refused at startup rather than
  read as `off`. It fails **open** on a Redis outage — this is a capacity
  control, not a security control, and refusing every expensive request
  fleet-wide during a blip is the outage it exists to prevent.

- **Both shedders are mounted by every HTTP service, under a derived guard.**
  The cost budget mounts *after* the tenant resolver, which is not a style
  choice: before it, every request falls into the unattributed bucket and one
  tenant's flood would shed every other tenant's work. `gateway-service` is
  exempt with the reason written down — it derives `X-Org-Slug` from the Host
  for the backends to resolve and never resolves a tenant itself, so there is
  no org id to key a budget by. The guard is derived from `cmd/` rather than
  listed, for the reason the rate-limit guard is: the gateway once carried a
  rate-limit configuration nothing read, for a full release.

- **The platform outbox: events commit with the state change they describe.**
  `events.OutboxBus.Publish` writes the event into the transaction the context
  carries and **refuses** when there is none. An event that describes a state
  change has to be atomic with it — write the row then publish and a crash
  between the two loses the event with nothing to replay from; publish then
  write and the platform has announced something that did not happen. Neither
  window closes by retrying, because the failure is that the process which
  would retry is the one that died.

  The transaction travels on the context (`PostgresDB.WithTxCtx`) rather than
  being threaded by hand through every layer, because the first call site that
  finds the threading inconvenient writes the event outside the transaction —
  which looks identical and is not. Publishing on the *outer* context (the one
  the closure captured) fails loudly for the same reason.

  **The id is not a cursor, and this is measured.** A `bigserial` hands out its
  number at INSERT time while transactions commit in whatever order they
  finish, so a later id can become visible before an earlier one. Two
  concurrent transactions, driven by hand: the lower id committed second, a
  relay paging by `id > lastSeen` **lost that row permanently**, and the
  state-based claim (`published_at IS NULL … FOR UPDATE SKIP LOCKED`, the shape
  the SCIM queue has used since v95) delivered both. Migration **v192** is
  shaped around that: the backlog index is partial, so it stays the size of the
  backlog rather than of the table; `org_id` is `NOT NULL` with a foreign key
  and the FORCE RLS belt lands *with* the table rather than in a later
  migration; `UNIQUE (org_id, event_id)` lets a consumer recognise a
  redelivery, per tenant, because a collision across tenants is a coincidence
  and must not fail one tenant's write on another's.

  Delivery is at-least-once and says so: the relay marks a row published after
  the broker accepts it, and a crash between those two facts redelivers. Making
  it exactly-once would need the broker and this database to commit together,
  which they cannot.

  **Nothing publishes to it yet, and no process runs the relay.** The primitive,
  the relay and the retention sweep are measured against a real PostgreSQL, but
  a mechanism being shipped is not the same as its being exercised. The
  producers are task 3.3 and the relay binary needs a sink, which is task 3.2 —
  the sequencing is deliberate, and it is written down rather than left for a
  reader to notice that this table is one step from the defect the deleted bus
  had.

- **The relay that drains it, with no leader.** `events.Relay` claims a batch,
  publishes it to a `Sink`, and marks what the sink accepted — all in one
  transaction, so there is no claim column, no "processing" state and no
  sweeper for rows a dead relay left behind: dying rolls the transaction back
  and the row is simply unlocked.

  **No leader election, a deliberate departure from the plan.** `FOR UPDATE SKIP
  LOCKED` already *is* the coordination — a row another relay holds is invisible
  to this one. A leader would add a lease, and a lease adds a failure mode this
  design does not have: between a leader dying and its lease expiring, nobody
  relays. What it would buy is global ordering, which this outbox explicitly
  does not promise. Measured: **four relays draining concurrently delivered 60
  events exactly 60 times**, no row claimed twice.

  The sink accepts *and then* the transaction commits, so a crash between those
  two redelivers. That ordering is chosen: a consumer can recognise a duplicate
  by `event_id` and cannot recover an event that was never sent. Measured end to
  end — the sink refused every attempt across five full drains and the backlog
  stayed intact at 25 rows with nothing delivered; when it came back, all 25
  arrived, each exactly once. A forced crash after acceptance redelivered all
  three of its events, and the same three ids arrived twice.

  A poison event stops at `MaxAttempts` rather than consuming the relay forever,
  and **stays in the table** with its last error: something to investigate, not
  something to delete.

- **Retention: delivered rows age out, the backlog never does.** A delivered
  outbox row is a receipt — after an incident the first question is "was this
  published, and when" — but the table sits on the write path of every service,
  so keeping them for ever makes every vacuum slower for a benefit that expired
  weeks ago. `SweepPublished` deletes in **bounded batches**: one `DELETE` of a
  month's events takes a long lock on the table every service writes to, which
  is a self-inflicted outage on the write path.

  `published_at IS NOT NULL` is in the predicate, so an undelivered event can
  never be aged out — measured with the case a careless predicate gets wrong: a
  **ninety-day-old event the sink refused** survives every pass while the
  forty-day-old delivered rows go. Zero `KeepFor` is off: deleting delivery
  receipts is not something to start doing because a struct was zero-valued.

- **KEDA scales on pressure, not on CPU — and the chart refuses two
  autoscalers on one Deployment.** `templates/keda-scaledobject.yaml`, off by
  default. CPU and memory are *lagging*: a plane under load queues first and
  burns CPU second, so utilisation crosses its target a minute after the queue
  got deep, and the replicas it summons are a minute late to a problem that
  started without them.

  Each plane scales on the signal named for it — ISSUE on the admission gate's
  own queue-wait p95, VERIFY on requests per second per pod, EVENT on outbox
  delivery lag p95. (The plan named NATS consumer lag; there is no NATS yet,
  and the EVENT plane's queue *today* is the outbox, so this asks the same
  question of the queue that exists. When NATS lands it gains a trigger rather
  than changing meaning.)

  **The interlock is the part worth stating.** KEDA does not scale pods itself:
  it *creates* an HPA per ScaledObject. A service carrying both KEDA and the
  chart's own HPA gets two HorizontalPodAutoscalers on one `scaleTargetRef`,
  each computing a replica count from different metrics and each writing it.
  They do not negotiate; the Deployment follows whichever wrote last and
  oscillates for as long as both exist — which looks like flapping under load,
  i.e. like the thing autoscaling was turned on to prevent. The chart refuses to
  render it. A second interlock refuses an empty `prometheusAddress`: a trigger
  with nowhere to read pins the Deployment at `minReplicas` and reports the
  error on a status nobody is watching.

  CI asserts no ScaledObject carries a `cpu` or `memory` query, because that
  would put the lagging indicator back and nothing would look wrong.

### Fixed

- **Three background sweeps ran once per replica, and two of them had external
  consequences.** A sweep started in a service's `main` runs in every pod of
  that Deployment. `access-service` ships at two replicas and autoscales to
  eight in production; `audit-service` at three, to ten. Twelve sweeps in this
  tree already run through `leader.RunPeriodic`. These three did not, and
  nothing about them was special:

  - **The EDR ingestion poller** called the customer's CrowdStrike / Intune /
    Jamf tenant **once per replica** — it selects sources whose `last_sync_at`
    is older than their interval, and `last_sync_at` is only written when the
    sync *finishes*, so every replica sees the same source as due in the same
    minute. A source configured to poll every five minutes polled two to eight
    times in that window, on the customer's own rate limit, and each sync writes
    posture results the Ziti enforcement path reads to revoke access.
  - **The Guacamole external audit sync** inserts each remote session with a
    **fresh UUID primary key**, so its `ON CONFLICT DO NOTHING` can never fire
    for a logically duplicate event: two replicas polling the same window wrote
    two audit rows for one recorded session. On a compliance product that is not
    waste, it is a wrong answer — an auditor counting privileged remote sessions
    gets the replica count times the truth. It also advances a single shared
    cursor no replica holds a lock on.
  - **The Elasticsearch reconciler** indexed the same 500 documents once per
    replica and stamped `indexed_at` once per replica. ES writes are idempotent
    by document id so nothing was corrupted; what it cost was N× the write load
    on the highest-volume path the product has, at exactly the moment ES is
    already behind — which is the only time the reconciler has anything to do.

- **The usage counter a customer is billed from was inflated by the replica
  count.** The metering rollup reads a singleton cursor row, fetches the events
  after it, does `count = count + 1` for each — an **increment**, not an
  idempotent write — and advances the cursor. The cursor was read with no lock,
  so all three `audit-service` replicas read the same cursor, fetched the same
  batch, incremented every counter and advanced the cursor to the same place.
  The comment above the rollup said "the cursor guarantees each event is rolled
  up at most once", which is true of one process and false of three.

  Fixed with a `FOR UPDATE SKIP LOCKED` on the cursor row, held for the whole
  batch in one transaction — **not** with leader gating, which is what the rest
  of this tree uses for sweeps: leader election runs on Redis and falls back to
  "every replica runs" when there is no client, which is fine for work that
  merely repeats and not for a counter that must not double-count during a Redis
  outage. The lock lives in the same database as the number it protects.
  Measured: four concurrent aggregators over 40 events bill 40, and with the
  lock removed they bill more.

  A **missing** cursor row is now an error log rather than silence — rolling
  nothing up for ever loses exactly as much revenue as double-billing gets
  wrong, and it looks like a healthy idle worker.

- **The SIEM forwarder shipped the same audit feed once per replica.** Same
  shape as the metering cursor: unlocked read, batch, deliver, advance. The data
  downstream is not wrong — a SIEM dedupes on event id, which is why the
  existing code already tolerates a failed cursor advance — but SIEM products
  **bill by ingest volume**, so a customer paid the replica count times for one
  audit feed and every correlation rule saw each event three times. Fixed the
  same way: the cursor row held with `FOR UPDATE SKIP LOCKED` for the whole
  batch, because "the customer's SIEM bill triples whenever Redis is down" is
  not a degradation anyone would sign off on. A missing cursor row is now an
  error rather than a silently stopped feed.

- **The audit chain sealer was already safe, and is now recorded as such.** It
  takes `pg_advisory_xact_lock` per org — the right primitive when the work is
  not a set of claimable *rows* but a sequence only one writer may extend. The
  census gained `advisory-lock` as a fourth valid answer rather than forcing it
  into a shape it does not have.

  All three sweeps above now run through `leader.RunPeriodic`. A **derived census**
  (`internal/common/leader/sweeps_census_test.go`) finds every `time.NewTicker`
  in `internal/` and `cmd/` and fails on one no entry names, so the fourth
  cannot be added silently: the author must say which answer applies — leader,
  a `FOR UPDATE SKIP LOCKED` claim, or genuinely per-process. A `claim` entry
  that contains no `SKIP LOCKED`, and an entry for a file that no longer has a
  ticker, both fail. Fourteen tickers remain **explicitly undecided**, counted
  and named rather than silently passed — the same shape as orgscope's
  `needsScoping` register, and for the same reason.

### Removed

- **The in-process event bus, which nothing imported.** `internal/common/events`
  carried a `Bus` interface, a `MemoryBus`, subscriptions and a package-level
  global with `Publish`/`Subscribe` helpers — 346 lines, plus 315 of tests —
  and **not one publisher or subscriber anywhere in the tree** outside its own
  file. Leaving it next to the outbox would have been worse than leaving it
  unused: a developer looking for "the event bus" would find an in-memory one
  and reach for whichever read more conveniently, and the difference between
  them is that one loses everything when the process dies. "This session was
  revoked" must not be delivered on a best-effort basis to whoever happened to
  be subscribed in this replica. The event envelope and the event-type
  vocabulary are kept — they are what an outbox row is made of.

### Changed

- **The SCIM list endpoints page in a total order, and stop dropping users.**
  SCIM cannot become a cursor the way the audit event list did: RFC 7644
  §3.4.2.4 pages by `startIndex` and requires `totalResults`, so the client
  picks the offset and the count has to be computed. What could be fixed was
  the ordering, and it needed fixing for correctness before it needed an index.
  `ORDER BY created_at` alone is not a total order, and here the ties are
  **guaranteed** rather than unlucky: `created_at` defaults to `NOW()`, which
  in Postgres is the *transaction* timestamp, so every row one transaction
  writes carries the identical value — measured at 200 rows sharing one
  `created_at`. Tied rows with no second key can land on two pages or on
  neither, which on a provisioning API is an account created twice downstream
  or one that never arrives. The lists now order by `(created_at, id)` from one
  place, and migration **v191** indexes `(org_id, created_at, id)` on `users`
  and `groups` so that ordering is a seek rather than a sort.

  Writing that test found a live defect. `first_name`, `last_name` and `email`
  are nullable and the list scanned them into plain strings, so `rows.Scan`
  failed for every user without a name — and the loop answered with
  `continue`. The response carried `totalResults = N` with **none** of the N
  users in it, HTTP 200, nothing logged; a SCIM client reads a short page as
  the whole directory. Fixed with `COALESCE` and by returning the scan error
  instead of swallowing it, in both the user and group lists. The two halves of
  that fix overlap — with `COALESCE` in place no scan fails, so restoring the
  `continue` leaves every behaviour test green — so the loop's error handling
  is pinned in the source as well.

  The audit report listings (`report_exports`, `compliance_reports`) carried
  the same ordering defect and got the same tie-break. They did **not** get a
  cursor, deliberately: these are per-tenant lists of tens of rows, and the
  deep-page cost this task targets has nobody to pay it there.

  What this still does not fix, because the protocol does not allow it: a row
  inserted ahead of the client's position between two pages shifts every later
  `OFFSET` and the row at the boundary is never returned — measured as one user
  in two hundred silently missing after a single concurrent insert. That is a
  property of index-based paging; a cursor removes it, and SCIM has nowhere to
  put one.

- **The admin console's analytics read from the replica, not the primary.** 26
  queries across `analytics_enhanced.go`, `risk_analytics.go`,
  `predictive_analytics.go` and `dashboard.go` now go through
  `PostgresDB.Reader()`. They are aggregates over `audit_events`,
  `login_history`, `user_sessions` and `users`, bucketed by day, hour and week
  — simultaneously the most expensive ADMIN queries and the ones least able to
  notice a second of replication lag, which is what the offload exists for.
  Behaviour is unchanged by default: with no replica configured `Reader()`
  returns the primary pool, so every call lands exactly where it did.

  A second batch follows the same way: `ai_intelligence.go` and
  `pam_overview.go`, 15 more queries — risk averages, alert counts, secret and
  rotation and access-request tallies. Summaries of the past, none of which
  decides anything.

  The census is now complete, and its boundary was measured rather than
  guessed. Every one of the 22 remaining files both reads and writes, and every
  one is a CRUD surface — which matters because of what the console does after
  a write: it is a TanStack Query application and it invalidates the list it
  just changed. Counted: **384 `invalidateQueries` calls across 81 files**, out
  of 90 that mutate at all. So "list" is not a lag-tolerant read on those
  screens; it is a read-after-write issued milliseconds after the POST returns,
  and an administrator who cannot see the rule they just created creates it
  again. File-level offloading therefore ends here — the two batches took
  everything on the other side of that line — and every file carries its
  recorded decision. What remains is finer than a file: the stats, score and
  trend handlers inside those CRUD files are lag-tolerant and need the census at
  function granularity to move.

  The census records the **deliberate non-offloads** too, which is what
  saves the next batch from re-deriving them. A file with reads and no writes
  looks offloadable by the same test the batches pass, and not all of them are:
  `dsar_processor.go` is a worker polling for work it is about to act on — a
  lagging replica would hand it a request another replica already took, or hide
  one that is waiting — and `tilequery.go` runs whatever SQL its caller hands
  it, so offloading it would offload every caller at once. A file with reads and
  no writes must now be in exactly one of the two lists; one in neither is an
  undecided file, and an undecided file is how the next person ends up guessing.

  The guard runs in both directions, because only one of them is obvious. A
  declared file must use **only** the replica and must not write — a write
  through `Reader()` is refused by the server with SQLSTATE 25006, which is an
  error in production rather than in CI. And a file that is **not** declared
  may not touch `Reader()` at all, which is what stops a query being offloaded
  in passing without anyone deciding whether it tolerates lag. Each entry has
  to say why it does; "it is a read" is rejected, because a read-after-write is
  also a read.

### Added

- **Each service can connect as its availability plane's Postgres role
  (`database.planeRoles`).** Migration v189 created `openidx_issue`,
  `openidx_admin` and `openidx_event` with their own `statement_timeout` (2s /
  10s / 30s) and said in its own description that nothing used them yet: a
  deployment opts in by pointing a service's `DATABASE_URL` at one. This is
  that switch, off by default, with a per-service assignment table so it can be
  changed without editing a template.

  **The open question was the grants, and it is now measured.** The roles
  *inherit* their privileges through `openidx_app` and hold none of their own,
  while the 220 tables arrive across 190-odd migrations — some granting
  explicitly, the rest relying on the default privileges v53 set. A table that
  got neither would be a service that starts, passes its health check, and
  answers one endpoint with `permission denied for table`. Applying the whole
  chain as a NOSUPERUSER NOCREATEROLE NOBYPASSRLS owner and asking the
  database: all three roles reach every table and every sequence.

  **One interaction would have been silent.** `DB_STATEMENT_TIMEOUT` is sent as
  a connection runtime parameter, and a runtime parameter beats the value
  `ALTER ROLE ... SET` attaches to the role. `values-prod.yaml` sets
  `database.statementTimeout: "30s"`, so a production install that simply
  flipped the flag would have given all three planes 30 seconds, on every
  service, with nothing in any log to say so — measured at 45 000 ms for all
  three with `DB_STATEMENT_TIMEOUT=45s`. The chart refuses that combination and
  names the file to clear it in.

  Six interlocks in all, each naming the knob that resolves it, including
  `pgcat.enabled`: both inject `DATABASE_URL` as a pod `env` entry, and more to
  the point a transaction pooler opens its server connections as its own pool
  user, so restoring the budgets means giving pgcat three pool users and
  splitting the cell's backend budget three ways — a sizing decision with a
  real cost, not a flag. Every interlock, the rendered per-service assignment,
  and the fact that the migration and bootstrap Jobs keep the owner DSN are
  asserted in CI, and each assertion was checked by breaking what it guards.

- **identity-service runs as one plane or the other (`SERVICE_PROFILE`).** The
  service straddles two availability classes: finishing a login (ISSUE) and
  running the console (ADMIN). ADMIN is the first plane shed under load, which
  buys nothing while the same process serves both — a flood at the admin
  console lands on the code path that answers logins. `SERVICE_PROFILE=auth`
  now registers only the login surface and the caller's own authentication
  factors; `SERVICE_PROFILE=admin` registers only user/role/group CRUD,
  providers, policies, settings, analytics and lifecycle, plus the portal and
  notification groups. Unset (or `all`) registers everything, exactly as
  before, so an existing deployment is unaffected.

  The filter is in the **type**, not in the call sites: `planeGroup` stands in
  for `*gin.RouterGroup` and declines what this profile does not serve, so all
  182 registration lines are untouched — the same move that put the tenant
  scope in `database.ScopedPool` rather than in 1,967 edits. All 182 routes are
  classified (71 ISSUE, 111 ADMIN); a route missing from the table is served by
  **both** profiles, because a route that quietly vanished from a running
  deployment is worse than one served twice, and a test fails until it is
  classified. An unrecognised `SERVICE_PROFILE` is fatal at startup rather than
  treated as `all`: the flag exists to remove routes, and silently keeping them
  would hand back the isolation the deployment was split to get.

  **The chart renders the split** (`identityService.planeSplit`), off by
  default — with it off, the rendered Deployment is byte-for-byte what it was.
  On, it is `-identity-auth` and `-identity-admin`, and the Ingress sends the
  ISSUE paths to the first and everything else to the second. Both halves keep
  the `identity-service` component label on purpose: the NetworkPolicy, the
  ServiceMonitor and the PodDisruptionBudget all select on it, and a rename
  would drop the pods out of all three. They are told apart by an added
  `openidx.io/plane` label, absent when the split is off, so an existing
  Deployment's immutable selector is unchanged.

  The edge rules are **generated** from the same table the process registers
  routes with (`files/identity-planes.json`, `go run ./tools/identityplanes`) —
  77 ISSUE routes reduced to 65 rules, with everything else falling through to
  ADMIN. They could not have been a prefix: `POST /users/forgot-password` is
  ISSUE while `GET /users` is ADMIN.

  Routability is now a constraint the classification has to satisfy, not
  something to remember: no path may be served by two planes (an Ingress cannot
  match on the method), and no ISSUE prefix may reach over an ADMIN route. Six
  entries do not follow the ISSUE/ADMIN rule because of it, each with its
  reason recorded — and all six move *to* ISSUE, because a route wrongly on
  ISSUE costs a little surface while one wrongly on ADMIN stops working the
  moment the admin plane is shed.

  Three of those six were found by disagreement: the CI step that drives the
  **rendered** Ingress rules with all 182 concrete paths contradicted the Go
  test, which had treated a Kubernetes `Prefix` as a string prefix. It is
  element-wise — `/invitations` claims `/invitations` itself, not just what is
  under it — so the whole invitations family belongs to one plane. Both sides
  now use the same matcher.

- **The audit event list pages by cursor, not by `OFFSET`.** `ORDER BY
  timestamp DESC OFFSET 50000 LIMIT 50` asks Postgres to produce fifty thousand
  rows and throw them away before returning fifty, so the deepest pages — an
  auditor walking a year, an export paging to the end — are the slowest. A
  cursor costs the same at page 1 and page 100,000. `?cursor=` takes an opaque,
  version-prefixed position and `X-Next-Cursor` hands back the next one; a
  malformed cursor is a **400**, never a silent fall back to the first page,
  which would give the caller a page they have already read and call it the
  next one. Migration v190 adds `(org_id, timestamp DESC, id DESC)`, because
  neither existing index could answer the query: `idx_audit_events_timestamp`
  is single-column and install-wide, so scanning it walks every tenant's events
  and discards the ones that are not yours, and `(org_id, event_type)` leads
  with the wrong second column.

  Two findings came out of it. **`ORDER BY timestamp DESC` alone is not a total
  order** — the column defaults to `NOW()` and a burst writes several rows in
  the same microsecond, so tied rows may come back in any order and not the
  same order twice; under `OFFSET` paging that let a row appear on two
  consecutive pages or on neither, which on an audit log is the worst available
  wrong answer. The `id` tie-break is a correctness fix the cursor happened to
  need anyway. And **the `COUNT(*)` is the other half of the cost, which keyset
  does not touch**: it reads every matching row whatever the page number, so a
  cursor that fixed only the `OFFSET` would still blow the deep-page budget. It
  is not run at all on the cursor path, and `X-Total-Count` is then omitted
  rather than sent as a zero. The offset path keeps its published behaviour
  exactly.

  Measured against a real PostgreSQL: cursor paging visits every row exactly
  once, in order, across a run of rows sharing one timestamp; no other tenant's
  row appears; `EXPLAIN` uses v190's index and does not sort. Three mutations
  turn it red. A fourth — removing the tie-break — does **not**, because
  Postgres returns tied rows in the chosen index's order and that index carries
  `id`, so the hazard stays latent; the ordering is therefore pinned as a
  decision in one place rather than pretended to be covered by behaviour.
  Task 2.5, audit half; SCIM `/Users` still pages by offset.


- **One Postgres login role per availability plane, with a query ceiling the
  server enforces.** Migration v189 provisions `openidx_issue`
  (`statement_timeout` 2s), `openidx_admin` (10s) and `openidx_event` (30s).
  Every service connects as `openidx_app` today with no limit at all, so one
  expensive ADMIN or EVENT query — an audit search, a governance report, a SCIM
  bulk page with a bad predicate — is indistinguishable to Postgres from the
  login path and holds a backend for as long as it likes. Cancelling a Go
  context does not help: it abandons the call while the backend keeps burning
  CPU and holding locks, so once a query is *running* the database is the only
  layer that can stop it. Each role is created `IN ROLE openidx_app`, so it
  inherits v53's DML grants and, with them, the v37 `FORCE` RLS policies that
  are granted `TO openidx_app` — a plane role is exactly as tenant-scoped as
  `openidx_app`, never more. `NOBYPASSRLS` is spelled out on each one because a
  role that quietly bypassed the belt would not fail; it would return every
  tenant's rows. `idle_in_transaction_session_timeout` is set alongside (60s /
  120s / 300s), which the plan did not ask for: without it the statement
  timeout is bypassed by `BEGIN`, one fast query, and holding the transaction
  open. Measured against a real PostgreSQL — all three roles see their own
  tenant and no other, a cross-tenant write is refused, and a 15s query on the
  ADMIN role is cancelled by the server at ~10s while ISSUE is untouched — and
  verified by four mutations, of which `BYPASSRLS` is the one that matters: the
  role then sees both tenants' rows. The roles ship passwordless and **nothing
  points at them yet**, so until a deployment cuts a service's `DATABASE_URL`
  over, this changes no behaviour.

  The roles are provisioned by the chart's superuser bootstrap hook, beside
  `openidx_app`, not by the migration: the migration Job connects as the
  database *owner*, which the PostgreSQL subchart makes a plain `NOCREATEROLE`
  login, so `CREATE ROLE`, `GRANT` and `ALTER ROLE … SET` are all refused there.
  `TestMigrationsRunAsLeastPrivilegedOwner` said so, with
  `permission denied to create role`, and it was right. Every privileged
  statement in v189 is therefore guarded by "is it already so?" — once the hook
  has run, the migration only reads `pg_roles` and `pg_db_role_setting` and
  changes nothing; on an external database with a privileged DSN it does the
  work itself; with neither it fails loudly, which is the contract v53 already
  documents. A pre-existing plane role carrying `BYPASSRLS` raises rather than
  being quietly repaired: that is not a drifted setting, it is a tenant
  boundary that is not there. Task 2.4.

### Fixed

- **"A replica outage transparently falls back to the primary" was true only at
  startup.** Three places said it — the `Reader()` doc, the read-replica health
  checker, and `values-prod.yaml` — and all three were describing
  `NewPostgres`: if the replica pool fails to open, `readPool` stays nil and
  `Reader()` returns the primary forever after. Once the pool was open,
  `Reader()` handed it back unconditionally. A replica that died later — a
  failover, a reboot, a partition, an RDS maintenance window — failed every
  read that had been offloaded to it, and kept failing until someone restarted
  the process, with readiness green throughout because the replica checker is
  non-critical by design. The read pool now retries on the primary when the
  replica does not answer, and opens a breaker after three consecutive
  infrastructure failures so a dead replica costs one failed dial per 30s
  rather than one per request. A `PgError` is deliberately *not* treated as the
  replica being down: the server answered, the statement is at fault, and that
  includes `25006` (a write on a read-only replica) — which is what keeps
  "NEVER use `Reader()` for writes" enforceable instead of silently re-aiming
  writes at the primary. Measured against a replica pool pointed at a dead
  port: `QueryRow`, `Query` and `Begin` all keep answering, still tenant-scoped,
  and the breaker opens. `openidx_db_replica_fallback_total` and
  `openidx_db_replica_breaker_open` with two alerts; `make ha-drill` gained a
  section. Task 2.3.

- **The `ScopedPool` suite had never run in CI.** The `rls-isolation` job ran
  `go test -run 'RLS'`, and `TestScopedPool_*` does not contain those three
  letters — so the tests proving ~1,950 unedited call sites carry the tenant
  scope (task 2.1b) only ever ran on a developer's machine. The regex now names
  them, and because `-run` matching nothing exits 0, the step asserts each of
  four tests actually reported `PASS` rather than trusting the regex.

- **The read path was outside the tenant belt, and nothing could have told
  you.** Task 2.1b moved the tenant scope into the type of `PostgresDB.Pool`
  and left `Reader()` returning the bare pgx pool. With no read replica
  configured `Reader()` falls back to the primary, so nothing broke, nothing
  failed to compile, and no test changed colour — while about a dozen read-path
  queries (user by id, by username, by email, sessions, groups, oauth clients)
  would have carried no `app.org_id` in `RLS_MODE=local`. Under `FORCE` RLS
  that is not an error: it is **zero rows**, so a login would simply have said
  the user does not exist. `Reader()` now returns a `*ScopedPool` like `Pool`;
  exactly one production call site (`WithReadTx`) failed to compile and the
  rest became scoped unedited. Measured against a real PostgreSQL as a
  non-superuser role, and the assertion verified by mutating the call back to
  `Reader().Raw()`, which fails with `no rows in result set`.

### Added

- **`orgscope` now lints the tenant belt's exit, not just its predicate.**
  `ScopedPool.Raw()` is the deliberate way to reach the database with no tenant
  scope — correct for install-wide tables, migrations and pool statistics — and
  it is exactly as easy to type as `Pool` at every one of ~1,950 call sites,
  with no compile-time difference. `tools/orgscope/rawpool.go` reports three
  things: a tenant table reached through `Raw()`; a database call through
  `Raw()` whose SQL the tool cannot read (this repo assigns most queries to a
  variable first, so it **fails closed**, `Begin()` included); and an unscoped
  pool handed to a function that is not on `rawHandoffAllowed`, a register that
  demands a reason per entry like `installWideTables`. Crucially an `org_id` in
  the SQL does **not** clear these findings, and their wording says so — the
  policy compares it to `current_setting('app.org_id')`, so the row is
  invisible however the `WHERE` clause is written. The escape is the same
  `//orgscope:ignore <reason>` the rest of the tool uses. The CI gate now
  covers `./internal ./cmd`, since the legitimate handoffs live in `cmd/`.
  Sixteen tests, plus a mutation against the real tree. Task 2.1b.

### Added

- **A transaction pooler in the chart, with the unsafe combination made
  unrenderable.** `pgcat` ×2 behind one Service, off by default. The connection
  budget becomes `replicaCount × poolSize` (2 × 40), a constant — without it the
  fleet is `services × replicas × DB_MAX_CONNS`, which autoscaling multiplies.
  Enabling it repoints the eight request-serving Deployments at the pooler and
  deliberately leaves the migration Job, the bootstrap hook and the backup
  CronJob on the direct DSN: a migration's advisory lock is session-scoped and
  `pg_dump` needs one session to hold its snapshot, so neither survives
  transaction pooling. The chart **refuses to render** `pgcat.enabled=true`
  while `config.rlsMode` is not `local`, with no override, because a pooler in
  front of session-scoped tenant state hands one tenant's scope to the next
  client — measured in
  `docs/evidence/2026-09-13-rls-transaction-pooling.md`, not theorised. It also
  refuses a zero `preparedStatementsCacheSize`, which is pgcat's own default and
  means every pgx query fails with SQLSTATE 42P05. pgcat's Prometheus exporter
  is scraped by its own ServiceMonitor; `OpenIDXPoolerClientsWaiting` replaces
  `OpenIDXDBPoolSaturation` as the alert that sees the wall, and
  `OpenIDXPoolerNoRedundancy` covers the new single point of failure in front of
  the database. Five CI assertions cover all of it, each verified by breaking
  the thing it guards. Auditing the generated config against pgcat v1.2.0's own
  source caught three things every render-time check passed: the pinned tag
  `1.1.1` does not exist (the registry's only released tag is `v1.2.0`),
  `prepared_statements` is not a `[general]` key and pgcat ignores unknown keys
  in silence, and the image declares `CMD ["pgcat"]` with no `ENTRYPOINT`, so
  `args` alone would have replaced the binary with the path to its config file.
  The canary gate is unchanged: nothing turns this on until `RLS_MODE=local` has
  run for two weeks. Task 2.2.

### Added

- **An anycast edge as code, provider chosen by one variable.** DDoS at
  L3/L4 and volumetric L7 is bought, not built (design ADR-3), and the
  provider is an open decision. `deployments/terraform/edge` is a root whose
  `edge_provider` selects one of three modules behind one interface:
  `edge-cloudflare` (proxied DNS, zone TLS floor, Managed Ruleset,
  Authenticated Origin Pulls, rate-limit and cache rulesets),
  `edge-aws` (CloudFront with HTTP/3, WAFv2 in CloudFront scope with the
  AWS managed groups, per-source rate-based rules and size constraints,
  optional Shield Advanced, a secret origin header) and `edge-azure` (Front
  Door Premium, Microsoft Default Rule Set 2.1 + Bot Manager, rate-limit and
  size custom rules, cache rule set, `X-Azure-FDID` origin verification).
  All three render the same `modules/edge-common/rules.json` — the design's
  §5.3 table as data — and export `edge_cidrs` (for `OIDX_EDGE_TRUSTED_CIDRS`
  and the origin firewall) and `origin_verification` (what the origin must
  demand so an IP allow-list is not the only cloak). A Go test keeps the rule
  file and the design table naming the same paths and the size limits equal
  to the services' own caps; CI validates the root and the standalone
  modules. Task 1.1.

### Added

- **The tenant scope moved into the type, so ~1,950 call sites got it without
  being edited.** Task 2.1a made a transaction-local scope possible; applying
  it everywhere was planned as eight weeks of mechanical edits across 1,967
  `db.Pool.Query` / `QueryRow` / `Exec` call sites — in which every missed line
  would be a query running with no tenant scope at all, returning zero rows
  under FORCE RLS rather than failing a test. `database.ScopedPool` is now the
  type of `PostgresDB.Pool`, with the same method set as `*pgxpool.Pool`, so
  1,933 call sites kept compiling and reading exactly as they were and now
  route through the scoped path. "Did we remember this line?" became "does it
  compile?". The compiler found the 11 places that pass the pool as a value;
  each was judged individually — `Raw()` for install-wide tables, migrations
  and pool statistics, a narrow interface for the ones that read tenant
  tables. One of those was a trap worth naming: `audit.CrossOrgAuditor` writes
  with a bypass context, and handed a raw pool it would carry no marker in
  local mode, so the fail-closed `WITH CHECK` would reject the mandatory
  cross-org audit row. Tests prove an unedited `db.Pool` call shape is scoped
  and that `Raw()` deliberately is not. Task 2.1b, in place of the migration.

- **The tenant scope can travel with the transaction, which is what a
  connection pooler needs.** The scope is stamped onto the pooled *connection*
  at checkout, and that is a hard ceiling on scale: session state belongs to a
  connection, so the fleet's Postgres connection count is services × replicas ×
  pool size, and autoscaling multiplies it. The standard answer, a transaction
  pooler, has been forbidden here for a good reason — transaction pooling does
  not carry session state, so `app.org_id` set at checkout would follow a
  backend handed to another tenant's client, which is a cross-tenant leak.
  `RLS_MODE=local` sets the scope *inside* each transaction with
  `set_config(..., true)`, which Postgres resets at COMMIT, so a recycled
  backend carries nothing. `database.WithTx` plus `Query`, `QueryRow` and
  `Exec` wrappers provide it; in `session` mode, still the default, they pass
  straight through and nothing changes for any existing deployment.

  Measured against a real Postgres as a non-superuser role, on a pool
  restricted to one connection so every tenant reuses the same backend: two
  tenants alternating twenty-five times each see only their own rows; two
  hundred concurrent readers produce zero cross-tenant reads; after a scoped
  transaction commits an unscoped query sees zero rows rather than the previous
  tenant's; a cross-tenant write is refused by `WITH CHECK`; the bypass marker
  does not outlive its transaction; and error paths leak no connections. The
  suite refuses to run as a superuser, because Postgres exempts superusers from
  every policy and the assertions would otherwise pass with the belt cut — the
  new `rls-isolation` CI job asserts that refusal as a negative control before
  running the real thing. Both mutations of the scope statement, making it
  session-scoped and omitting it, turn the suite red. pgcat still waits on two
  weeks of canary and the `orgscope` rule (task 2.1b). Task 2.1a.

- **The origin refuses anyone who did not come through our edge.** Edge
  decision K1 is Azure Front Door Premium (the stack already runs on AKS with
  Flexible Server and Azure Cache), so origin cloaking takes two layers rather
  than Cloudflare's single mTLS one. The network layer is an NSG on the AKS
  subnet admitting only the `AzureFrontDoor.Backend` service tag on 80/443 and
  denying `Internet` explicitly — a service tag rather than a copied CIDR list,
  because Azure keeps the tag current and a copy rots. That alone is half a
  control: the tag admits *every* tenant's Front Door, so the application layer
  demands `X-Azure-FDID` equal to our profile's GUID and answers 403 without
  it, at the ingress (`edge.originVerify.*`, rendered as a configuration
  snippet, with `allow-snippet-annotations` enabled on the controller because
  it has defaulted off since ingress-nginx 1.9 and an ignored annotation is an
  open origin) and at APISIX (`EDGE_ORIGIN_VERIFY_HEADER`/`VALUE`, a global
  `request-validation` rule). Both refuse to configure half-way: a header with
  no value renders nothing rather than accepting any value. Certificate
  Transparency publishes the hostnames, so secrecy was never the control.
  Task 1.2.

- **A DDoS game-day: six attack scenarios and the runbook to answer them.**
  A design that says "the edge absorbs this" is not evidence.
  `test/load/ddos/` holds six k6 scenarios — JWKS/discovery flood, token
  flood with invalid clients, credential spray across many source addresses,
  slow-request and oversized-header, oversized SCIM and default bodies, and
  expensive audit search — each sharing the two thresholds the whole day is
  built on: VERIFY latency must not move (p99 < 30 ms) and legitimate ISSUE
  success must hold (> 99%). `scripts/ddos-drill.sh --check` syntax-checks
  every scenario and asserts the wiring without a cluster or k6 (in CI and
  `make ddos-drill`); the live run refuses a production or loopback target
  before it needs k6, runs against a staging cell and writes a summary to
  `docs/evidence/`. `docs/runbooks/ddos-under-attack.md` is the full version
  of the design's §5.7: which signals say attack rather than launch, how to
  turn the edge to under-attack mode, cutting the source as narrowly as the
  attack allows, taking capacity from ADMIN for ISSUE without touching
  VERIFY, and standing down in reverse. The live measurement is M1's
  game-day. Task 1.5.

- **A bot gate at the login door, keyed on the account rather than the
  address.** A credential spray spread across ten thousand sources makes
  three attempts from each: no per-IP bucket ever fills, and the database
  lockout sees only accounts that exist and then locks them — which is what
  the attacker who wanted the victim locked out came for. `internal/botgate`
  counts failed password checks per typed account name (hashed,
  case-folded, existing or not, so enumeration learns nothing) in the
  session Redis, and after `LOGIN_FAIL_CHALLENGE_AFTER` (5) failures in
  `LOGIN_FAIL_WINDOW_SECONDS` (900) the next attempt from anywhere answers
  `403 challenge_required` until it carries a solved challenge or the window
  passes. A correct password clears the counter, so a legitimate user never
  meets the gate. An edge bot score passed down in `X-Edge-Bot-Score` below
  30 is a challenge before the first failure. Cloudflare Turnstile is the
  first `ChallengeVerifier` (`TURNSTILE_SECRET`); a solved token admits the
  attempt and resets the count, a rejected or unreachable verifier never
  admits. `BOT_GATE` is tri-state like the other gates: off by default,
  observe writes `would_challenge` decisions to the audit trail so the
  threshold is chosen from data, enforce refuses; the startup gate census
  names it. A counter outage fails toward the password check, never toward
  a lockout. The login page's Turnstile widget is the remaining half. Task
  1.4.

### Changed

- **The edge actually caches discovery and JWKS, and never caches the entry
  document.** The compose TLS proxy's `/.well-known/jwks.json` and
  `openid-configuration` locations had carried `proxy_cache_valid` for years
  with no cache zone defined anywhere — and `proxy_cache_valid` without
  `proxy_cache` is a comment, so every discovery and JWKS request reached
  the oauth-service and a JWKS flood was the cheapest way to make the edge
  hammer the ISSUE plane. An `openidx_edge` zone now exists and both
  locations use it with `proxy_cache_lock` (one origin fetch per miss) and
  `proxy_cache_use_stale` (a verifier never sees a JWKS outage). All three
  nginx configurations that serve the console mark hashed assets immutable
  for a year and `index.html` `no-cache`, repeating the security headers in
  that location because nginx's `add_header` replaces rather than merges.
  Tests pin the zone, its use, and the entry-document policy. Task 1.3.

- **A Redis blip is no longer a login outage of its own length.** The
  auth-path rate limiter fails closed when its Redis is unreachable, and
  that stays the default: brute-force protection must not silently vanish
  with a cache. But "unreachable" was binary — the first failed `INCR`
  turned every login into a 503, so a ten-second restart, a failover or a
  rolling upgrade of the rate-limit instance became exactly that long an
  outage, and the defence had a failure mode nobody had to attack. For a
  bounded window after the first failure (`RATE_LIMIT_LOCAL_FALLBACK_MAX`,
  60 s) each replica now enforces the auth tier from a process-local counter
  with a per-replica share of the quota (`RATE_LIMIT_REPLICA_HINT`, which
  the Helm chart sets from the deployment's replica count), then fails
  closed as before. The local map is capped: a flood of distinct sources
  during the window fails closed for new keys rather than allocate, so an
  outage cannot double as memory exhaustion. A successful Redis call resets
  the window. `openidx_rate_limit_local_fallback_seconds` climbs while on
  fallback and `OpenIDXRateLimitOnLocalFallback` pages at 10 s, before the
  window is spent. Zero keeps the strict first-failure-is-503 contract the
  existing tests pin. Task 0.7.

- **CORS says one thing everywhere.** The oauth-service wrote
  `Access-Control-Allow-Origin: *` on every response by hand while the
  production gate refused a wildcard `CORS_ALLOWED_ORIGINS` — the gate held
  for seven services and the eighth ignored it, and the threat model claimed
  the gate. The policy is now explicit in `middleware.OAuthCORS`: the
  OAuth/OIDC *protocol* endpoints (token, introspect, revoke, userinfo,
  device flow, dynamic registration, discovery, JWKS) answer `*` by design,
  because a public client on a relying party's origin must reach them and
  `*` can never carry cookies; the session-carrying login, MFA, consent and
  step-up pages follow the configured origin list like every other service
  and refuse an unlisted origin instead of reflecting it.
  `OAUTH_PROTOCOL_CORS_WILDCARD=false` closes the exception for a deployment
  where every relying party is known. At the edge, the tenant origin list
  that was copied into eleven compose routes and seven production services
  becomes one global `cors` rule each (the plugin answers preflight itself,
  so the catch-all OPTIONS routes are gone), with route-level `*` only on the
  protocol routes. Tests pin the list to exactly one copy and the wildcard to
  the protocol routes; the threat model's TB1 row now says what the code
  does. Task 0.6.

- **Every request-serving deployment autoscales, and scales the right way
  round.** The HPA and PDB templates listed seven services; `access-service`
  and `gateway-service` were not among them, so `values-prod.yaml`'s
  `autoscaling: { enabled: true }` for the two proxies rendered nothing and
  they ran at a fixed replica count under load with no disruption budget.
  Both are now covered (11 PDBs render where 9 did). Every HPA carries a
  `behavior` block shared from `autoscaling.behavior`: scale-up has no
  stabilisation window and may double or add four pods per minute, whichever
  is more; scale-down waits five minutes and sheds at most a quarter per
  minute, because the quiet after a wave is often the gap before the next
  one and a flapping HPA is a cold start under fire. The default CPU target
  drops from 80% to 60%: identity traffic saturates connections and database
  waits before CPU, and by the time CPU reads 80% p99 is already gone. KEDA
  replaces the CPU signal in plan task 3.6. Task 0.5.

- **Operational endpoints no longer leave the cluster.** The production
  route loader published `/api/v1/<service>/health` and `/oauth/health` for
  every service with no plugins, and nothing at any edge stood in front of a
  root `/health`, `/ready` or `/metrics`. `/health/ready` pings Postgres,
  Redis and Elasticsearch on every call and answers with each dependency's
  status and latency; `/metrics` is the whole Prometheus surface. Public,
  they were a reconnaissance feed and a free way to make the edge hammer
  the data tier under a flood. All three APISIX configurations (compose
  file, production loader, edge seed script) now carry one route at
  priority 100 that answers 404 at the edge via `fault-injection` for
  `/health`, `/health/*`, `/ready`, `/metrics` and the loader's old public
  paths, in every `DARK_MODE`. Probes and the scraper reach the pods
  directly; an external load balancer checks nginx's static `/health` or
  L4. The compose route test that required the public health routes now
  requires their absence. Task 0.4.

- **Every listener refuses to wait for a slow attacker.** A slowloris needs
  no bandwidth, only a server that keeps a half-sent request alive; Go's
  `http.Server` does so indefinitely unless told otherwise, and each of the
  eight services built its own server literal with read, write and idle
  timeouts and no header timeout — seven mains, seven chances to forget it,
  all seven forgot. `server.NewHTTP` is now the one way a service constructs
  its listener: `ReadHeaderTimeout` 5 s, a 16 KiB header cap (Go's default is
  1 MiB, an allocation the attacker sizes) and 100 HTTP/2 streams per
  connection, none of which a caller can disable. Body caps are mounted per
  service (1 MiB on oauth, governance and audit; 5 MiB on admin-api and SCIM
  provisioning for `/Bulk`; 10 MiB on identity for CSV import), answering
  413 before any handler runs; the access proxy and gateway are left to the
  edge's cap because they forward published applications. The compose nginx
  gains `client_header_timeout`/`client_body_timeout` 10 s, `send_timeout`,
  `reset_timedout_connection` and a per-source `limit_conn` of 100 with a
  commented realip block for when a provider sits in front. Every
  rate-limited APISIX route, in compose and in the edge seed script, now also
  carries `limit-conn` keyed on the real client address, and the OAuth
  upstream stops retrying (`retries: 0`, 3/10/10 s timeouts): a retry under
  load multiplies the attack it is failing under. Tests pin each layer: a
  trickled header is cut inside the timeout while `ReadTimeout` is still 10 s
  away, an 8 KiB header gets 431 with no handler run, and the compose and
  edge configurations are parsed rather than grepped. Task 0.3.

- **The client-IP chain survives an edge in front of it.** Every per-IP
  control — the auth-path rate limiter, audit actor IPs, known-IP device
  trust, geo rules — reads gin's `ClientIP()`, which is the client only when
  the hop that forwarded the request is trusted. APISIX keyed `limit-req` on
  `remote_addr` and the services trusted loopback alone, so the moment an
  anycast or CDN provider is placed in front, every TCP peer is the provider
  and the whole world shares one bucket: one attacker can 429 everyone, and a
  thousand-source brute force looks like one client. The opposite setting,
  `OIDX_TRUSTED_PROXIES=*`, lets the caller pick its own bucket.

  Three things change. `OIDX_EDGE_TRUSTED_CIDRS` carries the provider's
  published ranges and is unioned with `OIDX_TRUSTED_PROXIES` (a `*` inside it
  is dropped, not honoured); production services now refuse to start on
  `OIDX_TRUSTED_PROXIES=*` and warn when it is empty. APISIX gains a `real-ip`
  global rule — in compose trusting the private network the TLS proxy lives
  on, on the public edge gated on `EDGE_TRUSTED_CIDRS` in
  `seed-edge-routes.sh` and deliberately absent when that APISIX is the true
  edge. The Helm chart adds `edge.trustedCidrs` and an `edge.cidrSync`
  CronJob (`files/edge-cidr-sync.sh`, Cloudflare / CloudFront / static) that
  rewrites a ConfigMap every service mounts optionally and rolls the
  deployments only on change; any bad, empty or implausibly short feed leaves
  the current list untouched and fails the Job (`OpenIDXEdgeCidrSyncFailed`).
  Tests pin the contract at the seam: behind a trusted edge two clients get
  two buckets, behind an untrusted one they collapse into one, and an
  untrusted caller cannot move itself by forging the header. Task 0.2.

- **Redis is three instances, one per loss profile.** OpenIDX kept four kinds
  of state in one Redis: rate-limit counters, login/MFA/authcode session
  state, token and session revocation markers, and leader locks. The counters
  are the one workload an attacker can inflate at will — a flood of source
  addresses is a flood of keys — and on a shared instance that flood ends one
  of two ways. Under `noeviction` (the compose default) Redis starts refusing
  writes and the auth-path limiter, which fails closed by design, turns into an
  attacker-operated login kill switch. Under `allkeys-lru` (what
  `docker-compose.prod.yml` ran) the instance stays up by forgetting keys, and
  a forgotten `oauth:user_tokens_revoked_at:<uid>` marker is a revoked access
  token that answers again. Either way the defence became the attack.

  `REDIS_RATELIMIT_URL` and `REDIS_REVOCATION_URL` now point the two roles at
  their own instances; the primary `REDIS_URL` keeps session state and locks.
  Both are optional and an empty value aliases the primary, so a single-Redis
  install is unchanged. `database.RedisClient` gained `RateLimit` and
  `Revocation` fields with nil-safe `RateLimitDB()` / `RevocationDB()`
  accessors; every service mounts the limiter on the rate-limit role and all
  sixteen revocation call sites (`revoked_session:*`, the revoke-all marker,
  the per-token blacklist) go through the revocation role. A census test in
  `internal/revocation` fails the build if a marker is ever written through
  the primary client again, and the health checker pings every distinct
  instance so readiness cannot say "redis up" while markers have nowhere to
  go. Compose ships `redis-ratelimit` (256 MB, `allkeys-lru`, no persistence)
  and `redis-revocation` (`noeviction`, AOF); the production overlay's session
  instance moves from `allkeys-lru` to `noeviction`. Helm: `redis.roles.*` or
  `externalSecrets.redisRoles` (on in `values-prod.yaml`). Task 0.1 of
  `docs/plans/2026-09-13-global-scale-cell-architecture-plan.md`.

## [1.35.0] - 2026-09-10

### Added

- **A fresh second factor for a privileged launch and an admin write**
  (`STEPUP_GATE`, default `off`). The product has been able to demand a
  mid-session re-authentication since `/oauth/stepup-challenge`, `-verify` and
  `-status` shipped, and nothing has ever demanded one: the `step_up` JWT those
  endpoints mint is read by no handler, no middleware and no gate, so
  completing a challenge left the caller exactly as permitted, or refused, as
  before. Meanwhile a laptop that signed in at 09:00 could open an RDP session
  to a domain controller at 19:00, or reveal a stored credential, or delete a
  user, and be asked nothing.

  What was missing was a fact, not a mechanism. `sessions.auth_methods` (v133)
  records that a session used MFA and never records *when*, so a ten-hour-old
  factor and a ten-second-old one are the same row. Migration **v186** adds
  `sessions.mfa_verified_at`, stamped at login — derived from the auth methods
  the login already records, so a login path added later cannot record `mfa`
  and forget the timestamp — and stamped again by `/oauth/stepup-verify`, which
  is what finally gives step-up an effect. Refreshing an access token
  deliberately does not refresh it, so a native client holding a long-lived
  refresh token cannot refresh its way out of proving who is holding the
  device. Existing sessions are backfilled from `started_at` where their
  recorded methods include `mfa` — the moment that session's factor really was
  verified, not an invention — so an upgrade does not declare every live MFA
  session stale.

  The gate (`internal/stepup`) is the same tri-state as the assignment, ABAC,
  PAM-risk and posture gates: `off` (default, no query at all), `observe`
  (record who would be asked, permit) and `enforce`. Both branches write to
  `unified_audit_events` through the shared decision shape, carrying the
  factor's age and the window alongside the canonical keys — an operator in
  observe mode is choosing a *number*, which a denial count alone cannot
  inform. Enforcement points: the PAM launch and reveal routes, and every write
  made with admin authority (hung off `requireAdminRole` in the access service
  and a `/api/v1` middleware in the admin API, rather than a list of sensitive
  endpoints, so a route written tomorrow is covered the day it lands). Reads
  are never gated. Machine identities — API keys, service accounts,
  client-credentials tokens — are never gated in any mode: step-up asks a
  person to touch a key, and an unattended integration has nobody to ask, so a
  gate there would produce an outage rather than a prompt. A refusal is `403
  step_up_required` naming `/oauth/stepup-challenge`, because a 403 that only
  says no leaves a user with a legitimate need and no route to it.

  `security.reauth_interval` gets its first reader: it has existed as a v63
  column, a field of the console's settings document and
  `SessionPolicy.ReauthInterval`, consulted by nothing. It now sets the window,
  with `STEPUP_MAX_AGE` (15 minutes) as the deployment default. A window of
  zero under an enabled gate means the default, not "no window" — otherwise
  turning the gate on would produce a gate that gates nothing.

  A census requires every mutating `/pam/` route to carry a gate or a written
  reason. Writing it found `POST /pam/apps/:id/launch`, which opens a brokered
  Windows session through Guacamole and which the first pass had missed while
  gating its five obvious siblings.


- **A client access design** — `docs/CLIENT-ACCESS-DESIGN.md`: registration,
  MFA, ZTNA tiers, permissions per role per client, revocation, secrets at rest
  and the production gate, for the Windows agent, the Android agent and the
  companion app, with an ordered implementation plan (Android and Windows first)
  and the operator rollout order. Every "today" statement in it was read from
  the file it names. Its three load-bearing findings: the Android agent's OAuth
  enrollment could never work (fixed below); **revoking a device leaves its
  30-day refresh token alive**; and on Windows every secret sits under
  `%ProgramData%` protected by Unix mode bits Windows ignores.

### Fixed

- **The companion app told people their phone was Compliant when it had never
  been examined.** The Go engine's posture checks dispatch on `runtime.GOOS`
  with branches for linux, darwin and windows; anything else gets a warning
  saying the check is not supported there. The companion app IS anything else —
  gomobile builds it as `GOOS=android` and `GOOS=ios` — so seven of the ten
  checks, disk encryption and screen lock among them, returned that warning
  without looking at the device. `Engine.Posture()` computed compliance as
  "nothing failed and nothing errored", and warnings are neither, so the
  summary came out compliant and the home screen drew a green badge with a
  tick. Disk encryption is configured at severity `critical`.

  Nothing in the repository could see it. The code compiles for Android, the
  tests pass on the Linux runner where those same checks take a real branch,
  the JSON is well-formed, and "0 failures" is perfectly true of a device
  nobody looked at.

  `CheckResult.Unsupported` now separates "I could not measure this" from "I
  measured it and it is mildly concerning". Compliance requires that nothing
  failed, nothing errored, **nothing was skipped for want of an
  implementation**, and that at least one check actually ran — so a build that
  cannot examine the device says so instead of calling it healthy. The card
  gains a third headline state, names the checks that could not run, and says
  a managed device reports posture through the device agent instead.

  Two more checks were answering where they cannot see:

  - `os_version` reported `uname` on Android and iOS, which is the **Linux
    kernel release** — "5.10.101" where a `min_version` policy means "14". The
    comparison is not wrong so much as meaningless, and a mismatch returns
    `StatusFail`, so it would have marked healthy phones as failing policy.
  - `process_running` globbed `/proc`, which is the process table on Linux and
    nowhere else this agent runs. On Windows and macOS the glob matches
    nothing, on Android the kernel has hidden other processes from unprivileged
    apps since API 24, and on iOS there is no `/proc` — and in every case the
    empty list meant every configured process was reported **missing**. A red
    mark on a healthy machine teaches an operator to ignore the red marks.

  Both now decline where they cannot answer.

- **`tools/posturevocab`**, a new gate: it holds each posture check next to the
  operating systems it can actually examine, across both clients that report
  posture to the same `check_type` column — the Go engine and the Kotlin
  Android agent. Coverage is derived from where a check DECLINES, and an
  unrecognised declining shape is an error rather than a guess. It fails the
  build when two clients implement one check for one platform: two
  implementations of one word, in two languages, reporting to one column will
  drift, and the server cannot tell which one answered. One collision is
  registered with its reason (`agent_version`, which describes two different
  binaries installed side by side); the other two the first run found were
  defects, and were fixed rather than registered.


- **Six settings queries read rows nothing has ever written.** `system_settings`
  is a key/value table; the console reads and writes the whole settings
  document under the key `system`. Four other places read settings out of the
  same table under keys no code and no migration has ever created —
  `settings` (the OAuth session policy), `security` and `authentication` (the
  SOC 2 / ISO 27001 assessments, five queries), and
  `failed_login_lockout_threshold` / `failed_login_lockout_duration` (the
  account lockout). Every one of those queries returned no rows on every
  install that has ever run, and every one treated no-rows as "not configured"
  and carried on with a compiled-in default. Nothing failed and nothing logged.

  Visibly: the console's Security tab could set an idle timeout, an absolute
  timeout, a remember-me duration, a re-authentication interval, IP binding and
  a concurrent-session policy, and the OAuth session policy applied its
  defaults regardless; "Max failed logins" and "Lockout duration" were saved
  and the lockout ran on 5 attempts and 15 minutes whatever they said; and the
  ISO 27001 assessment deducted 40 points and reported *"No security policy
  configuration found in system_settings"* on installs whose policy was fully
  configured — a compliance finding, in the document an auditor reads, that was
  simply false.

  All six now read through `internal/common/syssettings`, the single reader,
  with one key constant. Two field names were wrong as well and are corrected
  (`require_special`, not `require_special_chars`; `max_age`, not
  `max_age_days`), and the ISO session-management control now converts the idle
  timeout from seconds to the minutes it reports. A census test holds the tree
  to it: both halves are derived from the source — keys read from the SQL
  string literals, keys written from the INSERT literals, the migration seeds
  and the settings repository's `PutRaw` calls — and a key read with no writer
  fails the build. One key is registered as deliberately read-only with its
  reason (`oauth_rsa_private_key`, the pre-v79 signing key imported once at
  boot), and an entry that stops reproducing fails too, so the register can
  only shrink.

  Two dead reads are removed rather than repointed: the ISO cryptography
  control queried `tls_enabled`, `tls_min_version`, `encryption_at_rest` and
  `key_rotation_enabled`, none of which exists anywhere in the settings
  document, so its four values have always been the literals they are
  initialised to. They still are, and the comment now says so — sourcing them
  from the deployment's real TLS and encryption configuration is a separate
  change.


- **A device waiting for approval looked exactly like a broken one.** The
  client knew only what was on disk — enrolled, has a Ziti identity, signed in —
  which cannot tell "enrolled and waiting for an administrator" from "enrolled
  and working", or either from "revoked". The server has always known: `GET
  /agent/config` branches on the agent's status to decide which posture checks
  to send, and answers `403` for a revoked one. It never said so.

  It does now: `enrollment_status` and `device_trusted` on the config response
  (the IAM device-trust flag the overlay's `#device-trusted` attribute follows,
  read from the linked `known_devices` row). The engine gains `DeviceState()`,
  which asks with the device's own agent credential and returns a flat payload;
  it is bound for gomobile and wired through all three plugin bridges, and the
  desktop control server serves it at `GET /device-state`. The companion app
  renders it as a banner above everything else, with one line of what the state
  means and one of what changes it.

  Five states rather than three, because two of them were being hidden:
  **revoked** is named instead of surfacing as a network error, and **cannot
  check with the server** is kept distinct from a refusal — a phone in a lift
  must not be told it has been revoked. Trust is only ever shown alongside an
  active status, and a server too old to report the field produces "unknown"
  rather than a confident "active" the server never granted.

- **Device enrolment's no-database fallback had no environment gate.**
  `HandleEnroll` ends in a branch that accepts any non-empty token and mints a
  working agent credential for it, under the comment "Dev mode: no DB, accept
  any non-empty token". It is latent rather than live — `cmd/access-service`
  fatals without `database_url` — and that is why it needed a gate rather than a
  comment: what keeps it unreachable is a startup check in a different package,
  so a refactor that makes the pool optional, or a handler constructed without
  one, would arm an unauthenticated enrolment endpoint silently. It is now
  allowed only under `APP_ENV=development`, and refused **when no config is
  present at all** — a gate whose safe state depends on someone having wired
  configuration is not a gate. The refusal is a `503` and is audited.

- **On Windows the agent's secrets were protected by a mode Windows discards.**
  `user-tokens.json` (the signed-in user's access token and their 30-day
  refresh token) and `control-endpoint.json` (the loopback bearer that fully
  drives the control engine — sign-in, enrolment, PAM launch, Ziti dial) were
  both written with `os.WriteFile(..., 0600)`. Go maps that to "not read-only"
  on Windows and nothing else, so each file inherited the ACL of
  `%ProgramData%\OpenIDX\agent` and, through it, `%ProgramData%`, where
  `BUILTIN\Users` can read. Every local account could read the refresh token
  and the control bearer, and both call sites said `0600`, which is what made
  it invisible. `authstore.go` even carried the note "hardening follow-up:
  DPAPI".

  New `agent/internal/secretfile` writes each file the way the platform
  enforces: on Windows **DPAPI** (`CryptProtectData`, per-user scope, so the
  bytes are useless to another account) plus an **explicit file DACL** —
  SYSTEM, Administrators and the writing user, with inheritance switched off so
  `%ProgramData%`'s entries stop applying. Elsewhere it is the same 0600 file as
  before, re-asserted on every write (`os.WriteFile` applies its mode only when
  it creates the file, so a token file left world-readable once stayed that way
  through every later sign-in). A file written before this exists still loads,
  so an upgrade does not sign anyone out.

  The Windows-only tests are run by a Windows job. `windows-client-build.yml`
  runs the agent's `go test ./...` on `ubuntu-latest`, where every
  `//go:build windows` file is compiled out — so its `windows-latest` job now
  runs the packages with Windows-specific behaviour, and the DPAPI round trip
  and the DACL assertions execute on the platform they describe.

  Not covered, deliberately: `agent.json` carries the agent's own `auth_token`
  and is read by both the SYSTEM service and the user's tray, so a per-user
  blob would break one of them. That one needs a directory-ACL decision and is
  recorded in `docs/CLIENT-ACCESS-DESIGN.md` §4 rather than half-done here.

- **Any signed-in user could answer another user's push-MFA prompt.**
  `POST /api/v1/identity/mfa/push/verify` is on the authenticated identity
  group, and `isIdentitySelfService` admits every authenticated user to
  anything under `/mfa/` — "the caller's own MFA verification", says the
  comment. The handler read `challenge_id` and the two-digit number from the
  body and never compared the challenge's user to the caller, so the comment
  was not true of this route. `VerifyPushMFAChallenge` now takes the
  authenticated subject and refuses a challenge that is not theirs (`403`).

  Three things in the same handler, found with it:

  - **The number match had no attempt limit.** A wrong code returned an error
    and left the challenge pending, so all ninety two-digit values could be
    tried in turn. Three wrong answers now deny the challenge outright; when
    no Redis counter is available the first wrong answer is final, because a
    missing counter must never read as an unlimited one.
  - **The approving device was never checked.** Revoking a phone deletes its
    overlay identity, untrusts it and (above) revokes its tokens, and left its
    push registration on the approver list. An approval now requires the push
    registration to be enabled and, when it was created by a device enrolment
    (the v135 `agent_id` linkage), the enrolled agent to be active. A **deny**
    is never refused on device grounds — a revoked phone reporting "this wasn't
    me" is a signal worth keeping.
  - **A prompt could be raised for somebody else.** `POST /mfa/push/challenge`
    took `user_id` from the request body on that same open route: one account
    could make another account's phone buzz on demand, and learn the challenge
    id it got back. It is raised for the caller only now (`403` otherwise). The
    login flow is unaffected — it calls `CreatePushMFAChallenge` in-process.

  Also corrected: `push_mfa.auto_approve` logged "Auto-approving push
  challenge" and approved nothing. It skips the FCM/APNs send; the prompt still
  goes out over ntfy and still needs a tap and the right number. The log line
  now says that.

- **Revoking a device did not revoke its tokens.** `executeDeviceRevoke` deleted
  the Ziti identity, terminated the overlay sessions and untrusted the known
  device — every pillar except the one a phone actually talks to. Nothing
  recorded which device a token belonged to, and the native clients hold a
  **30-day** refresh token (`refresh_token_lifetime = 2592000`, v84/v85), so a
  revoked phone could not dial a service and went on acting as the user over
  plain HTTP for up to a month, including approving push-MFA challenges.

  Migration **v185** adds `oauth_refresh_tokens.agent_id` (nullable, partial
  index, no backfill — NULL means "not bound", the pre-v185 state). A native
  client names its device with `agent_id` at the code exchange and the server
  binds it only if the agent is one it records as enrolled by that same user and
  not revoked (`internal/oauth/device_binding.go`); rotation carries the binding
  forward like `family_id`, so a chain that has refreshed is still findable.
  `/agent/enroll/oauth` binds the enrolling bearer's own session to the agent it
  has just issued — the Android path, where the server knows both halves and no
  client claim is involved. `executeDeviceRevoke` then revokes every bound
  family, marks the sessions those families ran under revoked, publishes the
  `revoked_session:<id>` markers the refresh grant honours, and reports both
  counts; the console's revoke toast says what happened, including when no
  session was bound to the device.

  **Signing out now reaches the server.** `Engine.Logout`, the Windows tray's
  Sign out and `openidx-agent logout` call `/oauth/revoke` (RFC 7009) before
  clearing local state, which used to be all they did — the deleted refresh
  token stayed valid for its full lifetime. The local session is cleared either
  way, and a failed revocation is reported rather than swallowed.

  Bounded honestly: an access token already minted to the device keeps working
  until it expires (one hour for the native clients), because only the refresh
  grant consults the session marker. `agent_id` is a routing key for revocation,
  not an authentication of the device — a client can omit it and be handed an
  unbound token, exactly as before.

- **The Android agent's first screen could not enroll a device, on any
  install.** `EnrollmentActivity` shows "Sign in with your work email to enroll
  this device" and runs a PKCE flow as `client_id=openidx-agent-android` with
  scope `agent.enroll`. No migration ever seeded that client — the native
  clients were `openidx-mobile` (v84) and `openidx-desktop` (v85) — and
  `scopeAllowedForClient` refuses a scope the client is not registered for, so
  the authorize request answered `invalid_client` since the day the screen was
  written. The QR/token path beside it worked, which is why nobody noticed.

  Migration **v184** seeds the client (public, PKCE, redirect
  `com.openidx.agent://oauth/redirect`, scopes `openid profile offline_access
  agent.enroll`). The auth middleware now exposes the token's granted `scope`
  beside `amr`, and `/agent/enroll/oauth` **requires `agent.enroll`** — so a
  console session token, which no browser client can obtain that scope for, can
  no longer enroll a device by accident (`403 insufficient_scope`). The same
  handler now makes the same auto-trust decision as the enrollment-session
  path (MFA-verified from `amr`, `DEVICE_AUTOTRUST_MODE`) instead of passing a
  literal `trusted=false`.

  The guard that would have caught this on the day it was written:
  `TestEveryShippedClientIsSeededByAMigration` derives every `client_id`,
  redirect URI and requested scope from the shipped clients' own source
  (`agent/internal/sso/sso.go` and the Kotlin `OAuthEnrollmentFlow`) and checks
  each against every migration's `oauth_clients` INSERT. A client named in
  source and seeded nowhere fails the build rather than the user's first
  sign-in.

- **The iOS build could finish a login in the browser and never receive the
  redirect.** Two `openidx://` links arrive from outside the app and must be
  routed by the operating system — `openidx://oauth-callback`, the server's 302
  after login (`agent/internal/sso/sso.go`'s `MobileRedirectURI`), and
  `openidx://enroll`, the QR-free enrolment link. Android routes both through a
  committed manifest. **iOS routed neither**: `client/.gitignore` excludes
  `/ios/` because `flutter create` generates it, Flutter's template carries no
  `CFBundleURLTypes`, and nothing put the entry back. The `.ipa` attached to
  every release therefore had no way to complete a sign-in, on a build that
  compiled, analyzed and packaged clean.

  Verified rather than assumed in the other direction too: the remaining two
  links the client parses — `openidx://qr-login` from the camera scanner and
  `openidx://approve` from a notification tap — arrive inside the app and need
  no platform registration, so Android's two intent-filters were already
  complete.

  `scripts/ci-configure-ios-deeplinks.sh` registers the scheme in the plist
  `flutter create` just generated, reading the scheme out of the Android
  manifest so the two platforms cannot drift, and refusing to run rather than
  no-op when the plist is absent. All five iOS-materializing CI jobs call it,
  and `scripts/check-ios-deeplink-config.sh` fails the build on the next job
  that skips it — including one that runs the step *before* the create, where
  there is nothing to patch.

- **The mobile engine's boundary was unchecked in four different senses, and
  three of them were invisible.** The gomobile engine in `agent/mobile` is the
  code that runs on every enrolled phone; its seventeen exported bindings are
  the whole contract between the Flutter client and the agent.

  1. **No CI job ran its tests.** The agent module's only test invocation was
     `go test ./internal/...`, and measured with `go list`, exactly two packages
     holding tests sit outside `./internal/...` — `agent/mobile` and
     `agent/cmd/openidx-agent`, the agent's own entry point. Five tests, run
     nowhere, including the one asserting the bindings are gomobile-bindable at
     all.
  2. **That invocation could not fail.** It ended `2>&1 | tail -20`, and GitHub
     runs `run:` under `bash -e` without `pipefail`, so the step reported
     `tail`'s status. Reproduced: `bash -e -c 'false 2>&1 | tail -20'` exits 0.
     It was the only instance of the shape in the tree, and
     `scripts/check-run-blocks-can-fail.sh` now carries a second rule that
     flags it — with the real line, verbatim, as a self-test case.
  3. **The signature census was a hand-written list of sixteen** where the
     package exports seventeen. The one it omitted was `RegisterPushDevice`,
     the push-registration binding all three platform bridges wire. It now
     derives the set from the package's own AST.
  4. **The bindings are re-declared by hand in three more languages** — the
     Dart plugin, the Kotlin `when` arms, the Swift `case`s — and nothing
     checked the four agree. They do today. What they permitted is quiet and
     one-sided: add a binding, wire Dart and Kotlin, forget Swift, and Android
     is fine while iOS answers `MissingPluginException` at runtime, on a screen
     that looks finished, in a build that compiled and analyzed clean.
     `agent/mobile/bridge_test.go` now derives the Go side and requires each
     platform to answer for it in both directions.

  The workflow's path filter gained `client/plugins/openidx_engine/**` for the
  same reason: filtering on `agent/**` alone would have left the new census
  blind exactly where the defect lives — editing the Swift plugin would not
  have run the test that exists to check the Swift plugin.

- **The Race Detector CI check went red for 13 GB of type-checking, not for a
  race.** `go test -race ./...` reaches `./tools/...`, where two gates answer a
  question about the whole module: `deadconfig` type-checks every package and
  `deadservice` builds SSA over every binary and runs rapid type analysis. Under
  the race detector those cost **8.04 GB** and **13.03 GB** of peak memory
  respectively, measured on a 4-CPU / 16 GB machine — the shape of a hosted
  runner. `go test` runs four packages at a time, so the two together (14.22 GB
  measured, then the kernel OOM killer) is more than the runner has.

  What that produced was not a test failure: no `FAIL`, no `WARNING: DATA RACE`,
  neither the job's 30-minute cap nor the per-package `-timeout 20m` reached —
  just `The runner has received a shutdown signal` and `exit code 143`, under a
  check whose name says "race". Whether the two overlap is scheduling luck,
  which is why the same command passed on the runs either side of it.

  Both whole-module halves already skipped under `-short` for this reason; the
  race job passes no flag, and a blanket `-short` there would have silently
  stopped running six other packages' real tests (the migration downsweep proof,
  the RLS enforcement belt, the proxy assignment org scope, the audit chain, the
  gateway integration case). So the skip is keyed on the race build tag instead
  — the cost belongs to the instrumentation, not to a flag, and `go test -race
  ./...` typed by hand on a 16 GB laptop fails the same way. Same command after
  the fix: **0.82 GB, 2 seconds**.

  Nothing stops being proven: both tools have a dedicated CI job that runs the
  analysis uninstrumented over the whole module as a hard gate on every push,
  and both are in the required-checks list.
  `tools/racecost/racecost_test.go` derives from `go list` which test binaries
  do module-scale analysis and requires each to carry the skip, so a third
  analyzer is named before the job has to die for it.

### Security

- **A temporary vendor-access link went around every control the product has,
  including the one that vouched for it** (migration **v188**). The feature
  built for exactly the "let an outside engineer onto this server" question was
  the one place none of the PAM controls applied. Redemption redirected to a
  Guacamole connection built at *issuance* with an empty parameter map: no ZTNA
  check, always the direct broker, no session recording, no credential
  injection — so the vendor had to be told a password out of band — and no
  `pam_entry_sessions` row, so the access was unrecorded. A link now names a
  `pam_entries` row (`pam_entry_id`, required) and redemption runs the same
  launch core as the console's Connect button, entry controls and all. Links
  issued before this are refused with an explanation rather than falling back,
  because keeping the old path alive for them would keep it alive.

  Four claims that surface made and did not keep, found alongside it:

  - `require_mfa` was stored, selected back into the struct, and never compared
    to anything — and `public_surface_test.go`, the guard that makes every
    anonymously-reachable route carry a written justification, listed MFA among
    the checks this route performs. The register vouched for a check that never
    ran. The field is **gone** rather than implemented: with no session there is
    no `mfa_verified_at` for `STEPUP_GATE` to read, so enforcing it here would
    have meant a bespoke OTP bolted onto an anonymous URL. Vendor MFA belongs on
    a vendor identity; `docs/VENDOR-ACCESS-ROADMAP.md` V1 carries it.
  - `notify_on_use` was the same shape, and now **notifies the link's issuer**
    through the multi-channel notification service. `notify_email` is withdrawn:
    the service is keyed by user id, and a caller-supplied recipient on a
    security notification is a way to make the product email anyone. Creating a
    link now requires a resolvable issuer (`issuer_unresolved`), which also
    fixes a link created under `SoftAuth` writing the literal `"<nil>"` into a
    UUID column.
  - The IP allowlist compared **strings**, so every CIDR entry an operator wrote
    matched nobody and the link silently refused everyone. It now compares with
    `net/netip` — prefixes, IPv6, and IPv4-mapped clients from a fronting proxy
    — and a malformed entry is rejected at creation, where it can still be fixed.
  - The link's address fell back to `browzer.localtest.me` when
    `access_proxy_domain` was empty; the setting defaults to `localhost`, so the
    common case issued `https://localhost/temp-access/<token>` — a link that
    resolves, loads, and reaches the **recipient's** machine. `ValidateProduction`
    now refuses any loopback value, the Helm chart sets `ACCESS_PROXY_DOMAIN`
    from the API ingress host, and an empty value is refused at issuance with a
    message naming the setting.
  - A launch that could not start answered the vendor with the launch core's own
    JSON, on a route that renders HTML: `{"error":"the OpenZiti PAM broker is
    not configured"}` as their page. The core now returns its failure instead of
    writing it, so the two authenticated callers render the code and detail and
    the anonymous page renders neither — it says the session could not start and
    gives the link id to quote, while the reason goes to the log and the audit
    row, where the operator is.
  - **And none of those refusals had ever rendered at all.** Every one was
    `c.HTML(status, "error.html", …)`, and nothing in this repository has ever
    registered a template renderer — no `LoadHTMLGlob`, no `LoadHTMLFiles`, no
    `SetHTMLTemplate`, and no `error.html` file. gin's `HTMLRender` was nil, so
    each call dereferenced it and panicked: an expired link, a revoked one, an
    address off the allowlist, all decided correctly and none of them able to
    say so. The vendor got a dropped request or a bare 500 from the recovery
    middleware. The refusals now write their own page, which is what makes them
    independent of a deployment step nobody performs, and a test drives each one
    through a context with no template registered — production's actual state.

- **A guard for switches that decide nothing, and the two it found**
  (`tools/inertswitch`, a required check). `require_mfa` and `notify_on_use`
  above were one shape: bound from a request, stored in a column, selected back,
  rendered by the console as a switch, and never once compared to anything. That
  is invisible to everything else here — it type-checks, it round-trips through
  Postgres so no zero-value check fires, the console renders it so the UI tests
  pass, and `tools/deadconfig` asks a different question (whether a field has a
  READER; these have several). What they never have is a decider.

  The census holds the bool fields an API caller can set — derived from the
  types this tree binds with `ShouldBindJSON`, so nothing has to be remembered
  onto a list — next to the fields something decides on, and subtracts.
  Transfers into a model struct are followed; two blind spots (a value that
  round-trips through the database, a decision made in SQL) are suppressed
  rather than guessed at, both in the direction of silence.

  Its first run found two more, both fixed rather than registered:

  - `sandbox_enabled` on `PUT /api/v1/developer/settings` was stored, returned,
    and round-tripped unchanged by a console that never rendered a control for
    it. There was no sandbox to enable. **The field is withdrawn** from the
    request and the response; a caller that still sends it is ignored rather
    than stored as a promise.
  - The system-wide **passwordless settings** decided nothing at all. An
    administrator who turned magic links off for the organization still handed
    them out, because `CreateMagicLink` asked only the per-user preference — the
    weaker of the two switches was the only one anybody consulted. Magic links
    and QR login are now refused when the organization has them off,
    `magic_link_expiry_minutes` and `qr_session_expiry_minutes` replace the
    hardcoded fifteen and five, and `max_magic_links_per_hour` is enforced over
    a trailing hour (an unlimited supply of single-use sign-in credentials to
    one mailbox is the shape of a mailbox-access attack, which is why the
    setting exists). `biometric_only_enabled` and `require_device_trust` are
    **withdrawn**: the first duplicated two per-user settings that are already
    enforced with no rule for which wins, and the second named a control that
    exists elsewhere — `POSTURE_DEVICE_TRUST_GATE`, with a posture service
    behind it — so a second flag of the same name with no gate behind it is how
    an operator comes to believe device trust is required when it is not.

- **A privileged session had two ways off the overlay, and took one of them by
  default** (`PAM_REQUIRE_ZTNA`, default `off`). The product's ZTNA claim is
  that privileged access reaches its target through the OpenZiti overlay. A
  brokered PAM session has two legs, and neither was held to it.

  The **target hop** is `pam_entries.reach_mode`. Migration v82 created it
  `NOT NULL DEFAULT 'direct'`, so an entry created without a deliberate choice
  had guacd open a socket to the target's real address from the broker's
  network — the overlay untouched, nothing refused, nothing recorded.

  The **user hop** is the connect URL, `{public base}/#/client/{id}?token={t}`.
  Minting it is gated about as hard as anything in this product: fresh MFA, the
  entry's ACL, the approval gate, moderation, checkout controls. *Using* it was
  gated by possession — any browser, on any network, with no client and no
  enrolled device. A website entry skipped both legs, returning a raw URL and
  brokering nothing at all.

  Under `enforce`: a launch whose reach mode is not `ziti` is refused **before
  any credential is resolved** (a refusal must not decrypt a vault secret on its
  way to being refused), a website entry is refused outright with the remedy
  named, and every allowed launch is routed through the overlay broker.
  `observe` refuses nothing and audits what `enforce` would refuse — an
  operator turning this on needs the list of entries that will stop working
  before they stop working, and the only place that list comes from is the
  attempts being recorded.

  **The half this flag cannot deliver, stated rather than implied.** The target
  hop is the service's decision and is made completely. The user hop is not:
  nothing in an HTTP request proves the caller reached the service over the
  overlay, and a header saying so is set by whoever is calling — a control the
  checked input switches off. That leg is closed by the broker being published
  as a Ziti service and at no other address, so the URL's host routes for a
  machine running the client and for nothing else. What the code does about it
  is refuse to START under `enforce` unless `GUACAMOLE_ZITI_PUBLIC_URL` is set
  and differs from `GUACAMOLE_PUBLIC_URL` — empty means the overlay broker has
  no address of its own, equal means it is published at the ordinary one, and
  either way the flag would read "enforce" over an open leg.
  `docs/CLIENT-ACCESS-DESIGN.md` §4b carries the operator's own check: a curl
  from an unenrolled host that must fail to connect.

  **And the console had to be told.** A gate that refuses on the server and
  nowhere else is this branch's defect class inverted — a control that enforces
  without displaying. The launcher kept offering Connect on entries the service
  would answer `403`, and the connection-path diagram kept drawing their network
  hop as a working direct route. `GET /pam/broker/status` — which exists so the
  launcher can explain a missing broker rather than dead-end on a `503` — now
  reports the mode as `require_ztna`, and the console disables Connect with the
  reason on hover and draws that hop as a refusal. The value reported is what the
  service will *do*, not the raw setting: an unrecognised value reads `off` in
  both places, so the console cannot show "enforce" over a gate that is not
  enforcing. An absent field refuses nothing (an older service, or a probe that
  has not resolved yet — guessing `enforce` would grey out a button that works),
  and `observe` refuses nothing in the console because it refuses nothing on the
  server; greying out what the server would allow is the same lie in the other
  direction.

  **The session window learned which leg failed.** An allowed overlay launch
  returns a URL on the overlay broker, which routes only for a machine running
  the client — so on a machine without one the frame never connects and the
  phase monitor calls it failed. The window answered that with its generic card:
  "this may be temporary, or you may not have access to the target", two guesses
  that are both wrong there, above a **Try again** that would fail identically
  forever. This is the user&rarr;broker leg — the half no check can enforce —
  arriving as an unexplained failure at the one moment it becomes real. The
  launch response already carried `reach_mode`, so the console passes it into
  the window's handoff, and an overlay session that never connects now names the
  client as what is missing and offers enrolment beside the retry. A direct
  session keeps the generic card, as does a handoff written without the field:
  telling someone on a direct session to install a client they do not need is
  the same wrong answer pointed the other way.

- **The end-user PAM launcher put a session token in the address bar.** There
  are two places a brokered session is launched. The Connections page opens a
  chrome-less `/pam-session` wrapper and hands the connect URL over through a
  single-use `localStorage` entry, and says why in its own comment: the URL
  carries a bearer token, so it must not reach the address bar or the browser's
  history, and a failed session behind it must show OpenIDX's card rather than
  Guacamole's home and connection manager. **Quick links** — the launcher on
  the end-user page, the one most people actually use — called
  `window.open(connectURL)`. Same token, same broker, opposite decision, and
  nothing failed: the second launcher was written later, from the API rather
  than from the first launcher.

  Both now go through one `openPamSessionWindow`, which builds the handoff —
  URL, unguessable single-use key, and the overlay flag the window needs to
  explain a failed ZTNA launch. A launcher that skipped the wrapper also lost
  that message, so this and the entry above are the same fix. When storage
  throws (private mode, quota) the wrapper still opens and shows its "expired"
  card: falling back to the raw URL would put the token in history for exactly
  the users whose browser is set to keep less of it.

  `scripts/check-pam-launch-wrapper.sh` is what stops a third launcher
  rediscovering the wrong answer — every caller of `api.pam.connect` must use
  the helper and must not read `connect_url` itself, since importing the helper
  does not prove you used it. It fails if it matches no launcher at all, so a
  rename cannot leave it green over code it no longer sees. `quick-links-section`
  also gets its first test file: nothing in the suite had touched it.

- **On a phone, the engine's credentials were protected by a mode bit, and a
  mode bit protects nothing there.** The companion app's engine writes three
  credentials into its sandbox — `user-tokens.json` (the 30-day refresh token),
  `agent.json` (the agent's own auth token), `ziti-identity.json` (the overlay
  private key) — all at `0600`. Inside an app container that mode is not
  protection that was added; every file there is already private to the app's
  UID. An earlier entry closed the way those bytes leave the device, the
  platform backup. What it did not close is that **Android and iOS both decrypt
  app storage at the first unlock after boot and leave it decrypted**, so a
  rooted phone, a jailbroken one, or one imaged while merely unlocked reads them
  as text.

  The control for that is a key the file system does not hold, and Go can reach
  neither the Android Keystore nor the iOS Keychain. `agent/mobile.Keystore` is
  therefore a gomobile **reverse** binding — a Go interface implemented by
  `AndroidKeystoreSealer` in Kotlin (AES-256-GCM under a non-exportable
  `AndroidKeyStore` key, StrongBox where the hardware offers it) and
  `KeychainSealer` in Swift (AES-GCM under a Keychain key marked
  `…AfterFirstUnlockThisDeviceOnly`, so it is in no backup and restores onto no
  other device). The key never crosses the boundary, and that is the design
  rather than an omission: an `AndroidKeyStore` key cannot be exported at all,
  so a boundary that carried key material could not use a hardware-backed one.

  Four things keep it from being a control that displays without enforcing.
  `Start` takes the keystore as a parameter and has no signature that omits it,
  so a host cannot forget to pass one and still compile. Before the engine
  touches a credential, `secretfile.SelfTest` wraps a probe and refuses to start
  unless the result differs from the plaintext, **does not contain** it, opens
  back to it, and differs again on a second wrap — the last catches a fixed
  nonce, and the second catches the one that would otherwise get through, a
  header wrapped round the secret, which round-trips perfectly while leaving the
  token in the file in full. `Start` also re-seals what an earlier build wrote
  in the clear, because a control that protects only the *next* write leaves the
  credential it was added for sitting there until something happens to rewrite
  it. And `scripts/check-mobile-keystore.sh` reads the Kotlin and the Swift for
  the one question no runtime check can answer: a constant key compiled into the
  app produces real ciphertext with a fresh nonce and passes everything above.

  `agent.json` moved onto `secretfile.WriteShared`, which takes the keystore
  seal but not the per-user Windows layer — the SYSTEM service and the user's
  tray both read that file, and a per-user DPAPI blob or a writer-named DACL
  would lock one of them out. On a desktop, where no keystore is registered, it
  is byte-for-byte the file it has always been.

  **Not covered, and recorded rather than implied:** `ziti-identity.json` is
  written and read back by the OpenZiti SDK, not by this code, so sealing it
  would hand the SDK ciphertext and unsealing it to a temporary file would put
  the private key back on disk to no purpose. It needs an SDK-side change and is
  named in `docs/CLIENT-ACCESS-DESIGN.md` §4.

- **The update manifest said what to install, and nothing said who wrote it.**
  The previous entry in this section made the artifact's SHA-256 mandatory. That
  proves the download arrived intact and cannot prove anything more: the same
  document supplies the `url` and the `sha256` that matches it, so whoever
  chooses the manifest's bytes chooses what the machine installs — `msiexec /i`
  under SYSTEM on Windows, `sudo -n dpkg -i` on Linux, or a replace-and-re-exec
  of the agent's own binary. The Authenticode signature on the MSI is not a
  second chance: nothing on the apply path reads it, `msiexec` run by a service
  installs an unsigned package without a word, and on Linux and macOS there is
  no Authenticode at all.

  The signing identity existed the whole time.
  `agent/packaging/openidx-codesign.cer` is committed, self-signed, and its
  private half is held only as the `WINDOWS_CERT_PFX_BASE64` secret; it signs
  `openidx-agent.exe` and the MSI, and never signed the document that names
  them. `latest.json` now carries a `signature` — base64 RSASSA-PKCS1-v1_5 over
  SHA-256 of a canonical form of its fields — and the agent verifies it against
  that certificate, pinned into the binary, **before a byte is downloaded**. The
  canonical form is signed rather than the JSON bytes, so PowerShell's
  `ConvertTo-Json` and Go's `encoding/json` never have to agree on key order or
  spacing, and its first line is a domain separator so a signature the same key
  made for anything else cannot be replayed as a manifest.

  The trust anchor is a required parameter of `Fetch` and `CheckAndApply` whose
  zero value trusts nobody, so a caller that forgets to pass one installs
  nothing rather than anything. An operator publishing their own builds to their
  own manifest URL sets `update_trusted_cert` in `agent.json` (PEM), which
  replaces the pinned publisher rather than adding to it.

  Two facts are derived rather than asserted, because both are duplications that
  would otherwise drift in silence: the embedded certificate is compared
  byte-for-byte with the packaged one (`//go:embed` cannot read outside its
  package, so there are two copies), and a test rebuilds the release workflow's
  PowerShell signing input out of the YAML and requires it to equal what Go
  verifies — a reordered field or a CRLF would produce signatures that verify
  nowhere, on a release that had already shipped. The release step also verifies
  its own signature with the public half before publishing, so a
  `WINDOWS_CERT_PFX_BASE64` holding the wrong key fails the job instead of
  shipping a manifest every agent refuses.

  **Behaviour change for operators, two of them.** An `agent-v*` tag now *fails*
  unless `WINDOWS_CERT_PFX_BASE64` and `WINDOWS_CERT_PASSWORD` are set: an
  unsigned manifest is not a degraded update channel, it is a file every agent
  rejects, and failing in CI is better than discovering it on endpoints. And an
  agent pointed at a manifest published before this change will refuse it,
  naming the missing signature; re-cut the release to publish a signed one.

- **The local control socket was world-connectable for the length of one
  syscall.** On Unix the control server has no bearer token: the socket's
  filesystem permissions *are* the authentication, and what they guard has no
  second lock — `/token` hands out the signed-in user's access token,
  `/pam/connect` launches a privileged session, `/ziti/dial` opens the overlay.
  That mode was established one step too late. `net.Listen` creates a Unix
  socket at `0777 &^ umask`, and a daemon's usual umask of `022` leaves it
  `0755` until the `os.Chmod(0600)` on the following line — at a fixed,
  predictable path under `$XDG_RUNTIME_DIR` or `/tmp`. A connection accepted in
  that window is not closed by the chmod that follows it. The bind now happens
  under a narrowed umask, so the socket is `0600` from the instant it exists;
  the chmod stays as belt and to repair a socket left by an older build. The
  test that proves this calls the bind alone and reads the mode with no chmod in
  between, because reading it afterwards proves only that the chmod ran.

- **The control server's bearer token was compared with `!=`.** Go's string
  comparison returns at the first differing byte, so the time it takes leaks how
  many leading bytes were right — and this is the one place in the product where
  that is most usable, because the caller is on the same machine and can retry
  without network jitter. `internal/oauth` compares the client secret with
  `subtle.ConstantTimeCompare` for exactly this reason; this one was missed.
  `authWrap` also had **no test that sent a wrong token**: every existing case
  attaches the correct bearer, and on Unix the token is empty so the wrapper is
  a no-op — meaning on the platform CI runs most, the happy path proved nothing
  about it either. Twelve cases now cover refusal, including the prefix guesses
  a timing attack builds toward, and one that states the Unix contract
  explicitly rather than leaving it to be inferred.

- **The agent executed plugins from a directory anyone could write.**
  `plugin.Discover` walks `plugin_dir`, takes any file with an executable bit,
  and hands it to `exec.CommandContext`. Both callers of `LoadPlugins` are
  long-running daemons — `openidx-agent serve` and, on Windows, the service,
  **which runs as SYSTEM** — and nothing checked who else could write the file
  about to be run. A world-writable plugin directory, or a tight directory with
  a world-writable binary in it, meant the privileged process was running
  whoever got there last rather than the operator's code.

  This is the rule every tool facing this shape keeps: sudo refuses a
  world-writable sudoers, ssh a group-writable key, git a repository owned by
  someone else. The plugin root, each plugin's own directory and the executable
  are now all checked; a bad plugin is skipped rather than costing the operator
  the good ones, and a bad root refuses the lot. The error names who can write
  and what to run to fix it, because a control people cannot act on is one they
  switch off.

  **On Windows the check reads the DACL.** It could not at first, and refused
  every path instead: mode bits are what the Unix half reads, Windows discards
  them — the Go runtime maps `0755` to "not read-only" and nothing else — so the
  same code there would have reported every path as trusted while checking
  nothing, in the one place where the caller is the SYSTEM service. It now reads
  the path's owner and DACL and refuses any allow-entry that grants write,
  append, delete, delete-child, change-permissions or take-ownership to a
  principal outside `{SYSTEM, BUILTIN\Administrators, NT
  SERVICE\TrustedInstaller, the account this process runs as}` — and refuses an
  owner outside that set as well, because an owner can rewrite the permissions of
  what it owns whatever they currently say. TrustedInstaller, and read-and-execute
  for Users, are allowed on purpose: both are the `%ProgramFiles%` default, and a
  check that refuses the ordinary installation layout is a check that gets
  switched off. Inherit-only entries are skipped, a NULL DACL is refused (it
  grants everyone full control), and an entry type this code cannot evaluate is
  refused rather than assumed harmless. The account this process already runs as
  is trusted for the same reason the Unix half does not compare ownership against
  the uid: a file only that identity can write is not a new way to control the
  process. Tests build their fixtures as protected DACLs so nothing is inherited from the
  runner, and cover the case a refuse-everything implementation would also have
  passed: a privileged-only tree that must load. They did not run at first: a
  `//go:build windows` file is compiled out on Linux, and the only job that can
  execute one named its packages by hand — a list that had lost `agent/internal/plugin`
  and `internal/remotesupport` while carrying `agent/internal/authstore`, which has no
  Windows-only code. The list is derived from the build tags now, and
  `scripts/check-windows-tests-run.sh` keeps it that way.
  Nothing in the repository sets `plugin_dir` — it is read in one place and
  written nowhere — so no shipped configuration is affected either way.

- **The agent's self-updater installed an artifact it had not verified, whenever
  the manifest said not to.** `downloadVerified` checked the downloaded file's
  SHA-256 only `if wantSHA != ""`, and `Fetch` required a manifest to carry only
  `version` and `url`. A manifest that omitted `sha256` — or supplied an empty
  string — therefore reached `apply()` unchecked, and `apply()` runs
  `msiexec /i` as SYSTEM on Windows, `sudo -n dpkg -i` / `rpm -U --force` /
  `installer -pkg` on Linux and macOS, or replaces the agent's own executable
  and `syscall.Exec`s into it. The one control on that path was switched off by
  the very input it existed to check.

  Three `//nolint:gosec` comments in `apply_other.go` each justified themselves
  with "artifact is checksum-verified", which was conditionally false — and the
  `nolint` silenced the linter that would have asked. The package doc said the
  updater applies "a newer **signed** artifact"; nothing verifies a signature
  anywhere, and saying so made the weaker control read as the stronger one.
  Neither URL was scheme-checked either, so a plain-`http` manifest made the
  digest moot: whoever rewrites the artifact rewrites the digest with it.

  Now: `sha256` is **mandatory** and shape-checked (64 hex characters, so
  `"TODO"` is rejected as malformed rather than failing later as a confusing
  mismatch); verification is unconditional, with no path through
  `downloadVerified` that returns a file it did not check; both the manifest and
  artifact URLs must be `https` (loopback excepted, documented, for local
  artifact servers and the tests); and the download is capped at 1 GiB, because
  the digest catches a substituted artifact only after it is on disk and the
  agent runs on endpoints. The doc comment now states what is verified, that the
  manifest is therefore the root of trust, and that signature verification is a
  separate item rather than something already done.

  `Fetch`, `downloadVerified` and `CheckAndApply` — every function that touches
  the network or decides what runs — had **no tests**; only the two pure helpers
  did. Thirteen cases now cover the refusals. A second test reads the release
  workflow's PowerShell manifest generator and requires the three fields `Fetch`
  demands over https, because producer and consumer are in different languages
  with nothing checking they agree.

  **Behaviour change for operators:** an existing `update_manifest_url` whose
  manifest omits `sha256`, or is served over plain http, will now be refused with
  an error naming the reason instead of silently installing. The manifest the
  release workflow publishes already carries a `Get-FileHash` SHA-256 and an
  https URL, so the shipped path is unaffected.

- **A refresh-token lifetime that could not bind on the case it existed for.**
  `oauth_clients.refresh_token_lifetime` is enforced — `GetRefreshToken` refuses
  a token past its `expires_at` — but rotation issues each successor with
  `now + lifetime`, so the window restarts on every use. Every native client
  refreshes far more often than the window: the desktop agent hourly, the phone
  whenever it opens. **The thirty days the three native clients were seeded with
  therefore bound only on a device that went dark for thirty days**, which is the
  opposite of the case the number was there for. A phone taken while unlocked, or
  an agent on a machine that changed hands, kept a working chain for as long as
  it kept refreshing — indefinitely, until someone noticed and revoked the device
  by hand.

  Migration **v187** gives the authorization an end rather than the token:
  `oauth_refresh_tokens.family_started_at`, copied forward by every rotation and
  backfilled from each family's `MIN(created_at)`, plus
  `oauth_clients.refresh_token_max_lifetime`. The refresh grant checks it before
  minting anything and revokes the whole family past the cap — the whole family,
  because the client's own token is the newest of the chain and revoking only
  that would leave every earlier entry as a live way back in. A stored column
  rather than a `MIN()` at read time: rows age out with their own `expires_at`,
  so a computed origin would recede ahead of the client forever, which is the
  same never-binding failure one level down.

  Values, and they are a decision rather than a measurement — the one
  `docs/CLIENT-ACCESS-DESIGN.md` §2 recommended, taken as written: **14 days per
  token and a 90-day family cap** for `openidx-mobile` and
  `openidx-agent-android`; **30 days and the same 90-day cap** for
  `openidx-desktop`, which re-attests posture continuously so a long offline
  window costs less there. An operator who has already retuned
  `refresh_token_lifetime` keeps their value — the UPDATE matches only the seeded
  `2592000`. Browser clients stay uncapped on purpose: their token lives in a
  browser rather than at rest on a device someone can pick up, and capping the
  console would sign administrators out on a schedule nobody asked for.
  `TestEveryNativeClientHasAFamilyCap` derives the native set from the clients'
  own source, so a fourth one that ships without a cap fails the build.

- **The list of every authorization control that is switched off had no
  reader.** `Config.ReportModeGates` names each of the eight gates that is
  configured but not deciding — assignment enforcement, ABAC, step-up, OPA, the
  PAM session-risk gate, the device-posture gate and the two API auth
  requirements — with the value each currently has. It was correct, it had a
  test proving it named every open control, and **no running process ever called
  it**. A report nothing displays is the defect this branch is about, one layer
  above the gates it describes; and its own test could not notice, because a test
  that calls the function is itself a caller, so the list looked read.

  `ValidateProductionConfig` — the function every `cmd/*/main.go` already calls
  at startup — now logs one line per open control plus a summary carrying the
  count and a `fully_enforcing` flag, so a log query can alert on the number and
  can tell "nothing is open" from "this build stopped reporting". It runs
  **before** the production branch can abort, because an operator fixing a
  validation error is exactly the operator who needs to see which controls are
  open. In every environment, not only production: development is where someone
  writes an ABAC deny policy, watches it permit the request, and has nothing
  anywhere to read. `Warn` in production, `Info` elsewhere — report mode is the
  designed default there, and a warning nobody can act on is one people learn to
  skip.

  The new tests are about the reader rather than the list: they go through
  `ValidateProductionConfig`, so deleting the call reddens four of them.
  `docs/CLIENT-ACCESS-DESIGN.md` §5 claimed these warnings "already ship in
  `ProductionWarnings`" — they do not and never did; `ProductionWarnings` covers
  configuration hygiene and names no gate. That claim is corrected. Not claimed:
  no console surface renders this; the startup log is the whole of it.

- **The mobile clients' credentials were in the platform's cloud backup.** The
  engine's config directory is `getFilesDir()` on Android and
  `Library/Application Support` on iOS, and it holds three credentials:
  `agent.json` (the agent's auth token), `user-tokens.json` (the access token
  and the 30-day refresh token behind it) and `ziti-identity.json` — the private
  key and certificates that put the device on the ZTNA overlay. Both paths are
  in their platform's default backup set. The Flutter client's manifest carried
  no `android:allowBackup`, whose platform default is `true`, so all three were
  uploaded to the user's Google Drive by Auto Backup and extractable with
  `adb backup`; the iOS plugin set no `isExcludedFromBackup`, so the same three
  were in iCloud and in every unencrypted iTunes backup of a machine the phone
  had synced to.

  The Go code writes those files `0600` and said so in a comment claiming that
  outside Windows "the mode is the control". That is true on a Linux or macOS
  desktop and inert in an app sandbox, where every file is already private to
  the app's own UID and a mode bit has nothing to say about what the backup
  agent copies out. The protection was an attribute whose *absence* was the
  danger, which is why reading the manifest did not show it.

  Both clients now deny cloud backup (`android:allowBackup="false"`) **and**
  device-to-device transfer (`dataExtractionRules` excluding every domain from
  both channels — from API 31 D2D is governed separately and is allowed by
  default whatever `allowBackup` says, so either alone still hands the identity
  to the next phone). The iOS plugin marks the config directory
  `isExcludedFromBackup` *before* calling `MobileStart`, because after the
  engine's first write there is a window in which a backup takes the tokens.
  `scripts/check-mobile-secrets-at-rest.sh` fails the build if either client
  loses either half, if the iOS call moves after the start, or if the rules
  resource reads as a control while carrying an `<include>`; 14 self-test cases
  cover those shapes. The Kotlin agent already had `allowBackup="false"` and
  keeps its secret in `EncryptedSharedPreferences`; it gained the D2D half so
  the rule has no exception to explain. Not claimed: the engine's files are
  still not keystore-wrapped — that needs a callback across the gomobile
  boundary and is recorded in `docs/CLIENT-ACCESS-DESIGN.md` §4 as its own item.

- **The zero-trust policy editor's conditions never reached the evaluator, and a
  hardcoded default enforced something else.** `internal/governance` asserts a Go
  type on every condition it reads (`rule.Condition["start_hour"].(float64)`),
  and a failed assertion is not an error — the rule is skipped and the evaluator
  uses the default it was written with. So a condition the evaluator cannot read
  does not disable the policy; it quietly enforces **09:00–18:00 Monday–Friday**
  (timebound), **the RFC1918 private ranges** (location) or **a risk threshold of
  50** (risk-based), while the console shows the administrator the values they
  typed.

  Both halves were wrong. Three keys did not exist in the evaluator at all — the
  page offered `days` where it reads `allowed_days`, `allowed_ips` where it reads
  `allowed_ip_prefixes`, and `min_risk_score`/`max_risk_score` on risk-based
  where it reads `risk_threshold` — and `blocked_ips` had no evaluator concept
  whatsoever. On top of that every value was submitted as a **string** while the
  evaluator wants `float64`, `bool` or a list, so even the keys whose names
  matched (`start_hour`, `end_hour`, `conflicting_roles`, `require_mfa`,
  `device_trust_required`) failed their assertion. Of the thirteen inputs the
  editor offered, three could be read, and all three belong to the one policy
  type the form cannot create.

  This is on a live enforcement path: `internal/access` calls
  `POST /api/v1/governance/policies/{id}/evaluate` from the proxy.

  The editor now sends the keys the evaluator reads, coerced to the types it
  asserts on, and `evaluateSoDPolicy`'s two-step lookup was folded into the same
  single-statement form the other evaluators use so the contract is stated one
  way. `internal/governance/policy_condition_test.go` derives that contract from
  the type assertions themselves and checks the page against it — names and
  types, both directions. The i18n test's copy of the condition list is derived
  from the page too; it was the copy that still named `days` and `blocked_ips`.

- **The ABAC policy editor offered seven subject attributes; the evaluator
  populates nine; they overlapped on one.** `abac.SubjectAttributes` builds
  `user_id, username, email, department, job_title, employment_status, enabled,
  roles, groups`. The dropdown offered `department, location,
  device_trust_level, time_of_day, risk_score, group_membership, ip_range` — so
  six of the seven choices an administrator could pick were attributes no
  subject has ever carried. `EvaluateCondition` returns false for an attribute
  that is absent, so a condition on any of them is false for every user and the
  policy never matches: it saves, lists as enabled, and decides nothing.

  The direction that matters is deny. `abac.Gate` composes
  deny-wins-else-allow-else-allow, so a DENY written on one of those attributes
  permits exactly what it was written to stop — under `ABAC_ENFORCE=enforce`,
  the state the rollout in the readiness guide works toward. `group_membership`
  was the sharpest: the evaluator carries `groups`, one word away, so a policy
  gating on group membership silently did nothing while the spelling that works
  was not offered at all.

  Two of the four resource types were dead the same way. Both enforcement points
  — `internal/oauth` at token issuance and `internal/access` at the proxy —
  authorize an **application** and pass the application id; `Gate` selects
  `resource_type IN ($1, '*')`, so a policy scoped to `route` or `service` is
  never even selected. The prefilled subject in the Test dialog used
  `risk_score`, so the example a user starts from was itself unmatched.

  The vocabulary now lives in `internal/abac/vocabulary.go` next to the code that
  honours it, both PEPs use the declared constant instead of a bare literal, and
  `internal/abac/vocabulary_test.go` checks three things: that
  `SubjectAttributes` really builds the declared keys and no others, that the
  console offers nothing outside them, and that every offered resource type is
  one an enforcement point asks about. The i18n test's three hand-copied ABAC
  key lists are derived from the page's own lists now — they were the copies
  that went stale when the vocabulary was corrected.

- **The authorization policy was written against an input the product does not
  send.** `deployments/docker/opa/policies/authz.rego` keys its rules on
  `input.*`; a rule reading a path the client never marshals is not stricter or
  looser, it is a rule that cannot fire — OPA answers undefined, the body fails,
  and nothing logs it. Three separate cases:

  - Two rules in the shipped policy. "Users can modify their own resources"
    required `input.resource.owner`, and `opa.ResourceContext` had an `Owner`
    field nothing ever set — the middleware runs before the handler and never
    loads the row, so it cannot know who owns it. The cross-tenant `deny`
    required `input.resource.tenant_id`, which that struct did not even declare;
    the install's cross-tenant control, as far as this policy was concerned, had
    never produced a message. Both rules and the field are gone, each with a note
    saying where the control really lives (per-route ownership checks in the
    services; `org_id` under FORCE ROW LEVEL SECURITY at the database).

  - **`dev-kube/opa.yaml` carried a second, different `package openidx.authz`
    policy** — the same package the middleware queries — in which *every* rule
    read something the product does not send: `input.user.role` (singular; the
    product sends `user.roles`, a list), `input.action` (not a field at all),
    `input.resource.owner`, and `data.roles` (a data document nothing loads).
    Under `default allow = false` that policy denies every request, so turning
    `ENABLE_OPA_AUTHZ` on against that deployment — the first step of the
    documented rollout — would have 403'd admin-api, governance and provisioning
    wholesale. It now carries the canonical policy verbatim.

  - **`policies/access_control.rego` (255 lines) and
    `internal/governance/POLICY_README.md` (385 lines) described a policy engine
    that does not exist** — no `PolicyEvaluator`, no `LoadPoliciesFromDirectory`,
    no `internal/governance/policy.go`, and no OPA dependency in `go.mod`. The
    readiness guide had recorded that policy as deleted while it sat in the tree.
    Both files are deleted.

  `internal/common/opa/policy_input_test.go` derives all of this rather than
  listing it: every `openidx.authz` policy in the repository (including rego
  embedded in a ConfigMap) is checked against the JSON paths `opa.Input` marshals
  by reflection, the copies must be the same policy, and a `.rego` file that is
  not the served policy fails the build — because no Go code here reads or
  compiles rego, so nothing else can ever be evaluated.

- **Six of the policy's resource types named services it does not guard.** The
  same question asked of the other half of the input: `input.resource.type` is
  what the role-permission table and four rules key on, and a type no guarded
  route produces is a row that cannot match. `authz.rego` guards admin-api,
  governance and provisioning; its table also carried rows for `group`, `role`
  and `identity` (identity-service), `certificate` (not under the guarded group)
  and `route` (access-service), and its auditor rules keyed on `report`
  (audit-service). So `group-admin`, `role-admin`, `identity-admin`,
  `security-admin` and `access-admin` read as enforced permissions in the policy
  an operator reviews, and granting or withholding any of them changed nothing.
  The dead rows and the `report` rules are removed, each with a note naming the
  service that really serves it and what wiring that service would have to
  settle first (identity-service has eight deliberately anonymous routes,
  access-service fourteen, audit-service an open service-to-service ingest
  endpoint). `internal/common/middleware/opa_resource_census_test.go` now parses
  those types out of the policy — rules and table keys both, replacing a
  hand-written list that named six and missed the table's ten — and fails when
  one becomes unreachable.

- **Three authorization decisions were computed from the URL the caller wrote,
  not the route the router chose.** gin backtracks from a static path segment to
  a parameter when nothing static matches, so a request can read like one route
  and be served by another. Every one of these now decides on the matched route
  template (`c.FullPath()`), and each is held there by a census derived from the
  service's own route table rather than by a list of paths somebody thought of.

  - **identity-service: naming the target `me` satisfied the admin gate.**
    `requireAdminUnlessSelfService` asked whether the request path was
    self-service. `POST /api/v1/identity/users/me/roles` is not a registered
    route, so it is served by `/users/:id/roles` — the administrative role-grant
    handler — while the string the caller wrote begins `/users/me/`. Eleven
    routes collided this way, every one of them an administrative operation
    answering a caller with no admin role: grant, list, replace and remove a
    user's roles; read their role assignments; set and reset their password;
    offboard them; delete them; revoke all their MFA bypass codes; and revoke a
    bypass code by writing `verify` in its place. Each was stopped further down
    — three by an explicit ownership check in the handler, the other eight by
    PostgreSQL refusing `me` for a `uuid` column — so the gate has been open
    without being walked through. `internal/identity/authz_surface_test.go`
    derives all three tiers by driving the real middleware, records every one of
    the 8 anonymous and 71 self-service routes with a mandatory reason, and
    requires every self-service route whose template names a target to say where
    its ownership check lives.

  - **governance-service: the internal service token reached more than
    `/evaluate`.** The shared secret that lets the access-proxy call the policy
    evaluator was scoped by testing whether the request path ended in
    `/evaluate`. Fourteen requests reached handlers that do not: delete and
    update on policies, ABAC policies, approval policies, campaigns and reviews,
    and reads of access requests — reached by writing `evaluate` where an id
    belongs. The middleware's own comment says the scope exists so "a leaked
    token can't drive user-facing governance operations"; those are exactly
    user-facing governance operations.

  - **OPA was asked about a resource type that was a UUID.**
    `deployments/docker/opa/policies/authz.rego` keys five rules on
    `input.resource.type`, among them the role-permission map. The middleware
    took that type from the request path's last segment, so
    `/api/v1/identity/users/<uuid>` asked about a resource of type
    `3f2a…`. 101 of the 341 routes OPA guards were affected — every read, update
    and delete of a specific object — so on all of them the role map and the
    object-scoped rules silently did not apply. Nothing logged it, because a
    rule that does not match is not a denial.

### Added

- **The unauthenticated surface of access-service, derived and declared
  (`internal/access/public_surface_test.go`).** The service registers 325
  routes; fourteen of them answer without the tenant-JWT middleware. Those
  fourteen are the product's unauthenticated attack surface, and until now
  nothing said which they were — the authentication hole listed under Fixed
  lived in two of them for the life of the code, while four comments elsewhere
  in the package named one of those two as the pattern they copied.

  The guard does not read a list to find them. It registers every route with a
  stub auth middleware that refuses everything, then drives each route: one
  that answers anything else is outside the middleware *by construction*. A
  hand-kept list would already have missed `POST /api/v1/access/enroll`, the
  Tier-0 dark-platform door, which is registered on the router directly rather
  than in the group with the other four agent routes.

  What is written down is the decision about each route, and it is checked. Each
  entry records the shape of its refusal — refuses before reading anything;
  resolves the subject first and so answers 404 for one that does not exist;
  or exists to answer an anonymous caller (a login redirect, an OIDC callback,
  an installer, a link whose path is the secret). The first shape is driven
  against a *nil database*, which makes "did this handler read something before
  it refused" an observable question: a handler that touches state first panics,
  and the panic is the finding. Restoring the defect below — reading the body
  and querying before the credential check — turns it red with the fix named.

- **J4's automatable half, proved through the running services
  (`test/integration/network_access_test.go`).** "Enroll agent/BrowZer →
  posture check → reach a dark service" was the last Definition-of-Done journey
  with no automated verification. Its third step needs a Ziti controller, a
  router and a dark service to dial, and stays an operator drill
  (`tools/darkprobe`, the going-dark runbook). Its first two steps are HTTP
  against access-service, and they are the steps that decide the third.

  Eight assertions across one enrolled device: an anonymous caller cannot
  report its posture, cannot guess its token, cannot report for an agent id
  nobody enrolled, and cannot take a compliant device's trust away; the device
  itself can, and the verdict lands in the trail and in the administrator's
  view; a report filed under another device's id is refused; and the
  configuration is served to the device and to nobody else. Writing it is what
  found the authentication hole listed under Fixed — the journey's question is
  not "is posture recorded" but "who is allowed to say what a device's posture
  is", and the answer was "anybody".

- **J8's audit half, proved against the running trail
  (`test/integration/audit_chain_test.go`).** The product claims a
  tamper-evident audit log. `internal/audit/chain_test.go` proves the sealer's
  arithmetic; this proves the property — that the events the product *writes*
  are sealed by the sealer that is *running*, and that the verification endpoint
  an auditor calls notices when one changes.

  The test does the thing the control exists to catch: it edits a sealed row
  directly, with the privileges an operator or an intruder with database access
  would have. Tamper-evidence is not a claim about who can reach the database —
  it is the claim that reaching it is not enough, because the change shows. The
  endpoint reports `intact: false`, names the event, and prints the stored and
  computed hashes; restoring the row exactly makes it whole again, which is what
  keeps `intact: false` from being an answer the chain gives to everything.

  It writes the event it verifies: the test posts one through the audit ingest
  endpoint — the same path `internal/access` posts every credential reveal to —
  and waits for the running sealer to chain it before doctoring the row. That
  wait is the point of the test rather than an inconvenience in it, because
  waiting for a real sweep is what separates "the deployed sealer sealed a row
  the product wrote" from "a sealer built inside a unit test hashed a struct".

  Asking the question was worth it independently of the answer: the same
  question one step earlier — *are the events even there* — is what turned up
  the ingest defect below.

- **J5, privileged access, proved through the running services
  (`test/integration/privileged_access_test.go`).** The credential half of the
  journey — the only path in the product that ever hands PAM secret material to
  a person — driven against access-service and audited by audit-service, which
  the integration job now boots alongside the other five.

  `jit_checkout_test.go` says in its own header why it stopped short:
  "governance HTTP handlers are not driven (gin+JWT wiring is heavy). This
  validates the checkout mechanics that the HTTP layer delegates to." The
  mechanics are not the control. The org predicate, the `allow_reveal` flag,
  the ACL for non-admins and the audit row all live in the handler, and a test
  of `vault.Service` reaches none of them.

  Four assertions, separately: an ungranted user is refused; the same user,
  granted, gets the credential; `allow_reveal=false` refuses **even an
  administrator** (the handler's own claim about injection-only entries); and
  the reveal is in the audit trail naming who and what. The last one is what
  found the two defects below.

- **A census of settings nothing reads (`tools/deadconfig`, wired into CI as a
  hard gate).** Every struct field carrying a `mapstructure` tag is a setting an
  operator can put in a config file or an environment variable; the type checker
  says which of them the code ever reads. Subtracting the second from the first
  is the only thing that can see this defect — the field parses, the viper
  default makes it non-zero, the docs describe it, and nothing fails at runtime,
  because the product does what it did before.

  Both halves are derived from the tree rather than listed, for the reason
  `tools/orgscope` was inverted: a field nobody remembered to add to a list is
  not unchecked in a way anyone can see, it is invisible. Reads are resolved
  through `go/types`, not matched by name — prose about a field is not a read of
  it, and `Enabled` is a field on six config structs here, so a name match let
  one struct's live field clear another's dead one. Test files are not loaded: a
  field only a test touches is one the product does not consult, which is
  exactly the shape `ENABLE_MFA` had.

  The register (`tools/deadconfig/known.go`) is empty and is meant to stay that
  way, because the destination for a finding is not a register entry — it is
  `internal/common/config/retired.go`, where the field, its default and its
  binding go and the name stays behind saying so at startup.

  The first run found six across 295 settable fields; all six are fixed below.

- **The mirror census: a documented setting nothing binds (`tools/deadconfig`,
  same gate).** The half above finds a field an operator can set that the code
  never reads. This finds the direction an operator meets first — a settings
  table naming an environment variable the product has no binding for.

  The published Configuration Reference, `docs/docs/deployment/configuration.md`,
  had **63 of its 88 rows** in that state: `PASSWORD_MIN_LENGTH` and the four
  `PASSWORD_REQUIRE_*`, `OAUTH_ACCESS_TOKEN_TTL` and its three siblings,
  `MAX_SESSIONS_PER_USER`, `SESSION_TTL`, `RATE_LIMIT_ENABLED`/`RPS`/`BURST`,
  `CSRF_SECRET`, `JWT_PRIVATE_KEY`, `SMTP_SKIP_VERIFY`, `AUDIT_RETENTION_DAYS`,
  the four `MFA_TOTP_*`, the database and Redis pool knobs. One of them,
  `MFA_WEBARUTHN_ENABLED`, was misspelled — which is the clearest possible
  evidence that nobody had ever tried it. The YAML example and all three `.env`
  samples were written against the same phantom names, and the page described a
  `--config` flag that does not exist and a config file named after a service
  when the loader looks only for `config.yaml`.

  The page is rewritten from the bindings. Every row is now a variable the
  product reads; settings that are real but live elsewhere — the password policy
  and session limits in the console, token lifetimes per OAuth client, OTP
  parameters in Settings → SMS, pool sizing in the DSN — have their own section
  naming where, because "it isn't here" is what made the phantom rows grow in
  the first place. `PUSH_MFA_ENABLED` and `PUSH_MFA_CHALLENGE_TIMEOUT` gained
  the unprefixed bindings the shipped config file already assumed.

  The bound set is derived: the environment map, every `os.Getenv` literal in
  the tree, viper's `OPENIDX_<KEY>` spelling of every field, and the console's
  own `import.meta.env.VITE_*`. The one written list holds three variables that
  belong to the Postgres, Redis and Grafana images, each saying whose it is.

- **J6, the governance loop, proved end to end
  (`test/integration/governance_loop_test.go`).** With J7 above, this closes the
  last two journeys the Definition of Done listed with no automated proof
  behind them. The only browser spec aimed at J6,
  `e2e/access-reviews-flow.spec.ts`, stays on the hold side of `e2e/suite.txt`
  deliberately: it is 738 lines driven entirely by mocked responses, so
  promoting it would prove the console renders fixtures, not that a reviewer's
  decision does anything.

  The integration case drives a certification decision through the API against
  the running services and asserts its three effects separately, because they
  fail independently: the item is recorded revoked, the underlying role is
  actually removed, and the reviewed user's **live** access token stops working.
  The third crosses a process boundary — governance writes the revocation
  marker, oauth-service reads it on every `/oauth/userinfo` — and it is the half
  that failed before: `internal/revocation` exists because the two once spelled
  that Redis key differently, so a reviewer could revoke somebody, see it
  recorded and audited, and the person kept working until their token expired.
  The integration job now boots governance-service, so the two are really
  separate processes rather than one test binary.

  Red-proofed by restoring the old divergent key: the first three assertions
  stay green and the fourth goes red, which is the exact shape of the original
  defect.

### Fixed

- **The posture endpoint that decides a device's network tier accepted reports
  from anyone (`internal/access.HandleReport`, `HandleConfig`).**
  `POST /api/v1/access/agent/report` and `GET /api/v1/access/agent/config` are
  registered outside the JWT middleware, because an agent has no tenant JWT and
  authenticates with the credentials enrollment issued it. Neither handler read
  those credentials. `/agent/report` took the agent id out of the JSON body,
  falling back to a header, and trusted it; `/agent/config` took it from a
  header or an `agent_id` query parameter.

  A posture report is not a status line. `applyPostureDeviceTrust` turns the
  verdict into the `device-trusted` Ziti role attribute, which is the Tier‑2
  gate the reconciler's dial policies require for the remote/PAM and admin
  surfaces. So an unauthenticated HTTP request could grant a device network
  access it had not earned, or strip a compliant laptop of the access it had —
  and could write posture rows and compliance verdicts for any agent id at all.

  Proven against the running service, with no credentials and an agent id that
  had never been enrolled: `202 {"compliance_score":1,"status":"accepted"}`,
  and the row was in `agent_posture_results`. The same request now answers
  `401 {"error":"invalid agent credentials"}`.

  Both shipped agents already send the credential — the Android one as
  `X-Auth-Token`, the Go one as `Authorization: Bearer` — and
  `api/openapi/access-service.yaml` has always documented a `401` on both
  paths. Only the server never looked, so no deployed agent is affected by the
  fix. The lookup now lives once in `internal/access/agent_auth.go`; the two
  handlers that already had a copy of it (the remote-support WebSocket and the
  Windows-app discovery report, both of which cite `/agent/report` in their
  comments as the pattern they follow) delegate to the same function. The
  authenticated id is also the subject of the report: a body naming a different
  agent is refused rather than honoured.

- **Every audit event access-service ever emitted was refused and dropped
  (`internal/audit.LogEvent`).** `audit_events.id` is
  `uuid NOT NULL DEFAULT gen_random_uuid()`, and `LogEvent`'s INSERT names the
  column — so the default never applied, an event that arrived without an id
  put `""` into a uuid column, and Postgres refused the write. The ingest
  endpoint answered 500.

  Its only caller in the product is `internal/access.logAuditEvent`, and it has
  never sent an id. So **every PAM credential reveal, every entry created or
  deleted, every grant added or removed, every proxy allow and deny** was
  refused and dropped, on every install, for as long as this code has existed.
  The loss showed as one warning line in the emitting service's log — and that
  line only exists because of an earlier fix on this branch; before it, the
  response status was discarded and the loss was completely silent.

  Proven in the endpoint's own responses before the fix: the body
  access-service sends → `500 {"error":"INTERNAL_ERROR","message":"log event"}`
  and no row; the same body with an id → `201` and the row lands. `LogEvent`
  now assigns an id when the event has none, and keeps one the caller supplied.

  Found by writing J5's integration test — the journey that ends "…and it is
  audited".

- **The audit trail did not say who** (`internal/access.logAuditEvent`). Even
  once events land, the event this service builds carried no `actor_id`, so the
  actor column — the one the console filters on and an auditor reads first —
  was blank for every credential reveal, every recording download and every
  proxy decision. Some handlers put the id into `details.user_id` on the way
  past, which is a JSON blob, not a column: "who revealed this credential" was
  not a question the trail could answer. Red-proofed: with the fix removed the
  assertion reports `actual: ""`.

- **The OAuth signing key was stored in plaintext on the reference stack, and
  the compose file refused to start without a secret that signs nothing.** Two
  halves of one mistake, found by the same census.

  `JWT_SECRET` had a config field, an environment binding, a line in the
  generator, a `${JWT_SECRET:?required}` in both compose files, a Kubernetes
  secret key, a Vault mapping, a production check that blocked startup without
  it, and a row in `SECURITY-HARDENING.md` reading *"Used to sign access + ID
  tokens. Rotate together with `OAUTH_JWKS_URL` cache invalidation."* Nothing
  signed or verified anything with it. Every token OpenIDX mints or accepts is
  RS256, signed with the rotatable key in `oauth_signing_keys` and verified
  through JWKS; the shared middleware rejects any other algorithm **by name**.
  So an operator who rotated `JWT_SECRET` after a suspected compromise rotated
  nothing, and every outstanding token still verified. `docs/architecture/
  secret-rotation.md` had already noticed and filed it as "vestigial … consider
  removing it"; it is removed, retired in `internal/common/config/retired.go`,
  and that page now names the real procedure —
  `POST /api/v1/admin/oauth/signing-keys/rotate`.

  `ENCRYPTION_KEY` is the secret that *does* protect the signing key — it
  encrypts it at rest — and **no service in either compose file received it**.
  `secretcrypt` falls back to a no-op cipher and warns, so the key that mints
  every token in the system was written to the database in plaintext on the
  reference stack, and on the production compose file, while the same files
  refused to start over the inert one. The Kubernetes paths were unaffected:
  Helm and `dev-kube` mount the whole secret with `envFrom`. Both compose files
  now pass it to the six services that read it, and
  `deployments/docker/encryption_key_reaches_services_test.go` derives that set
  from the tree — a package that reads `Config.EncryptionKey`, and any binary
  that imports one — so a service added later is covered without anyone
  remembering the test exists. Red-proofed by removing the key from
  `oauth-service`.

- **The admin console's OTP settings reached nothing
  (`internal/identity.SetOTPSettings`, applied by the SMS config watcher).**
  Settings → SMS offers OTP code length, lifetime and attempt ceiling. The
  values were stored, validated, clamped to sensible ranges by
  `sms.ValidateOTPSettings`, round-tripped back to the page — and
  `createOTPChallenge` called `DefaultOTPConfig()` unconditionally, with no
  other `OTPConfig` constructed anywhere in the tree. An administrator who set
  eight-digit codes valid for a minute got six digits valid for five minutes,
  with the page showing what they asked for.

  The settings now travel with the provider the watcher hot-swaps, so a change
  in the console takes effect without a restart, and they are re-clamped on read
  because a row stored before `ValidateOTPSettings` existed can still be in the
  table. The rate-limit window and the codes-per-hour ceiling deliberately do
  not move: they are not on the page, and a settings row must not widen them.

  Red-proofed against a real database by restoring `DefaultOTPConfig()` at the
  call site: "the code is 6 digits; the administrator asked for 8".

- **`PUSH_MFA_ENABLED=false` did not turn push MFA off
  (`internal/identity.ErrPushMFADisabled`).** The field had a default and a line
  in a shipped config file and no reader, so an operator who turned the factor
  off could still enrol a phone and still be sent a challenge. Turning a factor
  off is a security decision — a compromised push transport, a vendor being
  retired — and it was one the product accepted and discarded. Enrolment and
  challenge creation now refuse with a named error, the challenge refused before
  the device list is read so a phone enrolled earlier cannot be used either.

- **`log_level` in a configuration file did nothing (`logger.SetLevel`).** A
  service builds its logger before it loads its config — it has to, or a config
  error has nowhere to go — so the level came from `os.Getenv("LOG_LEVEL")` and
  the config field had no reader at all. `LOG_LEVEL` worked; `log_level:` in a
  file was parsed into a field nothing consulted. Loggers now share one atomic
  level that every binary sets from its config immediately after loading it, and
  an unrecognised name is refused rather than silently ignored. A test derives
  the set of binaries that must do this from the tree, so a tenth service is
  covered without anyone remembering the test exists.

- **A disabled user's access token kept working for an hour
  (`internal/revocation.RevokeUserTokens`, wired into every sever path).**
  Writing J7's missing integration case — "disable or kill-switch a user and
  everything is severed" — found the journey's third half broken. Identity's and
  provisioning's `deprovisionUser` and the access-service kill switch each
  collected the user's live session ids and published `revoked_session:<id>`,
  which the **refresh grant** honours. Nothing they wrote is read by
  `/oauth/userinfo` or `/oauth/introspect`: those consult the per-user revocation
  cutoff and the per-token blacklist and nothing else, and no sever path wrote
  the cutoff. So an administrator disabling a leaver, or firing the kill switch
  on a compromised account, cut new logins and cut the refresh — and the access
  token already in that browser answered for the rest of its hour and
  introspected `active: true`, while the console showed the account disabled.

  That put the controls in the wrong order. An access-review revocation, the
  slowest and least urgent control in the product, already wrote the cutoff
  (that half was fixed when `internal/revocation` was created); the kill switch,
  the one you reach for when an account is compromised, did not. All three sever
  paths now call `revocation.RevokeUserTokens`, which lives in the package that
  owns the key so a fourth spelling cannot appear. The kill switch reports it as
  `iam_access_tokens_revoked` rather than swallowing a failure, because "the
  tokens were not actually cut" is something an operator needs in the record.

  `test/integration/leaver_test.go` drives all three halves against the running
  services and asserts them separately: a test that checked only the login and
  the refresh would have passed for the whole time this was broken, which is how
  it stayed broken.

### Removed

- **Five settings that were read by nothing are retired**, joining `ENABLE_MFA`,
  `ENABLE_AUDIT_LOGGING` and `OAUTH_LOGIN_UI` in
  `internal/common/config/retired.go`. Each is gone from the struct, the viper
  defaults and `configs/audit-service.yaml`, and an install that still sets one
  is told so at startup — in every environment, because development is where an
  operator tries a switch and needs to hear that it does nothing.

  `configs/audit-service.yaml` is deleted for the same reason one level up: it
  was the only file in `configs/`, it was named after a service while `Load`
  looks only for `config.yaml`, and its `${VAR:default}` lines implied an
  interpolation step nothing performs — so an operator could edit it all day
  and no process would ever open it. The reference for what can be set is the
  Configuration Reference, which is gated. The test that kept a retired setting
  out of shipped configuration now reads every surface an operator actually
  copies (`.env.example`, the compose and dev-kube samples, the apisix-edge
  examples) in both the YAML and the `KEY=value` shape, rather than one file
  nothing read.

  - `JWT_SECRET` (`jwt_secret`) — see Fixed above: a required production secret
    that signed and verified nothing.
  - `FCM_SERVER_KEY` (`push_mfa.fcm_server_key`) — the legacy FCM server key.
    Google decommissioned the legacy HTTP and XMPP APIs in 2024 and no build
    ever sent it; push goes out over FCM HTTP v1. Set
    `PUSH_MFA_FCM_CREDENTIALS_FILE` and `PUSH_MFA_FCM_PROJECT_ID` instead. Two
    documents told operators to configure it; both now describe HTTP v1.
  - `SMS_OTP_LENGTH`, `SMS_OTP_EXPIRY`, `SMS_MAX_ATTEMPTS` — duplicates of the
    installation settings the admin console owns, read by nothing. The console's
    copies now work (see Fixed); these did not and could not, since the identity
    service hot-swaps SMS configuration from the database.

  Both spellings of a retired setting are reported: the one the shipped config
  and the docs named, and viper's own `OPENIDX_<KEY>` form, derived from the key
  rather than listed so the two cannot fall out of step.

### Added

- **Upstream pools reach the operator, and the data plane
  (`/api/v1/access/upstream-pools`, `internal/access/upstream_pools_handlers.go`,
  Upstream Pools console page).** Migration v130 built the place to declare a
  route's backend set — algorithm, hash key, per-node weights, active health
  checking — and `internal/access/upstream_pools.go` renders it into the APISIX
  upstream object. Neither half could be used: no handler, route or console page
  could create a pool, so `upstream_pools` was empty on every install. Building
  the missing half turned up a third gap neither register had recorded:
  `BuildEdgeRoutesForPools`, the only function that renders a pool-backed route
  for the data plane, was **called by nothing**. `APISIXReconciler.Reconcile`
  loaded the BrowZer routes and stopped there, so a pool inserted by hand and
  linked by hand would still never have reached APISIX. The reconciler now
  converges both sets in one pass and prunes only the generated prefixes it was
  able to read, so a failed pool read leaves the edge alone instead of emptying
  it. `proxy_routes.upstream_pool_id` is settable from the route API and the
  pool it names is resolved inside the caller's organization first — the foreign
  key alone would have accepted another tenant's pool and sent this route's
  traffic to their backends.

  Two behaviours here are not CRUD, and they are why this was built rather than
  deleted. **A pool can be configured and not be in effect:** `BuildUpstream`
  refuses to render a pool with no usable member, because an upstream with no
  node black-holes the route, so the route falls back to the single address in
  `to_url`. Right at runtime and, until now, silent — an operator draining the
  last backend for maintenance would be told "member removed" while traffic kept
  flowing. Every response describing a pool carries `in_effect` and the reason,
  and the page leads with it. **Deleting a pool moves traffic:** the foreign key
  is `ON DELETE SET NULL`, so a delete would quietly revert every route on the
  pool to one backend with no health checking. It is refused while any route
  still names the pool, and the refusal lists them.

  This empties the dead-service register (`tools/deadservice`) — `UpstreamPool`
  was its last entry — and takes both `upstream_pools` and
  `upstream_pool_members` off the unwritten-table register.

- **The tamper-evident audit log, made real (migration v181,
  `internal/audit/chain.go`).** The docs index, the architecture page, the audit
  reference page and the README's readiness checklist all state that OpenIDX
  keeps a tamper-evident HMAC hash-chain audit log. `internal/audit/logger.go`
  has carried the primitives from the beginning — HMAC-SHA256 over a canonical
  form, a previous-hash link, a chain walk that names the first break — and no
  binary has ever reached them; no migration created a column to store a hash
  in; and the tests covering the chain declared their own `ComputeHashForChain`
  method inside the test file to make the assertions work. Four published claims
  rested on code that has never run. Now: v181 adds `chain_seq`, `prev_hash` and
  `event_hash` with a unique `(org_id, chain_seq)` index, a background sealer
  chains each organization's events under a per-org advisory lock, and
  `GET /api/v1/audit/chain/verify` answers whether that tenant's trail is
  intact — naming the event where it broke. The chain is **per tenant**, because
  `audit_events` is under FORCE RLS and an install-wide chain would be
  unverifiable by the tenant whose rows it covers. It is sealed by a sweep
  rather than on insert, because sixteen statements across the tree insert into
  that table and a per-org lock at each would put a serialization point in the
  middle of login; the cost is reported rather than hidden — verification
  returns the unsealed count, so the sweep's lag is visible in the evidence.
  `AUDIT_CHAIN_SECRET` is generated by `scripts/generate-secrets.sh`, separate
  from every other secret on purpose (whoever can write the audit database must
  not hold the key to re-seal a doctored trail), and `ValidateProduction`
  refuses a production start without it. Detects an edit to any sealed row, a
  deleted sealed row, and a row backdated into a sealed run; a table-driven test
  rewrites **each** of the fourteen stored columns in turn and requires every
  one to break the chain, because a hash covering most of a row is worse than
  none — verification would pass and vouch for the edit.

- **`tools/deadservice` — a gate for whole services no binary can reach.**
  `internal/governance/request.go` is 676 lines of access-request workflow:
  submit, approve, deny, cancel, manager resolution, notification hooks, and an
  escalation sweep that finds every request past its approval SLA and adds the
  escalation approvers. It has tests. It is the only code that writes
  `request_approval_chains`, a table migration v58 created for it and v64 put
  under the RLS belt. `NewRequestService` is called nowhere: the live workflow
  is a different implementation in `workflows.go`, which never writes that
  table, so the sweep's `INNER JOIN` matches zero rows on every install and
  would keep matching zero even if the checker were started. Nothing in the
  repository could see this — it compiles, its SQL is valid and carries its
  tenant predicate, its tests are real tests exercising real code, and
  `tablewriters` counts its `INSERT` as a writer because a census of SQL
  literals cannot tell a statement that runs from one that cannot. An earlier
  fix on this branch spent its effort on a bug inside that sweep. The gate is
  Rapid Type Analysis from every binary's `main`; a finding is a type whose
  constructor is unreachable and not one of whose methods any binary reaches,
  which is the shape that misleads rather than every unused helper. The register
  opened at **41**, with a verdict apiece saying whether the answer is to wire
  it or delete it, and it shrinks. The largest entry is its own task: the
  tamper-evident HMAC hash-chain audit log advertised on the docs index, the
  architecture page, the audit reference and the README's readiness checklist is
  implemented in `internal/audit/logger.go`, reachable from nothing, and no
  migration creates a column to store a chain in.

- **`tools/zeroanswer` — a gate for the defect class behind the three entries
  below.** A one-row aggregate (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `EXISTS`)
  always returns exactly one row, so a discarded `Scan` error there can never
  mean "there is no data" — it means the query did not run, and the destination
  keeps its zero, which the caller then prints on a dashboard, writes into a
  compliance report, or reads as a control that passed. Nothing else in the
  repository can see this: the SQL is valid so `sqlprepare` plans it, the tenant
  predicate is present so `orgscope` passes it, the handler answers 200 with a
  well-formed body so the contract test passes it, and `COUNT` over no rows is
  also 0. Only the error told the two apart. The register (`known.go`) opened at
  83 with a verdict per site saying what the zero does, and shrinks; a new
  finding fails the build, and so does an entry that no longer reproduces.

### Fixed

- **An invitation token was never spent (`handleAcceptInvitation`).** Accepting
  an invitation read the row `WHERE status = 'pending'`, created the account,
  and forty lines later ran `UPDATE user_invitations SET status = 'accepted'`
  with the error discarded. If that write failed the invitation stayed pending
  and the token stayed usable — a single-use credential that could create a
  second account, and a third. Even checked, `SELECT`-then-`UPDATE` is a
  check-then-act: two requests arriving together both pass the read before
  either writes. One `UPDATE … RETURNING` now reads and burns at once, so
  exactly one caller can claim a token, and a failure anywhere after it puts
  the invitation back rather than costing the invitee their invitation over a
  taken username. The same handler also skipped the password write entirely
  when hashing failed (`if err == nil`) and discarded the role and group
  inserts, so it could answer **201 "Account created successfully"** for an
  account with no password and none of the access the invitation promised;
  those three now share a transaction and the response says plainly when it
  could not be finished.
- **No way to run the guards CI runs (`make guards`).** There are 29 shell
  guards under `scripts/` with 27 self-tests, invoked from several different CI
  jobs with different flags, and nothing ran them as a set — so "I ran the
  guards" meant "I ran the ones I remembered", and the rest were found by CI
  twenty minutes later. That happened on this branch: a database-gated test
  helper that read only a private environment variable, and so would have
  skipped on every CI run, went in because `check-test-reachability.sh` was not
  among the five run by hand beforehand. `scripts/run-ci-guards.sh` reads the
  invocation list out of `.github/workflows` rather than keeping a copy of it,
  because a hand-kept list drifts from CI exactly the way the unit-test matrix
  drifted from the tree — and a runner that omits a guard CI runs is worse than
  none, since it reports that the guards passed. It runs all 54 in about 40
  seconds, treats an invocation CI writes with `|| true` as informational, and
  reports the one whose argument CI computes as **not run** rather than as a
  pass. Six cases of its own keep it honest, chief among them that finding no
  guards is an error and not an empty success.
- **Six Ziti handlers answered success over a record they had not changed, and
  a SCIM mirror the provider reads back.** Each of these makes the controller
  call first, checks it, and returns on failure — then wrote the database mirror
  with the error discarded. So `DELETE /ziti/services/:id` answered *"ziti
  service deleted"* while the row and its BrowZer route survived; the identity
  delete did the same; `PUT` on a service policy answered 200 with the new
  service and identity roles while the console kept showing the old ones for a
  policy the network was already enforcing differently; and the identity
  attribute patch — the attributes overlay policies match on — did likewise.
  All six now report the divergence and say which way round it is: the network
  changed, the record did not, and here is what will look wrong until it does.
  In the same file, `handleGetEnrollmentJWT`'s write is genuinely best-effort —
  a cache of a token the controller had just returned — and now carries a
  `//silentwrite:ok` saying so, which is the distinction the gate exists to make
  visible.
  `UpdateSCIMUser` had the same split: the `users` row was checked, its
  `scim_users` representation was not. That representation is what a SCIM `GET`
  answers with, so a failure left the identity provider reading back the values
  it had just replaced — and a provider that reconciles against what it reads
  either sends the change for ever or concludes it never applied. The two are
  one transaction now.
- **A refused remote-support session was not ended
  (`HandleAgentConsent`).** The denial branch carries the comment *"A denial
  ends the session immediately (fail-closed)"*, and the statement under it
  discarded its error. On a failure the session was **not** ended, the audit
  still recorded `remote_support.consent_denied` with outcome `success`, and
  the agent was answered `{"consent_status":"denied","status":"ended"}` — so
  the person at the device refused to have their screen watched, was shown a
  confirmation, and the session stayed live, with every record saying they had
  been listened to. Both consent branches now check the write and the row count,
  audit the failure as a failure, and tell the agent the refusal could not be
  recorded and the session may still be active.
- **A device the console called trusted could be untrusted (`trustDevice`).**
  The function ran two statements: a nudge marking the user's Ziti identity
  attributes stale, whose error was checked and logged, and the `UPDATE` that
  actually sets `known_devices.trusted`, whose error was discarded. The
  belt-and-braces statement was the checked one. An administrator could approve
  a trust request, the request row would say approved, the user would be
  notified — and the posture gate would go on refusing the device for a reason
  visible nowhere. It now reports both a failed write and a row count of zero,
  and both callers pass that up instead of announcing an approval the device
  never received.
- **A directory sync could report success over a group it did not sync
  (`internal/directory`).** Both the LDAP and the Entra ID membership passes
  ran, per group, a `DELETE` of the directory-managed rows followed by an
  `INSERT` per current member — both errors discarded, and no transaction round
  the pair. The dangerous ordering is the `DELETE` failing while the `INSERT`s
  succeed: a membership the directory **removed** survives, and `RunSync` goes
  on to write `sync_status = 'synced'`. That is deprovisioning that did not
  happen, on the schedule an operator relies on to take access away when
  somebody leaves a team, with the console saying the sync worked. The reverse
  order silently drops access the directory still grants, and between the two
  statements the group is briefly empty, so a membership check landing there is
  answered no for a user who has the access. One transaction now moves the old
  rows and the new ones together, and the sync reports which groups kept the
  membership they had.
- **An approval chain could come out shorter than its policy
  (`createApprovalRows`).** Five `INSERT`s into `access_request_approvals`, one
  per approval-step type, every one discarding its error. Losing the whole
  chain is visible — nobody can approve the request. Losing *part* of it is
  silent and worse: `handleApproveRequest` fulfils a request when the count of
  pending approvals reaches zero, so a two-step policy that produced only its
  first row is granted by one approver with the second step skipped, and the
  audit trail says it was approved. The builder reports failure now, and the
  handler withdraws the request rather than leaving a half-routed one standing.
- **The writes whose failure nobody learns about (`tools/silentwrite`, new
  gate).** 137 statements across the tree change the database through
  `_, _ = …Exec(…)` or a bare call, and cannot tell whether they did. Many are
  best-effort by design — a last-seen timestamp, a queue counter, a telemetry
  row — and wrapping those in error paths nobody reads would be worse code. But
  "best-effort" is a judgement the tree records nowhere: `_, _ =` is Go's
  spelling for "I meant to drop this", equally true of the timestamp and of the
  revoked credential. The gate reports each one and is cleared either by
  handling the error or by a `//silentwrite:ok` reason above the call saying
  what is lost — the `//orgscope:ignore` convention this repository already
  uses. The fixes above take the count to 113, one site carries a reason, and
  the gate holds it there: it can only go down.
- **115 log fields carried a request value nothing cleaned
  (`internal/common/logsafe`, new guard).** CodeQL filed two "Log entries
  created from user input" alerts against `internal/admin/attestation.go`.
  Reading the file showed the shape plainly: two fields there already went
  through `logsafe`, and three more logged a campaign id taken straight from
  `c.Param("id")`. The earlier sweep had fixed the sites CodeQL named rather
  than the class behind them, so an AST census over the tree — function-scoped,
  because two handlers in one file routinely both call something `id` or
  `token` — found 115 of them across 24 files: agent ids, session ids, SAML
  provider ids, group and role ids, an OAuth redirect URI, a social-login
  provider's `error_description`. All now go through `logsafe.String`.
  This is not a log-forging fix: `encoder_test.go` already established that
  both zap encoders escape a field, and the guard against forging a line is
  `no_interpolated_message_test.go`. It is a fix for the other three reasons
  the package exists — nothing bounded the length, so a megabyte of `id` in
  every warning fills a disk and buries the entry that mattered; the escaping
  belongs to the encoder and does not survive the hop to Elasticsearch and on
  to a SIEM; and it is the shape a static analyser will keep reporting until
  the class is closed. `TestNoRequestValueReachesALogFieldUnwashed` now fails
  the build on the next one, and eight cases built from synthetic source keep
  the guard itself honest in both directions.
- **The dead-service gate brought a vulnerable dependency in with it
  (`golang.org/x/mod`).** Promoting `golang.org/x/tools` to a direct dependency
  so `tools/deadservice` could do reachability analysis also recorded
  `golang.org/x/mod v0.38.0` in `go.mod`, and that version carries
  CVE-2026-56864 and CVE-2026-56865 — a malicious `GOSUMDB` serving arbitrary
  module content, and a transparency-log tile verification bypass. `govulncheck`
  stayed green (nothing reaches `sumdb/tlog` from any binary here) while the
  filesystem scan went red, which is the difference between the two tools rather
  than a disagreement. Bumped to v0.40.0, pulling `x/tools` to v0.49.0 and
  `x/net` to v0.58.0 with it. `go mod tidy` then dropped
  `github.com/open-policy-agent/opa` and eight of its transitive dependencies:
  the embedded OPA engine's only importer in the tree was
  `internal/governance/policy.go`, the third policy evaluator deleted earlier on
  this branch, so the requirement had been holding a compiled-in Rego runtime
  the product never called. Policy decisions go to the OPA **server** over HTTP,
  as they always did.
- **`cmd/` had no unit-test job, and one package's tests had never run at all
  (`tools/testmatrix`, new gate).** The unit-test matrix in CI was a
  hand-written list of `internal/*` and `pkg/`. It did not name `cmd/`, so the
  ten service main packages had no per-package job — which is how the seven red
  production-config tests below went unremarked across several pushes. They were
  never unverified (`go test -race ./...` covers the module), but that signal
  arrives twenty minutes in under a check named "Race Detector", and a red tick
  with that name reads as a concurrency problem rather than as a broken
  production gate in seven services. The matrix now names every package, in
  `package`/`paths` pairs so several small directories can share a runner, and
  `tools/testmatrix` fails the build when a directory holding `_test.go` files
  is named by neither the matrix nor a register entry citing the job that does
  run it — the same inversion applied to `tools/orgscope`, for the same reason:
  a hand-maintained allow-list cannot notice what is missing from it.
  The gate also refuses coverage that compiles nothing, which turned up
  `cmd/rekey`: its single test file is behind `//go:build integration`, so
  although the package sits under `./cmd/...` every job compiled zero tests out
  of it. Two tests — a 294-line end-to-end proof that rotating the key-encryption
  key re-seals every stored secret under the new key and leaves the plaintext
  readable, the tool an operator reaches for after a key compromise — had never
  executed anywhere. They pass; the Integration Tests job now names
  `./cmd/rekey/...` so they keep doing so.
- **Seven production-config gate tests went stale when the audit chain became
  required (`cmd/*/main_test.go`).** `AUDIT_CHAIN_SECRET` joined the
  `ValidateProduction` critical list in the audit hash-chain change above. The
  config package's own tests were updated; the seven `cmd/*` copies of "a valid
  production config" were not, so each service's only automated proof that a
  production start is accepted began failing. They run in CI — but only inside
  `go test -race ./...`, since the per-package unit matrix does not list `cmd/`
  at all, so a self-inflicted red would have arrived twenty minutes late under a
  job named "Race Detector".

- **An access review's revocation wrote a key nothing read
  (`internal/revocation`).** When a reviewer revokes somebody's access in a
  certification campaign, governance calls `killUserSessions` to set *"the
  user-wide token-revocation marker the auth middleware checks, so a live
  session cannot keep using access an access review just revoked"*. It wrote
  `auth:user_revoked:<uid>` — a key format that came from `internal/auth`'s
  `TokenService`, whose `isUserRevoked` was **its only reader in the entire
  tree**, and which no binary reaches. The enforcement point,
  `internal/oauth`'s `IsAccessTokenRevoked`, reads a different key,
  `oauth:user_tokens_revoked_at:<uid>`. So an access review could revoke
  access, record it and audit it while the user's live session and outstanding
  access tokens kept working until they expired on their own — and the reviewer
  had no way to know, because the write succeeded. Neither half was wrong on its
  own: each was a correct implementation of a contract the other did not share,
  and the piece they shared lived in unreachable code where it looked
  authoritative. `internal/revocation` now holds one definition — the key, the
  value format, the TTL and the `iat <= cutoff` comparison — and both `/oauth/
  logout-all` and the review path go through it. The comparison is `<=`, not
  `<`, so a token minted in the same wall-clock second as the revocation does
  not survive it. Two guards: a test that writes the marker exactly as
  governance writes it and requires `IsAccessTokenRevoked` to see it, and a
  census that fails if any file outside the package spells a revocation key
  itself — restoring the old literal in `killUserSessions` makes it name the
  file and the fragment.

- **The kill switch did not revoke the elevation the product actually grants,
  and reported zero (migration v183, `internal/jitgrant`).** OpenIDX had two
  representations of a just-in-time elevation. The live one is an
  `access_requests` row — `resource_type` role/group/application, status
  `fulfilled`, `expires_at` set — that governance's approval workflow creates
  along with the assignment, and that its expiry sweep ends. The other was the
  `jit_grants` table, written only by `internal/governance/jit.go`, a service no
  binary could reach, so it has been **empty on every install ever run**. Five
  live paths aimed at it. The kill switch — the control an operator presses when
  an account is compromised — revoked `jit_grants` and published
  `pam_jit_grants_revoked`, so it left the user holding every elevated role the
  approval workflow had granted them and answered `0`, which on that response
  reads as *"this user held none"*. The lifecycle sweep's revocation of disabled
  users' elevations and deprovisioning's revocation of a leaver's did nothing at
  all. User Access 360 listed a user's active elevations (always empty) and the
  portal dashboard counted them (always 0), on two pages whose entire job is to
  say what access somebody has. All five now go through the new
  `internal/jitgrant`, which holds one definition of an active elevation and one
  way to end one — the shared revocation used to be unexported inside
  `internal/governance`, which is precisely why the other three packages each
  wrote their own SQL against the wrong table. The tests that "covered" these
  paths seeded `jit_grants` rows by hand, so they proved only that a query could
  find a row invented for it; they now seed a real elevation, and reverting the
  kill-switch fix makes `TestKillSwitch_SeversAllPillars` report
  `JITGrantsRevoked:0` with *"active jit grants remain: 1"*. One gap is recorded
  rather than closed: `handleCreateAccessRequest` accepts any duration
  `parseDuration` takes, so a "time-bound" elevation still has no ceiling.

### Removed

- **A second, unreachable SCIM 2.0 server in `internal/identity` — and the
  documentation that described it instead of the live one.** 6,114 lines across
  eleven files: full Users and Groups handlers, a SCIM schema layer, a
  member-management path, a PATCH path parser with filtered operations, a
  recursive-descent filter parser and a SQL renderer for it, and 2,257 lines of
  tests exercising all of it. `RegisterSCIMRoutes` is exported, complete and
  called by nothing: its single mention anywhere in the tree is its own doc
  comment. The product's SCIM is `internal/provisioning`, mounted by
  `cmd/provisioning-service` at the same `/scim/v2` paths and covering the same
  surface. Removing the eleven files leaves `internal/identity` building and
  vetting unchanged — nothing outside them referenced a single one of their 201
  declarations.
  The cost of the duplicate was paid by the documentation. `docs/SCIM.md`
  advertised seven filter operators (`eq`, `ne`, `co`, `sw`, `ew`, `gt`, `lt`)
  and an example composing two conditions with `and`;
  `docs/SCIM-FEATURES-LOCATION.md` printed two curl commands, one filtering
  `name.givenName sw`, both quoting values with `'`.
  The live parser implements exactly one form —
  `attribute eq "value"`, double-quoted, over a four-attribute allowlist for
  Users and two for Groups — and answers **400 `invalidFilter`** to everything
  else, deliberately, because an IdP treats a filtered lookup as an existence
  check and a silently-ignored filter would return the whole page: the IdP then
  creates a duplicate account or skips a deprovision. So six of the seven
  documented operators, the composition and three of the four printed examples
  failed against the running product. They were written against the richer
  parser — the one no binary reaches. Both documents now describe the live
  behaviour, including what is refused and why, and
  `TestEveryDocumentedSCIMFilterIsOneTheProductAccepts` extracts every
  `?filter=` expression printed in them and drives it through the parser, so a
  filter example that cannot work cannot be published again.
- **`internal/auth`'s `TokenService`, `SessionService` and `RBACMiddleware`.**
  JWT mint/validate/revoke, Redis sessions with a concurrency cap, and gin RBAC
  enforcement — 1,498 lines with four test files, each type constructed **only
  by its own tests**. The live equivalents are `internal/oauth` (tokens,
  sessions, and a per-client concurrent-session policy that is richer than the
  cap here) and each service's own auth middleware. The project readiness guide
  held `token.go`'s configurable fail-closed revocation up as a pattern to copy;
  it survives where it matters — `IsAccessTokenRevoked` returns the error and
  its callers fail closed — so what was deleted is the copy, not the pattern.
  One of these files was load-bearing in the worst way: `UserRevocationKey`
  lived in it, and governance called it, which is the defect above. The
  package's live half (`context.go`, `roles.go` and their tests) is untouched.

- **Two governance services no binary could reach, and the table one of them
  wrote (migration v182).** `internal/governance/request.go` was a 676-line
  second implementation of the access-request workflow — submit, approve, deny,
  cancel, manager resolution, notification hooks and a `StartEscalationChecker`
  that swept every org for requests past their approval SLA. It had tests, and
  two migrations existed for `request_approval_chains`, the table only it wrote.
  `NewRequestService` was called by nothing: the live workflow is
  `workflows.go`, which writes `access_request_approvals` and has never touched
  the chain table, so the escalation sweep's `INNER JOIN` matched zero rows on
  every install and would keep matching zero even if the checker were started.
  It also carried a defect that would have been a P0 the day anyone wired it: a
  failed approval-record `INSERT` was logged and skipped, and completion was
  "no approval row still pending" — so a missing row silently **reduced** the
  approvals a request needed. `internal/governance/policy.go`'s
  `PolicyEvaluator` went with it: the third OPA evaluator in the tree, after
  `internal/common/opa` (which the fail-closed middleware uses) and
  `internal/abac`. `ApprovalStep` and its constants, which the live workflow
  reads out of a policy, survive in `approval_chain.go`.

### Fixed

- **A single logout that did not log anyone out, and a returned credential the
  record still shows as held.** Two more writes whose failure was invisible to
  the caller, both on paths whose whole job is to take access away. The
  IdP-initiated SAML SLO deleted the session row in a bare `Exec` inside an
  `if org, err := ...; err == nil`, then cleared the cookie and rendered *"You
  have been logged out"* regardless of what happened: a cleared cookie is not a
  logout, it only stops **this** browser from presenting the token, so anyone
  else holding it — the shared machine the user just walked away from, a proxy
  log — kept a live session while the user was told the opposite. The delete is
  checked now, the cookie is left alone when it fails (a browser that has
  forgotten a token the server still honours is the same asymmetry, and it costs
  the user the retry), and the confirmation page is not shown. Returning a
  checked-out vault credential revoked the grant (checked) and then marked the
  request expired (`_, _ = ...`), so a failed `UPDATE` left the request reading
  `fulfilled` — still checked out to that user in the console, still counted as
  held by the JIT expiry sweep — under a `200 {"status":"returned"}` and an
  audit event saying `jit_credential.checkout_returned` / `success`. The grant
  really is gone by then, so the answer is a 500 the caller can retry rather
  than a return that did not finish, and the audit event is no longer written
  for one.

- **Offboarding a leaver could leave them everything, and report success.**
  `handleOffboardUser` is five statements — disable the account, revoke the API
  keys, remove the group memberships, remove the role assignments, terminate the
  sessions — and only the first had its error checked. The other four ran as
  bare `Exec` calls with the error discarded, and the handler then answered
  *"User offboarded successfully"*. So a leaver could be disabled while keeping
  every API key, every group, every role and every live session, and the person
  who pressed the button was told the offboarding was complete — which is the
  reason nobody would go back and look. It is one transaction now: a step that
  cannot run changes nothing and answers 500. Three more credentials that could
  not be spent but were accepted anyway: a **magic link**'s `status='used'`
  marker (a failed mark left the emailed sign-in link redeemable again, for as
  long as it had left to live), a **phone-call MFA challenge**'s completion
  marker (same shape, same code re-presentable), and the **access tokens** a
  user's *"revoke this application's access"* was supposed to delete — the
  refresh-token delete beside it was checked, this one was not, so the
  application kept calling the API while the user was told the authorization was
  revoked.

- **A certification decision recorded access as revoked while the access was
  still held.** `handleDecideAttestationItem` marked the item
  `decision='revoked'` with a statement that answers 500 on failure, and *then*
  ran the `DELETE FROM user_roles` / `user_application_assignments` /
  `group_memberships` / `vault_access_grants` that actually removes the access —
  each with its error discarded. So a reviewer clicked **Revoke**, the
  certification recorded the access as removed, the campaign counted the item as
  decided and could auto-complete on it, and the role was still assigned. In an
  identity governance product this is the worst available failure: the evidence
  says the access was removed and it was not. The read that decided *which*
  access to tear down had the same defect — a failed read left the resource type
  empty and every branch fell through, deleting nothing. The decision and the
  revocation now share one transaction, so a revocation that cannot run leaves
  the item pending and answers 500. Seven more writes that silently did not
  happen: a **logout** left both the durable revocation and the Redis marker the
  proxy actually reads (so the session kept working while the person was told
  they had signed out); **continuous verification** could not revoke a session it
  had just denied; the **PAM risk gate** tore down the live connection but could
  not mark the session suspended, so it still read as active on the dashboard;
  the **idle-timeout** revocation; an **AI-agent credential rotation** that
  minted a new key without revoking the old one and reported success; a
  **cancelled agent enrolment** whose token stayed live; and — the sharpest of
  those — the `used_at` marker that *is* the single-use property of an enrolment
  token, so a failed mark left a one-time token redeemable again.

- **A CAEP `account-disabled` event that did not disable the account was
  acknowledged as applied.** `applyCAEPEvent` discarded the error on `UPDATE
  users SET enabled=false` and returned `"applied"` regardless — so a federated
  partner reporting a compromised account got a `202`, the receiver wrote
  `outcome='applied'` to its own record, and the account stayed enabled. RFC
  8935's `202` acknowledges receipt, so the transmitter never re-delivers; the
  dedup row would have discarded the re-delivery in any case. Three more in the
  same eight lines: the **refresh-token revocation**'s error was discarded (a
  refresh token surviving a session revocation is a live credential for the
  account you were just told to shut down), a **missing organization** silently
  skipped the disable and still reported success, and **`resolveUserBySubject`**
  could not tell "this subject is not a user here" from "the lookup did not
  run", reporting both as `ignored`. An event that cannot be applied now answers
  `503` and is *not* recorded as seen, so the transmitter re-delivers. **The
  tests that covered this named a table the product does not have:** the
  fixtures created `refresh_tokens`, the code deletes from
  `oauth_refresh_tokens`, and the discarded error meant both tests passed while
  proving nothing about refresh-token revocation. The fixture is corrected and
  the assertion that was never there — that the tokens are gone — is.

- **A Security Event Token whose replay check could not run was applied
  anyway.** `handleSSFReceive` asks whether it has already seen a SET's `jti`
  for this tenant before applying it. No row is the *normal* answer there and
  arrives as `pgx.ErrNoRows`, and the read discarded its error — so "already
  seen", "never seen" and "the check did not run" were one value, and the third
  meant a re-delivered CAEP event was applied a second time. The comment on the
  *write* half of the same protection already recorded that its error had been
  discarded and was fixed; the read was left. It now tells `ErrNoRows` from a
  real failure and answers `503` when the check cannot run, because applying an
  event you cannot check for replay is the unsafe direction and a transmitter
  will re-deliver. Three more of the same shape: a **remote-support session**
  could be started while another was already running on the same agent when the
  concurrency check failed; the **posture checks a proxy route declares** were
  skipped in silence when the Ziti identity lookup failed (the score stays 0, so
  a policy requiring posture still refuses — the silence was the defect); and a
  **vault checkout ledger entry** — the record that a stored credential was used
  — went missing under a log line that named the insert rather than the reason.

- **The rest of the class: 55 more aggregate queries whose failure was served
  as a number.** `tools/zeroanswer`'s register is now **empty** — it opened at
  83, after `internal/audit` had already gone from 73 to 0, and every entry left
  it by the query being fixed rather than by being waived. The certification
  campaign page reported a campaign with nothing in it when its item counts
  failed, and drew a progress bar from `(certified+revoked)/total` where any of
  the three could be the false zero; `campaign_runs.total_items`, the permanent
  record of how big a review was, took a failed count as **zero items** — a
  certification with nothing to certify, according to its own record. An
  escalation whose "does this approver already exist" check failed added a
  **duplicate pending approval**, and that INSERT's error was discarded too, so
  neither was recorded anywhere. The authentication, usage, feature-adoption,
  capacity, AI-agent, recommendation, entitlement and sign-in analytics all
  answer 500 now instead of rendering zeros the console cannot distinguish from
  a quiet week. The remaining fail-closed checks — known device, known IP, the
  PAM quick-link existence gate — keep failing closed and now say so, because a
  control that silently degrades is a control nobody knows has degraded.

- **A failed query rendered as a calm number on every surface that counts
  something.** Twenty-four sites of the class above, found by
  `tools/zeroanswer`. The pagination totals — published apps, proxy routes,
  known devices — served `0` in the same response that carried the rows, so a
  list did not know its own length and paging past the first page looked
  impossible. The Relations & Integrity Doctor reported **`ok`** for a check it
  could not run, which is the one answer an integrity check must never give
  from no evidence. The end-user's own security page told somebody who has
  enrolled MFA that they have none, and reported no risky sign-ins because it
  could not read them. The risk dashboard's six tiles rendered *"0 high-risk
  logins, 0 failed logins, average risk 0"* — indistinguishable from a quiet
  day, on the surface where an operator decides whether to look further. And in
  the **risk engine itself**, four of the five scored factors bias *harsher*
  when their query fails (an unreadable device count reads as a new device) but
  one biases *quieter*: a failed count of recent failed logins removed the
  brute-force signal from the score entirely. Factors that cannot be measured
  are still scored from zero — inventing a number would be worse — but they are
  now logged by name, so an engine running on fewer factors than it thinks is
  visible instead of silent. This engine has already been caught running with a
  factor permanently at zero: the WebAuthn count read a table no migration
  creates, for the life of the query.

- **A failed count auto-completed an access certification campaign.**
  `handleDecideAttestationItem` counted the campaign's still-pending items to
  decide whether the last decision had been made — and discarded the error, so a
  query that could not run left the count at zero, marked the campaign
  `completed`, stamped `completed_at` and published `review.completed` to
  whatever evidence pipeline was listening. An access certification closed
  without the access being certified, with an audit trail saying it was. Two
  more in the same class: `continuous_auth`'s **velocity risk scored 0** when
  its query failed (the comment directly above it already recorded that this
  factor scored 0 for its *entire life* because it read a table that does not
  exist — the query was fixed, the discarded error that hid it was not), and
  `campaign_runs.reviewed_items`, the permanent record of how much of a
  certification campaign was reviewed before it expired, took a failed count as
  **zero reviewed** rather than leaving the column alone.

- **A compliance report could be produced entirely out of measurements nobody
  took.** Every figure in the SOC 2, ISO 27001 and GDPR reports came from an
  aggregate — `COUNT`, `SUM`, `AVG`, `MAX` — and every one of those queries
  discarded its error. An aggregate returns exactly one row, always, so a
  failed `Scan` there can never mean "there is no data": it means the query did
  not run, and the destination kept its zero. The report then published that
  zero as a measurement. *"0 overdue access reviews." "0 data-subject requests
  outstanding." "Average session length: 0 hours."* — in a document an auditor
  reads as evidence. This is not hypothetical: two queries in this file named
  columns the schema does not have (`access_reviews.due_date`,
  `sessions.created_at`), and both were found by a tool that plans the SQL, not
  by anything in the reporting code, because nothing in the reporting code was
  looking at the error. A third failure mode needed no broken query at all —
  the organization was read as `org, _ := orgctx.From(ctx)`, so a report
  generated without a tenant filtered every metric on an empty `org_id` and
  came back all zeros. Each section now runs through `metricQuery`, which
  remembers the first measurement that could not be taken and names it; a
  section that cannot be measured fails the report and the endpoint answers
  500, because a compliance report is the one document where *"I could not
  measure this"* must never be rendered as a measurement. The two grouped reads
  behind ISO 27001 A.12 are the same defect in multi-row shape — an `if err ==
  nil` around the loop meant a failed query left the per-day breakdown empty,
  which is a **logging coverage of 0%** and a `non_compliant` verdict on the
  strength of a query that never ran. **The tests that covered all this could
  not fail:** three of them built a service with no database at all, generated
  all three reports and asserted things like `TotalUsers >= 0` — true of the
  zero value, which was the only value any field ever held. They are replaced
  by one test that asserts the refusal, and by a real-schema test that
  generates all three reports against a migrated database and checks the
  numbers against seeded rows.

- **The detailed SOC 2 and ISO 27001 assessments scored controls from figures
  nobody measured** — the same defect as above, in the eleven control
  assessors behind `POST /audit/reports/soc2-detailed` and
  `.../iso27001-detailed`. Thirty-five aggregate queries, every error
  discarded, and the resulting numbers went into a control's **Evidence**
  lines (`"Total active users: 0"`, `"Active API keys: 0, Expired but not
  revoked: 0"`), its **score**, the report's overall percentage and its summary
  sentence. A control assessed from a query that did not run is
  indistinguishable, in the finished document, from one assessed from real
  data. Each assessor now returns the measurement failure and the report is
  refused. Nothing had been driving those two generators at all; a real-schema
  test now produces both and cross-checks a control's evidence against a count
  it takes from the database itself. Also fixed there: **ISO 27001 A.12
  required an event type this product has never written.** Its list of
  required audit event types was `authentication`, `authorization`,
  `user_management` — and `user_management` is a *category*; the event type
  stamped on a user lifecycle row is `identity`. So A.12 deducted ten points
  and reported *"Required event type 'user_management' has no events in
  period"* against every installation ever assessed. A control that
  manufactures a finding against a correctly configured system is worth less
  than no control. And in `internal/audit/service.go`, the four counts printed
  into the SOC 2 findings' evidence (`"%d/%d users have MFA enabled; %d failed
  auth attempts in period"`) and the security dashboard's failed-authentication
  count — which reads as *"no attack in progress"* when it is really *"the
  query broke"* — are checked as well.

- **Every audit event the access service posted was filed under the default
  organisation, and a refusal was silent.** `internal/access.logAuditEvent` is
  how the most sensitive actions in the product reach the audit trail — every
  revealed PAM credential, every injected credential, every downloaded session
  recording and transcript, every proxy allow and deny. It sent no tenant
  signal at all. The ingest endpoint (`POST /api/v1/audit/events`) is
  server-to-server and carries no JWT, and `cmd/audit-service` mounts
  `TenantResolver` globally with `router.Use`, which — as that middleware's own
  comment states — means its JWT and `X-Org-ID` steps cannot fire and every
  request lands on step 1 or the step-4 default-organisation fallback. With no
  header, always step 4: on a multi-tenant install the product's most sensitive
  reads were missing from the audit log of the tenant they belonged to and
  present in another's. The POST now carries `X-Org-Slug` — step 1, which
  *looks the slug up*, so an unknown one is a `400` rather than a free write
  into an arbitrary tenant. The response status was also thrown away: only a
  transport error produced a log line, so a `400` for a body the trail refused
  or a `500` when the write failed dropped the row with nothing recorded
  anywhere. A non-2xx is now a warning naming the status, the action and the
  tenant, because a dropped audit row is the one loss that must never be
  silent.

- **Six of the audit log's eight filter choices returned an empty list.** The
  console's event-type filter offered eight names copied from the `EventType`
  constants in `internal/audit/service.go`, and only two of them —
  `authentication` and `authorization` — are ever written. Choosing
  `user_management`, `group_management`, `role_management`, `configuration`,
  `data_access` or `system` returned nothing, and an empty audit list reads as
  *"nothing happened"*, which on this surface is the worst available wrong
  answer: an auditor asking for every configuration change was told there were
  none. Meanwhile the values the trail does hold — `identity`, `provisioning`,
  `oauth`, `access`, `security`, and the specific rows `internal/access` writes
  one at a time (`pam.session.risk_suspend`, `pam.recording.sealed`,
  `certificate.rotate`, `session.revoked.continuous_verify`,
  `platform_admin_cross_org_access`) — could not be filtered for at all. The
  filter now reads `GET /api/v1/audit/event-types`, which asks the tenant's own
  trail and returns each type with its count, ordered by frequency: what is
  offered is what is there. A catalogue would have to be kept in step with
  twenty writers by hand, and the drift it replaced is exactly what that costs.
  **Migration v180** adds the `(org_id, event_type)` index that scan and the
  filtered read both want — every read of `audit_events` is tenant-scoped
  first, so the console's own `WHERE org_id = $1 AND event_type = $2` had been
  walking every row of that type across the whole install and discarding the
  other tenants'.

- **The GDPR report's data-access section counted an event nothing writes** —
  and an earlier commit on this branch said it was fixed when it was not. All
  four of its queries filtered `event_type = 'data_access'`, a value declared as
  `EventTypeDataAccess` in `internal/audit/service.go` and written by no line of
  this codebase, so total access events, access by actor, access by data type
  and the last access timestamp were empty on every report ever generated and
  `ComplianceStatus` was permanently `"partial"` — a control telling an auditor
  this installation cannot account for who read what. The earlier fix corrected
  the by-data-type query, which asked for a `resource_type` column
  `audit_events` does not have, and the commit message said the section "has
  therefore been empty in every report". The column was **one** reason and not
  the reason. What this trail records as a read is an action under
  `event_type = 'authorization'`, and `internal/audit.DataAccessActions` now
  names the five that are one — a revealed credential, an injected credential on
  either path, a downloaded session recording or transcript — with the session
  events that are *not* reads named as deliberately excluded, because an
  overstated control is as useless as an empty one. The test that covered this
  had seeded a `data_access` row: it built the value the product never produces
  and then proved the query could find it. It now seeds the row
  `internal/access` actually writes.

- **Every switch on the notification preferences page controlled nothing.**
  The page offered seven types — `access_request`, `security_alert`,
  `session_revoked`, `review_assigned`, `group_request`, `password_expiry`,
  `mfa_change` — and this product has never sent a notification of **any** of
  them; the four it does send (`access_granted`, `device_trust`, `security`,
  `broadcast`) appeared on no switch, and one column offered a channel,
  `email`, that nothing has ever delivered on. It was worse than a naming
  mismatch: `isNotificationEnabled` is consulted by `CreateNotification`, and
  four of the six senders never went through it — the broadcast fan-out, the
  ISPM MFA reminder, the AI-recommendation reminder and the device-trust
  request all ran `INSERT INTO notifications` directly as set-based writes. A
  preference no writer reads is not a preference, however it is spelled. Each
  of those statements now carries the preference predicate itself, measured
  against a real database: the user who switched security reminders off
  receives none, the user who never opened the page receives them, because an
  absent row means enabled — the same default `isNotificationEnabled` applies.
  `internal/notifications.TypeCatalogue` is now the one place a type is named,
  `GET /notifications/preference-types` serves it, the console's picker reads
  it instead of its own stale list, and `PUT /notifications/preferences`
  refuses a preference for a type this deployment does not send. The lookup
  behind that default is no longer silent either: `isNotificationEnabled`
  answered *every* failure — a missing table, a permission error, a dead
  connection — with "enabled", so a preferences store that had stopped working
  was indistinguishable from a population that had simply never opened the
  page. A failed read still sends, because nobody should stop being told their
  device was approved by a broken query, but only `pgx.ErrNoRows` is the quiet
  default now; anything else is logged.

- **The migration chain could not be rolled back past v29.** Every migration
  carries a `Down` half and `RollbackTo` exists to run them — it is what an
  operator reaches for when an upgrade goes wrong — and nothing had ever
  executed the chain in that direction. Measured on a fresh PostgreSQL 16,
  rolling back from v179 one version at a time, it stopped at v29 with
  `DROP TABLE IF NOT EXISTS posture_check_types;` →
  **`ERROR: syntax error at or near "NOT"`**: a spelling PostgreSQL has never
  accepted (the keyword is `IF EXISTS`), in five statements across three
  migrations. Behind that, at v13 and v10, nine more statements matched a UUID
  primary key with `LIKE`, which raises
  `operator does not exist: uuid ~~ unknown`. So the rollback path was blocked
  at v29 on every install, and the twenty-nine migrations below it had never
  been reachable in reverse at all. All fourteen statements are fixed and the
  chain now completes the full round trip: 179 up, 179 down to zero, 179 up
  again. **A new test does exactly that** against a throwaway container, and
  asserts the schema left behind after a full rollback is exactly the four
  tables it should be — the migrator's two bookkeeping tables plus the two v51
  re-creates on the way down, which is recorded rather than papered over.
  `scripts/check-test-reachability.sh` was widened in the same change: it
  matched one literal variable name, so a helper gating on a private
  `OPENIDX_*_DATABASE_URL` of its own was invisible to it — the guard failing
  in the way it exists to prevent.

- **The OpenID Connect discovery document omitted three things this server
  does.** `revocation_endpoint` and `introspection_endpoint` (RFC 8414 §2) were
  absent although `POST /oauth/revoke` and `POST /oauth/introspect` are both
  routed, so a relying party that reads discovery to find where to revoke a
  token at sign-out found nowhere — and did not revoke. And
  `token_endpoint_auth_methods_supported` listed only `client_secret_post` and
  `client_secret_basic`, although dynamic client registration creates a
  **public** client when `token_endpoint_auth_method=none` and the token
  endpoint skips secret verification for that type (PKCE carries the proof
  instead): every conforming SPA and native client was told it had no usable
  authentication method here. All three are now advertised, and they move with
  the issuer under subdomain tenancy. The drift was invisible because it was on
  the wrong side of a dead file: `api/openapi/oauth-service.yaml` documented
  both endpoints, `docs/docs/api/authentication.md` showed them in its sample
  document, and `internal/oauth/discovery.go` — a **second, unmounted**
  discovery implementation with a 415-line test suite — carried them too. Only
  the document actually served lacked them. The dead implementation is deleted
  and its assertions moved onto the live handler, so a discovery test now goes
  through the route a relying party fetches.

- **Six of the webhook events the console offers had never been published.**
  The subscription form listed ten event types. `user.updated` and
  `group.updated` were emitted only from `internal/identity/handler.go` — a
  complete second user-and-group CRUD implementation, fourteen exported
  handlers, that **no router has ever mounted** — so their emitters ran
  nowhere. `user.locked`, `login.failed`, `role.updated`, `policy.violated` and
  `review.completed` were emitted by nothing at all: the failed-login path wrote
  an audit row and sent no webhook, an account lockout was logged and announced
  to no one, and a completed access-certification campaign told nobody. An
  operator wired an integration up, saw the subscription listed, saw the
  delivery log stay empty, and had no way to tell that from a quiet week. Every
  one now publishes from the handler that actually runs: `user.updated` and
  `user.deleted` from the mounted user handlers, `user.locked` on the failed
  attempt that crosses the lockout threshold (once, not on every retry after),
  `login.failed` beside the audit row, `role.updated` from the role handler,
  `policy.violated` when the ABAC gate denies a sign-in, `review.completed` when
  an attestation campaign's last item is decided — and the four group events
  that had no publisher and no constant, `group.created`, `group.deleted`,
  `group.member_added` and `group.member_removed`, the last being the event a
  downstream system needs in order to **revoke** the access that came with a
  group. Publishes are now made on a context detached from the request but
  carrying its organization (`orgctx.Detached`): webhook subscriptions are
  RLS-scoped, so an org-less publish matches nothing and delivers nothing,
  quietly, for every tenant. `internal/identity/handler.go` is deleted.

- **Revoking a user's MFA break-glass codes has never revoked one.**
  `DELETE /users/:id/bypass-codes` is how an administrator destroys every MFA
  bypass code a user holds — what you do the minute a break-glass code leaks.
  Its handler opened `requestedUserID := c.Param("user_id")`, and the route
  declares `:id`. gin returns `""` for a name the matched route does not
  declare, so the revoke ran against the empty user and PostgreSQL refused the
  statement outright (`mfa_bypass_codes.user_id` is `UUID`): every call this
  endpoint has ever received answered **400 `invalid input syntax for type
  uuid: ""`**, worded as though the administrator had sent something wrong. The
  handler now reads `c.Param("id")`, and a new DB-backed test drives the real
  route: two active codes for the target are revoked, a third belonging to
  somebody else is left alone, and the `revoked_all` entry lands in
  `mfa_bypass_audit`. Proved red first with exactly the failure above.

### Added

- **`tools/sqlprepare` no longer skips `42P08`.** "Inconsistent types deduced
  for parameter" was on the skip list beside `42P18`, described as a limit of
  `PREPARE`. It is not one: pgx sends parameters **untyped**, so the deduction
  the sweep performs is the deduction the runtime performs, and a statement
  that cannot settle on one type for a parameter fails when it is executed. The
  skip hid a live failure — an `INSERT ... SELECT` written in this same change,
  reusing one parameter for `notifications.type` and
  `notification_preferences.event_type`, passed the sweep and raised
  `inconsistent types deduced for parameter $5` on its first execution against
  a real database. Five statements were caught and cast the moment the skip was
  removed; `42P18`, where the server genuinely has nothing to deduce from,
  stays a skip.

- **A webhook event catalogue that cannot drift from the code.**
  `internal/webhooks.EventCatalogue` is now the single place an event type is
  named — type, category, and the sentence an operator reads when choosing what
  to subscribe to — and `catalogue_test.go` holds it against the tree in **both
  directions**: an entry nothing publishes fails the build, and a `Publish`
  naming something outside the catalogue fails it too. The census resolves
  literals, `webhooks.EventX` constants, a variable assigned two constants, and
  one level of forwarding (a helper that takes the event type as a parameter is
  resolved at its call sites), and a `Publish` whose event type it cannot read
  is itself a failure in the services that own a publisher — so nothing can hide
  behind an expression. `GET /api/v1/webhooks/event-types` serves the catalogue
  and the console's picker now reads it instead of a hard-coded list that had
  drifted six entries away from reality; `POST /api/v1/webhooks` rejects a
  subscription to an event type this deployment does not publish, with the
  endpoint to consult, because the moment a subscription is created is the only
  moment an operator can be told.

- **`tools/routereach` — parameters with no route, handlers with no router.**
  The census that found the defect above, and a second class beside it. It
  holds each service's route table next to the handlers its package defines and
  reports two disagreements: a handler that reads `c.Param("x")` when no route
  it is mounted on declares `x`, and a `func(*gin.Context)` that no route
  registration names and no non-test line references. Reachability is
  propagated to a fixpoint through same-package calls, so a helper handed the
  request context is checked against the routes of every handler that can reach
  it, and the parameter sets of a handler's routes are unioned rather than
  checked one at a time. The parameter check is exact here because no `.Group()`
  prefix in this tree declares a parameter — asserted against the real sources
  by the tool's own test, not assumed. **`_test.go` files are deliberately not
  scanned**: a handler whose only caller is a test that mounts it on a router
  the test built is the sharpest form of the second finding, and that is how
  `internal/oauth`'s second OpenID Connect discovery document came to light —
  415 lines of passing test for a document no service serves, beside the
  different one every relying party actually fetches. 1,060 routes, 1,021
  handler-shaped functions, **17 mounted by nothing**, each registered in
  `tools/routereach/known.go` with its verdict; a route that declares
  parameters and resolves to no handler is itself a finding, because a census
  that quietly stops covering something is the failure these registers exist to
  prevent. Wired as a required check (`Route-reachability lint`).

- **`tools/tablewriters` — the tables the product reads and nothing writes.**
  The API-usage card reads `api_usage_metrics` for total requests, average
  latency and error rate; migration v54 created that table with exactly the
  columns an hourly request aggregate needs, and nothing has ever inserted a
  row into it. So the card has reported three zeros on every install that has
  ever run, and a zero from an empty table is indistinguishable from a measured
  zero. Nothing else in the repository can see this: the SQL is valid, so
  `sqlprepare` passes it; the tenant predicate is present, so `orgscope` passes
  it; the handler returns 200 with a well-formed body, so the contract test
  passes it; and `COUNT(*)` of an empty table is 0, not an error, so nothing is
  logged. The only thing that can see it is a census, so this one holds the set
  of tables the migration registry creates next to the set of tables a SQL
  literal in `./internal`, `./cmd` and `./pkg` writes, and subtracts. Both
  halves are derived rather than listed, for the reason `orgscope` was
  inverted. Literals come out of the AST rather than a grep, because prose
  about SQL is not SQL — a comment quoting a query a previous fix deleted was
  read by the first draft as a live read of a table dropped two migrations ago.
  A table a migration seeds is not a finding: the seed is its writer. **Nine of
  226 live tables have no writer**, each registered in
  `tools/tablewriters/known.go` with its verdict, and the register can only
  shrink: an unregistered finding fails the run and so does an entry that no
  longer reproduces. Five are read — `api_usage_metrics`, `risk_factors` (the
  continuous-auth engine computes five weighted factors and returns the empty
  slice it started with), `ai_agent_activity` (three reads: a per-agent
  activity list, a 24-hour ranking and a failure count, all empty because
  nothing outside the admin API so much as reads an agent credential, so no
  agent has ever acted), and `upstream_pools` with its members (v130 built the
  place to express a load-balanced backend set and the reconciler that renders
  it; nothing can create one). Four are dead schema: `health_check_history`,
  `posture_check_types`, `scim_groups` — the unused half of v3's SCIM pair,
  whose install-wide unique key an earlier commit in this programme carefully
  re-scoped — and `user_mfa_policies`.

- **`tools/sqlprepare` — every SQL literal in the tree, planned by a real
  PostgreSQL.** A green CI run's database log carried `column "request_count"
  does not exist`, and following it found a class no reviewer or compiler can
  catch: a query naming a column that has never existed is syntactically
  perfect Go and SQL, and the handler around it discards the error. The tool
  hands each statement to `PREPARE` against a database with all migrations
  applied — parse, name resolution and planning, no execution and no rows — so
  a missing column, a missing table, an unresolvable type or an aggregate
  outside its `GROUP BY` surfaces and nothing else does. Syntax errors are
  skipped as fragments of runtime-assembled queries and parameter-inference
  errors as limits of `PREPARE` itself; a file the sweep cannot parse fails the
  run rather than quietly shrinking the count. It runs in the integration job,
  the only place with a migrated database. The first sweep found **39
  statements that cannot succeed against the schema this repo creates**, each
  registered in `tools/sqlprepare/known.go` with its verdict; a finding the
  register does not carry fails the run, and so does an entry that no longer
  reproduces, so the list can only shrink. Among them: no security alert has
  ever been written (`security_alerts` has none of the six columns the INSERT
  names), the SIEM forwarder's cursor table is created by no migration,
  scheduled-report listing fails outright, the DSAR export silently omits
  sections, two compliance controls report zero findings because api-key
  revocation lives in `status` and not a `revoked_at` column, and the API-usage
  dashboard's four queries all name columns that were never created — so it
  reports 0 requests, 0 errors and 0 ms latency as measurements.

### Removed

- **Four tables no code has ever touched (migration v177).** The other half of
  what the census found: `health_check_history` (v54), `posture_check_types`
  (v29), `scim_groups` (v3) and `user_mfa_policies` (v5) are read by nothing and
  written by nothing, and between them carry DDL, indexes, grants, foreign keys,
  row-level-security policies and a docker seed that maintains five rows nobody
  consults. `scim_groups` is the unused half of its SCIM pair — `scim_users` is
  written on every SCIM user operation, group provisioning writes the product's
  own `groups` table — and an earlier commit in this programme carefully
  re-scoped its install-wide unique key, which is what dead schema costs: it
  consumes the attention the real tables need. Two of the four sat behind the
  v37 FORCE-RLS belt, which is the argument for dropping rather than leaving:
  a belted table with no rows looks, to every census here, like a tenant
  boundary being maintained. The rollback recreates all four in the shape the
  chain had produced — org_id, foreign key, index, policy and the re-scoped
  unique key included — read off a database with the full chain applied.

- **The Usage Analytics API card, and the table behind it (migration v176).**
  `api_usage_metrics` was created by v54 with exactly the columns an hourly
  request aggregate needs, and no handler, worker or seed has ever inserted a
  row. The card read it for total requests, top endpoints, error rate and
  average latency, so all four have been 0 on every install that has ever run —
  and the read could not have worked either, naming three columns the table does
  not have. Request volume, latency and status codes *are* measured: the
  Prometheus middleware every service mounts exports them on `/metrics`, for the
  Prometheus and Grafana this repo ships. A second copy aggregated into Postgres
  was never written, and writing that aggregator is a feature rather than a fix,
  so the endpoint, the console card, its i18n keys and the OpenAPI path go with
  the table.

### Fixed

- **The SQL register is empty: every statement in the tree now plans against
  the schema.** The last four. `oauth_clients.redirect_uris` is JSONB and the
  BrowZer domain rewrite called `unnest()` on it, so after a domain change every
  OAuth client kept redirecting to the old domain — the exact failure a domain
  change exists to prevent. The bulk-access anomaly's "breakdown by resource
  type" asked `audit_events` for a `resource_type` column (it is `target_type`)
  and discarded the error, so every anomaly this detector raised named nothing.
  Migration **v179** gives `saml_service_providers` the `metadata_xml` column
  its refresh has always written to: without it the whole UPDATE failed to plan,
  and with it the only path by which a service provider's **rotated signing
  certificate** reaches this database — an administrator clicked refresh, got an
  error, and assertions kept being signed against the old certificate. The
  fourth was another false positive of the tool, now fixed there: the
  access-review roll-up's literal is the first half of a query the code appends
  a `GROUP BY` to, and `sqlprepare` prepared it alone and reported a grouping
  error for a query that groups correctly at runtime. It now recognises a
  literal the code appends to and skips only the errors a suffix can explain — a
  missing column or table on such a fragment is still a finding.

- **The console's tenant switcher has never worked, and nine other statements
  the database refused.** `handleSwitchTenant` and `handleGetCurrentTenant`
  selected `display_name` and `enabled` from `organizations`, which is
  `(id, name, slug, domain, plan, status, …)` and has neither; both handlers map
  any error from that row to 404, so switching tenant answered "Organization not
  found" for every organization that exists — a feature that reads to whoever
  hits it as a permissions problem. A **joiner rule that granted nothing**: the
  lifecycle `assign_role` action inserted into `user_roles` with a `created_at`
  column (the table records `assigned_at`), so no automated rule has ever
  assigned a role, on any install. **Zero dormant accounts** on the security
  posture card, because the count asked for `users.last_login` and the column is
  `last_login_at` — zero is the answer that makes the card look best. A
  **biometric policy targeted at a role matched nobody**, because the role
  lookup selected a `roles` column from `users` (roles are rows in `user_roles`).
  Plus the top-failed-users list (uuid into a varchar `COALESCE`), the push-MFA
  enrolment label (one parameter used as both text and uuid), the API-key
  adoption figure (`revoked_at` again), the churn-prediction input, and the risk
  profile's average session duration (`sessions.created_at` → `started_at`).
  Each was found by `tools/sqlprepare`; the tenant switch and the lifecycle
  action are covered by new tests that run the real migration chain, both proved
  red first. One register entry went the other way and is **withdrawn**: the
  unified-audit reader's SELECT list, which the code uses as the search argument
  of a `strings.Replace` that swaps it for `COUNT(*)`, was prepared as though it
  were a statement and written up with a verdict that was true of nothing.
  Measured since: the replacement fires and the count query it builds is valid.
  `sqlprepare` now skips a "missing FROM-clause entry" on a literal that has no
  FROM clause — a SELECT list is not a statement — while a missing *table*,
  which always comes from a statement that has the FROM clause naming it, stays
  a finding.

- **Four compliance controls that reported compliant because their queries
  could not run.** Six statements across the SOC 2 / ISO 27001 / GDPR reporting
  named columns the schema does not have, and each failed silently into a zero.
  `access_reviews.due_date` (the deadline is `end_date`) — the overdue-review
  count read 0 on every report ever generated, so the dashboard stated that no
  access review was overdue. `sessions.created_at` (it is `started_at`), twice —
  average session length always 0 hours, so the "sessions run too long" control
  never fired. `audit_events.resource_type` (it is `target_type`) — the GDPR
  report's access-by-data-type section was empty in every report.
  `api_keys.revoked_at` (revocation is `status`), in **both** halves of the
  expired-key control — an install with expired keys still being accepted
  reported zero findings and lost no points. A control that cannot fail is not a
  control, and zero findings reads to an auditor as evidence. Migration v178
  retires v10's seeded "Q1 2026 Access Review" fixture where it is untouched:
  with the overdue query corrected, that pending row dated March would otherwise
  give every install a permanent overdue finding no operator created and none
  could close. Pinned by a new suite that runs the real migration chain rather
  than creating its own tables — the sibling DB tests in that package define the
  columns they then assert on, which is part of why these six survived.

- **The right to erasure had never run, and the data package always omitted
  four sections.** Both halves of the GDPR subject-rights implementation were
  broken in the same way, and neither could be seen from outside. *Erasure
  (Article 17):* the statement that anonymises the user row set `phone_number`
  and `avatar_url`, neither of which exists on `users`, so it failed with
  SQLSTATE 42703 — and being the **first** statement, its error was returned
  before a single session, MFA enrolment or consent was wiped. No erasure
  request has ever run to completion on any install. *Export (Article 15):* four
  of the twelve categories named columns the schema does not have —
  `audit_events.resource_type` (it is `target_type`), `mfa_totp.verified_at`
  (`enrolled_at`), `mfa_webauthn.friendly_name` (`name`),
  `mfa_push_devices.device_type` (`platform`/`device_name`/`device_model`) — and
  each failure was logged at Debug and the section left out, while the result
  reported `categories: 8` as though eight were all there were. The subject's
  own activity log and all three MFA enrolment records were missing from every
  data package this product has produced. Both are fixed against the real
  schema, and both now say when they cannot do what they claim: a category that
  fails is named in the bundle under `_incomplete` and counted in the response,
  and a failed erasure statement returns an error instead of marking the request
  completed. The erasure also now wipes the tables that actually hold a phone
  number (`mfa_sms`, `mfa_phone_call`, `phone_call_challenges`) and the device
  records (`known_devices`, `trusted_browsers`) — the "no leftover phone numbers
  / device IDs" its own comment has always promised — and the export gained
  those four as categories. Driven end to end by a new test against a migrated
  database, proved red first on both halves.

- **A risk score with nothing behind it.** The continuous-auth engine computes
  five weighted factors — session age, source-address change, device
  fingerprint, out-of-hours activity, action velocity — sums them into a 0-100
  score, and returned `RiskFactors` exactly as empty as it was initialised, on
  every response, while writing the literal `{}` into
  `session_risks.risk_factors`, the column that exists for that detail. A score
  of 45 that cannot say which factor produced it is not evidence for the step-up
  it triggers. Each factor is now recorded as it is measured — type, raw points,
  the deployment's weight, the weighted share of the scale, and a sentence
  saying what was measured — and travels with the score, in the response and in
  the history row under a `source` discriminator so the column's two writers can
  be told apart. The v77 `risk_factors` table it should have been written to is
  dropped by v176: nothing ever wrote it, its only reader had no caller, and the
  one test that exercised that reader seeded the rows itself. The replacement
  test drives the whole path, from a measurable condition to the factor list on
  the score and in the stored row.

- **The SQL gate added in this release could not fail the build.** ci.yml's
  integration step opens `set -uo pipefail` — no `-e` — so a bare failing
  command does not stop the script and the step's exit code is whatever the
  LAST command returned. Measured: `bash -c 'set -uo pipefail; false; echo
  reached; true'` prints `reached` and exits 0. `go run ./tools/sqlprepare
  -fail` was added as a bare command, so it would have printed its findings into
  a green job — the defect this branch keeps finding, written into the file
  whose job is checking. It and `go run ./cmd/migrate up` now say `exit 1`
  themselves, the four service builds in the same block are guarded (an
  unbuilt service surfaced sixty seconds later as "services did not become
  ready", naming the wrong cause), and
  `scripts/check-run-blocks-can-fail.sh` keeps the next one honest: in a
  block that sets shell options without `-e`, a gating command must be
  guarded unless it is the last command, whose status *is* the step's. Eight
  self-test cases, five of them negatives (`|| true`, a `-e` block, no `set`
  line, the last command, non-gating commands).

- **The SIEM forwarder created its own cursor table, as a role that cannot
  create tables.** `internal/audit/siem_forwarder.go` opened with
  `CREATE TABLE IF NOT EXISTS siem_forward_cursor` executed through the service
  pool, which connects as `openidx_app` — the runtime role v53 created without
  DDL rights. Measured against a fully migrated database:
  `has_schema_privilege('openidx_app','public','CREATE')` is false. So the
  statement always returned "permission denied for schema public" and every
  poll after it failed on a missing relation: audit events have never reached a
  SIEM on any install that uses the app role, which is every deployment this
  repo ships. The least-privilege work and this forwarder were each correct
  alone and were never read together. Migration **v175** creates the cursor and
  grants the forwarder exactly SELECT, INSERT and UPDATE on it; the runtime DDL
  is replaced by a read that says once which migration is missing.

- **Listing scheduled reports failed outright**, and silently: `recipients` is
  `TEXT[]` and the query COALESCEd it with the JSON literal `'[]'`, which
  PostgreSQL rejects while planning, while the error path answers an empty slice
  and a nil error — so the page was empty rather than broken.

- **No access request had ever been auto-approved.** `access_requests.
  resource_id` is a UUID and the lookup COALESCEd it with `''`, resolved at plan
  time, so the query errored on every call.

- **No security alert had ever been written, on any install.**
  `internal/risk/alert.go` INSERTs twenty-one columns into `security_alerts`
  and six of them do not exist — `tenant_id`, `ip_address`, `user_agent`,
  `deliveries`, `acknowledged_by`, `acknowledged_at` — so the statement has
  never executed since it was written. The single-alert read, the list and the
  acknowledge path named the same absent columns, so the alerts page would have
  been empty even if a row had arrived some other way, and the failure surfaced
  only as an error the caller logged. Two of the six were a naming
  disagreement: `tenant_id` is `org_id`, which the same statement already set
  (the file's own comment claimed the table "carries both", which was never
  true of the schema), and `ip_address` is `source_ip` — a caller that filled
  only `IPAddress` would have written an empty address even once the statement
  ran. Migration **v174** adds the other four, which are real fields with
  nowhere to go, plus an index for the list the page issues. The second writer
  needed no columns at all: `internal/audit/anomaly.go` INSERTed `type`,
  `event_id`, `actor_id`, `timestamp` and `metadata` — the audit-events
  vocabulary applied to this table — and every one maps onto a column that was
  already there, so a detected anomaly now raises an alert instead of logging
  that it could not. Found by `tools/sqlprepare`; the register is down from 39
  to 34.

- **The agent module was scanned for vulnerabilities against the wrong Go
  standard library, and it was the toolchain-pin change that did it.**
  `go-version-file` reads go.mod's `go` directive, not its `toolchain`
  directive, so pointing every `setup-go` step at the root go.mod installed Go
  1.26.0 rather than the pinned 1.26.8. The root scan was unaffected — the
  `toolchain` line makes the go command re-exec 1.26.8 — but Go only ever
  switches *up*, so the agent, pinned to 1.25, kept the installed 1.26.0 and
  govulncheck reported the 19 advisories that release carries and 1.26.1 fixes,
  two of them reachable from the agent's own SSO path. Before the pin change
  the loose `'1.26'` spec happened to resolve to the runner's cached 1.26.7,
  which is the only reason this was ever green. The agent scan now gets its own
  `setup-go` reading `agent/go.mod`, and
  `scripts/check-go-toolchain-pin.sh` gained two rules: a `go-version-file`
  must name a file that exists, and a step running in another module must be
  preceded by a `setup-go` for that module's go.mod. Eleven self-test cases,
  and the guard was shown red against the real workflow with the new step
  removed.

- **ABAC evaluation failed on every request, which under
  `ABAC_ENFORCE=enforce` denies everything.** `abac_policies.resource_id` is a
  UUID column and the policy query compared it to the empty string; PostgreSQL
  resolves that at plan time, so the statement never ran, the error became
  `Allowed: false`, and the evaluator answered "policy evaluation error,
  failing closed" for every call — in observe mode recording a would-deny on
  every request, and in enforce mode denying them. Found by `tools/sqlprepare`
  on its first sweep.

- **The trusted-proxy hardening resolved every client to the proxy's own
  address in the deployments this repo ships.** `ConfigureTrustedProxies` trusts
  loopback only, on the stated premise that "every service sits behind the edge
  and is reached over loopback". Neither reference deployment is: in
  `deployments/docker` the TLS proxy forwards with
  `proxy_pass http://oauth-service:8006` and the gateway proxies container to
  container, and under Helm an ingress pod forwards to a service pod — and
  `OIDX_TRUSTED_PROXIES` was set in no compose file, no chart value and no
  `.env.example`. gin walks `X-Forwarded-For` right to left and stops at the
  first untrusted address, so the edge's correctly written header was discarded
  whole and `c.ClientIP()` returned the hop. Everything keyed on the client IP
  therefore shared one value: the per-IP rate-limit bucket (including the
  tighter auth-path budget that exists to slow a brute force, since pre-auth
  requests have no user to key on), audit record IPs, known-IP device-trust
  auto-approval and geo rules. The default stays loopback — widening it would
  trust a forwarded header on installs whose services are directly reachable —
  but the mismatch is no longer silent: a request arriving from an untrusted hop
  with a forwarded header is logged once per hop, with the address to add, and
  counted in `openidx_forwarded_for_from_untrusted_hop_total` (alert
  `ForwardedClientIPDiscarded`). The detector is mounted from inside
  `ConfigureTrustedProxies`, so there is one call site to get right rather than
  eight. `OIDX_TRUSTED_PROXIES` is now passed through by the compose file,
  exposed as the chart's `config.trustedProxies`, and documented in
  `.env.example`. Existing installs behind a non-loopback edge should set it;
  the warning names the address.

- **Every CI job downloaded a Go toolchain it did not need, and one of those
  downloads failed the build.** `go.mod` pins `toolchain go1.26.8`; `ci.yml`
  asked `actions/setup-go` for `'1.26'`. The runner's tool cache holds 1.26.7,
  so setup-go reported "Successfully set up Go version 1.26" and the next `go`
  command fetched go1.26.8 from `proxy.golang.org` — roughly 70 MB, per job,
  unretried, on every run. Twelve jobs did this. On 2026-09-06 one of those TLS
  handshakes timed out and failed `Unit Tests (internal/notifications)` before a
  single test body ran, which reads as a test failure and was a CDN blip on a
  download that should not have happened. Every setup-go step now passes
  `go-version-file: go.mod`, so the pin lives in one place and the exact
  toolchain is installed directly. `scripts/check-go-toolchain-pin.sh`
  (self-tested, wired into the `ci-resilience-guards` job) fails on a version
  spec, including an exact one — two pins drift. The build matrix keeps its
  minor-version label because that string is part of a check name branch
  protection may require.

- **The gateway — the service that faces the internet — sent no security
  headers.** Seven of the eight HTTP service mains mount
  `middleware.SecurityHeadersForEnv`; `cmd/gateway-service` did not, and nothing
  in `internal/gateway` set one either. So the one host a browser actually talks
  to answered with no HSTS, no `X-Content-Type-Options: nosniff`, no
  `X-Frame-Options`, no `Referrer-Policy` and no CSP on everything it produces
  itself: `/metrics`, the combined OpenAPI spec, and every 404, 429 and 502 the
  proxy generates. Proxied responses carry the backend's headers, so the gap was
  the gateway's own. Verified against the real binary both ways — before the fix
  a gateway-generated 502 carried none of them, after it carries all six.
  Duplicate CSP on proxied responses is harmless and the code says why: the
  gateway forwards only the six `/api/v1` JSON groups, browsers enforce the
  intersection of repeated policies, and the Guacamole path overrides do not
  apply because those prefixes are not proxied here.
  The omission was invisible because seven services looked like the rule, so the
  list is now DERIVED: `TestEveryHTTPServiceMountsSecurityHeaders` finds every
  `cmd/` main that builds a gin engine and fails unless it mounts the headers or
  is declared exempt with a reason. `scripts/smoke-test.sh` asserts the same
  thing against the running gateway, because "mounted in main.go" and "on the
  wire" are two different claims.

- **The gateway's request-body logger truncated the request it was observing.**
  `internal/gateway/middleware/logging.go` read the body through an
  `io.LimitReader` and then handed the *truncated* bytes back to the handler, so
  turning on `LogRequestBody` would have silently cut every request over
  `MaxBodySize` before the code that had to act on it ever saw it — a logging
  option corrupting its own subject. It now reads the body in full, restores it
  in full, and applies the limit to what is *logged*. The body also went into
  the log verbatim on a path that carries passwords and authorization codes; it
  goes through `logsafe.JSONBody` now.

- **`logsafe.JSONBody` parsed an unbounded body.** Moving redaction ahead of
  truncation (see the entry below) meant the parser saw the whole body rather
  than the first 10 KB, and decoding into an `interface{}` tree costs several
  times the input. Input over 64 KiB is now reported by size and not parsed.
  Depth needed no separate bound: `encoding/json` refuses beyond 10,000 levels
  of nesting, which bounds the recursion before it starts. Raised by a Semgrep
  finding whose named CWE (502, unsafe deserialization) does not apply to Go's
  `encoding/json` — but the concern underneath it did.

- **The OAuth authorization code was written to the log in clear, on every
  callback, by every service.** Three request loggers exist in this tree. The one
  in `internal/common/middleware` has redacted query parameters for its whole
  life and is mounted by nothing; the gateway's is mounted by nothing either. The
  one every service actually mounts -- `internal/common/logger.GinMiddleware`,
  used by `cmd/{identity,oauth,access,admin-api,audit,governance,provisioning,
  gateway}-service` -- logged `c.Request.URL.RawQuery` verbatim. Five callback
  routes read `code` from the query string (`internal/oauth/social_login.go`,
  `social_link.go`, `service.go`; `internal/access/service.go`, `multi_idp.go`),
  `internal/oauth/handlers_passwordless.go` reads the magic-link `token`, and two
  routes read `session_token`; all of them went into the log unredacted. The
  panic-recovery handler (`internal/middleware/recovery.go`) did the same, on the
  entry most likely to be forwarded to an error tracker. A control that exists
  only in the copy nobody runs is not a control.
  The redaction now lives once, in `internal/common/logsafe`, and all three
  loggers plus the recovery handler use it. A guard
  (`TestNoLoggerWritesARawQueryString`) fails on any raw query string reaching a
  log field, so which copy is mounted stops mattering.

- **The redaction itself missed the values worth redacting, and had a
  one-character bypass.** The list named secrets from memory: `access_token` and
  `refresh_token` were there, `id_token_hint` was not; `token` was there,
  `session_token` was not; `code`, `state`, `nonce`, `user_code`, `SAMLRequest`
  and `RelayState` were absent entirely. And the parameter name was matched
  BEFORE URL-decoding while the handler decodes, so the two disagreed about what
  a parameter was called: `?%74oken=hunter2` was read by the handler as
  `token=hunter2` and logged as `%74oken=hunter2`, in clear (measured). Names are
  now matched decoded, an undecodable name is redacted rather than trusted, and
  the exact list is only half the rule -- the other half matches by WORD, so
  `session_token`, `backup_code` and `provisioning_key` redact without anybody
  listing them. A census guard
  (`internal/common/middleware/query_param_census_test.go`) derives every query
  parameter the tree reads and requires each to be classified: redacted, or
  declared public with a reason. Ninety-four are classified today; a
  ninety-fifth cannot arrive unclassified.

- **`sanitizeJSON` failed open in three ways at once.** Its five "pattern
  variations" were three byte-identical duplicates plus one with a space, so
  `"password" : "x"` was missed; it redacted only the first occurrence of each
  pattern, so a second password survived; and it matched only a quoted string
  value, so a numeric pin, an array of recovery codes and a nested
  `{"credentials":{...}}` object went through whole. `LogBody` is off by default
  and no service sets it, so this never reached a real log -- it was a trap armed
  for whoever turned the flag on to debug something. It now parses the body and
  redacts by field name at any depth, in any container; a body that is not JSON
  is withheld with its size reported rather than guessed at. Related: sanitising
  ran AFTER the 10 KB truncation, and truncated JSON does not parse, so with the
  new implementation every large body would have been discarded whole. Redact
  first, cut second.

- **The correlation id every log line is stamped with was chosen by the
  client.** Seven places read `X-Request-ID`, `X-Correlation-ID` or
  `traceparent` off the request and adopted whatever arrived -- three
  `RequestID` middlewares (`internal/middleware/requestid.go` twice,
  `internal/common/middleware/logging.go`,
  `internal/common/middleware/middleware.go`), the gateway's correlation
  middleware and its `GetCorrelationID` fallback, and `TracingHeaders`, which
  relays them to the backend. That value is echoed back in the response, kept on
  the request context, written into every log entry for the request, and set on
  the outbound request to each service: a caller sending five kilobytes of "A"
  got five kilobytes back and five kilobytes per entry (measured, not
  hypothesised), and could equally pick an id that collides with somebody else's
  request. An inbound value is now adopted only when it is id-shaped --
  `logsafe.PlausibleID`, which accepts a UUID, a W3C traceparent and a vendor
  scheme, and rejects anything longer than 128 bytes or outside
  `[A-Za-z0-9-_.:]` -- and is replaced with a fresh UUID otherwise. Replaced,
  not cleaned: an id quietly rewritten still ties one request's entries together
  but no longer matches what the caller kept, which is the only job it has. One
  implementation now, and a guard (`TestCorrelationHeadersAreValidatedWhereThey
  AreRead`) that fails on an eighth copy -- the same lesson `logsafe` itself was
  created for, one level up.

- **`logsafe`'s own comment named the wrong mechanism.** It said zap's console
  encoder writes a newline raw where the JSON encoder escapes it, so a hostile
  value in a FIELD could forge a log line. Measured, that is backwards: the
  console encoder delegates fields to a JSON encoder, so a newline comes out as
  `\n` and an ANSI escape as `\u001b` under both. The half that is raw is the
  MESSAGE, so the forging shape is `logger.Warn(fmt.Sprintf("... %s", input))`,
  which the comment did not mention. Naming the wrong mechanism is worse than
  naming none -- it invites "just use the JSON encoder", which fixes nothing.
  The comment now says what was measured, `encoder_test.go` measures it (so the
  claim fails a build rather than ageing), and the reasons a field still needs
  cleaning are stated as what they are: the length bound no encoder applies, the
  sinks downstream of zap that do their own escaping or none, and the fact that
  a percent-encoded `%0A` in a request target really does arrive in
  `URL.Path` as a newline. A new guard forbids the interpolated-message shape
  outright; the tree had two (`internal/server/graceful.go`), now zero.

- **Request-derived values reached the log unfiltered across
  `internal/common/middleware`.** CodeQL flagged one site -- the cross-org
  warning added earlier on this branch (`tenant_resolver.go`) -- and the same
  shape was in eight more: the CSRF middleware's `origin`/`referer`/`path`, the
  request logger's `path`/`method`/`client_ip`/`user_agent`/`query_params`, the
  OPA middleware's `path`/`method`, the rate limiter's `key` (which embeds the
  client IP) and `path`, and `internal/common/logger`'s second request logger.
  All now go through `logsafe.String`. `request_body` deliberately does not: it
  is a payload rather than an identifier, `logsafe.MaxLen` would cut it to 256
  bytes and defeat the option somebody turned on, and it is already bounded at
  10 KB -- said in the code rather than left for a reader to wonder about.

- **The mandatory cross-org audit trail had never been written by a test, and
  could not have been where it was aimed.** `TestCrossOrgIsolation`'s
  platform-admin subtest skipped on every run of its life -- "admin is not a
  platform admin in this environment" -- so `audit.CrossOrgAuditor`, the row
  that makes a platform admin crossing a tenant boundary accountable, was
  asserted nowhere. That code is the kind that fails silently: a failed insert
  is logged and the request succeeds anyway, so a broken trail looks exactly
  like a working one. Chasing the skip found why it could never have passed:
  `TenantResolver` is mounted **before** route-level auth on identity-service
  and five other services, so at resolution time the context carries no roles,
  `SuperAdminPredicate` is false for every caller, and steps 2 and 3 of the
  resolver's documented precedence are unreachable there. `admin-api` mounts it
  on `/api/v1` after auth and is the one service where the control is live. The
  suite now proves both halves where they are true: X-Org-ID is inert on a
  service that resolves before auth; on admin-api a `super_admin` crosses and
  the audit row lands under the **target** org, a plain admin does not cross and
  no row is written, and the RLS bypass the insert depends on is shown
  load-bearing on a NOSUPERUSER connection (CI connects as a superuser, where
  RLS is ignored and the bypass would look unnecessary). admin-api now starts in
  the integration job alongside the other three. No migration seeds a
  `super_admin` role -- v134 grants a permission to one and matches nothing --
  so the fixture creates and removes it.

- **Nine tests that ran no code at all.** Seven in `internal/directory` over
  the directory authentication router, one named after a function it never
  called, one that read fields off a zero value it had built itself. Each was
  the shape `_ = service.AuthenticateUser` -- a method VALUE assigned to the
  blank identifier, which is not a call: the function under test never ran, and
  the only thing established (that the method exists) the compiler already
  guaranteed. The directory ones carried the comment "Without a real DB, we
  test the method signature exists" in a package that has had a testcontainers
  harness the whole time. `scripts/check-inert-tests.sh` could not see any of
  them -- it looks for an unconditional `t.Skip`, and these do not skip; they
  run and report a tick. New `tools/inerttests` (go/ast, so a method value and
  a method call are told apart exactly) fails the build on the shape, with an
  8-case self-test whose negative cases are the legitimate look-alikes it must
  not touch: a call assigned to `_`, a compile-time interface assertion, a real
  test that discards one result. All nine replaced with tests that run the
  code: the directory router's refusals (an Entra directory must not hand a
  password to the LDAP connector; an unknown type must not fall through to it;
  a disabled or other-tenant directory authenticates nobody), the sync-log
  reads' tenant scoping, `ListenAndServe` actually serving and releasing its
  port, and the org-lookup adapter narrowing a twelve-field `Organization` to
  the two-field value it puts on every request's context.

- **A second tenant could not name a role, a service account or a SCIM group
  the way the first one had.** `roles.name`, `service_accounts.name` and
  `scim_groups.display_name` were UNIQUE across the whole install while the rows
  were per-tenant: all three tables already carry `org_id NOT NULL` and FORCE
  ROW LEVEL SECURITY, and every query that reads them by name already names the
  organization. Only the key disagreed, and what it cost is a refusal rather
  than a leak -- the second organization to want a role called `developer` is
  told `duplicate key value violates unique constraint "roles_name_key"` about a
  row its own queries can never see. `developer` is not a corner case: the seed
  creates `admin`, `manager`, `user`, `auditor` and `developer` for the default
  organization on every install, so the five most ordinary role names are taken
  before the second tenant arrives, and a SCIM group named `Engineering`
  colliding across tenants is the ordinary case rather than the unlucky one --
  there the failure lands inside directory provisioning rather than in front of
  an operator. Migration **v173** re-keys all three to `(org_id, <name>)`, the
  same shape v138 gave `ispm_rules`, `ispm_scores` and `ai_agents`; no column is
  added and no belt changes, because all three tables already have both.
  `ziti_identities.name` and `ziti_services.name` are deliberately left
  install-wide: those names live in the Ziti controller, an install has one
  controller, and widening the local key would move the collision out of a clean
  database error and into a provisioning failure against the overlay.

- **Searching users returned a 500 on every call.** `ListUsers`'s search branch
  ends `ILIKE $1 ESCAPE '\\'`, written inside a Go **raw** string, so the SQL
  text carries two backslashes where Postgres allows exactly one character:
  `ERROR: invalid escape string ... Escape string must be empty or one
  character` (SQLSTATE 22025), on every search, on every install. The console's
  user-search box could never have worked. Both sites now send one backslash,
  and the escaping the clause exists for is asserted -- a search for `a_b` must
  not match `axb`.

- **One user with no first name broke the entire user list.** `users.first_name`
  and `last_name` are nullable and `UserDB` scans them into plain strings, so a
  single such row failed the whole call with "cannot scan NULL into *string" --
  not a bad row, a bad page. The product's own create path writes `""`, which is
  why it stayed hidden; a directory-synced user, a SCIM import or a row predating
  the column produces one. The three user SELECTs and the three WebAuthn lookups
  (where the same scan turned a passkey login into "user not found") now
  COALESCE both columns.

- **The DB-backed benchmark suite had never run, and could not have.** Sixteen
  benchmarks across `internal/identity` and `internal/oauth` pointed at a
  hardcoded DSN naming a database (`openidx_test`) that neither CI nor the
  compose stack creates, so they skipped everywhere -- and the benchmark job runs
  `go test -bench=. ./...` with no Postgres service at all. Underneath the skip:
  every id was a string like `bench_role_8f3a` fed to a `uuid` column, the
  seeding Execs discarded their errors, `ON CONFLICT (name)` named indexes that
  no longer exist, one insert named three columns `user_sessions` has never had,
  another seeded the wrong table entirely, and every timed call ran under a bare
  `context.Background()` so it returned "orgctx: no organization context" before
  touching the database. They now read `DATABASE_URL`, seed through valid
  statements under an org-scoped context, fail rather than continue when a
  fixture does not land, and check after the timed loop that the call they timed
  did not error on every iteration. `BenchmarkAuthenticate` reports ~80 ms/op
  now, which is bcrypt actually running; it used to report ~1 µs. The two user
  defects above are what running them turned up.

- **A resolver that could not answer looked exactly like one that answered
  "no".** `TenantResolver`'s documented precedence promises four steps, but
  steps 2 (JWT `org_id` claim) and 3 (platform-admin `X-Org-ID`) read the gin
  context, so they exist only where the middleware is mounted after the auth
  middleware that fills it. Six services mount it globally with `router.Use`,
  ahead of route-level auth; only `cmd/admin-api` mounts it on an authenticated
  group. On the six, every request silently lands on the default org whether the
  caller is a platform admin or not, and that stayed unnoticed for a release
  because both outcomes look identical from outside. The doc comment and all
  seven wiring sites now say which they are, and a new `Logger` field reports the
  mismatch -- once, at the moment a caller actually sends `X-Org-ID` to a
  resolver that cannot act on it. Deliberately narrow: a caller who simply is not
  a platform admin has roles in context and logs nothing, because a warning on
  ordinary refusals is one an operator filters out. Nothing about the resolution
  changes; the fail-safe direction was already right, it was just invisible.

- **The gateway's route table had no test, behind a reason that was untrue.**
  `TestRegisterServiceRoutes` skipped with "route conflicts in the routes
  package"; `registerServiceRoutes` registers 63 routes on a fresh engine
  without conflict, and has since the duplicate health registration moved out.
  It now asserts every proxied service is reachable by every method a REST
  client uses, that each proxied group resolves to a backend URL (and vice
  versa, so neither list can drift alone), that the docs endpoints are served,
  and that `/health` is **not** registered here -- registering it twice panics
  the gateway at boot, in production, which no test could previously catch.

- **Authorization-code expiry and single-use were both untested.** The expiry
  subtest was a bare skip ("requires code TTL modification or long wait"), and
  the one named for replay protection asserted that a login helper returned a
  token. Neither needed what it claimed: the code is available to the harness,
  and expiry is a column. An expired code is now shown to be refused as
  `invalid_grant` and removed from the table, and a replayed code is shown to
  mint nothing -- both verified by mutating `ConsumeAuthorizationCode` and
  watching them go red.

- **`scripts/check-inert-tests.sh` looked only at the first line of a body.**
  A skip preceded by comments -- which is where the reason for not writing the
  test gets parked -- slipped past it, and two inert tests sat green behind a
  paragraph the whole time the guard was in CI. Blank lines and comments no
  longer clear the finding; a statement still does.

- **A denied access request could be approved back to life.** `handleApproveRequest`
  read the request only to compare `requester_id` against the caller; it never
  looked at the request's **status**, and the pending-count that decides whether
  to fulfil counts rows marked `pending` while being blind to rows marked
  `denied`. On a request with two approvers where the first denied, the second's
  row was untouched: their approval drove the count to zero and the request was
  flipped from `denied` back to `approved` and **fulfilled** -- the role granted
  over the top of a recorded refusal, with both decisions in the audit trail and
  nothing to say one had overridden the other. A decided request (denied,
  cancelled or already approved) now answers `409` and grants nothing. Found by
  the first test ever written for the denial path.

- **Five of the seven OpenAPI specs were not YAML.** `28df9119` wrote the
  shared-responses block into a path item, on top of that operation's
  `parameters:` key, in `audit-service`, `governance-service`,
  `identity-service`, `oauth-service` and `provisioning-service`; a sixth,
  `access-service`, parsed but referred to a `ServerError` response it never
  defined. It shipped in v1.34.0. Nothing noticed because nothing in this
  repository ever parsed them -- `docs.yml` copies `api/openapi/*` into the
  published site verbatim, so the API reference for five services was being
  served a file no parser accepts. All seven now parse with every local `$ref`
  resolving, no operation lost, and `scripts/check-openapi-parses.sh` holds it.

- **Twenty-eight tests could not fail.** `internal/governance/request_test.go`
  was nine functions and fourteen subtests, every one a bare
  `t.Skip("DB mock not available")` -- named after `SubmitRequest` /
  `ApproveRequest` / `DenyRequest`, methods this service has never had, while
  the package carried a container-backed `setupTestDB` the whole time.
  `jit_test.go` skipped duration-bounds cases as needing "service init" over
  validation that runs before `RequestElevation` touches a database.
  `response_test.go` skipped four cases as needing "a real Redis client" in a
  package that has used miniredis since it was written, three of them named
  after methods that do not exist. And `TestJITRequestValidation` re-implemented
  the validation inside the test body and asserted its own copy -- a tautology
  that would stay green if `RequestElevation` dropped every check. All replaced
  with tests that drive the real code; `scripts/check-inert-tests.sh` fails on
  the shape.

- **Two database-backed test suites ran nowhere.** `ci.yml`'s unit matrix gives
  every package a live Postgres and exports it as `DATABASE_URL`; it does not
  set `OPENIDX_TEST_DATABASE_URL`, which is the developer escape hatch for a
  workstation with Postgres but no Docker daemon. `internal/oauth`'s SAML
  service-provider **tenant isolation** suite and the **v172** migration test
  (per-organization SET replay protection) read only that variable and skipped
  when it was unset -- so they skipped on every CI run, and on any workstation
  where nobody exported it by hand, while the job reported success. A skipped
  test displays as a pass. Both now prefer the variable and otherwise start a
  throwaway container, the way the other nine database-backed helpers already
  did. `scripts/check-test-reachability.sh` fails on the shape, and its
  self-test puts each of the two suites back into the form it was merged in and
  requires the guard to go red on both.

- **A dispatched release left the images unstamped.** `release.yml` already had
  a `workflow_dispatch` path, for environments that cannot push a tag ref at
  all -- a branch-scoped git credential answers HTTP 403 for `refs/tags/*`.
  That path published binaries, a GitHub Release, signed checksums and a signed
  Helm chart, and stopped there: the tag it creates is made under
  `GITHUB_TOKEN`, GitHub deliberately starts no workflow from a token-created
  push, so `docker.yml` never ran and the images kept only their `:sha` tag.
  The outcome looked like a full release and was a release whose version tags
  did not exist -- the failure `docker.yml`'s own retag job carries a comment
  against. `release.yml` now hands off to `docker.yml` on that path
  (`workflow_dispatch` being one of the two events `GITHUB_TOKEN` may still
  start), `docker.yml` accepts the version and stamps both spellings --
  `X.Y.Z` / `X.Y` / `X` and `vX.Y.Z` / `vX.Y` / `vX`, plus `stable` -- from
  either trigger. The un-prefixed three are not decoration: on a tag push
  `docker/metadata-action`'s `type=semver` publishes them and that matches a
  tag ref and nothing else, so stamping only the `v` form would have left a
  dispatched release complete-looking while the documented
  `docker pull ...:1.34.0` returned 404. `scripts/check-release-dispatch.sh` holds
  the two paths together in CI -- its self-test regresses `docker.yml` to the
  pushed-tags-only shape the repository actually had and requires the guard to
  go red.

## [1.34.0] - 2026-09-06

The project-readiness programme (PR #883). One organising defect class: **a
control that displays without enforcing is a lie** — extended, phase by phase,
to a spec that describes an eighth of a surface, a documented endpoint that
404s, and a "release" artifact signed with a debug key.

The programme closed with a full audit on one tree
(`docs/evidence/final-audit.md`): build, vet, 77 Go test packages, 1,181
console tests, the org-scope gate and 55 guard runs, all green — and two
defects, fixed below.

### Added

- **Tenant isolation on the nine ISPM/AI tables** (migration v138). `ispm_rules`,
  `ispm_findings`, `ispm_scores`, `ai_agents`, `ai_recommendations`,
  `bulk_operations`, `enrolled_agents` and `notification_digests` had no
  `org_id`: one tenant's "Scan" deleted every other tenant's open findings, and
  the posture score was neither one tenant's nor the install's. All now carry
  `org_id` under FORCE RLS, with the install-wide unique keys re-scoped and an
  isolation test per handler file.
- **Cancelling a bulk account operation did nothing, and one organization's bulk
  runs were visible to every other** (migration v161). A bulk operation is the
  console's "do this to these fifty accounts" control — enable, disable, delete,
  add or remove a role or a group, force a password change.

  **Pressing Cancel on a running operation stopped nothing.** Cancel marked the
  operation cancelled in the database, and the code doing the work never looked
  at that mark: it worked through every account it had been given, and then
  recorded the operation as "completed", erasing the cancellation. So an
  administrator who realised mid-run that they were deleting the wrong fifty
  accounts could press Cancel, watch the screen say it was cancelled, and have
  every one of those accounts deleted anyway with the record showing a normal
  completion. Cancel now stops the run before the next account, and a cancelled
  run stays cancelled.

  **An operation that changed nothing reported success.** Every action was
  correctly limited to the caller's own organization, so naming an account from
  another organization changed nothing — and, because that is not an error in
  the database, each such account was recorded as a success. A run over fifty
  accounts that belonged to someone else reported fifty successes. Each is now
  recorded as a failure, with the reason.

  The runs themselves had no organization: the list showed every organization's
  operations, including what each one did and which role or group it applied,
  and opening one returned its per-account detail — **which is a list of
  usernames** — so one administrator could read another organization's
  directory through it. Cancelling addressed a run by identifier alone, so one
  organization could cancel another's import mid-flight. All of that is now
  scoped to the organization that started the run.

  Also fixed: the per-account detail list dropped any row it could not fully
  read, and the field it stumbled on is empty for every account that succeeded —
  so a run that worked appeared to have done nothing at all.

  **Operators of installations with more than one organization should note**
  that existing runs are assigned to the organization of whoever started them,
  and their per-account records follow the run.
- **Anyone signed in could end someone else's supervised session.** A privileged
  session on a connection that requires supervision cannot start until a second
  person joins to watch it. Ending that supervision also ends the session
  itself — it is the supervisor's stop button.

  The endpoint that does this is documented as being for the person being
  supervised or the person supervising, and it checked neither. **Any signed-in
  member of the organization could end any supervised session by naming it.**
  The effect is to cut a session short rather than to gain access to one, so
  this cost availability rather than granting anything — but it is a restriction
  the product described and did not apply. It now checks, and administrators
  keep the ability to clear a stuck session.

  The three screens behind this feature also resolved which organization the
  caller belonged to, refused anyone without one, and then did not use it. The
  database's own isolation rule was confining them regardless; they now say so
  themselves.
- **The credential vault's permission checks now name the organization
  themselves.** Whether somebody may reveal a stored credential, who may see the
  record of past reveals, and which permissions may be withdrawn were all
  decided by queries that relied on the database's own isolation rule rather
  than saying so in the query.

  On an ordinary request that is enough. But the vault has one path — the one
  that injects a credential into a remote session on the product's own behalf —
  that deliberately steps outside the boundary, and there the database rule is
  switched off and only what the query says is left. Those five checks now say
  it, and a test exercises them **in that condition** rather than the ordinary
  one. No exposure is known to have followed from this; it removes the
  dependence.
- **A cloud broker credential belonging to one organization could be spent by
  another.** The cloud just-in-time endpoint (`POST /pam/connect/cloud`) takes
  the id of a vault secret to authenticate with. It carried no administrator
  requirement, and the id was used exactly as sent: the endpoint established
  which organization the caller belonged to, refused anyone without one, and
  then never applied it to the credential it fetched. That fetch is the
  product's internal credential-injection path, which by design steps outside
  the database's tenant rule — so nothing else was scoping it either.
  Any signed-in user could therefore name another organization's AWS broker
  credential, have it used to assume a role of their own choosing, and receive
  working temporary cloud credentials in the response. The session was recorded
  against the caller's organization, so the organization whose credential was
  spent had no record of it.
  The credential fetch now requires the organization to be named explicitly and
  refuses to decrypt anything belonging to another one. Every caller passes it,
  and roughly twenty further vault and rotation queries across four packages now
  name the organization as well.
- **The log of security events received from a federated provider now records
  which organization each was applied to** (migration v172). When an upstream
  identity provider pushes a security event — a session revoked, an account
  disabled, a credential changed — OpenIDX applies it and writes a row so a
  re-delivery of the same event is not applied twice. Applying the event has
  always been confined to one organization. Recording it was not: the column
  meant to hold the organization existed and nothing ever filled it, so the log
  could not say whose event any row was. The de-duplication key was
  installation-wide for the same reason, which on a multi-tenant installation
  meant a second organization receiving the same event id would apply it and
  then fail to record it, losing its protection against a repeat. Both now name
  the organization, and a failure to write the record is logged rather than
  discarded — that row is the protection.
- **The approval that clears an AI agent's tool call to run now names the
  tenant that granted it.** Sensitive tools reached through the MCP gateway wait
  for a person to approve them. The check that asked *does this tool need
  approval* said which organization it was asking about; the check on the very
  next line — *has this call been approved* — did not, and that is the one that
  lets the call through. The approve/deny endpoint had the same shape: it
  resolved the administrator's organization, refused when there was none, and
  then decided an approval by the id in the URL without using it. The database's
  own tenant rule was scoping both, so no call was ever cleared by another
  tenant's approval; the checks now say so themselves, and hold when a caller
  steps outside that rule.
- **An access-certification item could be delegated to a reviewer in another
  organization, and then never decided.** The Attestation surface lets an
  administrator hand a certification item to a different reviewer. The user id
  in that request was written onto the item with no validation at all — not
  that it named a user, not that the user was enabled, not that the user
  belonged to the administrator's own organization. Row-level security did not
  stand in the way: it constrains which *rows* a tenant may touch, and this is a
  *value* written into a row the tenant already owns.
  A reviewer in another organization cannot see the item — reviewer names are
  read through an organization-scoped join, so it simply renders blank — so
  nothing was disclosed. What was lost is the certification: the item stays
  pending for ever, and a campaign completes only when its pending count reaches
  zero, so a single delegation froze the campaign permanently. `delegate_to`
  must now name an enabled user of the administrator's organization, which is
  the rule the product already applied to reviewers it assigned itself.
  Every one of the twenty-eight attestation statements also names the tenant
  now, and a campaign whose description is empty no longer drops silently out of
  the list it belongs to.
- **The approval request raised when an untrusted device is refused had never
  once been raised** (migration v171). When a device that has not been marked
  trusted reaches a resource protected by a device check, the product refuses it
  and — in its own words — "files a pending device-trust request so an admin can
  approve it". An administrator is meant to see that request on the Device Trust
  Approval screen and let the person in.

  An earlier migration gave those records a required organization column. The
  step that writes them was never updated to fill it, so **every attempt failed
  at the database and the failure was written to the log and discarded** —
  deliberately, because that step is best-effort and must never block the
  request it is refusing. The result: the check refused the device, said it was
  raising a request, and raised nothing. On every installation, for as long as
  that column has existed. A person locked out by a device check waited for an
  approval that was never in anybody's queue.

  The equivalent step on the self-service side always filled the column
  correctly; this was its counterpart. The organization now comes from the
  already-signed-in person, which is exact.

  A test did assert that the request was filed. It built its own copy of the
  table **without** the required column — a shape the product has not had since
  that migration — so it passed against a constraint that was not there. It now
  matches the real schema.

  Also in this change: report exports, agent enrolment sessions and these
  device-trust requests are all brought under the database's own isolation rule,
  which completes that work — every record type in the product that names an
  organization is now confined by the database as well as by the application.
  Two supporting fixes went with it: the background job that writes a finished
  report's status now carries the organization it is working for (without it the
  export would have stayed at "generating" for ever, with the file on disk), and
  the public endpoint an agent uses to redeem its enrolment code now says
  explicitly that it works across organizations, since it runs before any
  organization can be known.
- **A record that names the organization had never had one written into it**
  (migration v170). When an application registers itself with OpenIDX
  automatically — the standard mechanism for a client to sign itself up — it is
  handed a management credential so it can read, update or remove its own
  registration afterwards. The record holding that credential has had a column
  for the owning organization since it was created, and nothing had ever put a
  value in it. Every one of those records, on every installation, named no
  organization at all.

  That mattered because the plan was to bring this record under the database's
  own isolation rule. Doing that first would have made every one of them
  invisible, and every management call — read, update, remove — would have
  answered **"invalid registration credential"** for every application on every
  installation, with a perfectly valid credential in hand. The column is now
  filled from the application it belongs to, and only then enforced.

  A record whose application no longer exists is removed rather than assigned to
  someone: it could never be used again, and filing another organization's dead
  credential under theirs would be worse than deleting it.

  **This was not an exposure.** The lookups involved use the application's
  identifier, which is unique across the whole installation, and both management
  screens read the application itself — already confined to its organization —
  immediately afterwards, so a caller from elsewhere was already refused there.
  What changes is that these lookups no longer depend on a property of a
  different record, and keep working for maintenance jobs that deliberately
  range across organizations.

  Also brought under the same rule: the codes used when signing in on a device
  that has no keyboard (a TV, a console). Their organization was already
  recorded and every lookup already used it; the four follow-up updates that
  addressed a code by its row now name it too.
- **The system-health repair tool required no administrator role** (migration
  v169). The Relations & Integrity Doctor on the System Health page finds
  inconsistencies across the whole installation — an application whose network
  service no longer exists, two applications claiming the same address — and
  offers to repair them. It is deliberately install-wide: it deliberately steps
  outside the per-organization boundary so that an operator can see the whole
  picture.

  **Its two endpoints required only that the caller be signed in.** Every
  neighbouring administrative endpoint requires an administrator; these did not,
  and because they deliberately step outside the organization boundary, nothing
  else was confining them either. Any signed-in user of any organization could:

  - read a report naming every organization's published applications, their
    public addresses, their sign-in client identifiers and their network service
    names;
  - apply every repair marked safe, across every organization, in one request;
  - apply one of the two repairs the product itself marks risky — removing a
    service from the network controller, or consolidating an application, which
    rewrites another organization's routes and re-points their discovered paths.

  Both endpoints now require an administrator, and a test drives the product's
  real routing table to prove it, so a route added here in future cannot quietly
  skip the check.

  Also in this change: the App Publish records (published applications and their
  discovered paths) are brought under the database's own isolation rule. Their
  earlier migration had recorded a reason for leaving them out — half of it had
  since stopped being true, and the other half needed one line so that the
  background path-discovery job carries the organization it is working for.
  Changing the classification of a path — which decides whether it is published,
  behind what sign-in, and under what device requirement — now has a test
  covering the cross-organization case it did not have.
- **One organization could add a permission to another organization's AI tool
  gateway** (migration v168). The MCP gateway lets an administrator register an
  upstream an AI agent may be proxied to, and then list which callers may use
  which tools on it. That list is an allowlist: a line on it grants permission,
  and nothing else decides the question.

  Adding a line took the upstream's identifier from the address bar and **never
  checked the upstream belonged to the administrator's organization**. So an
  administrator of one organization could name another's upstream and add a line
  to it. The line names a role — and role names are not unique across
  organizations, so a line granting "analyst" was then applied to *that*
  organization's analysts, on *their* upstream, and appeared on their own policy
  page as though one of their administrators had written it.

  Everything around it was already confined correctly: listing, opening and
  deleting an upstream all checked the organization. The upstream was protected
  and the permission attached to it was not.

  Fixed in the same change: the tool-permission check, the approval-requirement
  check and the pending-approvals list now each carry the organization; four
  places where an empty organization was treated as *every* organization are
  gone; registering an upstream or adding a permission without an organization
  is refused rather than silently writing a record no one can see afterwards;
  and the four screens behind this now answer "forbidden" instead of running
  with no organization at all. Both record types are also brought under the
  database's own isolation rule.

  **Operators of installations with more than one organization should note**
  that existing records are assigned to the organization that owns them, and any
  record stored without one is attributed to the primary organization — worth a
  look at the tool permission list on each gateway after upgrading.
- **Group-to-application assignments were protected by a rule the database did
  not apply to every connection** (migration v167). When an application is
  assigned to a group, that record decides who may reach the application. It was
  given a database rule confining it to its own organization, but not the second
  setting that makes the rule apply to the account that owns the tables as well
  as to everyone else.

  On the deployment this project documents, migrations and the running services
  connect as different database accounts, so the rule applied and the records
  were confined — **this was not an exposure there**. On an installation where
  the two are the same account (a single-account database, a hosted service
  whose application user owns the schema, a developer's machine), the rule did
  not apply to the application at all, and this record was protected only by the
  product's own filtering. Every comparable record — direct user assignments,
  group memberships, the applications themselves — already had both settings.
  This one now does too.

  A check was added that asks the database directly whether every record type
  with such a rule also has the second setting, so a future migration cannot
  omit it quietly. Run against the previous schema it identified this record
  type and no other.
- **Revoking someone's network access reported success even when the
  disconnection failed** (migration v166). When an access review revokes access,
  or a time-limited grant expires, the product records the decision and then
  hands the actual work — removing the network permission and cutting the user's
  live connections — to a background worker.

  **The worker marked every item done regardless of whether it had worked.** If
  the network controller was unreachable, or the call to sever the connection
  failed, the failure was written to the log and the item was recorded as
  completed anyway. The reviewer saw a revocation; the user's live connection
  stayed open; every record agreed it had been cut. The worker now records a
  failure as a failure.

  **A failed hand-off was retried never and read by nobody.** Both queues have
  had an attempt counter since they were created and neither worker ever used
  it, so one transient controller error lost the change permanently — a granted
  request whose permission was never applied, or a revocation that never
  happened. And nothing in the product reads the failure state, so there was no
  screen, alert or report where it appeared. Failures are now retried, and a
  hand-off that exhausts its retries is written to the audit trail of the
  organization it belongs to, where it can be seen.

  Both queues also gain database-level protection and can no longer be stored
  without an organization. The background worker is unaffected: it is
  deliberately installation-wide and already had an explicit exemption.
- **A device reported by one organization's endpoint-security connection could
  cut off another organization's user** (migration v165). OpenIDX can read
  device compliance from CrowdStrike, Intune, Jamf or Wazuh and use it as a
  posture signal: a device the security tool reports as non-compliant fails its
  posture check, and that is what revokes the session and disconnects the
  device from the private network.

  **The step that decides *whose* device it is looked across all
  organizations.** A reported device is matched to a local identity by email
  address, hostname or serial number, and that lookup named no organization —
  so a device reported by one organization's connection could be matched to a
  user in another, and which one was decided by the database's own query plan.
  The effect was a disconnection, not a disclosure: one organization's security
  tool calling a laptop non-compliant could cut off someone else's user, on
  nothing more than a shared email address — which is the ordinary case for one
  person employed by two organizations on the same installation. The match is
  now confined to the organization that owns the connection.

  The connections themselves also gain database-level protection, which the
  migration that created them said they had and never applied, and their
  organization can no longer be left empty. As with the outbound provisioning
  connections above, the "empty organization means all organizations" shortcut
  in the queries is gone, and these endpoints now refuse a request that arrives
  without an organization. The background poller that reads the security tools
  is unaffected: it is deliberately installation-wide and already had an
  explicit exemption.

  **Operators of installations with more than one organization should note**
  that device records follow their connection exactly, but a connection stored
  with no organization is assigned to the oldest one — and the next poll writes
  posture results, so check which connection belongs to whom first.
- **Outbound provisioning connections were not protected by the database, and
  their organization could be left empty** (migration v164). These are the
  connections that push your users out to Slack, Okta, Entra and similar: a base
  URL, an encrypted administrative credential, and a queue of pending changes.

  Their records carried an organization, but the database was never told to
  enforce it — the migration that created them says it made them
  "org-scoped for RLS" and that protection was never applied. Every query
  relied on the application remembering to filter. It now relies on the
  database, which refuses to return another organization's rows regardless.

  **The organization could be empty, and an empty organization meant all of
  them.** The column allowed no value at all, and every "scoped" query treated
  an empty organization as a wildcard. Reached that way, the list returned every
  organization's provisioning connections, delete removed any of them along with
  their history and pending queue, and a full sync would have pushed the entire
  installation's directory — every username, email and name — into one
  organization's downstream service.

  **This was not reachable in a running deployment**, and we would rather say
  so than imply otherwise: the provisioning service resolves the organization
  for every request before any of these endpoints run, and rejects the request
  when it cannot. The wildcard was one configuration change away from mattering,
  and it contradicted the database protection being added — so it is gone, and
  the endpoints now refuse a request that arrives without an organization
  instead of treating it as every organization. A connection can no longer be
  stored without one either.

  The background worker that delivers queued changes is unaffected: it is
  deliberately installation-wide, and already ran with an explicit exemption.

  **Operators of installations with more than one organization should note**
  that pending changes and delivery history follow their connection exactly, but
  a connection that was stored with no organization is assigned to the oldest
  one. If you have more than one organization, check which connection belongs to
  whom before the next sync runs.
- **One organization could reclassify another's roles, and the button that saves
  a classification had never worked** (migration v163).

  The Entitlement Catalog lets an administrator annotate a role, a group or an
  application: its risk level, its owner, its tags, and whether it requires
  review. Those annotations had no organization, and the identifier they were
  stored under was unique across the whole installation — so an administrator
  who knew another organization's role identifier could set that role's risk
  level, name an account of their own as its owner, retag it, and switch its
  "review required" badge off. The change appeared on the other organization's
  catalog. Annotations are now the annotating organization's own, and naming an
  entitlement or an owner from outside it is refused.

  **The Save button had never worked at all.** The statement that stores an
  annotation put a text value into a column that holds an identifier, which the
  database rejects before it runs — for every request, whatever was being saved.
  So every Save on the Entitlement Catalog has returned "internal server error"
  since the feature shipped. Fixed.

  **The risk breakdown could show a negative number.** The catalog's summary
  counted this organization's roles, groups and applications, then subtracted a
  count of annotations taken from the entire installation. Where another
  organization had annotated more entitlements than this one owns, the "low
  risk" figure came out below zero — a count of things, printed negative, beside
  figures that were correct. Both halves are now this organization's.

  **Notification digests** are also now scoped to the organization, though they
  were never reachable across organizations: each request only ever read the
  calling user's own row. Worth stating plainly for anyone relying on the
  feature: **nothing sends a digest.** The schedule is stored and no part of the
  product reads it, so choosing a daily or weekly digest in Notification Center
  has never resulted in one being sent. That remains outstanding work; this
  release does not change it.

  Two unused tables were removed: one that nothing had ever written to and whose
  only reader asked it for two columns it does not have, and one referenced
  nowhere in the product at all. The Feature Adoption analytics page is
  unaffected — it has always computed its figures live, because the read of the
  stored table failed silently every time.

  **Operators of installations with more than one organization should note**
  that existing annotations are assigned to the organization that owns the
  entitlement they annotate, which is exact, and existing digest settings to the
  organization of the user they belong to.
- **One organization could switch off another's private-network protection for
  an application, and read their internal server names** (migration v162). Two
  records had no organization: the per-application feature switches (whether
  private-network access, browser-based access or remote-desktop brokering is on
  for a route) and the results of the "Test connection" button.

  **The switch was protected in one direction only.** Turning a feature *on* for
  an application belonging to another organization was already refused. Turning
  one *off* was not checked at all, so an administrator who knew an
  application's identifier could switch off another organization's
  private-network protection for it — and, on installations that provision
  directly rather than through the reconciler, the underlying network service
  was deleted outright. The owning organization's console went on showing the
  application as protected, because the one statement that would have updated
  that display *was* limited to the caller's own organization and so changed
  nothing. Both directions are now checked.

  **The connection-test history named internal hosts.** Each stored test result
  holds the application's upstream address, the host and port a connectivity
  probe dialled, the private-network service name, and the raw error text of a
  failed connection — which names the server it could not reach. That history
  was read by application identifier with no organization attached, so it was
  readable across organizations, and by a caller with no organization at all.
  Both the test and its history now require one and return only the caller's own.

  **The health indicator beside each feature was never written.** The coloured
  dot on the Zero Trust page and the badge on an application's feature panel
  read from a field nothing in the product ever set, so they have shown
  "unknown" for every feature on every application since the field was
  introduced. The connection test already measures exactly what they report —
  it resolves the private-network service and validates the remote-desktop
  connection — and now records its verdict, so the indicator means "the last
  connection test said this". It stays "unknown" until a test has run, and a
  test that did not probe a feature leaves that feature's indicator alone.

  **Operators of installations with more than one organization should note**
  that existing feature switches and test results are assigned to the
  organization that owns the application they belong to, which is exact.
- **One set of email templates for the whole installation, and an announcement
  another organization could send** (migration v160). Three records had no
  organization: the email templates, the notification routing rules, and the
  broadcast messages.

  Every administrator on the installation saw and could rewrite **one shared set
  of email templates** — the subject line and body of the mail the product sends
  about passwords, invitations, verification and one-time codes — and template
  names were unique across the installation, so the first organization to create
  a template called "welcome" owned that name for everyone and the next
  organization's attempt failed with an unexplained error. Each organization now
  has its own templates and its own names.

  A **broadcast** is an announcement an administrator sends to their users. The
  send endpoint worked out the recipients from the caller's organization but
  loaded the announcement itself by identifier alone, so an administrator could
  take another organization's unsent draft and deliver it, as their own, to
  their own people. Reading, listing and deleting a draft were unscoped
  outright. And a **notification routing rule** decides which channels an event
  reaches, so one organization could switch another's security-alert rule from
  in-app-and-email to in-app only, and those alerts would stop arriving by mail
  with nothing on screen to say so. All three now carry the organization.

  **Operators of installations with more than one organization should review
  their email templates and routing rules after upgrading.** Records are
  assigned to the organization of whoever last edited them; the five starter
  templates the product ships carry no editor, so they go to the oldest
  organization and other organizations start with none.

  Also fixed: an email template saved without a plain-text body disappeared from
  the template list entirely — the list dropped any record it could not read and
  said nothing. Also recorded, and not yet fixed: nothing in the product sends
  these templates. No mail the product delivers reads one, by name or otherwise,
  so the template editor has always saved copy that nothing uses. Wiring the
  mailer to them is outstanding work.
- **Any administrator could read, disable or delete another organization's
  device lockdown policies, and aim one at a device** (migration v159). A kiosk
  policy puts a managed device into locked-down mode: which apps may run, which
  screen is pinned, the branding shown, and the PIN required to leave. The
  records had no organization. The administrative list returned every policy on
  the installation — its own code comment said so — and reading, editing and
  deleting a policy needed only its identifier, so one organization's
  administrator could turn off another's device lockdown with nothing on the
  owning console to say the control had stopped existing.

  Assigning a policy to a device was worse: the endpoint took the policy from
  the address and the device from the request body and checked neither, so an
  administrator could aim another organization's lockdown — and its exit PIN —
  at a device. Policies, assignments and every one of the eight endpoints now
  carry the organization, and assignment verifies the policy belongs to the
  caller.

  **What this does not settle**, stated plainly: enrolled agents have no
  organization, by an existing deliberate decision. So an agent identifier names
  a device without naming a tenant, and while an administrator can no longer aim
  *another organization's* policy at a device, nothing yet stops them aiming
  *their own* policy at a device someone else enrolled. Whether the agent fleet
  should be per-organization is an open product decision.

  **Operators of installations with more than one organization should review
  their kiosk policies and assignments after upgrading.** Existing policies are
  assigned to the organization of whoever created them, and assignments follow
  their policy; anything unattributed goes to the oldest organization.

  Two more, alongside. Creating a kiosk policy without specifying the allowed
  apps, the lock-task features or the branding — all three optional — failed
  with an unexplained server error; it now works, using the defaults the schema
  already declared. And two tables this release removes, `policy_recommendations`
  and `compliance_gaps`: they were created for an AI policy-suggestion endpoint
  that was itself removed as dead earlier in this programme, and nothing in the
  product has read or written either since.
- **One organization's biometric rule could decide another organization's
  sign-in, and which rule won was decided alphabetically** (migration v158). A
  biometric policy says which authenticator types are allowed, whether a
  built-in authenticator (Face ID, Touch ID) is required, and which groups and
  roles the rule covers. The record had no organization, and the code that finds
  the rule for a user listed every rule on the installation, sorted them by
  name, and took the first one that applied — where a rule naming no groups and
  no roles applies to everyone. So any administrator anywhere could create an
  untargeted rule that governed every user on the installation, and the winner
  was whoever chose the earlier name. It could weaken as well as tighten: the
  default rule allows both authenticator types, so a permissive rule sorting
  first replaced a restrictive one and the check meant to refuse a roaming
  security key accepted it. Rules are now per organization.

  Administrators could also see, edit and delete each other's rules across
  organizations — the list returned every organization's, including the group
  identifiers and role names each rule targets — and a user's own biometric
  preferences, including whether their account is sign-in-by-biometric-only and
  whether the authenticator must verify the person, were readable and writable
  by user identifier alone. All of those now carry the organization.

  **Operators of installations with more than one organization should review
  their biometric policies after upgrading.** Existing rules are assigned to the
  oldest organization, because the records carry no information about who
  created them; any other organization relying on a rule it did not author must
  create its own.

  Two more, found alongside. The passwordless settings page divided a count of
  biometric-only accounts across the whole installation by a count of users in
  one organization, so a small organization sharing an installation with a large
  one saw a biometric adoption rate above 100%. And reading a user's biometric
  preferences answered any failure — a database error, a permission problem —
  with the built-in defaults and no error at all, which is indistinguishable
  from "this person has not chosen any"; a failure is now reported as a failure.

  Also recorded, and not yet fixed: nothing in the product consults a biometric
  policy. No registration path and no sign-in path checks one, so the policy
  page has always saved rules and constrained no enrolment. Giving those rules
  an enforcement point is outstanding work rather than something this release
  delivers.
- **One password policy, one MFA requirement and one set of allowed sign-up
  domains for the whole installation; and a continuous-authentication engine
  that had never once run** (migration v157). The admin console's settings page
  saves four records — general, security, authentication and branding. Their key
  was the table's primary key, so there were four records on the installation in
  total and every organization's administrators shared them. The security record
  holds the password policy (minimum length, required character classes,
  forbidden words, maximum age, history depth), whether multi-factor
  authentication is required and which methods are allowed, and the session
  timeouts; the authentication record holds the email domains allowed to
  register. One administrator lowering their minimum password length, or
  switching MFA-required off, did it for every organization — and each
  organization's page showed them whatever had been saved last, by anyone.

  This is not only a display problem. The password checker
  (`POST /api/v1/settings/validate-password`) reads that same shared security
  record, so the policy a password was measured against was whichever one had
  been saved most recently, by an administrator of any organization. Each
  organization now has its own four records, and its own policy.

  **Operators of installations with more than one organization should review
  their console settings after upgrading.** The existing records are assigned to
  the organization of whoever last saved them; every other organization starts
  from the built-in defaults, which are the stricter setting in each case, and
  should save its own.

  Separately, the continuous-authentication engine — which scores a live session
  for risk and can require a step-up or end the session — read its session
  information from a table that no part of the product has ever written a row
  to. Its three endpoints have therefore only ever returned an error, and its
  "record a risk event" endpoint reported success while storing nothing. The
  engine now reads the session and risk-history tables the product actually
  writes, under the caller's organization, so one organization can no longer
  score or end another's session. Three faults that this uncovered are fixed
  with it: two of the three endpoints graded every session "critical" because
  their thresholds were left at zero, an unrecognised event name was silently
  scored as nothing and reported as recorded, and the detail supplied with an
  event was discarded.

  Also recorded, and not yet fixed: the engine's device factor needs a device
  fingerprint, and nothing records one against a session. Rather than treat
  every session as an unrecognised device — a fixed number presented as a
  measurement — that factor now reports itself unavailable, and the response
  says which factors the score was actually built from. Recording a fingerprint
  at sign-in is outstanding work.
- **The developer portal kept one settings record for the whole installation,
  and its OAuth playground handed out a live flow's secret to anyone who knew
  the session's identifier** (migration v156). The developer settings page sets
  the maximum number of API keys a user may hold, which permissions an API key
  may carry, the webhook address allowlist, the browser origins allowed to call
  the API, the default rate limit, and whether sandbox mode is on. There was
  exactly one such record on the installation, shared by every organization:
  whichever administrator saved last chose all of it for everyone. Each
  organization now has its own.

  The console's OAuth playground — the tool for stepping through a sign-in flow
  by hand — stores the secret that lets that flow's authorization code be
  exchanged for a token. It was retrievable by session identifier alone: no
  check of which organization the session belonged to, no check that the person
  asking was the one who started it, and, unlike every other page in that part
  of the API, no check that they were an administrator at all. All three checks
  are now in place.

  **Operators of installations with more than one organization should review
  their developer settings after upgrading.** The existing record is assigned to
  the organization of whoever last saved it; every other organization starts
  from the defaults and should set its own.

  Also recorded, and not yet fixed: none of the developer settings is consulted
  by anything. No API-key issuance checks the maximum or the permitted
  permissions, no browser-origin check reads the allowlist, no limiter reads the
  rate limit. The page has always saved six limits and enforced none of them,
  which is why sharing the record between organizations has not caused visible
  harm. Making those values take effect is outstanding work rather than
  something this release delivers.
- **Every organization's single sign-on routing was visible to every
  administrator, and two organizations could not share a domain or an identity
  provider** (migration v155). A federation rule says which identity provider
  authenticates a given email domain — the record that decides where someone
  typing their work address is sent to sign in.

  The administrative list of those rules showed every organization's, not just
  the viewer's. The check that was meant to confine it sat in a part of the
  query that decides how to *label* a row rather than whether to *return* it,
  so it filtered nothing and merely left the provider name blank on the rules
  belonging to other organizations. Rules could also be edited or deleted by
  anyone who knew their identifier: an administrator elsewhere on the
  installation could switch off another organization's SSO for a domain, after
  which its users would quietly get a password prompt instead, with nothing on
  the owner's screen to say the routing had changed. And a rule could be
  created naming an identity provider belonging to a different organization.
  All of this is now confined to the organization that owns the rule, and a
  rule can only name a provider from that same organization.

  Two limits that made multi-organization installs impossible are lifted in the
  same change. An email domain could be registered **once per installation**:
  whoever claimed it first held it everywhere, and the next organization to try
  got an unexplained failure. An identity provider's issuer address was
  likewise unique installation-wide, so two organizations could not both
  federate to the same provider — two departments on one corporate tenant, or
  simply both using the same public provider. Each is now unique per
  organization, and a duplicate within one organization gets a message saying
  so rather than a generic error.

  **Operators of installations with more than one organization should review
  their federation rules after upgrading.** Each rule is assigned to the
  organization of the identity provider it routes to. A rule every
  administrator could see will now be visible to one.

  Also recorded, and not yet fixed: the custom claim mappings configured per
  application — "include the user's department in the token as `dept`" — are
  saved, listed back, and read by nothing. No token has ever carried them. The
  page's three destination switches (ID token, access token, userinfo) have no
  consumer behind them. The mappings are now confined to the organization that
  owns the application, so they can no longer be added to or removed from
  another organization's applications, but making them actually reach a token
  is outstanding work rather than something this release delivers.
- **A second organization could re-aim the rule that disables and deletes
  accounts** (migration v154). Joiner/mover/leaver automation is two kinds of
  rule — a workflow that runs on a person's arrival or departure, and a
  de-provisioning policy that sweeps for stale, disabled or orphaned accounts —
  plus a log of what each run did. Between them the actions available are: add
  or remove a role, add or remove a group membership, revoke every session,
  force a password change, disable the account, and delete the account.

  Everything those rules **do** was already confined to the organization the
  rule was run in. What the rules **were** belonged to nobody. Any
  administrator could list every organization's rules, open one, and change
  both what it looks for and what it does. A policy named "Stale Account
  Auto-Disable — 90 days" could be turned into "delete anything idle for zero
  days", which is every account, and handed back unchanged in name. Its owner
  then runs the rule they have always run, on their own directory, and the
  confinement of the action is no help at all: the accounts destroyed are
  theirs. The same reach allowed deleting another organization's offboarding
  rule outright — after which nothing on their console says the control that
  used to disable departing staff has stopped existing.

  The run logs were readable across organizations too, and they are not
  status: each entry names every account the run touched, the action taken
  against it, and the reason it was selected.

  All four record types now belong to an organization, and every listing,
  view, edit, deletion and run is limited to the caller's own.

  **Operators of installations with more than one organization should review
  their lifecycle rules after upgrading.** Rules are assigned to the
  organization of whoever created them; run logs follow the account they acted
  on; anything the upgrade cannot attribute goes to the oldest organization. A
  rule that every administrator could see will now be visible to one. If a
  second organization had been relying on a rule the first authored — which it
  was never entitled to — it needs its own.

  Fixed alongside it: a completed policy run was invisible in its own history.
  The run record leaves the error field empty when nothing went wrong, and the
  reader could not cope with an empty value, so it skipped the row silently —
  an administrator opening the history of a policy that had just disabled fifty
  accounts saw an empty list. The same fault could hide a whole rule from the
  policy list. Both readers now handle the empty values, and a skipped row is
  logged instead of disappearing. And running a workflow against an account in
  another organization is now refused outright rather than recorded as
  completed work that never happened.
- **One organization's sign-in rule could weaken the second factor for every
  organization** (migration v153). A risk policy is a rule the sign-in path
  consults: when this condition holds, ask for a second factor, ask for a
  stronger one, refuse the sign-in, or accept these particular factors. The
  rules carried nothing saying which organization they belonged to, and the
  sign-in path read all of them and applied every one that matched.

  The damaging direction is the permissive one. When a sign-in looks risky the
  system narrows the acceptable second factors to the two that resist phishing
  — a security key or a push approval. A rule that names acceptable factors
  does not add to that list, it **replaces** it. So a rule created in one
  organization saying "any factor is acceptable" put one-time codes by SMS and
  email back into every other organization's high-risk sign-ins. The condition
  needed to trigger it is not exotic either: "risk score at least 0" is true of
  every sign-in there has ever been. The same rule with "refuse" instead would
  have blocked every sign-in on the installation.

  Rules are now owned by an organization and only that organization's rules are
  consulted, read or written. Listing, viewing, editing, enabling and deleting
  are all limited to the caller's own.

  **Operators of installations with more than one organization should review
  their risk policies after upgrading.** These rules had no owner, so the
  upgrade assigns every existing one to the oldest organization — there is no
  other information on the record to go by. A rule that had been applying
  everywhere will now apply in one place. That is the intended direction, since
  no organization was ever meant to have another's rule applied to its
  sign-ins, but the rules you meant each organization to have will need
  re-creating there.

  Fixed alongside it: one rule with an empty description made the sign-in path
  fail to load **any** rules at all, on every sign-in, for the whole
  installation. It failed in the safe direction — the path falls back to asking
  for a second factor — but every refusal, every step-up and every factor
  restriction an administrator had configured was silently doing nothing. The
  same table is read elsewhere in the product with the empty value handled
  properly; this reader had never had it.
- **A delegated administrative permission followed the person into other
  organizations, and the permission cache shared it with their colleagues**
  (migration v152). A delegation record grants one person a named set of
  administrative powers — "may reveal stored credentials, until this date." It
  is read by the component that decides whether a request is allowed, and
  merged into that person's permissions for the request. The record carried
  nothing saying which organization it belonged to.

  Two lookups sit side by side in that component, and both run with the
  database's own restrictions deliberately lifted, because at that point in a
  request the organization has not yet been established and a restricted read
  would return nothing and refuse everybody. The first lookup limits itself to
  the caller's organization and its note says so. The second, added later, says
  it uses the same reasoning — but limits itself to the person, not the
  organization. So it did not limit itself at all: a delegation granted in one
  organization applied to that person wherever else they could act.

  The cache made it worse in a different direction. Permissions are cached for
  five minutes under a key made of the organization and the person's roles, and
  the delegation lookup was adding its own caller's personal grants to what got
  stored. Every other person in that organization holding the same roles was
  then served one individual's delegated powers as their own, for as long as
  the entry lived, and again on the next miss. Personal grants no longer go
  into a shared entry: the expensive role lookup is still cached, the
  delegation lookup runs per request, and entries written by the old code are
  no longer read.

  The administration API had the same gap on the writing side. Updating a
  delegation identified it by its identifier alone, and the permission list is
  one of the things an update can change — so an administrator of one
  organization could rewrite what another organization's delegation granted,
  and it would take effect on that person's next request. Deleting had the same
  shape, and creating accepted any person as the recipient. All of these are
  now limited to the caller's own organization, creation checks that the
  recipient, the granting administrator and the stated scope all belong to it,
  and the list's total count no longer counts every organization's records.

  Not changed, and stated plainly because it is worth a decision rather than an
  assumption: a delegation records a scope — a group, an application — and
  nothing consults it. The check that decides a request compares only what is
  being done, not where, so a delegation scoped to one group grants its powers
  wherever that power is checked. Narrowing it would take administrative access
  away from people who have it today, so it is documented rather than changed.
- **A remote session onto another organization's machine, with that
  organization's password** (migration v151). A brokered connection record is
  the definition of a privileged target: which machine, which port, which
  stored credential is typed into the session on the user's behalf, and whether
  the session needs an approval, a live supervisor, or a recording. The record
  carried nothing saying which organization it belonged to.

  The endpoint that opens a session is available to any signed-in user, which
  is correct — it is how a person launches the access they have been granted.
  It asked which organization the caller belonged to, refused if there was
  none, and then looked the target up by its address alone, never using the
  answer. Everything after that acts on whatever record comes back: the stored
  credential is fetched with the database's own restrictions deliberately
  lifted, because the server is the thing that types it in, and a working
  connection link is handed back. So a user of one organization who knew
  another organization's route identifier received a live remote desktop or
  terminal session on that organization's machine, signed in with that
  organization's credential. The credential store's own protection was intact
  and beside the point: it had been set aside on purpose, and the unscoped
  record was what chose which secret to set it aside for.

  The approval and supervision requirements could not have stopped this. Both
  are checked against records belonging to the caller's own organization, so
  the caller's own administrator could approve the caller for someone else's
  machine and the check would pass. A two-person rule that one organization can
  satisfy alone is not a control. Restricting the connection record is what
  makes those checks mean something, and it is now restricted and enforced at
  the database level.

  The list of brokered connections had the same gap in its simplest form — no
  condition at all, so every organization's internal hostnames, ports and
  connection settings were readable by any signed-in user. It is now
  administrator-only and limited to the viewer's own organization; the list end
  users see for launching their own access is unchanged and shows no
  infrastructure.

  Removed with it: a connection-token cache table that has been empty on every
  installation since it was introduced. Nothing read it, nothing called the
  code that filled it, and the statement meant to write to it referenced a
  constraint the table does not have, so every attempt failed silently into a
  log line. A later change widened one of its columns so the tokens it stored
  would be encrypted; there were never any tokens.
- **Every organization's remote support history was on every organization's
  console** (migration v150). A remote support session is an administrator
  watching or driving an end user's screen. The list of them ran with no
  condition restricting it to the viewer's own organization — so any
  administrator could see whose screen had been taken over, by which
  administrator, when, and whether a recording of it exists, across every
  organization on the installation. It is now filtered, and the table is
  enforced at the database level like the rest.

  Turning that enforcement on was not straightforward. The organization column
  on these rows has been optional since it was added, and the code that starts
  a session wrote it empty whenever the caller had no organization resolved.
  Enforcing on an optional column does not restrict those rows — it makes them
  vanish: the administrator who started such a session could no longer see it,
  end it, or delete its recording, while the session itself carried on, because
  the live connection is held in memory and never re-reads the record. The
  existing rows are therefore attributed to the administrator who started them
  first, the column is made mandatory, and only then is enforcement switched
  on. Starting a session without an organization is now refused outright rather
  than accepted and lost.

  The paths a device uses — answering the consent prompt, asking whether a
  session is waiting for it, and ending one — are deliberately exempt, because
  the device authenticates as itself and not as a member of an organization.
  Without that exemption an end user's machine could never be helped: the
  administrator would start a session the device never sees. The background job
  that expires stalled sessions is exempt for the same kind of reason — one it
  cannot see is one that never ages out.
- **One tenant could release another tenant's legal hold, and the recording was
  then deleted** (migration v149). A legal hold marks a session recording as
  evidence: while one is active, the job that enforces retention must leave the
  recording alone. Releasing a hold is therefore not a status change — it is
  what allows the next retention run to delete the recording.

  The release endpoint for remote-support recordings identified the hold by the
  session it belonged to and nothing else, so an administrator of one
  organization who knew another organization's session identifier could release
  that organization's hold. The recording it was protecting was deleted at the
  next retention run — irreversibly, and with almost nothing to see afterwards:
  the owning organization finds only a release timestamp attributed to an
  account that is not theirs. Placing and listing holds were unrestricted in the
  same way, which also exposed the stated reason for each hold, free text that
  routinely describes an ongoing investigation.

  The equivalent endpoints for privileged-session recordings did check that the
  session belonged to the caller, which is how the gap was noticeable at all —
  two implementations of one control, one guarded and one not. That check was
  also weaker than it appeared: it had no organization condition of its own and
  relied entirely on database-level enforcement, which does not apply when the
  application connects with a privileged database account. Both hold tables now
  carry an organization, the enforcement applies to them directly, and every
  endpoint names the organization in its own query rather than delegating.

  The retention sweeps remain deliberately install-wide and now say so where
  they run: a hold a sweep cannot see reads as no hold at all, so narrowing
  those queries would turn a retention job into a way of destroying evidence.
- **Temporary vendor access is under the row-level-security belt, and its usage
  record has a tenant** (migration v148). A temporary access link grants an
  outside party SSH, RDP or VNC into an internal host. An earlier migration
  (v71) had already stopped one tenant from reading or revoking another's links,
  and recorded why it went no further: the page that redeems a link runs with no
  signed-in user, so enforcing tenancy in the database would have broken
  redemption for the vendor, and every management screen was already filtered in
  code. The first reason no longer holds — the same pattern has since been
  solved four times over for other single-use secrets, most recently magic
  links, which redeem exactly this way — so redemption now runs with the
  enforcement deliberately lifted and the link's own organization carried
  through, and the links table is enforced like every other.

  The second reason is why the enforcement is worth having. It guards the next
  query written, not the ones audited when it goes in, and that query was
  already present: the record of who redeemed a link, from which address and
  with what browser, had no tenant column at all and was read by link alone —
  correct only because a separate check happened to run first. It now carries
  its own organization and is filtered on it.

  Two failures on the redemption path are fixed with it: the use counter and the
  usage record were both written without checking whether the write succeeded,
  so an unrecorded connection to an internal host would have gone unnoticed. The
  background sweep that expires stale links stays deliberately install-wide — a
  link past its expiry is expired for everyone, and a sweep that missed a tenant
  would leave a vendor connected — and now says so at the call site instead of
  being silently reduced to nothing by the new enforcement.
- **Breach response is per tenant, and its containment now does what it
  reports** (migration v147). `breach_incidents` and `breach_alerts` — the
  record of what was detected, which users and sessions it affected and what
  containment was applied — had no `org_id`. The console's incident list ran
  with no organization predicate at all, the alert feed filtered only on
  whether an alert had been acknowledged while each alert names a user, a
  session and an IP address, and the pattern analysis aggregated the whole
  install. Both tables now carry `org_id` under FORCE RLS, with existing
  incidents attributed through the users they name and alerts through their
  incident.

  The containment itself was the sharper half. Triggering incident response
  took a bare incident id, while the actions it invokes — disabling the
  affected users and revoking their sessions — were already scoped to the
  caller's organization. An administrator of one tenant could therefore trigger
  response on another tenant's incident, quarantine nobody, and leave that
  tenant's real incident marked as investigated with containment steps recorded
  against it. The incident is now scoped too, so the request is refused rather
  than silently doing nothing.

  Three further failures on the same path are fixed, each of which had been
  invisible because its error was discarded: the full quarantine wrote a
  `status` column that does not exist on the users table (every other disable
  path in the product sets `enabled = false`), so it reported disabling users
  it had not disabled — in its own tenant, not only across tenants; the update
  that records what containment ran wrote a `containment_steps` column no
  migration had ever created, so the quarantine action was never recorded
  either and the incident list showed `none` for fully quarantined incidents
  (v147 adds the column); and both list queries discarded row-scan errors and
  appended a blank row, so a single alert with no session — what the detector
  writes whenever it has no session id — truncated the whole alert list to one
  empty entry with no error shown.
- **The remaining second factors got a tenant** (migration v146). OpenIDX
  offers six second factors; three of them — TOTP, push and WebAuthn — already
  carried `org_id` and sat behind the row-level-security belt, and three did
  not: `mfa_sms`, `mfa_email_otp` and `mfa_phone_call`, along with
  `mfa_otp_challenges`, which holds the code hash, the recipient (a real phone
  number or e-mail address) and the requester's IP for every one-time code in
  flight. The administration console's MFA enrolment report listed all six side
  by side, three of its subqueries carrying an organization predicate and three
  not, under a comment recording the asymmetry as a property of the schema. No
  tenant could read another's rows — every query is keyed on the user, and a
  user belongs to one organization — so this is depth rather than a fixed
  disclosure; what it closes is the absence of any structural guarantee that it
  stays that way, and a challenge whose status and attempt counter were updated
  by bare id. It also completes a pair v143 left half-done: that migration
  belted the phone-call challenges without belting the enrolment they are
  issued against. The enrolment reads on the sign-in path run with the belt
  deliberately lifted and the tenant in the query instead, because the code
  that decides whether to demand a second factor reads an invisible enrolment
  as an absent one — under the belt alone, a user whose only factor is SMS
  would have signed in without it. The per-user uniqueness on each enrolment is
  deliberately left alone rather than made per-organization: the user already
  determines the organization, so a per-organization key would accept strictly
  more rows, and the extra rows are one user enrolled twice. Existing rows are
  attributed to their user.
- **The credentials that stand in for a password got a tenant** (migration
  v145). `hardware_tokens`, `hardware_token_events`, `mfa_bypass_codes`,
  `mfa_bypass_audit` and `magic_links` — five ways to authenticate without the
  password, none of which carried an organization. `hardware_tokens` is an
  inventory of physical tokens, holding the serial and the HOTP/TOTP seed, and
  every call site read and wrote it install-wide: the console's inventory page
  listed every tenant's tokens, and assignment took a bare token id *and* a
  bare user id, so an administrator could bind a token sitting available in
  another tenant's inventory to one of their own users — a transfer of a
  working second factor, not a disclosure of one. Bypass codes are the
  break-glass credential for getting a user past MFA: revoking one took a bare
  code id and revoking all of a user's took a bare user id, so one tenant could
  destroy another's break-glass at the moment it was needed, and the bypass
  audit log's user filter was optional — the console calls it with no user,
  which returned every tenant's history of who issued and used one.
  `serial_number` was UNIQUE across the install and is now unique per
  organization: unlike a SAML entity id it resolves no tenant, so the
  install-wide key only let the first registrant veto everybody else and
  confirmed the existence of hardware another tenant owns. Verification of a
  bypass code, a hardware token and a magic link runs with the belt lifted and
  the tenant in the predicate instead, because those paths do not all have an
  organization resolved yet and an RLS-empty read there would silently retire
  the factor. Existing rows are attributed to their user, their parent token or
  code, or the primary organization.
- **The SAML surface got a tenant** (migration v144). `saml_service_providers`
  — the registry of federation partners this install acts as a SAML identity
  provider for, holding their assertion-consumer URL and the certificate the
  IdP trusts — was listed, counted, fetched, updated, certificate-rotated,
  metadata-refreshed and deleted install-wide, all by bare id. One tenant's
  administrator could enumerate another tenant's partners, repoint their
  assertions at a host of their choosing, or delete their federation.
  `saml_sessions`, the single-logout bookkeeping, joins it under FORCE RLS.
  `entity_id` deliberately keeps its install-wide uniqueness, unlike v143's
  `provider_key`: a SAML entity id is a globally unique URI by specification
  and it is what resolves the tenant on an inbound request, so a per-organization
  key would make that lookup ambiguous. That lookup, and the equivalent one on
  the single-logout path, are documented as spanning organizations for the same
  reason API-key and route lookups do.
- **The sign-in tables got a tenant** (migration v143). `social_providers` —
  the configuration behind the social sign-in buttons — was listed with the
  organization predicate inside a `LEFT JOIN`'s `ON` clause, where it filters
  nothing on the driving table, so every tenant's providers were listed to every
  tenant; get, update and delete then took a bare id with no organization at
  all. Because the sign-in path reads this table for `allowed_domains` and
  `auto_create_users`, one tenant could change which e-mail domains may sign in
  to another tenant's deployment, whether unknown visitors are provisioned
  accounts there, or delete their sign-in button. `provider_key` was also
  UNIQUE across the install, so the first tenant to register `google` took the
  key from everybody else; it is now unique per organization. `trusted_browsers`,
  `passwordless_preferences`, `user_risk_baselines` and `phone_call_challenges`
  join it under FORCE RLS: they were keyed by the organization-scoped user, but
  trusted browsers were updated by bare id and a phone-call challenge could
  carry no user at all. Existing rows are attributed to the identity provider
  they extend or to their own user, with the primary organization as fallback.
- **The unified audit stream got a tenant** (migration v142).
  `unified_audit_events` — the console's Unified Audit page, the assignment-
  and ABAC-gate decision records, the agent lifecycle log, the MCP gateway's
  tool-call log, the Ziti and Guacamole sync and the usage metering rollup —
  had no `org_id` at all, and `QueryEvents` opened `WHERE 1=1`. Every tenant's
  admin could read every tenant's audit trail: the enforcement decisions taken
  on other tenants' applications, their users' actor IPs and, through the query's
  own `users` JOIN, their users' e-mail addresses; the summary endpoint counted
  install-wide the same way. The table now carries `org_id` under FORCE RLS and
  every writer names its tenant; the two external syncs derive it from the route
  they correlate to. Existing rows are attributed to their own user's
  organization, else the organization of the route they name, else the primary
  organization for controller-level events that match neither. Usage metering
  now reads the event's own `org_id` instead of joining `users`, so overlay
  traffic with no user attached is billed to the tenant that ran it rather than
  to an unowned bucket.
- **The compliance record got a tenant** (migration v141). `admin_audit_log`,
  `audit_archives` and `audit_retention_policies` had no `org_id` at all, and
  every handler read them accordingly: the admin log was listed `WHERE 1=1` and
  fetched by bare id, so one tenant's admin could read another's full
  administrative history including the before/after state of changes they had
  no access to make; retention policies were updated and deleted by bare id;
  and archives were listed, fetched **and restored** by bare id, so a tenant
  could name another tenant's export and have the product read that file back.
  All three now carry `org_id` under FORCE RLS, attributed to their own actor's
  organization where one survives.
- **The FORCE-RLS belt extended to fifteen more tables** (migration v140):
  `scheduled_reports`, `detailed_compliance_reports`,
  `audit_webhook_subscriptions`, `usage_metering_daily`, `email_branding`,
  `device_trust_settings`, `pam_active_checkouts`,
  `pam_checkout_authorizations`, `brokered_sessions`, `ssh_ca`,
  `sod_violations`, `privileged_accounts_discovered`, `entitlement_warehouse`,
  `upstream_pools` and `upstream_pool_members` carried `org_id` for as long as
  nine migrations with nothing underneath it, so a single query that forgot its
  predicate would have crossed tenants silently. Four also get `org_id NOT
  NULL`: under a belt, a NULL org is a row nobody can see rather than a row
  that is loudly wrong. `tools/orgscope`'s registers drop from 95 tables to 80.
- **ABAC actually decides something** — `internal/abac`, `ABAC_ENFORCE=off|observe|enforce`,
  wired at both enforcement points (the token endpoint and the access proxy).
  The admin page had authored allow/deny rules that no enforcement point
  consulted.
- **A Definition of Done that CI proves**: the smoke stack, the browser journey
  suite, a `kind` Helm install, `docs` under `--strict`, and the security scans
  gating rather than reporting.
- **Governance (IGA) guide page** — the site had PAM and ZTNA and called it four
  pillars.
- **`scripts/check-docs-drift.sh`** — no document may cite a repo path that is
  not there. Its first run found fifty broken citations.
- **`scripts/check-release-signing.sh`** — a release artifact's name must track
  the key that signed it.
- **`VERSION` + `scripts/check-version-sync.sh`** — the tree carried five answers
  to "what version is this?".
- Every published OpenAPI spec is proven against its binary's route table in
  both directions: 445 documented operations became 1,143 of 1,143.

### Fixed

- **A delegation's scope said more than it did.** The Delegated Administration
  page lets an admin scope a delegation to a Group, Role or Application,
  validates it, shows it as a badge — and the permission check compares resource
  and action only, so the delegated permissions applied wherever that permission
  was checked. The page now marks every narrowing scope **"not enforced"**, the
  create form explains what that means, and the governance guide says to grant
  the smallest permission set rather than rely on the scope. An `organization`
  scope is genuinely enforced (by the tenant predicate the delegation is read
  under) and is not marked. Enforcing the others needs the resource identity of
  each request, which the middleware does not have, and would silently revoke
  access someone is relying on — a product decision, now recorded as one instead
  of implied by a badge.

- **The clientless SSH relay never checked the host key.** `ws_connect.go`
  passed `ssh.InsecureIgnoreHostKey()` unconditionally, under a comment calling
  per-entry pinning "a follow-up" — so a PAM entry could carry a host key and
  nothing would look at it. An entry's `settings.ssh_host_key` (one
  `authorized_keys` line; no migration, the settings column is free-form) is now
  **enforced** via `ssh.FixedHostKey`: a different key fails the connection, and
  a stored key that will not parse fails it too rather than falling back to
  accepting anything. An entry with no pin connects as before and says so — a
  Warn log and `host_key_pinned: false` on the `pam.ws_connect` audit event —
  and `PAM_SSH_REQUIRE_HOST_KEY=true` refuses unpinned entries outright.

- **The 759 `go/log-injection` findings have a verdict, pinned by a test.** Log
  injection is forging a record with CR/LF in a user-supplied value. What
  prevents it here is the encoder, not a sanitiser at 759 call sites: production
  logs JSON, and zap's console encoder still writes structured *fields* as JSON,
  so a newline in a `zap.String` value comes out escaped either way.
  `TestUserValuesInFieldsCannotForgeALogRecord` encodes a forged value through
  both encoders and fails if a raw line break survives — and pins the one shape
  that *would* be a defect, a user value interpolated into the log message,
  which the console encoder writes verbatim. A sweep for that shape finds four
  sites, all interpolating configuration, none user input.

- **Every CodeQL finding at security severity 7.0+ now has a written verdict.**
  `docs/evidence/codeql-triage.md` lists all 40 (27 Go, 13 JS) with the evidence
  for each: what is vendored, what is a protocol requirement, what is already
  sanitised, what is admin-configured, and the one that was a real finding and
  is fixed. A verdict recorded in the code-scanning UI is keyed to an alert
  fingerprint and evaporates when a refactor moves the line — one alert in that
  list had been dismissed once already and came back for exactly that reason.
  The code-scanning results check passes: the one high-severity result in
  changed code was the SSH host key, and fixing it took the count to zero.

- **A token test that failed about as often as a run was slow.**
  `TestTokenService_WithConfig` asserted a token's expiry was within one second
  of a `time.Now()` taken *after* the token was minted. The expiry is
  `mint + 30m` serialised as a JWT `NumericDate`, which carries whole seconds,
  so the difference measured is the elapsed time **plus** a truncation uniform
  on [0s, 1s) -- half the tolerance gone on average before any work happened,
  and any measurable delay pushing a fraction of runs over. The failure rate is
  roughly the elapsed time in seconds: invisible locally, occasional under the
  race detector, certain across enough runs. The assertion now brackets the
  mint and requires the expiry to land in the window the mint could have
  produced, which no amount of slowness moves; setting the duration to 31
  minutes still fails it.

- **A CodeQL config that excluded nothing is gone.** An earlier commit on this
  branch added `.github/codeql/codeql-config.yml` with
  `paths-ignore: agent/third_party`, to keep nine findings in a vendored
  library out of the reader's way. The next analysis produced all nine: a Go
  database is whatever the build compiled, and the path filter is honoured for
  interpreted languages only. A file whose comment claimed it narrowed what was
  scanned, and did not, is the defect class this release spent itself deleting,
  so it is deleted too — `.github/workflows/codeql.yml` now carries the reason
  at the step where the next person would reach for one, and the nine vendored
  findings are on the dismissal list in the triage file where they belong.

- **A second migration system that applied nothing.** `migrations/` held 105
  files and a README calling itself "Database Migration System"; nothing in the
  repository has ever read them. Every service applies the registry in
  `internal/migrations` (Go constants, `loader.go`, v1–v172), and the loose tree
  had stalled at 52 with numbering that never matched — its
  `008_add_scim_identity_tables` is `audit_compliance` in the registry. Worse,
  `openidx migrate create` wrote into it, so a contributor's new migration was
  inert while `openidx migrate up` reported success, and code had been written
  against columns only the dead tree declared. The tree is deleted;
  `openidx migrate create <name>` now writes `internal/migrations/sql_v<N>.go`
  (version taken from the registry) and prints the `loader.go` entry to add;
  `openidx db seed` falls back to `deployments/docker/seed.sql`, the file the
  `seed` service really applies, and fails loudly when no seed exists;
  `openidx paths` names the real directory. `internal/identity/README.md`'s
  schema section, which described a `users_v2`/`groups_v2`/`organizations_v2`
  schema that exists nowhere in this repository, now describes the tables the
  package really reads. `loader.go`'s `//go:build !embed_migrations` named a
  build variant that never existed and is gone.

- **A red CodeQL check named a count, never a rule.** The code-scanning results
  check fails a pull request on one alert with a security severity of 7.0 or
  higher and reports only *"N new alerts including 1 high severity security
  vulnerability"*, while both CodeQL jobs stay green — so nothing in a CI log
  said which rule, in which file. The analysis had been writing the answer to
  `../results/<language>.sarif` on the runner and throwing it away.
  `scripts/codeql-alert-summary.sh` now prints, after each analysis, every
  result at or above that floor with its rule id, file and line, plus a count
  per rule. Diagnostic only: it cannot fail the build.

- **The contract prober accepted any TLS certificate, by default.**
  `tools/contractcheck` probes a running deployment to prove the console's
  declared response shapes match what the backend actually returns — but its
  `-insecure` flag defaulted to on and the transport hard-coded a disabled
  certificate check, so a probe could pass against anything that answered on the
  address, having proved nothing about the deployment it named. Verification is
  now on unless `-insecure` is asked for, the transport takes the flag's value
  instead of a constant, and a TLS 1.2 floor applies either way. (CI is
  unaffected: it probes each service on `http://localhost:<port>`.)

- **The audit trail was not recording.** `audit_events` is behind the FORCE-RLS
  belt, and the pool sets `app.org_id` at checkout from the request context — but
  the oauth (SAML/SSO), identity and provisioning services all wrote it from a
  goroutine on a bare `context.Background()`. Each put the right organization in
  the row and none put it on the connection, so the policy's `WITH CHECK`
  refused every insert and the only trace was a WARN log. Two more of the same
  class were worse: the joiner/mover/leaver policy runner disabled leavers with
  `UPDATE users ... AND org_id = $2` on a detached context, matching its
  predicate and affecting zero rows, and bulk operations and security alerts had
  it too. All now carry the tenant on the context, and
  `scripts/check-detached-org-writes.sh` fails the build on the next one.
- **Audit archives came out empty and said they were fine.** `createAuditArchive`
  runs detached on a bare `context.Background()`, and `audit_events` sits behind
  the RLS belt — so the pool set no `app.org_id` at checkout, the policy matched
  nothing, and every archive completed reporting an event count of zero with no
  error anywhere. The worker now carries the organization that asked for the
  archive.
- **Email branding was a shared row.** Both `email_branding` handlers ignored
  the caller's organization entirely — the read was `ORDER BY created_at LIMIT
  1` and the write was `(SELECT id FROM organizations LIMIT 1)` — so on a
  multi-tenant install every admin saw, and every save overwrote, the same
  single row. Both now scope to the caller's org, and migration v140's policy
  refuses the old write at the database.
- The assignment gate, the OPA `deny` path and the SMS mock provider each failed
  **open**; they now fail closed or refuse to start.
- Five documented `/access/*` auth endpoints that returned 404 (the served
  routes are `/access/.auth/*`).
- Constants dressed as measurements: a literal 365-day uptime, a "refresh" that
  refreshed nothing, a deterministic SAML "transient" NameID.

### Removed

- The server-rendered login (`GET /oauth/login`, the five `/authorize/mfa*`
  routes, `hosted_mfa.go`) — a second credential pipeline outside every i18n and
  accessibility gate this branch built.
- `internal/feature/`, `internal/oauth/store.go`, `client/lib/api/auth.dart` and
  the Expo `mobile/` tree: dead code that read as shipped capability.

### Changed

- The README's "70–80% saving" claim — forbidden on the console's landing page
  by its own test since the truthfulness rewrite — is gone from the README too.

## [1.33.3] - 2026-08-25

_No changelog entries were recorded for this release._

**Why several releases below say that.** `[Unreleased]` was never advanced when
v1.28.0 was cut, so everything written between v1.27.0 and v1.33.3 piled up
under one heading — 359 lines that all read as unshipped. The attribution here
was recovered rather than guessed: `CHANGELOG.md` was touched exactly twice in
that window (`427592d8`, in v1.28.0, and `ddb2ba3f`, in v1.33.2), so each entry
belongs to the release containing the commit that added it. The releases in
between shipped code but wrote nothing here, and saying so is more accurate
than distributing entries across them by feel.

**There is no v1.30.0.** The version sequence skips it — no tag, no release.

## [1.33.2] - 2026-08-24

### Fixed

- **Android/iOS client no longer boots to a blank white screen.** `main()` ran
  the desktop boot path on every platform: it awaited
  `windowManager.ensureInitialized()` (and later `TrayController.init()`), but
  `window_manager` / `tray_manager` are desktop-only plugins with no method-channel
  implementation on mobile. The call threw
  `MissingPluginException(No implementation found for method ensureInitialized on
  channel window_manager)` **before `runApp()`**, so the app started, painted
  nothing, and showed no crash dialog — it just sat on white. `main()` now
  branches on `EngineClientFactory.isMobile`: mobile calls `runApp()` directly
  (leaving `engineSupervisorProvider` un-overridden so `engineClientProvider`
  builds the in-process `MobileEngineClient`), while desktop keeps the unchanged
  window-chrome + tray + sidecar-supervisor path. The rest of the mobile
  code (`MobileShell`, `SettingsScreen`) was already platform-guarded; `main.dart`
  was the only unguarded entry point. The Flutter client version also now tracks
  the release tag (`1.33.2+13302`, was `0.1.0+1`) so the installed build is
  identifiable on-device.

## [1.33.1] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.33.0] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.32.0] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.31.0] - 2026-08-23

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.29.0] - 2026-08-19

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.28.0] - 2026-08-18

### Added

- **Clientless remote access + Quick Links launcher + attended-support consent.**
  A user can now reach support/collaboration systems and remote connections with
  no installed client, and admins manage it centrally. (1) **In-browser SSH**
  ("wasm-ssh" renderer): a PAM SSH entry opens an xterm.js terminal in the
  browser over a WebSocket->TCP relay (`GET /api/v1/access/pam/entries/:id/ws`)
  that dials the target over the Ziti overlay — no PuTTY/guacd, the browser tab
  is the SSH client. Reuses the existing PAM permission/approval gate (enforced
  before the socket upgrade) and credential vault; the token rides as a
  `bearer.<jwt>` WS subprotocol. `pam_entries.renderer` (migration v89) selects
  guacamole (default, unchanged) vs wasm-ssh. (2) **Quick Links** (migration
  v90): an admin-curated, user-searchable launcher. `type=external` opens a safe
  URL (Teams/Zoom/status/ticketing); `type=pam` references a connection and
  launches it clientlessly via its renderer. Org-scoped + forced RLS, role-gated
  by `min_role`, unsafe URLs rejected. New user page (`/quick-links`) + admin
  CRUD (`/quick-links-admin`). (3) **Attended-support consent** (migration v91):
  a remote-support session can require the person at the device to Allow it
  before the admin can view/control — the admin WebSocket is refused (403
  "awaiting device consent") until the device grants via
  `POST /agent/remote-support/sessions/:id/consent`; a denial ends the session.
  Plus a **live view<->control toggle** in the support viewer (hand control back
  and forth without restarting). Verified live end-to-end (real SSH handshake;
  quick-links create/list/reject; consent 403->101). Also fixed a pre-existing
  bug where `remote_support_sessions` lacked `org_id`/`recording_retention_days`
  (referenced by session-start but never migrated), and a migration-runner
  dollar-quote splitter bug that broke fresh `migrate` on v89.

- **Dark platform (Ziti-first / overlay-only posture) — Phases 1-6, fully opt-in.**
  A staged path to make OpenIDX's own surfaces reachable only over the OpenZiti
  overlay, defaults preserving today's public behavior at every step. (1)
  `SERVICE_BIND_ADDR` + `DARK_MODE_TIER1/2` config and `cfg.ListenAddr()` so every
  service can bind loopback-only (verified live). (2) `#enrolled-users` on every
  identity + gated `#device-trusted`, and a reconciler `ensureTierDialPolicy`.
  (3) A single hardened public enroll door `POST /api/v1/access/enroll`
  (session/token → Ziti enrollment JWT, rate-limited + audited; verified live,
  fail-closed on every bad path). (4) `DARK_MODE={off|tier2|tier1}` edge route
  set + `scripts/dark-mode.sh` (`--verify`/`--undark`/`--self-test`) + `make
  dark-drill`. (5) The reconciler now models OpenIDX's own surfaces as tier'd
  dark Ziti services via `defaultDarkServices()` (admin-api/governance/audit/
  provisioning/scim/access → Tier 2 `#device-trusted`; identity self-service +
  console → Tier 1 `#enrolled-users`; enroll/oauth/jwks never darked), plus
  `scripts/register-console-dark-app.sh` registering the admin console as a
  BrowZer dark app (Tier-1 shell, same-origin `/api/*` tunnels to the Tier-2
  backends). (6) Staged **cutover runbook + break-glass** in
  `OPENIDX_ZITI_ARCHITECTURE.md` (enroll fleet → drill → cut Tier 2 then Tier 1
  → `--undark`), linked from `DEPLOYMENT.md`, and **mutation-tested tier
  invariants** wired into `make dark-drill` (Tier-2 surfaces must be
  `#device-trusted`; no Tier-0 surface is ever darked; dark upstreams are
  loopback). Spec/plan under `docs/superpowers/`.

- **Scoped the Tier 3b cutover: `docs/tier3b-cutover-runbook.md`.** The
  availability plan recommended moving prod off the single VM onto the
  already-written EKS/managed path but left the *cutover* itself unsequenced. New
  runbook lays out the end-to-end move: preconditions (a passing `make ha-drill`
  and a live DR game-day PASS), closing the two open infra gaps (add an OpenSearch
  Terraform module; activate the RDS read replica via `externalSecrets.readReplica`
  — everything else is wired), standing up the EKS stack in parallel on a shadow
  DNS name, the data cutover (logical replication preferred, dump/restore
  fallback), a DNS traffic cutover that deliberately flips the **DB-independent
  verify surfaces first** so token validation never stops, post-cutover
  activation/verification, and rollback at each stage. It leans on the
  always-available invariant (verification does not depend on which stack/DB is
  live) that `make dr-game-day` checks at every gate. Also surfaced and wired the
  concrete config gap it identified: `values-prod.yaml` now carries a documented
  `externalSecrets.readReplica` flag (left `false` so a fresh cutover's
  ExternalSecret doesn't reference a missing key; flip on as a follow-on step).
  Verified `helm template` renders clean with the flag both off (no
  `DATABASE_READ_URL`) and on (rendered). Linked from the availability plan and
  `DEPLOYMENT.md`.

- **Repository pattern reaches the admin god-object (`SettingsRepository`).**
  Began strangling `internal/admin/service.go` (3,439 lines — the largest
  god-object in the design-patterns review) by extracting all `system_settings`
  access into `internal/admin/settings_repository.go`. That table is a key/value
  JSON store (`system`, `sms_config`, `mfa_methods`, ...) whose identical
  `SELECT value FROM system_settings WHERE key = $1` + `INSERT ... ON CONFLICT
  (key) DO UPDATE` UPSERT was copy-pasted inline across ~6 handlers, each free to
  pick its own pool. It's now one `GetRaw`/`PutRaw` port with a typed
  `ErrSettingNotFound` and nil-db guards; `admin.Service`'s `GetSettings`/
  `UpdateSettings` + the SMS/MFA-methods handlers delegate to it. **Pool
  judgment:** reads use the **primary**, not the replica — `system_settings`
  carries password policy, `RequireMFA`, lockout, and session limits, so a
  just-tightened policy must take effect immediately (read-after-write); a lagging
  replica could briefly enforce a weaker policy. Locked by a mutation-tested
  invariant guard (`TestSettingsRepositoryGetUsesPrimary`/`WritesUsePrimary`,
  wired into `make ha-drill`; verified it fails when a write is moved to
  `.Reader()`) and unit-tested with a fake repo and no database (defaulting,
  corrupt-row fallback, write-error propagation, nil-db guards).

- **`make dr-game-day` — the data-tier failover game-day is now runnable, not a
  copy-paste runbook.** `docs/disaster-recovery.md` §1D previously described the
  RDS Multi-AZ / Patroni failover drill as manual shell steps in a comment block.
  New `scripts/dr-game-day.sh` executes it end-to-end: a synthetic auth canary
  probes `/health/live` (verify path — must stay 200 the entire window, since
  verify is DB-free/serve-stale) and `/health/ready` (issue path — may 503 while
  the LB drains new logins, then must self-recover as pgxpool re-dials the
  promoted primary), then prints a pass/fail verdict and exits non-zero on any
  contract violation. It can trigger failover itself (`--trigger --provider
  rds|patroni`) or just observe. Crucially it ships a **`--self-test` mode** that
  stands up a local stdlib mock simulating a failover window and runs the whole
  canary/verdict logic against it — so the drill is verified with no
  infrastructure and can't silently rot into a false-green (a false-green DR
  drill is worse than none). `make dr-game-day` runs that self-test; verified it
  passes on a clean window and fails correctly on both a verify-path drop and a
  non-recovering issue path.

- **`make ha-drill` — one command to verify the always-available-auth
  guarantees.** Runs the focused Go tests that encode each availability tier
  (serve-stale JWKS + Auth-survives-issuer-outage; bounded DB timeouts +
  read-replica seam; dependency-outage classification + 503 brownout + Redis
  revocation breaker) plus the mutation-tested read/write pool-safety guards. The
  wrapper (`scripts/ha-drill.sh`) fails loudly if a guarantee test is renamed or
  removed (no silent "[no tests to run]" false-green), so the drill stays
  trustworthy. Runs in ~15s with no infrastructure; complements the DR failover
  game-day. See `docs/architecture/always-available-auth-plan.md` §5.

- **Repository pattern reference implementation (identity/User).** Introduced
  `internal/identity/user_repository.go`: a `UserRepository` interface +
  `PostgresUserRepository` pgx implementation
  (`GetByID`/`GetByUsername`/`GetByEmail`/`Exists` reads via `db.Reader()`, plus
  `Create`/`Update`/`Delete` writes on the primary pool) that isolates user SQL
  into one type, scopes every query to the caller's tenant, and makes the
  primary-vs-replica choice explicit (reads offload to the Tier 1.6 replica;
  writes never do). `identity.Service.GetUser`/`GetUserByUsername`/
  `GetUserByEmail`/`CreateUser`/`UpdateUser`/`DeleteUser` now delegate to it
  (behavior-preserving; domain side effects like audit logging, deprovisioning,
  and delete ordering stay in the service). Along the way this fixed a latent
  NULL-name scan error in the username/email lookups, guarded two nil-DB
  panics (`logAuditEvent`, `deprovisionUser`), and surfaces duplicate
  username/email as a typed `ErrUserAlreadyExists` (409). This is the template
  for splitting the god-object services (see
  `docs/architecture/design-patterns-review.md`). Business logic (full CRUD) is
  now unit-testable with a fake repo and no database (`user_repository_test.go`).

- **Repository pattern — second aggregate (identity/Group).** `Group` is now
  behind `GroupRepository` (`internal/identity/group_repository.go`) following the
  same template: `GetByID`/`GetByName` reads on the replica, `Create`/`Update`/
  `Delete` writes on the primary (Delete removes memberships then the group row),
  typed `ErrGroupNotFound`/`ErrGroupAlreadyExists`. `identity.Service`'s
  `GetGroup`/`GetGroupByDisplayName`/`CreateGroup`/`UpdateGroup`/`DeleteGroup`
  delegate to it. Unit-tested with a fake repo and no database
  (`group_repository_test.go`).

- **Repository pattern — third aggregate (identity/Session).**
  `SessionRepository` (`internal/identity/session_repository.go`) demonstrates
  per-query pool judgment: lag-tolerant reads (`ListByUser`/`CountActive`) use the
  replica, while `IsValid` deliberately reads the **primary** because session
  validity is a read-after-write security check (a just-revoked session must not
  read as valid off a lagging replica). Writes (`Create`/`UpdateActivity`/
  `Terminate`) use the primary. `identity.Service`'s `GetUserSessions`/
  `CreateSession`/`UpdateSessionActivity`/`IsSessionValid`/`CountActiveSessions`/
  `TerminateSession` delegate to it. The security-critical primary read is locked
  by a mutation-tested guard (`TestSecurityCriticalReadUsesPrimary`), and the
  writes-never-replica guard now covers all three repositories. Unit-tested with a
  fake repo and no database (`session_repository_test.go`).

- **Repository pattern generalizes to the oauth service (OAuth clients).** OAuth
  client CRUD is now behind `OAuthClientStore`
  (`internal/oauth/oauth_client_store.go`): `GetByClientID` reads the primary
  (client validation gates every token grant and checks the secret), `List` reads
  the replica, and `Create`/`Update`/`Delete` write the primary.
  `oauth.Service`'s `GetClient`/`ListClients`/`CreateClient`/`UpdateClient`/
  `DeleteClient` delegate to it; guarded by a mutation-tested invariant test and
  unit-tested with a fake store and no database. Also documented a pre-existing
  smell surfaced by this work: the oauth package has a *separate* `ClientRepository`
  (`client.go`, used by `token_flow.go`) that models the same `oauth_clients` table
  differently — a worthwhile unification follow-up (see
  `docs/architecture/design-patterns-review.md`). **(Resolved below in
  Removed — that duplicate turned out to be unwired, security-divergent dead code
  and was deleted.)**

### Fixed


- **Admin-console unit tests can run again (frontend test env repaired).**
  `vitest.config.ts` requested `environment: 'happy-dom'`, but `happy-dom` was
  never in `package.json` (only `jsdom` is a pinned devDependency), so `npm test`
  / CI's `npm test -- --run` died immediately with `ERR_MODULE_NOT_FOUND` and
  ran **zero** tests. Switched the config to the installed `jsdom` environment
  and added the one jsdom shim happy-dom provided that Radix UI needs:
  `Element.prototype.scrollIntoView` (a no-op mock in `src/test/setup.ts`),
  which `@radix-ui/react-select` calls on mount and which otherwise threw
  `candidate?.scrollIntoView is not a function` and failed every Select-based
  test. Result: the full suite now runs green — **761 tests across 122 files
  pass** (previously: could not start). This also unblocks the `ci-web`
  pipeline. No new dependency added.

### Security

- **Closed ~170 server-error information-disclosure sites: 5xx responses no
  longer leak `err.Error()` to clients.** Handlers across 30+ files (access/Ziti,
  identity MFA/risk, vault, credentials, audit, organization, portal, oauth
  client-management) were returning the raw wrapped error
  (`c.JSON(500, gin.H{"error": err.Error()})`) — which can expose SQL fragments,
  hostnames, driver text, and internal paths. Every 5xx `err.Error()` leak was
  migrated to the typed renderer `apperrors.HandleErrorWithLogger(c,
  apperrors.Internal("<action>", err), logger)`, which returns a safe, typed body
  (`{"error":"INTERNAL_ERROR","message":"<action>"}`) to the client while logging
  the real cause server-side with request-id/path context. Where a handler
  already logged the error immediately before leaking it, that now-redundant log
  line was removed to avoid double-logging (the renderer logs). Protocol
  endpoints kept their RFC 6749 shape (e.g. the OAuth authorize/consent path
  still returns `{"error":"server_error"}`, now with a static
  `error_description` instead of the raw error). A count check enforces zero
  remaining 5xx `err.Error()` leaks. **Surfaced and fixed a latent bug in the
  process:** `portal.ReviewGroupRequest` returned its "invalid decision"
  *validation* error as a 500 leak; it now returns a typed `ErrInvalidDecision`
  sentinel that the handler maps to a proper 400. `go build ./...`,
  `go vet ./...`, and the touched-package tests all pass.

### Removed

- **Collapsed the admin-console's two parallel API clients — deleted the entire
  dead `src/lib/api/` directory (client + domain wrappers + barrel; ~800 lines).**
  The console had two API layers: the live `src/lib/api.ts` (the `api` object,
  imported by ~199 modules) and a second, separate `src/lib/api/` package
  (`client.ts` axios instance + `admin`/`audit`/`governance`/`identity` wrappers +
  `types.ts` + an `index.ts` barrel re-exporting `apiClient as api`). Because a
  file (`api.ts`) wins module resolution over a same-named directory
  (`api/index.ts`), **every `@/lib/api` import hit `api.ts` and the whole
  directory had zero live importers** — a classic duplicate-that-can-drift trap
  (the two clients had already diverged on token-storage keys and the
  refresh-token endpoint, both fixed earlier). Verified exhaustively that nothing
  outside the directory imported any of its modules, then removed it. The one
  place that referenced it — `dashboard.test.tsx` — was `vi.mock()`-ing the dead
  `./lib/api/client` while the component under test actually imports `{ api }`
  from `../lib/api`, so the mock was inert; retargeted it to mock the real
  `../lib/api`, which also makes the test's stubbing actually take effect.
  `tsc --noEmit`, the full vitest suite (746 tests / 121 files pass; the −15 vs
  before are exactly the deleted `audit.test.ts` that only tested the dead
  `auditApi`), and `vite build` all pass.

- **Deleted a dead, security-divergent duplicate OAuth/OIDC pipeline
  (`client.go`, `authorize_flow.go`, `token_flow.go`; ~3,100 lines incl. tests).**
  The oauth package carried a second, fully parallel implementation
  (`Client` / `ClientRepository` / `AuthorizeFlow` / `TokenFlow`) operating on the
  same `oauth_clients` table as the live `OAuthClient` / `OAuthClientStore`, but it
  was **never wired to a live route** — only reachable from tests. It had also
  already diverged from the live path on a security check: the dead
  `ClientRepository.ValidateRedirectURI` permitted wildcard-subdomain redirect
  URIs (`https://*.example.com`, an open-redirect risk), while the live authorize
  handler requires exact byte-equality. Two representations of one table that can
  disagree — and insecure dead code invites someone to wire it — so the cluster
  was removed. The authoritative representation is `OAuthClient` (+
  `OAuthClientStore`); live token/authorize/userinfo flows remain in
  `service.go` / `authorize.go`. The three genuinely-live symbols the cluster
  exported (`TokenFlowResponse`, `generateUUID`, and the RFC 6749 error-code
  constants used by the 503 brownout path) were preserved in a small new
  `internal/oauth/oauth_types.go`. Redundant validation tests were dropped only
  after confirming equivalent live coverage
  (`TestAuthorizeHandler_ValidateRedirectURI`, `TestValidatePKCE`,
  `TestSecurityFeatures`); `TestOAuthConstants` was retargeted onto the preserved
  constants. `go build ./...`, `go vet ./...`, and `go test ./internal/oauth/`
  all pass. See `docs/architecture/design-patterns-review.md` §1.

### Changed

- **Hardened the shared error renderer (`internal/common/errors`).** `HandleError`
  now guarantees the client only sees safe, typed fields (never the wrapped
  internal error), and a new `HandleErrorWithLogger(c, err, logger)` logs the real
  cause server-side for 5xx (with request id + path) instead of silently dropping
  it. Closes an information-disclosure vector and an observability gap. Tests in
  `render_test.go` verify a DB error containing a password/hostname is logged but
  not leaked to the response body. First adopters migrated in
  `internal/identity/handlers_otp.go` (internal-error sites that previously
  discarded the underlying error now log it via `HandleErrorWithLogger`).

- **Always-available authentication — Tier 0 (verify-path survives a DB outage).**
  Token *verification* (validating an already-issued JWT) is now hardened to keep
  working through an outage of the OAuth/JWKS endpoint and the shared database:
  - **Serve-stale JWKS.** The shared verify path
    (`internal/common/middleware`, used by all services) and the gateway JWT
    middleware now keep serving the last successfully fetched signing keys when a
    JWKS refresh fails, bounded by `JWKS_MAX_STALE` (default 12h) past the
    `JWKS_TTL` freshness window (default 1h). Previously a failed refresh after
    cache expiry rejected otherwise-valid tokens, turning a database blip into an
    auth outage.
  - **Metrics + alerts.** New `openidx_jwks_refresh_failures_total`,
    `openidx_jwks_serve_stale_total`, and `openidx_jwks_stale_seconds`, with a
    `openidx.jwks_availability` PrometheusRule group (issuer-down, serving-stale,
    and near-max-stale alerts).
  - **Liveness/readiness probe split.** Every Helm service pointed both probes at
    `/health` (which 503s when the shared DB is down), so a DB blip would restart
    every pod at once and wipe warm JWKS caches. Liveness now uses `/health/live`
    (process-only), readiness uses `/health/ready` (drains from the LB on a
    critical dependency outage), for graceful degradation instead of a crash-loop.
  - Docs: `docs/architecture/always-available-auth-plan.md`.

- **Always-available authentication — Tier 1 (issue path survives DB failover).**
  - **Bounded DB connect timeout.** pgxpool's default `ConnectTimeout` was 0
    (unbounded), so a runtime reconnect to a dead primary during an RDS/Patroni
    failover could hang for minutes, pin the request, and exhaust the pool — a DB
    failover cascading into a service-wide outage. `internal/common/database` now
    sets a 5s connect timeout (`DB_CONNECT_TIMEOUT`) so failover fails fast and the
    pool re-dials the promoted primary.
  - **Optional per-statement timeout** (`DB_STATEMENT_TIMEOUT`, 30s in prod
    values) so a query on a degraded primary can't hold a connection open forever.
    Off by default; migrations run out-of-band and are unaffected.
  - Wired through the Helm configmap (`database.connectTimeout` /
    `database.statementTimeout`), set in `values-prod.yaml`. Tests:
    `internal/common/database/pool_config_test.go`. Added a Postgres failover
    game-day to the DR runbook.
  - **Optional read-replica pool.** `DATABASE_READ_URL` opens a second read-only
    pool exposed via `(*PostgresDB).Reader()`, which falls back to the primary
    when no replica is configured (correct-by-construction call sites). A replica
    outage never fails startup (degrades to primary-only) and is surfaced by a
    new non-critical `database_replica` health check. Delivered via the external
    secret store (`externalSecrets.readReplica`). Query call sites are not
    auto-routed — adoption is per-query where read-after-write is not required.
    Tests: `read_replica_test.go`, `read_replica_checker_test.go`.

- **Always-available authentication — Tier 2 (graceful brownout on the issue path).**
  Added `internal/oauth/unavailable.go`: a classifier that distinguishes a
  transient dependency outage (Postgres/Redis unreachable, pool exhausted, dial
  timeout, `57P0x`/`08xxx`/`53300`/`25006` SQLSTATEs, network errors) from a
  genuine application error, and returns RFC 6749 `503 temporarily_unavailable`
  with a `Retry-After` header for the former (clients back off and retry) while
  keeping `500 server_error` for the latter. Applied to the DB-backed OAuth
  issue-path sites (authorization-code creation, refresh-grant user-status
  check), so a database failover degrades login to a brief, retryable brownout
  instead of a hammered 500. Tests: `internal/oauth/unavailable_test.go`.
  - **Redis revocation-check circuit breaker.** `IsAccessTokenRevoked` (the
    hot-path revocation read used by token introspection/verification) now runs
    its Redis reads through a circuit breaker (`oauth-redis-revocation`,
    threshold 5, 5s reset). During a Redis brownout the breaker opens and the
    check fails fast instead of every request paying the 3s Redis read timeout.
    Callers already fail closed on error, so opening the breaker changes cost, not
    security. Observable via `openidx_circuit_breaker_state{name=
    "oauth-redis-revocation"}` (existing `CircuitBreakerOpen` alert). Test:
    `internal/oauth/revocation_breaker_test.go`.

- **Always-available authentication — Tier 3 (infra for HA prod).** The Terraform
  RDS module now provisions optional read replica(s) (`read_replica_count`,
  defaulted to 1 in prod / 0 in dev) and exposes `rds_reader_endpoints` /
  `rds_reader_addresses`. This is the managed reader endpoint the Tier 1.6
  `DATABASE_READ_URL` app seam points at — previously the app supported a read
  pool that prod had no way to create. Wire the output into the external secret
  `.../database-read-url` and set `externalSecrets.readReplica=true` to activate
  it. (`deployments/terraform/modules/rds`, `deployments/terraform/main.tf`.)

## [1.27.0] - 2026-07-13

### Added

- **PAM per-connection broker routing — direct vs OpenZiti (#439)** — each connection
  entry selects a `reach_mode`: `direct` (guacd dials the target) or `ziti` (guacd →
  loopback → ziti-tunnel → OpenZiti overlay → target, no inbound target exposure).
  Migration **v82** adds `reach_mode`/`ziti_service_name`/`ziti_intercept_port` to
  `pam_entries`.
- **PAM dedicated session brokers — deploy artifacts (#440)** — opt-in docker-compose
  overlay and Helm templates for two isolated Guacamole brokers (direct + ziti) with
  their own DB and admin credentials, kept separate from any shared Guacamole. Gated by
  `pamBroker.enabled` (default off → zero manifests).
- **Split internal vs browser-facing Guacamole URL (#441)** — `GUACAMOLE_PUBLIC_URL` /
  `GUACAMOLE_ZITI_PUBLIC_URL`: the access service dials the internal broker for the REST
  API but hands the browser a reverse-proxy-reachable connect URL. Falls back to the
  internal URL when unset.

### Fixed

- **Brokered PAM launch was not idempotent (#441)** — the Guacamole connection name is
  deterministic (`pam-<entryID>`); once created, a relaunch without a persisted connection
  id hit Guacamole's `409/400 "already exists"` → 500. Now the launcher looks the
  connection up by name, updates it in place, and reuses it.
- **SAML service-provider schema drift** — `internal/oauth/saml_sp.go` read/wrote columns
  (`description`, `metadata_url`, `want_assertions_signed`, `encryption_enabled`,
  `last_used_at`) that no migration had created, so the SP admin list/create/update paths
  errored with `42703`. Migration **v83** reconciles the table (additive; TEXT columns
  `NOT NULL DEFAULT ''`, booleans default false, `last_used_at` nullable).

### Migrations

- **v82** — `pam_entries` reach mode (direct|ziti) columns + partial unique index on the
  ziti intercept port.
- **v83** — `saml_service_providers` column reconcile.

## [1.26.0] - 2026-07-12

### Added

- **PAM connection manager — RDM parity (#437)** — a Remote Desktop Manager-style privileged
  connection tree for brokered, passwordless sessions:
  - Folders/entries model (`pam_folders`, `pam_entries`) with tags, per-entry policy flags
    (`allow_reveal`, `require_approval`, `record_session`), grants (`pam_entry_grants`),
    favorites, access requests, and a session ledger (`pam_entry_sessions`) — all org-scoped
    under FORCE RLS.
  - Import path for existing connection inventories and a launch path that opens brokered
    sessions without exposing the underlying vault credential.
  - New **PAM Connections** console page (`/pam-connections`) and API client wiring; nav entry
    under the Privileged Access section.
  - CR/LF scrubbing on user-derived values in the import/launch log lines.

### Migrations

- **v81** (additive) — `pam_folders`, `pam_entries`, `pam_entry_grants`, `pam_entry_favorites`,
  `pam_entry_access_requests`, `pam_entry_sessions` with per-table org-scope RLS policies and
  `openidx_app` grants.

## [1.25.0] - 2026-07-12

Large security-and-correctness release (workstreams WS-01…WS-05) plus cross-pillar
correlation, OAuth signing-key rotation, PAM self-service, and a substantial dead-code
purge. Schema advances **v68 → v80** (migrations v69–v80, all additive). Deployed to the
reference box via a full catch-up (schema v68→v80, 8-binary swap); functional sweep of all
services clean.

### Security

- **OAuth step-up MFA bypass closed (WS-01)** — the step-up flow no longer rubber-stamps MFA,
  and MFA-gating can't be bypassed; the authorize-consent subject is derived from the session,
  not the request body.
- **Cross-tenant IDOR fixes (WS-03)** — tenant-scoped `published_apps`/`discovered_paths`,
  `temp_access_links`, and `device_trust_requests`; `GET /organizations` no longer enumerates
  other tenants and org write paths are authorized; Elasticsearch audit search is tenant-scoped;
  portal device registration now stamps the caller's `org_id` (was mis-tenanted to the default org).
- **Minted API keys now actually authenticate requests (WS-03)** — previously issued keys were inert.
- **Separation-of-duty enforced and fail-closed (WS-05)** — SoD policies are evaluated at
  access-request fulfillment and in identity; evaluation failures fail closed.
- **Fail-open hardening** — `CheckPolicies` fails closed when org context is absent; three
  fail-open error paths in the live security checks are closed. Approval policies'
  `auto_approve_conditions` evaluate fail-closed.
- **Log-injection sanitization** — CR/LF and user-derived values scrubbed from cross-pillar,
  step-up MFA, and IBDR/continuous-auth log lines (CodeQL).

### Added

- **Cross-pillar correlation** — correlate IAM, PAM, and Ziti per user: unified access map,
  kill switch, and lifecycle propagation; a user's devices are correlated across IAM trust and
  Ziti compliance.
- **OAuth DB-backed signing-key rotation** — `oauth_signing_keys` (migration v79) backs rotatable
  RS256 signing keys.
- **Governance (WS-05)** — audit + session-kill on access-review revocation; manager-based
  reviewer resolution; `org_id` + FORCE RLS on certification/ABAC tables; JIT expiry now revokes
  application access.
- **Provisioning** — provisioning rules are evaluated on SCIM user create/update (safe additive
  subset); SCIM `filter` applied in `ListSCIMUsers`/`ListSCIMGroups`.
- **Audit** — `detailed_compliance_reports` table (migration v74) with org-scoped evidence access;
  GDPR report routed; WebAuthn MFA counted from `mfa_webauthn` in SOC2/ISO metrics.
- **Identity** — `known_devices.device_type` (migrations v75/v76) so corporate-device
  auto-approval works.
- **PAM finalization — end-user self-service** — non-admin users get a first-class PAM surface:
  - `GET /api/v1/access/guacamole/my-connections` — org-scoped catalog of brokered Guacamole
    connections with the PAM flags the launcher needs (approval required / recorded /
    credential injected); never exposes the vault secret id or Guacamole-internal identifiers.
  - `GET /api/v1/access/guacamole/my-session-requests` — the caller's own session requests
    (previously only admins could list requests), joined with route info so an approved
    request can be launched.
  - New **My Privileged Access** console page (`/my-privileged-access`, in the user nav):
    launch/request brokered remote sessions, track request status, and manage JIT credential
    checkouts (one-shot retrieve + early return) in one place.
- **PAM finalization — management dashboard** — new aggregated stats endpoint
  `GET /api/v1/pam/overview` (admin-api, admin-guarded; explicit org predicates on top of
  FORCE-RLS) covering vault inventory by type, rotation health (enabled/failing/overdue
  policies, 30-day runs/failures), checkout activity (active leases, 30-day checkouts,
  pending JIT credential requests), and privileged sessions (active, 30-day, pending
  approvals, recordings on legal hold). New **PAM Dashboard** console page
  (`/pam-dashboard`) renders it with health labels and manage links; linked from the
  dashboard's Privileged Access card and the Privileged Access nav section.

### Changed

- **Admin PAM routes are now role-gated client-side** — `/pam-dashboard`, `/vault-secrets`,
  `/rotation-policies`, and `/guacamole-sessions` no longer mount for non-admins (redirect
  to the dashboard); the backend 403 remains the enforcement layer. Vault Secrets and
  Privileged Sessions now render a friendly "admin access required" state on 403 (matching
  Rotation Policies) instead of a generic failure.
- **Legal-hold reasons via a proper dialog** — the Session History place/release legal-hold
  flow uses an accessible reason dialog (reason required to place a hold) instead of
  `window.prompt`.

### Fixed

- **Governance revocation actually revokes** — access-review revoke decisions now revoke access;
  role-based approval steps get real approvers; stopped silent audit loss on JIT grant/expiry.
- **"Phantom table" correctness sweep** — features now read the real schema instead of
  never-created tables: MFA/WebAuthn metrics from `mfa_webauthn` (not `webauthn_credentials`),
  GDPR consent from `user_consents` (not `consent_records`), user groups from `group_memberships`
  (not `user_groups`), breach detection and continuous auth on real tables, MFA method status and
  biometric/passwordless from real enrollment tables.
- **Risk** — admin-configured risk policies are applied (was a `parseJSON` no-op); device tracking
  uses real `known_devices` columns; `GetUserDevices` no longer silently drops rows with NULL text
  columns.
- **Dashboard** — dropped a non-existent `users.deleted_at` predicate that errored and made the
  admin dashboard silently report zero users (#435).
- **Admin console** — reads the bare-array `/organizations` response so the tenant UI renders (WS-03).

### Removed

- **Dead-code purge (~8.8k+ lines)** — deleted five never-wired subsystems and additional dead
  paths: the OAuth `KeyManager` and its phantom `oauth_signing_keys` layer, the unrouted
  `CertificationService` and WebAuthn subsystem, the never-functional admin passwordless subsystem,
  the dead AI policy-recommendations route, and orphaned CSV-import handlers.

### Migrations

- **v69–v80** (all additive): governance org-isolation (v69), `users.manager_id` (v70),
  `temp_access_links`/`device_trust_requests`/`published_apps` tenant isolation (v71–v73),
  `detailed_compliance_reports` (v74), `known_devices.device_type`/`seen_count` (v75/v76),
  session-risk history (v77), recording retention policies (v78), `oauth_signing_keys` (v79),
  enrolled-agent ↔ known-device link (v80).

## [1.24.11] - 2026-07-09

### Changed

- **tailwind-merge 2→3** (#54, flagged dependabot runtime major) — used only via the default
  `twMerge(clsx(...))` `cn()` helper, so v3's custom-config breaking changes don't apply. Validated by
  `vite build`, eslint, and 730 vitest tests; admin-console dist rebuilt + deployed.

## [1.24.10] - 2026-07-09

### Changed

- **Frontend build/type tooling majors** — `@types/node` 22→25, `globals` 15→17, `@vitejs/plugin-react`
  4→5 (from the flagged dependabot backlog). `tsc`+`vite build` clean, `eslint` 0 errors; admin-console
  dist rebuilt + deployed. `eslint` 9→10 is **deferred** — the eslint-10 ecosystem isn't ready
  (`eslint-plugin-react-hooks` peer-requires eslint≤9; eslint 10 drops bundled `@eslint/js`).

## [1.24.9] - 2026-07-09

### Fixed

- **SSO audit events now counted in compliance reports & statistics** (#392) — the OIDC SSO audit
  events added in v1.24.7/v1.24.8 used `event_type=sso.login` (with `category=authentication`),
  backwards from the platform convention where authentication events use `event_type=authentication`
  and the compliance/statistics queries filter on it. As a result SSO activity was excluded from
  compliance reports and failed-auth stats. Normalized all OIDC SSO events to
  `event_type=authentication`, `category=sso` (the `sso.*` descriptor is retained as the `action`,
  e.g. `sso_login`, `sso_user_provisioned`), so SSO logins/failures are counted like every other
  authentication event.

## [1.24.8] - 2026-07-09

### Added

- **Failed-login audit for SSO/SAML** (#388, #389) — the OIDC callback and SAML IdP SSO handler
  now emit `outcome=failure` audit events at every failure exit (OIDC: invalid_state,
  token_exchange_failed, id_token_verification_failed, missing_email_claim, provisioning_failed;
  SAML: invalid_authn_request, unknown_service_provider, acs_url_mismatch, sp_disabled,
  response_build_failed). This surfaces attacks/misconfiguration (forged tokens, unregistered-SP
  probing, ACS-URL tampering) in the audit trail, complementing the success events from v1.24.7.
- **Audit events queryable by target** (#390) — `GET /api/v1/audit/events` now honours a
  `target_id` filter (the `AuditQuery.TargetID` field was previously unused), so auditors can scope
  the trail to everything affecting a specific user or resource.

### Changed

- **Dependency bumps** (#386, #387) — `go.uber.org/zap` 1.27→1.28, `pquerna/otp` 1.4→1.5,
  `spf13/viper` 1.18→1.21; frontend `autoprefixer`, `lucide-react`, `eslint-plugin-react-refresh`.
  Part of clearing the dependabot backlog (superseded/stale PRs closed; major bumps flagged for review).

## [1.24.7] - 2026-07-09

### Added

- **SSO/OAuth audit events are now persisted** (#384) — the oauth service's `logAuditEvent`
  previously logged only to the application log, so SSO/OAuth/SAML activity (logins, logouts,
  single-logout, JIT provisioning) never reached the `audit_events` table and was absent from the
  audit query API (`GET /api/v1/audit/events`) and compliance reports. It now persists to
  `audit_events` (async, org-scoped, best-effort — never blocks or fails the request), matching the
  identity service's pattern; the application log is retained.
- **SSO JIT lifecycle audit trail** (#384) — the OIDC callback now emits `sso.user.provisioned`,
  `sso.identity.linked`, `sso.identity.matched`, `sso.identity.backfilled`, and `sso.login`,
  giving a queryable record of how SSO accounts are provisioned, federated-linked, and
  authenticated (builds on the federated-identity work in v1.24.4–v1.24.6).

## [1.24.6] - 2026-07-08

### Changed

- **Backfill the federated identity link for email-matched JIT users** (#369) — completes the
  #364/#367 migration: when a returning OIDC user is matched by email (created before the
  `idp_id`/`external_user_id` binding existed), the login handler now best-effort backfills those
  columns (only when currently unset), so subsequent logins match by `(idp_id, sub)`. Keyed by the
  matched `users.id`; nil-guarded and error-logged, never affects login.

## [1.24.5] - 2026-07-08

### Changed

- **OIDC JIT provisioning matches returning users by IdP subject before email** (#367) — the login
  handler now looks an existing user up by `(idp_id, sub)` first (explicitly org-scoped), falling
  back to email, then creating. A federated user whose email changed at the IdP is no longer treated
  as new (which would have created a duplicate colliding with the unique `(idp_id, external_user_id)`
  index #364 populates). Additive: any lookup miss/error falls through to the prior email path, so
  existing behavior is preserved.

## [1.24.4] - 2026-07-08

### Security

- **Go toolchain → go1.25.12** (#363) — the pinned `toolchain go1.25.11` forced builds onto a
  `crypto/tls` affected by **GO-2026-5856**, failing the govulncheck gate and shipping the vulnerable
  TLS stack in binaries. Bumped to go1.25.12 (govulncheck clean).
- **SAML SLO session-cookie cleared with `Secure` in production** (#362) — `clearIdPSession` cleared
  `openidx_session` with `Secure=false` unconditionally; now tied to `IsProduction()` (matching the
  proxy session-cookie convention), so the deletion still clears over plain HTTP in dev while carrying
  `Secure` in production. Clears `go/cookie-secure-not-set`.

### Fixed

- **Capture `Close` errors on writable files** (#361) — three writable-file writers
  (session-recording append, append-only store, shell-completion install) deferred a bare `Close()`,
  discarding the error; for a writable handle the final flush can surface only at `Close`, so this
  silently dropped data. Each now propagates the `Close` error. Clears `go/unhandled-writable-file-close`.
- **Bind JIT-provisioned users to the IdP subject** (#364) — the OIDC login handler captured the ID
  token `sub` but discarded it, leaving `users.idp_id`/`external_user_id` unpopulated. It now persists
  the federated link on JIT create (best-effort, RLS-scoped). Resolves the dropped-value
  `go/useless-assignment-to-field` on `claims.Sub`.
- **Drop dead `entry.Error` assignment in the request logger** (#365) — the access logger emits via
  `logFields`, not by marshalling the entry, so the assignment was never read; the error is still
  logged. Clears `go/useless-assignment-to-field`.

## [1.24.3] - 2026-07-08

### Fixed

- **Out-of-bounds read in `User.GetFormattedName`** (#359) — the method returned
  `parts[0] + " " + parts[1]` whenever any name component was present, but `parts` holds only one
  element when a user has only a given name or only a family name, so `parts[1]` panicked with an
  index-out-of-range. Now joins the collected parts, which is correct for one or two components.
  Clears the repo's only `error`-severity CodeQL alert (`go/index-out-of-bounds`).

## [1.24.2] - 2026-07-08

### Security

- **Audit report export filename built from allowlisted constants** (#357) — the export file name
  was assembled from the raw request `report_type`/`format` strings, so CodeQL traced
  caller-controlled data to `os.Stat`/`os.Create` even behind the `filepath.Base` + `reportDir`-prefix
  guards it doesn't model. Both fields are already validated against fixed enums; the name is now
  built from a compile-time-constant `typeSlug`/`ext` chosen inside those switches (plus the
  server-generated ID and timestamp), so no request string reaches `filepath.*`. Closes the last
  three `go/path-injection` alerts as fixed — the repo is now at **0 open critical and 0 open high**
  CodeQL alerts. The `reportFilePath` clean+prefix guard remains as defense-in-depth.

## [1.24.1] - 2026-07-08

### Security

- **Audit report export path containment proven to static analysis** (#355) — `reportFilePath`
  already constrained the export file to a single element under `reportDir` via `filepath.Base`
  (#349), but CodeQL does not model `Base`-through-`Join` as a path-injection barrier, so the
  `os.Stat`/`os.Create` sinks stayed flagged. Added an explicit `filepath.Clean` + `reportDir`-prefix
  check (returning an error the caller handles) so containment is provable to static analysis,
  closing the three `go/path-injection` alerts as fixed. With this and the ziti request-forgery
  findings confirmed as trusted-config false positives, the repo is at **0 open critical and
  0 open high** CodeQL alerts.

## [1.24.0] - 2026-07-08

### Security

- **CodeQL critical + high remediation complete.** This release closes the backup-encryption weak-KDF
  (#353) and caps a sweep that brought the repo to **0 open critical and 0 open high** CodeQL alerts —
  via real fixes across v1.23.1–v1.23.5 (integer-overflow env parsing, Ziti management-API SSRF hardening,
  OAuth logout/session JWT signature verification, audit report path-injection, hardware-token secret
  encryption at rest) plus documented false-positive dismissals (HIBP SHA-1 k-anonymity, MySQL DDL,
  trusted-config Ziti base URL, e2e-test regex/randomness, helm empty-password placeholders, dev-profiler
  cert-check) and the structured-`zap`-field log-injection class.
- **Backup encryption KDF → scrypt** (#353) — `internal/backup` derived its AES-256 key from a raw
  `sha256(passphrase)`; it now uses `scrypt` (N=1<<15, r=8, p=1) over a random salt in a versioned,
  magic-prefixed format, with a legacy `sha256` fallback so existing encrypted backups still decrypt.
  Removed the dead `EncryptPassword` helper.

## [1.23.5] - 2026-07-08

### Fixed

- **Hardware-token secrets encrypted at rest** (#351, security) — the hardware-token (YubiKey OATH-HOTP)
  handler stored the TOTP/HOTP seed as `hex(sha256(secret)) + ":" + secret`, i.e. the seed was
  recoverable in plaintext (the hash prefix was security-theater). It's now encrypted with the identity
  service's AES-256-GCM `secretcrypt` cipher (the KEK-backed cipher already used for IdP client secrets);
  decrypt reads both the new `encv1:` format and the legacy format, so existing rows keep working and
  upgrade on the next write. Clears `go/weak-sensitive-data-hashing` (high).

## [1.23.4] - 2026-07-08

### Fixed

- **Audit report export path-injection** (#349, security) — the compliance report exporter built its
  output file path from the request-controlled `report_type`/`format` (`filepath.Join(reportDir, fileName)`)
  with no sanitization, so a `report_type`/`format` containing `../` could write/stat a file outside the
  report directory. Now routed through `reportFilePath()`, which applies `filepath.Base` to constrain the
  name to a single element under `reportDir`. Clears `go/path-injection` (high ×3).

## [1.23.3] - 2026-07-08

### Fixed

- **Ziti management-API request hardening + dependency security bump** (#347) — the generic Ziti
  `mgmtRequest` helper now builds requests through the validated `mgmtURL()` (parses `ZitiCtrlURL`,
  pins scheme+host) instead of raw string concatenation, so a malformed/hostile controller URL cannot
  redirect management calls. Also bumps the indirect `quic-go` dependency v0.59.0→v0.59.1 to resolve
  `GO-2026-5676` (govulncheck). The residual `go/request-forgery` findings on this helper are documented
  false positives (the host is pinned; the appended path holds only internal Ziti resource IDs).

## [1.23.2] - 2026-07-07

### Fixed

- **JWT signature verification on OAuth logout/session endpoints** (#345, security) — `handleLogoutAll`,
  `handleSessionInfo`, and `handleLogout` (end-session) parsed the caller's JWT with `ParseUnverified`
  and acted on the unverified `sub`, so a forged/unsigned token could revoke another user's sessions or
  read their session info. Added `parseVerifiedClaims` (RS256-pinned signature check against the service
  key, alg-confusion-proof, with an expiry-tolerant mode for the OIDC `id_token_hint`) and routed all
  parse sites through it; logout-all/session-info now return 401 on an unverified token, and end-session
  no longer acts on an unverified subject. Clears `go/missing-jwt-signature-check` (high ×3).

## [1.23.1] - 2026-07-07

### Fixed

- **CodeQL critical/high remediation** (#343) — (a) `database.go envInt32` now uses
  `strconv.ParseInt(s, 10, 32)` instead of `int32(strconv.Atoi(...))`, fixing a silent integer-overflow
  truncation of pool-sizing env vars (go/incorrect-integer-conversion ×2); (b) the Ziti management-API
  calls route through a new `mgmtURL()` helper that parses + validates `ZitiCtrlURL` (scheme/host) and
  the response-derived identity ID is `url.PathEscape`'d, clearing the server-side request-forgery
  vectors (go/request-forgery). The MySQL `ALTER USER` DDL (which cannot bind identifiers/passwords and
  is charset-validated + escaped) and the Ziti call against the trusted operator-configured controller
  base URL are documented false positives. No runtime behavior change.

## [1.23.0] - 2026-07-07

### Changed

- **Admin console code-splitting follow-ups** (#341) — `lucide-react` and `@tanstack` now build into
  their own cacheable chunks (`icons`, `query`; the `vendor` chunk drops ~1,176→1,071 kB), and the
  `Layout` outlet is wrapped in its own `<Suspense>` so navigating to an unvisited page spins only the
  content area (the sidebar/header stay rendered) instead of a full-screen fallback. Frontend-only.

## [1.22.0] - 2026-07-07

### Added

- **GCP service-account key rotation connector** (#339) — a new `gcp_sa` PAM rotation connector that
  rotates a Google Cloud service-account key, completing the cloud-IAM rotation pair (AWS shipped in
  v1.21.0). It reuses the engine `Minter`/`PostRotateCleaner` seam: `Mint` creates a new key via the IAM
  API (deleting the oldest USER_MANAGED key first if at GCP's 10-key limit) and stores the decoded
  key-file JSON; `Verify` obtains an OAuth token from the new key (retrying for propagation); cleanup
  deletes all USER_MANAGED keys except the newest after promotion. Selectable from the Rotation Policies
  admin page. Config: `service_account_email`, `admin_secret_id` (a vault secret holding an admin SA
  key-file JSON). The target service account must be dedicated to rotation. Google IAM calls sit behind
  a small interface so the connector is covered by mocked-SDK unit tests. Adds `google.golang.org/api`.

## [1.21.1] - 2026-07-07

### Fixed

- **CodeQL `go/unsafe-quoting` (critical) in AD `unicodePwd` encoding** (#337) — `encodePasswordAD`
  built the Active Directory password value by concatenating double quotes around the password
  (`"\"" + password + "\""`) before UTF-16LE encoding. The encoded bytes are sent as a binary LDAP
  attribute in a `ModifyRequest` (never interpolated into a filter/DN/parsed context), so this was not
  exploitable, but the pattern is now rewritten to a single bounded allocation that writes the quote
  code units directly — clearing the alert (and an allocation-size-overflow on the same function) with
  byte-identical output. Added byte-exact and embedded-quote regression tests.

## [1.21.0] - 2026-07-07

### Added

- **AWS IAM access-key rotation connector** (#335) — a new `aws_iam` PAM rotation connector that rotates
  an IAM user's access keys, selectable from the Rotation Policies admin page. Introduces an engine
  "minter" seam (`Minter` + `PostRotateCleaner`) for providers that mint the secret themselves: the
  connector calls `CreateAccessKey`, verifies the new key via STS `GetCallerIdentity` (retrying for IAM
  eventual consistency), and retires the superseded key only after the new one is promoted. AWS calls
  sit behind small interfaces so the connector is covered by mocked-SDK unit tests. Config:
  `target_user`, `admin_secret_id` (a vault secret holding admin AWS creds as
  `{access_key_id, secret_access_key}` JSON), `region`. The target IAM user must be dedicated to
  rotation (cleanup deletes all its access keys except the newest). GCP service-account keys are a
  planned follow-up on the same seam.

## [1.20.0] - 2026-07-07

### Changed

- **Admin console bundle code-splitting** (#333) — the console shipped as a single ~3.4 MB (875 KB
  gzip) JS chunk. Route pages are now lazy-loaded (`React.lazy` + `<Suspense>`) and `node_modules`
  vendors are split into cacheable chunks via vite `manualChunks`. The initial entry chunk drops from
  ~3,394 KB to ~62 KB (17 KB gzip); heavy libs now load only with the page that needs them
  (`swagger-ui-react` → API-docs page, `recharts` → dashboard). Frontend-only, no behavior change
  beyond a brief loading spinner on first visit to a route.

## [1.19.0] - 2026-07-07

### Added

- **Rotation-policies admin UI — SSH / SSH-key / PostgreSQL / MySQL connectors** (#331) — the Rotation
  Policies page can now create policies for all six registered rotators, not just `directory` and
  `generate_only`. The Connector Type dropdown gains **SSH (password)**, **SSH key-pair**,
  **PostgreSQL**, and **MySQL**, each rendering its required config fields (host, port, admin
  credential secret-picker, target user/role, DB name, SSL/TLS, pinned host key, …) driven by a
  declarative field schema that mirrors the backend validators. The SSH/DB rotation connectors shipped
  in v1.14.0 were previously creatable only via `curl`. Frontend-only — no backend or schema change
  (`connector_config` is a free-form map validated server-side by each connector's `ValidateConfig`).

## [1.18.0] - 2026-07-06

### Added

- **Guacamole recording legal-hold — admin console UI** (#329) — the Session History table on the
  Guacamole Sessions page now has per-recording **Place hold** / **Release hold** controls (with a
  reason prompt) and an **On hold** badge, wired to the existing legal-hold endpoints
  (`POST/DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`). Previously those endpoints — which
  exempt a held recording from the retention sweeper — could only be driven by `curl`. The
  `session-history` list endpoint now returns two read-only, org-scoped flags (`recording_available`,
  `on_legal_hold`) so the UI can render the correct state. No schema change (uses the v68
  `guacamole_recording_legal_holds` table shipped in v1.15.0).

## [1.17.0] - 2026-07-06

### Added

- **OpenZiti made easy** (#326) — the Ziti reconciler is now on by default (`ziti_reconciler=true`), the
  dev compose bundles the ZAC console (`ziti_console_url`), the router runs from a version-controlled
  declarative config (`deployments/docker/ziti-router/`) instead of sed/awk-patching at startup, agents
  auto-enroll, and a one-command Ziti quickstart (`scripts/ziti-quickstart.sh` + guided setup page).
- **One-command box deploy script** (#323) — `scripts/deploy-box.sh` automates the release recipe
  (backup → migrate → roll binaries → verify).

### Changed

- **Security hardening** (#324) — access-revocation and privilege checks tightened; OAuth signing keys
  are now **encrypted at rest** (via the prefix-aware `secretcrypt` helper — legacy plaintext keys are
  read transparently and re-encrypted on rotation); SCIM PATCH support extended in provisioning; the
  published default `ziti_admin_password`/`guacamole_admin_password` must be overridden in production
  (new `ValidateProduction` check).
- Dependency bumps: `go-ldap/ldap/v3` 3.4.8→3.4.12 (#325); Docker base images alpine 3.20→3.24 (#262),
  nginx (#93), node (#94). CI now compiles the integration test suite on every build (#73).

## [1.16.1] - 2026-07-06

### Fixed

- **IAM→Ziti revocation sweep failed on a uuid `user_id`** — the deprovision sweep added in v1.16.0
  queried `WHERE zi.user_id != ''` against the uuid column `ziti_identities.user_id`, which forced an
  empty-string→uuid cast and failed the whole query (`22P02`) every poll, so a disabled user's Ziti
  identity was never deleted. Dropped the redundant `!= ''` (`IS NOT NULL` suffices for a uuid column)
  and added a regression test. Released as a hotfix on top of v1.16.0.

## [1.16.0] - 2026-07-05

### Added

- **Guided Ziti Network Setup** — new admin-console page **Network Setup** (`/ziti-setup`) that makes
  the OpenZiti onboarding understandable, visual, and self-explanatory:
  - **Topology strip**: Clients → Edge Routers → Control Plane → Applications with live status dots.
  - **Setup checklist**: ordered steps (controller connection, CA trust, access-proxy identity,
    edge routers, app exposure, user-identity sync, client access) — each with live status, plain
    remediation text, and a deep-link action button.
  - **Install advisor**: which pieces must be installed *for this deployment* — controller, edge
    router (with `--tunneler-enabled` enrollment commands), BrowZer bootstrapper, client tunneler /
    OpenIDX Agent, hop nginx — labeled Required / Needed-for-your-setup / Optional.
  - **Per-route advice**: stored vs *effective* hosting mode (with auto-correct warnings), the full
    next-hop data path (`edge router → hop nginx :port → upstream`), what the client side needs,
    per-mode requirements, and the reconciler's live converge state per route.
  Backend: `GET /api/v1/access/ziti/setup/status` (aggregated checklist/advisor/route payload,
  reusing the reconciler's `effectiveHostingMode` + install-wide hop-port map so the UI explains
  exactly what will happen) and `GET /api/v1/access/ziti/reconciler/status` (per-service converge
  state, previously log-only). `/ziti-network` tabs are now deep-linkable via `?tab=`.

### Fixed

- **Ziti reconciler survives admin-panel reconnects** — the reconciler ran on the provider slot's
  context, so `POST /ziti/connect` (which Swaps the slot and cancels that context) silently killed
  the reconcile loop for good; subsequent route changes were never converged. It now runs on a
  process-lifetime context (no-ops while disconnected), and the connect handler wakes it via
  `Enqueue()` instead of imperatively hosting services alongside it — the reconciler stays the
  sole mutator, eliminating the double-hosting 502 path.
- **`PUT /ziti/settings` validates before persisting** — a malformed/empty controller URL or empty
  admin user is now rejected with 400 instead of being saved silently and only failing at the next
  connect. CI: the Benchmarks job could never post its PR comment (workflow token is read-only) and
  failed after the benchmarks had passed; it now has job-level write permission and degrades to a
  warning when the token can't comment.

### Security

- **Disabled/deleted IAM users are deprovisioned from Ziti** — the user-sync poller now sweeps
  Ziti identities whose user is disabled or gone (controller delete + mirror-row delete, batched,
  retried). Previously a revoked user's enrolled tunneler kept a valid Ziti identity — and network
  access — indefinitely. Infrastructure identities (access-proxy, admin, routers) are untouched.

## [1.15.0] - 2026-07-05

### Added

- **Guacamole recording legal-hold** (#318) — place a legal-hold on a Guacamole session's recording
  so it is never deleted by the retention purger. New `guacamole_recording_legal_holds` table
  (migration **v68**, FK → `guacamole_sessions` with a UNIQUE active-hold index), the recording
  retention sweeper (`sweepExpiredGuacRecordings`) now excludes sessions under an active hold, and
  admin-gated, audited endpoints:
  - `POST   /api/v1/access/guacamole/sessions/:id/legal-hold` (409 if one is already active)
  - `DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`
  - `GET    /api/v1/access/guacamole/sessions/:id/legal-holds`
  Each endpoint verifies the session is visible under the caller's org before acting. Mirrors the
  existing remote-support legal-hold; a testcontainer test proves a held recording survives the
  sweep and is purged once released.

### Upgrade

- Migration **v68** adds a table (additive). Run `cmd/migrate up` (or the compose `migrate` service)
  before/at deploy.

## [1.14.1] - 2026-07-04

### Changed

- **All registered rotation connectors are now creatable via the CreatePolicy API** (#316) —
  `validatePolicyInput` previously accepted only `directory`/`generate_only`, so `ssh`, `postgres`,
  `ssh_key`, and `mysql` rotation policies required a direct DB insert. A new optional
  `ConfigValidator` interface lets each connector validate its own `connector_config` (delegating to
  its existing config parser), and the engine now accepts any **registered** connector type.
  **Note:** the accepted connector-type set is now registration-dependent rather than a hardcoded
  pair; unregistered types are rejected with a clear error.

## [1.14.0] - 2026-07-04

Two new PAM credential-rotation connectors, extending the M5 rotation engine.

### Added

- **SSH key-pair rotation connector** (`ssh_key`) (#313) — rotates a POSIX account's SSH key: the
  stored secret value is a freshly generated ed25519 OpenSSH private key; the derived public key is
  installed into the target's `authorized_keys` (a single tagged line, replaced each rotation) over
  an admin SSH session, and rotation is verified by logging in as the target with the new key. Reuses
  the existing `FixedHostKey` verification. No new dependencies.
- **`ValueGenerator` engine seam** (#313) — an optional interface letting a connector produce the
  secret value itself (e.g. a private key) instead of the engine's default random password. Existing
  connectors are unaffected.
- **MySQL rotation connector** (`mysql`) (#314) — rotates a MySQL user's password via `ALTER USER`,
  authenticating with a bootstrap admin credential from the vault, verified by connecting as the
  target with the new password. New dependency: `github.com/go-sql-driver/mysql`. Because MySQL DDL
  cannot bind the password, the connector strictly validates identifiers, escapes the password as a
  single-quoted literal, and strips `NO_BACKSLASH_ESCAPES` on a pinned connection — verified against
  injection-shaped inputs.

### Notes

- Cloud-IAM (AWS/GCP) rotation is deferred (heavy SDKs, not locally verifiable).
- Follow-up: `validatePolicyInput` accepts only `directory`/`generate_only`, so `ssh`/`postgres`/
  `ssh_key`/`mysql` rotation policies must currently be created out-of-band (pre-existing gap).

## [1.13.1] - 2026-07-04

### Fixed

- **Elasticsearch client validates auth at construction** (#311) — `NewElasticsearchFromConfig`'s
  connectivity ping only inspected the transport error, so a wrong/absent password against a
  security-enabled cluster (a 401/403 with `err == nil`) silently "connected" and then failed every
  operation. It now checks `res.IsError()` and returns a clear error, so bad ES credentials surface at
  startup. Audit-service still treats Elasticsearch as best-effort (warn + continue), so this turns a
  silent operation-time failure into a clear startup warning. Surfaced by the v1.13.0 ES-auth smoke test.

## [1.13.0] - 2026-07-04

Elasticsearch authentication for the docker-compose deploy path — the last deferred item from
the prod-compose hardening bundle. Compose-only; the app-side ES auth was already built.

### Changed

- **Elasticsearch security enabled in prod compose** (#309) — `docker-compose.prod.yml` sets
  `xpack.security.enabled=true` + `xpack.security.http.ssl.enabled=false` + `ELASTIC_PASSWORD` on
  the `elasticsearch` service (HTTP basic auth over the private network), and wires
  `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD` into `audit-service` (the only ES consumer,
  which already passes them to the auth-aware client). Dev/infra compose keep security disabled.
- **`ValidateProduction` requires ES credentials** (#309) — when `APP_ENV=production` and
  `elasticsearch_url` is set, `elasticsearch_username`/`elasticsearch_password` must be provided
  (conditional, so ES-unused deployments are unaffected).

### Notes

- Baseline is HTTP basic auth; self-signed ES HTTP TLS (parity with the v1.12.0 Postgres TLS) is a
  documented follow-up. Dedicated least-privilege ES roles are also a follow-up (uses the built-in
  `elastic` user for now).
- Upgrade: set `ELASTIC_PASSWORD` and a matching `ELASTICSEARCH_PASSWORD` in `.env` before a prod
  `docker compose up`.

## [1.12.0] - 2026-07-04

Production-readiness hardening for the docker-compose deploy path. Compose-only —
systemd/managed deployments are unaffected.

### Added

- **Startup readiness probes** (#307) — `internal/common/health.WaitForDependency` (bounded
  retry) plus `ProbeHTTP`/`ProbeOPA`. Services now verify hard dependencies at boot instead of
  returning 500s later: the OPA-using services (admin-api, provisioning, governance) probe
  `OPA/health` and the access service probes its Ziti controller — **fail-fast in production,
  warn and continue in development**. The OPA probe is gated on `EnableOPAAuthz` so a deploy
  that doesn't use OPA never blocks on it; APISIX is intentionally not probed (its reconciler
  already self-heals).
- **Self-signed Postgres TLS in prod compose** (#306) — a `pg-certgen` one-shot service
  generates a server cert (owned uid 70, key mode 0600) into a `pg_certs` volume; the prod
  Postgres runs with `ssl=on`, and the app/migrate/seed DSNs default to
  `sslmode=${DATABASE_SSL_MODE:-require}` so DB traffic is encrypted out of the box. Point at an
  external managed Postgres by setting `DATABASE_SSL_MODE` and supplying your own certs.

### Changed

- **DB pool sizing is configurable** (#306) — `DB_MAX_CONNS`/`DB_MIN_CONNS` (defaults 25/5)
  replace the hardcoded pool limits in `internal/common/database`.
- **APISIX admin key sourced from `APISIX_ADMIN_KEY`** (#306) via native APISIX `${{...}}` env
  substitution (no more `CHANGE_ME_ADMIN_KEY` in the config), wired into all three compose files;
  `admin_allow_ip` tightened to loopback + the container bridge ranges (`10.0.0.0/8`,
  `172.16.0.0/12`).
- **Graceful-shutdown timeout is configurable** (#306) — `SHUTDOWN_TIMEOUT_SECONDS` (default 30)
  replaces the hardcoded 30s across all services.

### Notes

- Elasticsearch `xpack.security` remains deferred (needs ES-client auth wiring).
- Upgrade: the `openidx_app` password hook and now Postgres TLS certs are generated on **first
  init of a fresh `postgres_data` volume**; existing volumes need the operator to provision them
  once (see the v1.11.0 note for the role password).

## [1.11.0] - 2026-07-04

Docker-compose deployments are now tenant-isolated. Previously a fresh
`docker compose up` was pre-multi-tenancy at the schema level (`init-db.sql` had no
RLS belt and app services connected as the `openidx` superuser, which bypasses RLS
entirely). This release makes migrations the sole schema source in compose and cuts
the app services over to the non-owner `openidx_app` role so the FORCE'd RLS
policies enforce — matching the box and managed/RDS deployments.

### Added

- **`migrate` + `seed` one-shot compose services** (#303) — a `migrate` service builds
  the full v1–v67 schema (as the superuser) after Postgres is healthy, then a `seed`
  service applies the functional-delta bootstrap. App services gate on the seed
  completing (`depends_on: service_completed_successfully`). Wired into
  `docker-compose.yml`, `docker-compose.prod.yml`, and `docker-compose.infra.yml`.
- **`deployments/docker/bootstrap.sql`** (#303) — minimal first-init (the passwordless
  `openidx_app` role + `GRANT CONNECT`); migrations own everything else.
- **`deployments/docker/seed.sql`** (#303) — idempotent functional-delta bootstrap
  (`role_permissions` + default risk/posture/privacy/notification/lifecycle/ispm
  policies + tenant branding), org-scoped, applied under `app.bypass_rls`.
- **`deployments/docker/set-app-role-password.sh`** (#304) — first-init hook that sets
  the `openidx_app` password from `OPENIDX_APP_PASSWORD` (sorts after `bootstrap.sql`).
- **`test/integration/compose_seed_test.go`** (#303) — e2e guard: migrate-from-empty →
  `seed.sql` → asserts the login bootstrap and that RLS fails closed for a NOSUPERUSER
  role without an org GUC and returns default-org rows with one set.

### Changed

- **Compose app services connect as `openidx_app`** (NOSUPERUSER, NOBYPASSRLS) (#304),
  so the v37 FORCE-RLS policies enforce. `migrate`/`seed` stay on the `openidx`
  superuser (they own DDL + seed). Add `OPENIDX_APP_PASSWORD` to the postgres env and
  `.env` / `.env.production`.
- **`scripts/seed.sh`** now re-applies `seed.sql` (migrations own the schema + login
  bootstrap) instead of the removed `init-db.sql`.

### Removed

- **`deployments/docker/init-db.sql`** — retired as the schema source. Layering
  migrations on top of it was permanently blocked (v29 `ziti_certificates(identity_id)`
  ordering), and the file was itself broken on current Postgres (`NOW()` in a
  partial-index predicate). Migrate-from-empty is clean to v67 and already seeds a
  working admin install (default org, admin user, `admin-console` client, roles).
- **`TestInitDBParity` / `TestInitDBColumnParity`** (`internal/migrations/initdb_parity_test.go`)
  — no subject once `init-db.sql` is gone; migrations are the sole schema source.

### Upgrade note

The `openidx_app` password hook runs only on **first init of a fresh `postgres_data`
volume**. On an **existing** volume, set the password once:
`ALTER ROLE openidx_app WITH LOGIN PASSWORD '<OPENIDX_APP_PASSWORD>';` (or
`docker compose down -v` / `make dev-clean` to recreate the volume). This is a
compose-only change — systemd/managed deployments are unaffected.

## [1.10.1] - 2026-07-04

Encrypt-secrets-at-rest hardening pass. Secret columns that were previously stored as plaintext
are now AES-256-GCM encrypted at rest, keyed by `ENCRYPTION_KEY`. Rollout is lazy and
flag-day-free: reads are prefix-aware (tagged ciphertext is decrypted; legacy plaintext passes
through untouched), and environments without a usable key fall back to a warned passthrough rather
than crashing.

### Added

- **`internal/common/secretcrypt`** — shared AES-256-GCM helper (#298). `Encrypt` emits
  `encv1:<base64(nonce‖ciphertext)>`; `Decrypt` is prefix-aware (tagged → decrypt, untagged legacy
  plaintext → passthrough); `NewNoop()` provides a best-effort passthrough cipher for environments
  without a 32-byte key (services warn and continue rather than fail closed).

### Changed

- **Webhook signing secrets encrypted at rest** (#299) — `webhook_subscriptions.secret` is now
  encrypted on create and decrypted on read and before HMAC signature computation. Column widened to
  `TEXT` (migration **v65**; file-based `202607030001`).
- **Identity-provider client secrets encrypted at rest** (#300) — `identity_providers.client_secret`
  is encrypted on create/update and decrypted on every read path: identity get/list, the access
  service's multi-IdP route resolution, and the OAuth social-login token exchange. Column widened to
  `TEXT` (migration **v66**; file-based `202607030002`).
- **Guacamole pool tokens encrypted at rest** (#301) — `guacamole_connection_pool.token` is encrypted
  on write. The column is write-only (the in-memory pool serves reads), so there is no decrypt path — a
  database dump cannot yield usable session tokens. Column widened to `TEXT` (migration **v67**).

### Notes

- `oauth_clients.client_secret` was already SHA-256 hashed (constant-time compare, never re-returned)
  and is intentionally out of scope for this pass; the stale `-- TODO: Encrypt` marker was removed.
- Highest migration is now **v67**. `init-db.sql` defines all three columns as `TEXT` directly, so
  fresh installs need no backfill.

## [1.10.0] - 2026-07-03

Readiness-finalization pass across three workstreams: make the shipped PAM usable from the
admin console (W1), close correctness/tenant-isolation gaps (W2), and light production
hardening (W3).

### Added
- **PAM admin console** — the previously backend-only PAM surface is now driveable from the
  console: **Vault Secrets** page (list/create/versions/grants + reason-gated one-shot reveal +
  checkout ledger; #284), **Rotation Policies** page + per-secret rotate-now/history (#285),
  **Privileged Sessions** page (Guacamole pending-request approve/deny, active-session
  monitor/share/force-terminate, transcript download; #286), and a **`vault_credential`** option
  in Access Requests with one-shot retrieve + return-early (#287). A "Privileged Access" nav
  group + dashboard entry point (#289).
- **`GET /api/v1/access/guacamole/session-history`** — admin-guarded, org-scoped listing of
  Guacamole session rows with a `transcript_available` flag (no file paths), so transcripts are
  reachable from the console. (#286)
- **`GET /api/v1/vault/secrets/:id/grants`** — list a secret's access grants (metadata only). (#284)
- **OpenAPI specs** for all shipped PAM endpoints (vault, rotation, Guacamole sessions,
  `vault_credential` retrieve/return) across the admin-api/access/governance specs. (#288)
- **Column-level init-db↔migrations parity guard** (`TestInitDBColumnParity`) — fails CI when an
  `init-db.sql` column is created by no migration (the drift class that breaks migrate-only
  RDS/Helm installs). (#292)

### Changed / Security
- **Attestation tenant isolation** — `attestation_campaigns`/`attestation_items` (created by v54
  without `org_id`) gained `org_id` + the v37 FORCE-RLS belt (USING + WITH CHECK); handlers tag
  `org_id` on write and rely on RLS for reads. Closes a cross-org read/write exposure. Migration
  v61. (#290)
- **`org_id` + FORCE-RLS belt** added to `jit_grants` and `request_approval_chains` (previously
  org-scoped only in-handler). Migration v64. (#293)
- **Access-proxy idle timeout enforced** — routes' `idle_timeout` was dead config on the data
  plane (only absolute expiry was checked). The proxy + forward-auth paths now revoke and re-auth
  a cookie session idle beyond `idle_timeout` (sliding window; bearer tokens unaffected). (#294)
- **Production requires an explicit vault KEK** — `ValidateProduction` now fails unless `VAULT_KEK`
  or `VAULT_KEKS` is set, instead of silently falling back to `ENCRYPTION_KEY` for the vault
  key-encryption key. (#295)

### Fixed
- **Referenced-but-uncreated tables reconciled** — `admin_console_settings`, `auth_contexts`,
  `breach_incidents`, `breach_alerts` were referenced by code but created by neither a migration
  nor `init-db.sql` (latent 500s, the `jit_grants`-class drift). Migration v62 creates them.
  (`access_stats`, also flagged, was a false positive — a CTE, not a table.) (#291)
- **`ziti_certificates` column drift** — the migration schema had diverged wholesale from the
  code/init-db schema (`cert_data NOT NULL`, … vs `cert_type`/`not_after`/`status`/…), breaking
  cert-hardening on migrate-only installs. Reconciled to the code schema; also reconciled 8 other
  tables whose init-db `ALTER … ADD COLUMN` patches were never mirrored into a migration.
  Migration v63. (#292)

### Notes
- **OPA fail-open** was verified to be unreachable in production (the middleware's `devMode` is
  `cfg.IsDevelopment()`, false in prod → fails closed with 403); a regression test now pins the
  invariant. No code change to `opa.go`. (#295)
- **Deferred follow-ups** (tracked; not implemented):
  - **MySQL and cloud-IAM (AWS/GCP/Azure) rotation connectors** behind the M5 `Rotator`
    interface (v1.9.1 shipped SSH + PostgreSQL); **SSH *key* rotation** (v1.9.1 shipped SSH
    *password* rotation).
  - **Guacamole recording legal-hold** — retention works, but `recording_legal_holds` is FK'd to
    `remote_support_sessions` only; covering `guacamole_sessions` recordings needs a shared-hold refactor.
  - **Multi-tenant / production-GA hardening**: docker-compose `openidx_app` (non-owner) cutover +
    FORCE-RLS for compose; prod-compose TLS/Elasticsearch-security/APISIX-admin-key hardening;
    encrypt-at-rest for the legacy plaintext secret columns (`oauth_clients.client_secret`,
    `identity_providers.client_secret`, webhook secrets, guac pool token) via the vault; rotate the
    git-history-compromised APISIX admin key.

## [1.9.1] - 2026-07-02

PAM session assurance (M4) + rotation connectors (M5), plus a recording
data-loss fix.

### Added
- **Session transcripts** — a `guaclog`-based sweep generates a keystroke/command
  transcript for ended/terminated recorded Guacamole sessions and serves it via an
  admin-guarded `GET /api/v1/access/guacamole/sessions/:id/transcript`. Generation is
  `exec.LookPath`-gated (inert if `guaclog` is absent); `guaclog` is included in the
  access-service image. (#279)
- **Live session monitor** — `POST /api/v1/access/guacamole/sessions/:id/share` mints a
  read-only Guacamole connection-sharing link (falls back to the active-session list when
  the server lacks the sharing API). (#279)
- **Session-end detection** — a background sweep reconciles tracked sessions against
  Guacamole's active connections and marks naturally-ended sessions (2-minute grace;
  fail-safe when Guacamole is unreachable). (#279)
- **Attestation of privileged entitlements** — new `vault_access` and `rotation_policy`
  access-certification campaign types; a revoke decision deletes the vault grant / disables
  the rotation policy. (#279)
- **SSH + PostgreSQL rotation connectors** — the rotation engine can now rotate credentials
  on Linux/SSH hosts (`chpasswd` over SSH, host-key-pinned, password via stdin) and
  PostgreSQL (`ALTER ROLE` with server-side identifier/literal quoting). Each resolves its
  bootstrap/admin credential from the vault and verifies by authenticating with the new
  credential; both fail closed. No new dependencies. (#280)

### Fixed
- **Guacamole recording data loss** — `guacamole_sessions.recording_path` stored the shared
  recordings *directory*, so the retention sweep's `RemoveAll` could delete every recording.
  The full recording *file* path is now persisted and purge is guarded so it can never
  remove the recordings root. (#279)

## [1.9.0] - 2026-07-02

Privileged Access Management (PAM) — an integrated credential vault, automated
rotation, just-in-time credential checkout, and privileged-session brokering with
server-side credential injection. Built on the existing vault crypto, approval
workflows, Guacamole brokering, and recording/retention pipeline.

### Added
- **Credential vault** — tenant-isolated, envelope-encrypted secret store
  (per-version HKDF + AES-256-GCM under a rotatable key-encryption keyring that
  defaults to `ENCRYPTION_KEY`; fail-closed). Versioned secrets, per-secret access
  grants, internal server-side `use` vs. reason-gated + audited `reveal`;
  admin-guarded `/api/v1/vault/*` API. Migration v56. (#273)
- **Automated credential rotation** — leader-gated rotation engine with pluggable
  connectors (Active Directory / LDAP / Azure AD via directory write-back;
  generate-only). Candidate-version → apply-to-target → verify → promote, so a
  failed rotation never locks the account out. Scheduled, on-demand (admin), and
  rotate-on-checkout triggers. Migration v57. (#274)
- **Just-in-time credential checkout** — request a vault credential through the
  existing multi-step approval workflow (`resource_type=vault_credential`); on
  approval the requester retrieves the secret once for a bounded window, after
  which access auto-revokes and the credential rotates. (#276)
- **Privileged session brokering with credential injection** — Guacamole
  RDP/SSH/VNC sessions inject the target credential from the vault **server-side**
  (the browser never receives it), with an optional pre-session approval gate,
  admin force-terminate (with reason), and native session recording retained via
  the existing recording-retention policy. Migration v59. (#277)

### Fixed
- Created `jit_grants` and `request_approval_chains` — referenced by governance
  code but never created by any migration, so JIT elevation, the escalation
  worker, and `POST /api/v1/governance/requests` were returning 500s. Migration
  v58. (#275)

### Notes
- Each service that uses the vault (admin-api, governance, access) reads the shared
  `ENCRYPTION_KEY` / `VAULT_KEK` and instantiates an in-process vault; the access
  service additionally needs a shared recording volume for Guacamole recordings.

## [1.8.2] - 2026-07-01

### Added
- **Optional device-trust enforcement for clientless (BrowZer) access.** With
  `OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS=true` (off by default), an OIDC
  login for the clientless (BrowZer) client from an untrusted device is refused —
  the login page shows "This device must be approved before clientless access" and
  a device-trust request is filed for admin approval (admin console → **Device
  Trust Approval**); after approval, the retry succeeds. Closes the gap where a
  BrowZer route's `require_device_trust` was silently unenforced (BrowZer traffic
  bypasses the proxy's HTTP forward-auth). Enforced at the OIDC login
  (`handleAuthorizeCallback` — BrowZer's server-rendered login — and
  `handleLogin`); per-device, not per-route. (#268, #269, #270)

## [1.8.1] - 2026-07-01

Security & production-readiness hardening — remediation of the v2.0 GA
production-readiness audit (all P0s + four P1s + a P2 cluster).

### Security
- Access proxy now verifies a bearer JWT's signature + expiry (RS256 via the
  OAuth JWKS) before building a session; forged/unsigned tokens are rejected
  (P0-1, #255).
- Pre-tenant-resolution lookups against RLS-forced tables (API-key validation,
  proxy route/session/device/posture reads, Ziti startup, audit webhook
  bookkeeping) are bypass-wrapped so they no longer fail closed under the
  non-owner `openidx_app` role; WebAuthn login is org-scoped (P0-2, #254).
- OAuth token introspection now honors revocation — a revoked token reports
  `active:false` (#259).
- Removed the hardcoded APISIX admin key from the repo; templated from env
  (P0-4, #256). **Rotate the previously-committed key wherever deployed.**
- Enabled branch protection on `main` (Required Checks, enforce_admins) (P0-5).
- Production config validation now checks the *effective* DB sslmode (parsed from
  `DATABASE_URL`, not just the standalone field) (#263).
- Bumped auth/transport-critical dependencies (x/crypto, x/net, pgx/v5,
  go-webauthn, go-redis/v9); transitive advisories dropped 23→2 (#264).
- Platform-admin cross-org audit now records under RLS and logs failures;
  IP-threat DB errors are surfaced; dead runtime-DDL removed (P2, #265).

### Fixed
- 58 tables that existed only in `init-db.sql` are now created by migration
  **v54**, so managed-Postgres/RDS/Helm/`migrate` installs stop 500ing across
  MFA/SAML/social/lifecycle/ISPM/audit features; a parity test guards against
  recurrence (P0-3, #257).
- Split the deprovisioning policy-run log into `lifecycle_policy_executions`
  (migration **v55**) — it collided with the workflow `lifecycle_executions`
  schema, breaking deprovisioning execution records on every install (#258).
- Docs workflow no longer passes `latest latest` to `mike deploy` (#261).

### Changed
- Migrated off go-redis deprecated APIs (`SetEx`→`Set`, `GetSet`→`SetArgs`,
  `ZRevRange`→`ZRangeArgs`) (#264).
- `.gitignore` now excludes `*.zip` to prevent stray archive exports being
  committed (#266).

## [1.8.0] - 2026-06-29

### Added
- **Database-enforced tenant isolation (RLS activation)** — the v1.8 milestone of
  the multi-tenancy epic. The app now connects as a dedicated non-owner
  `openidx_app` role (`NOSUPERUSER NOBYPASSRLS`), so the `FORCE`'d row-level
  security policies (the predicate + FORCE shipped earlier in v37) finally
  enforce instead of being bypassed by a superuser connection. A no-GUC query on
  a scoped table now returns 0 rows; queries see only the request's org via the
  `app.org_id` GUC set at pool checkout; platform/cross-org paths opt in via
  `app.bypass_rls`. This is defense-in-depth *behind* the v1.7 app-layer `org_id`
  filtering. (#250)

### Changed
- **Migration v53** provisions `openidx_app` with blanket DML grants + default
  privileges (passwordless; the password is set out-of-band at deploy). Migrations
  and DDL continue to run as the owner role; services keep `AUTO_MIGRATE` off and
  the app `DATABASE_URL` points at `openidx_app`. `init-db.sql` provisions the
  same role for fresh installs. (#250)

## [1.7.2] - 2026-06-29

### Security
- **`github.com/jackc/pgx/v5` v5.5.4 → v5.9.2** — resolves GO-2026-5004.
  `govulncheck` now reports 0 affected vulnerabilities. (#248)

### Fixed
- **CI hard gates restored to green** (`Required Checks`). The org-scope, lint,
  and vulnerability gates had regressed:
  - **orgscope**: annotated the 19 org-unscoped queries the governance/devices
    work introduced (the Relations & Integrity Doctor's whole-install scans and
    queries keyed by globally-unique ids) with reviewed `//orgscope:ignore`
    directives. (#247)
  - **lint**: removed an unused var + orphaned import in `ziti_settings.go`;
    justified the deprecated, operator-supplied `google.CredentialsFromJSON` call
    in `play_integrity.go`; migrated the RLS pool hook `BeforeAcquire →
    PrepareConn` (deprecated by the pgx bump), preserving exact checkout
    semantics. (#247, #248)

## [1.7.1] - 2026-06-26

### Fixed
- **A fresh `apisix-edge` install can now stand up the full eight-service stack
  from a clean checkout.** The `gateway` service (`:8008`) is tracked as a
  systemd unit and added to the install's `enable --now` list (it had been
  running as an unmanaged `/tmp` process); the runbook now builds the service
  binaries into `~/oidx-runtime/bin` (the units' `ExecStart` targets); and the
  access-service launch wrapper ships as a sanitized `run-access.sh.example`
  (previously untracked, so a fresh install left the access-proxy with no start
  script). (#243, #244, #245)

## [1.7.0] - 2026-06-26

### Governance & devices: policies that enforce + real device trust (#234–#239)

Made the governance and devices domains actually work end-to-end. The policy
engine was a permissive no-op and device-trust signals were never populated, so
Zero-Trust controls silently passed everything; the device-trust approval
workflow existed but had no entry point; and a redundant policy engine sat
unwired. After this work: governance policies evaluate and enforce, device
posture and per-device trust flow into every access decision (forward-auth and
continuous re-verification), untrusted devices on trust-required routes file
approval requests that flip trust on approval, and the dead engine is gone.

#### Added
- **Device posture bridge** (D1): agent posture reports are written to
  `device_posture_results` so the access context evaluator enforces posture for
  the reporting device; migration v50 adds the upsert key. (#234)
- **Service-to-service auth for policy evaluation** (G1): a shared
  `INTERNAL_SERVICE_TOKEN`; the access-proxy presents it as `X-Internal-Token`
  (constant-time, scoped to governance `/evaluate`) so the policy call is
  authenticated instead of 401-failing-closed. (#235)
- **Device-trust request auto-creation** (D3): when an untrusted device hits a
  `require_device_trust` route, the proxy files a deduped pending
  `device_trust_requests` row — the missing entry point that feeds the existing
  approval queue. Approve/reject now notify the user, and new requests notify
  org admins, via the notifications service. (#238)
- **Migration v52**: reconcile the continuous-verify columns that existed only in
  `init-db.sql` (`proxy_sessions.{last_verified_at,verification_failures,geo_*,
  idp_id,device_trusted}`, `user_sessions.device_trusted`) onto migrate-based
  installs. (#239)

#### Changed
- **The governance policy engine actually enforces** (G1): `GetPolicy` /
  `ListPolicies` now load `policy_rules` (via a shared `loadPolicyRules`), so the
  per-type evaluators (separation-of-duty, risk, timebound, location,
  conditional-access) and the step-up loop run against real rules instead of an
  empty set. (#235)
- **`ProxySession.DeviceTrusted` is populated** from `known_devices.trusted`,
  matched by the request's device fingerprint (D2) — feeding the context checks,
  the inline policy DSL, and the governance `/evaluate` call. The continuous
  verifier re-derives it live each pass rather than reading a stale column.
  (#237, #239)

#### Fixed
- **Policy rule loading queried non-existent columns** (`condition/effect/
  priority` vs the real `rule_type/conditions/actions`); the error was swallowed,
  so rules silently never loaded — the true root cause behind "policies don't
  enforce." (#235)
- **The continuous session verifier errored every run** on migrate-based installs
  — its driver query referenced `proxy_sessions` columns present only in
  `init-db.sql`. (#239)

#### Removed
- **The dead `ZTPolicy` subsystem** (handler, store, model, tests; ~4,900 LOC)
  — never wired into any service, no table, no UI, its general-ABAC niche already
  served by the live `abac-policies` surface. Migration v51 drops the (never
  created) `zt_policies` / `zt_policy_versions` tables as a belt. (#236)

### Relations & Integrity Doctor — cross-domain health + referential integrity (#230, #231, #233)

A self-service "doctor" that scans the relationships *between* domains — proxy
routes, Applications tiles, OAuth clients, Ziti services, published apps,
identities — surfaces broken or orphaned wiring, and heals the safe cases
automatically; plus DB-level referential integrity so the most common orphans
can't form in the first place.

#### Added
- **Relations & Integrity Doctor** (`internal/access/health_engine.go`,
  `health_checks.go`): a check registry that scans cross-domain relations
  (route↔tile, app↔client, route↔Ziti, host uniqueness, published-app,
  identity↔Ziti, BrowZer-config dedup, domain presence, …), returns a structured
  report, auto-heals findings classified Safe, and leaves risky ones for an
  explicit fix. Exposed at `GET /api/v1/access/health/relations[?heal=safe]` and
  `POST /api/v1/access/health/fix/:checkId`, with a `HealRoute` after-mutation
  hook so a route change re-checks its own wiring. (#230)
- **Referential integrity** (migration v49): `applications.route_id →
  proxy_routes` and `applications.oauth_client_id → oauth_clients`, both
  `ON DELETE CASCADE`, backfilled from the existing id conventions — so deleting
  a route or client can no longer strand an Applications tile/app. (#231)

#### Changed
- Doctor check polish from review follow-ups: tightened classifications and
  counts (e.g. domain-presence counts `known_devices`, not a non-existent table).
  (#233)

### App, OAuth & clientless-publishing fixes (#223–#229, #232)

A run of fixes making OAuth client registration, the Applications view, and
clientless app publishing mutually consistent — registered clients are visible
and editable, and a published app maps cleanly to one host / one Ziti service.

#### Added
- **Applications tiles auto-sync for proxy routes**: creating/registering a
  client or proxy route surfaces a launcher tile without a manual step.
  (#224, #225)
- **App redirect_uris auto-register on the BrowZer OIDC client**, so a freshly
  published clientless app doesn't 400 on its first OAuth redirect. (#227)
- **One-app-per-host publishing**: an app publishes as a single host route → one
  Ziti service → one BrowZer target → one APISIX route, instead of exploding into
  one route per discovered path (which collided on the per-host BrowZer naming);
  discovered paths stay as advisory metadata. (#229)

#### Fixed
- **OAuth client registration 500** — new clients weren't assigned a UUID. (#223)
- **Registered clients didn't appear** in the Applications list. (#224)
- **Editing an application** now syncs its backing OAuth client (name/redirects),
  instead of drifting from it. (#226)
- **BrowZer config generators use the *effective* hosting mode** (fixing overlay
  error `1010` when a route's stored mode disagreed with its resolved mode).
  (#228)
- **`ziti_browzer_config` is a singleton** — the bootstrap reseed no longer
  appends a new row on every startup. (#232)

### Clientless edge on APISIX + console-managed publishing (#211–#221)

Moved the public `:443` edge from nginx to **Apache APISIX** as the single TLS
terminator, with the access-service pushing per-app BrowZer routes to it
dynamically; and hardened publishing so a clientless app can be created,
**edited, renamed, and deleted entirely from the admin console** without leaving
orphaned overlay/edge state. Resolves a class of failures hit while publishing
external HTTPS apps (`secops`, `es-dev`): BrowZer `1003`, OAuth/SAML 403s, and
stranded wiring after a rename/delete.

#### Added
- **APISIX edge** (`deployments/apisix-edge/`): a dedicated APISIX instance as
  the sole `:443` edge (TLS via the `*.tdv.org` wildcard), with `seed-edge-routes.sh`
  for the static routes (API fan-out, `/oauth`, `/scim`, `*.tdv.org` access-proxy)
  and systemd user units for the access + backend services. nginx is reduced to
  the admin-console SPA upstream. (#211, #213)
- **APISIX route reconciler** (`internal/access/apisix_reconciler.go`): the
  access-service pushes/prunes the per-app `browzer-<app>` edge routes from
  `proxy_routes` via the Admin API (gated by `APISIX_EDGE_ENABLED`). (#211)
- **Hosting-mode picker** in the proxy-route create/edit form — **Auto
  (recommended) / Hop — external·HTTPS / Direct — local·dark** — wired through the
  proxy-route CRUD (`hosting_mode`). (#220)
- **Edge routes for the oauth-service's management APIs**: `/api/v1/oauth/*` and
  `/api/v1/saml/*` now route to `:8006` (were missing, so they fell to the
  `/api/*` admin catch-all and 404'd). (#218, #219)
- **Router WSS config artifacts** (`deployments/apisix-edge/ziti-router/`): the
  edge router serves the clientless BrowZer overlay on `wss:3023` presenting the
  browser-trusted `*.tdv.org` cert via `transport.wss.identity`. (#214, #215)
- Docs: clientless edge architecture (`docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`)
  and a publish-a-service guide with the full certificate matrix
  (`docs/PUBLISHING_A_SERVICE.md`). (#212, #217)

#### Changed
- **BrowZer routes auto-select their hosting mode** from the upstream:
  `EffectiveMode` promotes a BrowZer route off `identity` (never valid for the
  `#browzer-users` dial) and picks **hop** for external HTTPS / Host-routed
  upstreams, **direct** for local/HTTP — explicit hop/direct still honored. (#220)
- **OAuth client management and SAML SP management are now always authenticated**,
  not just outside `development` — the management groups get the auth middleware
  unconditionally while the interactive OIDC flow endpoints keep their env-gated
  behavior. (#218, #219)
- The external-IdP **OIDC `form_post` bypass is OFF by default**
  (`BROWZER_OIDC_CALLBACK_PATHS=""`): once the WSS overlay is healthy the service
  worker tunnels the callback, so a direct bypass splits the cookie context and
  loops the app back to login. (#216)

#### Fixed
- **BrowZer `1003` (service not dialable by the overlay)**: the reconciler now
  **converges** Bind/Dial service policies (upsert by name) instead of
  create-if-exists, so a route that transitions identity→router-hosted (e.g.
  BrowZer enabled after OpenZiti) has its stale `#access-proxy-clients` policies
  corrected to `#ziti-routers` / `#browzer-users`. (#220)
- **OAuth/SAML management 403/404 through the edge**: routing gap (mis-routed to
  admin-api) + dev-mode no-auth on the oauth-service. (#218, #219)
- **Route delete and rename left orphans**: deleting a route now tears down its
  Ziti service + policies + `host.v1` config + service-edge-router policy, and
  prunes the APISIX route + bootstrapper target; renaming re-keys the edge wiring
  to the new host instead of stranding it under the old one. (#221)
- **BrowZer `1007` (no WSS routers) / `1016` (WSS cert)** on the clientless path,
  and the **psm Entra login loop** caused by the direct OIDC bypass. (#214, #215, #216)

### Per-app BrowZer publishing via the OpenZiti reconciler (#201–#208)

Publish multiple apps clientlessly behind BrowZer — each as its own dark Ziti
service — and toggle them from the admin console without breaking the overlay.
Motivated by publishing a second BrowZer app (`psm.tdv.org`, an external HTTPS
IIS/.NET upstream) alongside `netgraph`: the BrowZer WASM runtime sends a fixed
`Host: unknown` and **no SNI** on every overlay request, so the old shared
`browzer-router` (which demuxed apps by Host) could only ever serve one app.

#### Added
- **OpenZiti reconciler** (`internal/access/ziti_reconciler.go`, gated by
  `ZITI_RECONCILER`): declaratively converges the controller to the desired
  state read from `proxy_routes` — per-app services, bind/dial/service-edge-router
  policies, `host.v1` configs, and router/SDK hosting — on boot, a 30s tick, and
  on demand. Replaces the imperative provisioning path as the single owner of all
  Ziti mutations. (#201)
- **Per-app BrowZer services**: each clientless app gets its own Ziti service
  hosted by the edge **router** via a fixed `host.v1` config (`{protocol,address,
  port}`), so there is no Host demux — removing the single-app limit of the shared
  router. (#201)
- **`hosting_mode = 'hop'`** for Host-routed / HTTPS upstreams (e.g. IIS/.NET):
  a per-app plain-HTTP hop (nginx) that listens on a deterministic `base+index`
  port, rewrites the `Host` header, and proxies to the real upstream; emits a
  per-route landing-path 302 so the post-OIDC `/` lands on the app's entry path.
  (#202, #203)
- **Public per-app nginx vhost generator** (`internal/access/browzer_vhosts.go`,
  `BROWZER_VHOST_CONFIG_PATH`): the access-service renders one TLS `server {}` per
  `ziti+browzer`-enabled route (`server_name <app>.tdv.org` → bootstrapper
  `:8445`), so publishing a clientless app needs **no** front-nginx hand-edit.
  Hop-mode routes additionally get an external-IdP **OIDC `form_post` callback
  bypass** (`location ~ /(signin-oidc|signout-callback-oidc)$` → the route's hop
  port). Config: `BROWZER_BOOTSTRAPPER_ADDR`, `BROWZER_VHOST_SSL_CERT/KEY`,
  `BROWZER_OIDC_CALLBACK_PATHS`. A poll-reload entrypoint
  (`deployments/docker/oidx-nginx-entrypoint.sh`, wildcard-`include`d from
  `nginx.conf`) reloads the front nginx when the generated file changes. (#208)

#### Changed
- **The admin-console one-click feature toggle defers to the reconciler** when
  `ZITI_RECONCILER` is on: enable/disable only write the `proxy_routes` flags
  (`ziti_enabled` / `browzer_enabled` / `ziti_service_name`) and enqueue a
  converge — no imperative service/policy creation or SDK hosting. Imperative
  behavior is unchanged when the reconciler is off. (#206)
- `RegenerateConfigs` (the toggle path) now also rewrites the hop and public
  vhost configs, not just the bootstrapper targets and router config — so a
  newly-toggled app gets its hop/public block live without a restart. (#208)

#### Fixed
- **`psm.tdv.org` 502 + feature-manager↔reconciler conflict**: with the
  reconciler on, the UI toggle still provisioned imperatively (SDK-hosting the
  service with an `edge` terminator and `#access-proxy-clients` policies, and
  renaming `ziti_service_name`), colliding with the reconciler's router-hosted
  `tunnel` terminator — the access-proxy then forwarded plain HTTP to the app's
  `:443`. Fixed by attaching the `host.v1` config to existing services
  (`EnsureServiceConfig`, #205) and by making the toggle defer (#206).
- **BrowZer hop leaked `unknown:<port>` on server redirects**: the hop set the
  upstream `Host`, so the app emitted a correct absolute `Location`, but nginx's
  **default `proxy_redirect`** rewrote it back to the proxy's own address — and
  since the runtime's `Host` is `unknown`, that became
  `http://unknown:<port>/…` (the psm Entra-login 302). Generated hop blocks now
  emit `proxy_redirect off;`. (#207)
- **Reconciler self-heals drifted `host.v1` configs** (create-or-PATCH on data
  drift) so per-app hop-port reshuffles converge automatically with no manual
  `ziti edge delete config`. (#204)

### Dark (loopback-bound) services behind BrowZer + native client (#196)

Publish a service that is **completely dark to the outside** — bound to host
loopback, reachable only over the OpenZiti overlay — while still serving it
clientlessly via BrowZer and/or a native client.

#### Added
- **`BROWZER_HOST_LOOPBACK_ALIAS`** (env, `browzer_targets.go` `browzerUpstream()`).
  In rootless deployments the native access-proxy (a host process) reaches a dark
  target at `127.0.0.1`, but the BrowZer router (a separate network namespace,
  e.g. slirp4netns) cannot. Since both upstreams derive from one route `to_url`,
  this knob rewrites a `127.0.0.1`/`localhost` `to_url` to the alias (e.g.
  `10.0.2.2` with `allow_host_loopback`) **for the BrowZer router config only**.
  Unset (the default, e.g. docker-compose where router and app share a bridge) →
  no rewrite, behavior unchanged.
- Admin console **Identities**: a **Download `.jwt`** button on the enrollment
  modal, so a one-time enrollment token can be fed straight to
  `ziti-edge-tunnel enroll --jwt` / Ziti Desktop Edge for native (no-browser)
  access to dark services.
- `docs/OPENIDX_ZITI_ARCHITECTURE.md`: full OpenIDX + OpenZiti architecture
  guide, including a "dark services + native client" recipe (and the rootless
  loopback-alias wrinkle).

### One-click OpenZiti/BrowZer toggles on proxy routes (#195)

#### Added
- `RouteFeatureToggles` — compact **OpenZiti** and **BrowZer** switches rendered
  directly in each HTTP proxy route's action bar on the Proxy Routes page, so
  putting a route behind the overlay (and publishing it clientlessly via BrowZer)
  is a single click. BrowZer is gated on OpenZiti, matching `ServiceFeaturePanel`.
  Reuses the existing `/services/:id/features/{ziti,browzer}/{enable,disable}`
  endpoints (no backend change) and shares the `['service-status', routeId]`
  query cache with the expand panel so both stay in sync.

### Admin console bug fixes (found via Playwright page sweep)

A headless logged-in sweep of all ~83 console pages surfaced four real bugs:

#### Fixed
- **Governance endpoints returned 401 for every valid token** — governance's
  JWKS key parser ran `ProbablyPrime()` on the RSA *modulus*, which is `p×q`
  (composite by definition), so it rejected every key. All governance pages
  (access-reviews/requests, policies, abac-policies, approval-policies,
  campaigns) were unusable. Replaced with the correct odd-modulus check.
- **`GET /users/me/consents` 500** — the query selected `rt.scope` without
  including it in `GROUP BY` (SQLSTATE 42803). Now aggregates with
  `string_agg(DISTINCT rt.scope, ' ')`.
- **Migration v39** — creates `device_trust_requests`, `device_trust_settings`,
  `trusted_browsers`, `risk_policies`, which existed only in `init-db.sql` (the
  same gap class as v38), so their handlers 500'd on RDS/Helm/`migrate` deploys.
  Also made `GetDeviceTrustSettings` return defaults on no-rows instead of 500.
  *(A wider audit found ~70 more tables only in `init-db.sql`; closing that whole
  gap — and reconciling init-db.sql's own duplicate `lifecycle_executions` — is
  tracked as follow-up.)*
- **`/users` client crash** — avatar initials read `user.username[0]` without a
  null guard (`Cannot read properties of undefined`). Now uses optional chaining
  with a `'?'` fallback.
- **`/users` showed blank names/emails + "Invalid Date"** — the admin users API
  speaks SCIM (`userName`, `name.givenName`, `emails[].value`, `createdAt`,
  `active`) per the identity models + SCIM integration tests, but the console is
  flat snake_case throughout. The console now adapts SCIM↔flat for the users
  endpoint (read and create/update) in `users.tsx`, leaving the rest of the page
  flat. (Backend left unchanged — its SCIM shape is the codified contract used by
  `/scim/v2/Users` and internal oauth/webauthn callers.)
- **`/groups` showed blank descriptions, wrong type, "Invalid Date"** — same
  SCIM↔flat mismatch (`displayName`, `attributes.{description,parentId}`,
  `createdAt`). `groups.tsx` now adapts read and create/update. (Member counts
  show 0 — the list endpoint doesn't return them; an API enhancement, not a
  console fix.)
- **Other SCIM-shaped consumers** (found by auditing every console call to the
  identity user/group endpoints): the group "add member" user-search dropdown
  (`/users/search`, SCIM) and the bulk-operations group selector
  (`/groups`, a bare SCIM array — the code expected `{data:[{id,name}]}`) now
  map SCIM→flat too. Audited as already-correct: group members, user roles,
  roles, and `/users/me` (camelCase, which `user-profile` already matches).

### One-click "open internal app" — published apps as launcher tiles

#### Added
- `POST /api/v1/access/apps/:id/publish-app` publishes a registered app as a
  one-click tile: it creates a single host-level proxy route, auto-creates a
  **My Apps** launcher tile (`applications` row, `base_url` = the gated public
  URL), and registers the per-host `…/access/.auth/callback` on the
  `access-proxy` OAuth client so SSO round-trips without a manual OAuth edit.
- `ACCESS_APPS_DOMAIN` config: bare-label hosts (e.g. `netgraph`) resolve to
  `<label>.<ACCESS_APPS_DOMAIN>` so every app lives under one wildcard domain
  with a single wildcard TLS cert.
- Migration **v41**: `published_apps.public_host` + `landing_path` (where the
  tile opens, default `/`, e.g. `/ui/` for apps not served at the site root).
- Admin console **App Publish → Publish App** dialog (public host + landing
  path). Docs: `docs/app-publishing.md` "One-Click Publishing" section.

### Access-proxy forward-auth: honor X-Forwarded-Proto

#### Fixed
- The access-service built its OAuth callback (`/access/.auth/callback`) as
  `http://` from `c.Request.Host`, ignoring `X-Forwarded-Proto`. Behind a
  TLS-terminating proxy (nginx/APISIX) the public URL is HTTPS, so the emitted
  `redirect_uri` didn't match the registered/public `https://` URL and the
  browser callback hit a non-TLS port. Added a `callbackScheme()` helper
  (X-Forwarded-Proto → request TLS → http) and applied it to all four callback
  builders (the built-in access-proxy login/exchange + the external-IDP paths).

### Access-proxy / App Publish schema fix (migration v40)

#### Fixed
- **App Publish was broken on every migrate-based / RDS / Helm deploy.**
  `GET /api/v1/access/apps` 500'd because `published_apps`, `discovered_paths`
  and `service_features` lived only in `init-db.sql`; `GET /api/v1/access/routes`
  500'd with `column "idp_id" does not exist` because the `proxy_routes` (and
  `proxy_sessions`) schema had drifted ~12 columns behind `init-db.sql`
  (`idp_id`, `route_type`, `remote_host/port`, posture/risk/guacamole/browzer …).
  Migration **v40** creates the missing tables and adds the missing columns
  (idempotent). Verified by registering→discovering→publishing an internal app
  end-to-end.

### gateway-service startup fixes

`gateway-service` panicked on startup under gin v1.11.0 and never began serving
(installs fronting it with APISIX wouldn't have noticed). Three stacked bugs,
each masked by the previous panic:

#### Fixed
- **Route catch-all conflict**: each service's route file registered ~dozens of
  explicit routes *plus* a `/*path` catch-all with the identical proxy handler;
  gin v1.11.0 rejects a catch-all alongside explicit siblings (`/users`).
  Collapsed each service to the single catch-all — behaviourally identical (one
  handler, no per-route middleware) and the correct shape for a pass-through.
- **Duplicate `/health` registration**: the gateway `Service`, the standardized
  `newhealth` service, and the routes package each registered `/health` (and
  `/ready`) on the same engine → `handlers are already registered for path
  '/health'`. The gateway now uses the `Service`'s health routes only (which is
  what the k8s probes and compose healthcheck hit at `/health`).
- **Wrong proxy targets**: `serviceURLProvider` hardcoded `localhost:8501–8506`
  (ignoring env), so the gateway proxied to non-existent/incorrect ports. Fixed
  the defaults to the services' real ports (`8001/8002/8004/8005/8006`) and added
  `<SERVICE>_SERVICE_URL` env overrides (e.g. `IDENTITY_SERVICE_URL`).

### CI green-up + GetUser NULL-name fix

#### Fixed
- **`GetUser` 404'd on users with no name**: `users.first_name`/`last_name` are
  nullable, but the read scanned them into non-pointer strings, so any name-less
  user (valid per SCIM) errored the scan and surfaced as 404. The read now
  `COALESCE`s both to `''`.
- **CI Lint**: removed an ineffectual `countArgCount++` in `internal/admin/service.go`.
- **CI Integration job**: set `DEFAULT_ORG_FALLBACK=true` for the suite. It is
  single-org (most tests log in the seeded admin without an `X-Org-Slug`/subdomain
  signal); the config default flipped to `false` in v1.7.0, which had been failing
  every admin-token-dependent test. The cross-org test still sends `X-Org-Slug`
  explicitly, so isolation is still validated.

### Tenant login branding + production hardening (v1.9.0)

Per-tenant branding on both login surfaces, plus production-readiness fixes —
three of which were surfaced by a prod-like local docker-compose smoke and would
otherwise only have failed in a real multi-tenant deploy.

#### Added
- **OAuth server-rendered login page branding** (`internal/oauth/service.go`):
  `renderLoginPage` now applies the resolved tenant's `tenant_branding` (logo,
  favicon, colors, titles, custom CSS, footer, powered-by toggle) with safe
  defaults on no-org/no-row; text/attrs escaped, `custom_css` treated as trusted
  admin input. Unit test `internal/oauth/branding_test.go`.
- **SPA login branding** (`web/admin-console/src/pages/login.tsx`): applies
  favicon, secondary color, page background (color/image), injected `custom_css`,
  custom footer, and powered-by visibility — on top of the existing
  logo/primary/title/message handling.
- **Migration v38**: creates `tenant_branding`, `tenant_domains` and
  `tenant_settings` in the versioned migration set. They previously existed only
  in `deployments/docker/init-db.sql` (docker-compose), so managed-RDS/Helm
  deploys never had them — branding could not be saved and domain-based tenant
  resolution silently returned defaults. DDL is idempotent.
- **`DATABASE_SSL_MODE` plumbed through deploy configs**: parametrized in
  docker-compose (`${DATABASE_SSL_MODE:-disable}`), the Helm DB-URL secret
  (`database.sslMode`), and documented in `.env.example`. (The Go config/pool
  side already honored it.)
- **`values-prod.yaml` + runbook**: production tenancy env (`TENANT_BASE_DOMAIN`,
  `DEFAULT_ORG_FALLBACK=false`), `database.sslMode: require`, and the tenancy/RLS
  sections + multi-tenancy post-deploy smoke in `docs/DEPLOYMENT.md`.

#### Fixed
- **Public login-branding endpoint blocked in multi-tenant deploys**: the
  fail-closed `TenantResolver` rejected `GET /api/v1/identity/branding` when
  `DEFAULT_ORG_FALLBACK=false`, so the login page could never load tenant
  branding. The endpoint (which self-resolves the tenant from `?org=`/`?domain=`)
  is now exempt from tenant resolution.
- **`TestRLSBelt` was inert under a superuser DB role**: PostgreSQL superusers
  (and `BYPASSRLS` roles) ignore RLS even with FORCE, so the belt test passed
  vacuously against the default `openidx` superuser used by the postgres image
  and CI. It now runs its assertions as a dedicated `NOSUPERUSER` role —
  mirroring how production connects to RDS — making the CI gate meaningful.
  Documented the non-superuser connection requirement in `docs/DEPLOYMENT.md`.

#### Tenancy env injection (Helm)
- The `-config` ConfigMap now carries `TENANT_BASE_DOMAIN`, `DEFAULT_ORG_FALLBACK`,
  `DEFAULT_ORG_ID` and `DATABASE_SSL_MODE`, and every backend deployment mounts it
  via `envFrom` so the settings actually reach the pods.

### Multi-tenancy — RLS belt + per-org primitives (v1.8.0)

Defense-in-depth: Postgres Row-Level Security so a missing app-layer org filter
still cannot leak across tenants, plus the per-org primitives.

#### Added
- Migration **v37**: activates RLS on all 68 org-scoped tables — policies
  rewritten to `app.bypass_rls='on' OR org_id = current_setting('app.org_id')`
  with `ENABLE` + `FORCE ROW LEVEL SECURITY` (fail-closed when the GUC is unset).
- Pool-checkout GUC injection (`internal/common/database/rls.go`): each
  connection is stamped with the request's tenant scope from `orgctx`; no query
  call-site changes. `orgctx.WithBypassRLS` is the explicit opt-in for
  background/cross-org jobs (wired into ~25 ticker/sweep entrypoints + the migrator).
- Two-tenant RLS ship-gate test (`test/integration/cross_org_test.go:TestRLSBelt`):
  a raw cross-org `SELECT` returns 0 rows even with the app filter "broken".
- Per-org rate-limit buckets; `compliance_reader` org-scoped read-only audit role;
  admin-console **Branding** page; `docs/multitenancy-upgrade-runbook.md`.

#### Changed
- **BREAKING (operational):** with RLS forced, direct SQL against org-scoped
  tables sees no rows unless the session sets `app.org_id` (or
  `app.bypass_rls='on'`). See the upgrade runbook.

### Multi-tenancy — App-layer enforcement (v1.7.0)

The v2.0 multi-tenancy epic's enforcement milestone. Every service query now
reads `org_id` from request context and filters/populates by it
(`orgscope ./internal` = 0), and tenant isolation is **activated**.

#### Added
- Cross-org integration test (`test/integration/cross_org_test.go`): a token
  scoped to org A gets **404** (not 403) reading org B's data; a platform admin
  (`super_admin`) may read cross-org via `X-Org-ID` and every such access writes
  an `audit_events` row (`platform_admin_cross_org_access`).
- Platform-admin bypass + mandatory audit, wired through the `TenantResolver`
  (`OnPlatformCrossOrg` hook + `auth.SuperAdminPredicate`).
- Per-tenant JWT `iss` and per-tenant OIDC discovery, derived from the org slug
  and `TENANT_BASE_DOMAIN`.
- Admin-console tenant selector (super_admin-only) that scopes requests via
  `X-Org-Slug`.
- `orgscope` is now a hard CI gate (`-fail`).

#### Changed
- **BREAKING (config):** `DEFAULT_ORG_FALLBACK` now defaults to **false** — a
  request that resolves no tenant is rejected (400) instead of being scoped to
  the default org. Single-tenant installs must set `DEFAULT_ORG_FALLBACK=true`.
- JWT `iss` is per-tenant when `TENANT_BASE_DOMAIN` is set (token-format change;
  global issuer otherwise, so single-tenant installs are unaffected).

## [1.6.0] - 2026-06-11

**Multi-tenancy Foundation milestone.** First of four releases in
the v2.0 multi-tenant SaaS isolation epic (`docs/v2-multitenancy-
design.md`). v1.6.0 lays the schema + plumbing groundwork **without
changing any behavior** for existing single-tenant installs — the
ship gate for this milestone is "existing functionality unchanged."

Multi-tenancy enforcement comes in v1.7.0 (service-layer query
scoping) and v1.8.0 (RLS belt + per-org primitives). v1.6.0 is the
foundation other releases build on.

### Added

- **`internal/common/orgctx` package** (#136). Pure-additive
  `context.Context` carrier for the resolved organization (UUID id
  + slug) and a platform-admin marker. The tenant-resolution
  middleware writes into it; v1.7.0 service code reads from it.
  `With` / `From` / `MustFrom` / `WithPlatformAdmin` /
  `IsPlatformAdmin` exposed with `ErrNoOrgContext` sentinel. 10
  unit tests.

- **`internal/common/middleware.TenantResolver`** (#140). The gin
  middleware that resolves the request's organization from
  `X-Org-Slug` header (gateway-set from subdomain), JWT `org_id`
  claim already attached by the Auth middleware, or `X-Org-ID`
  header (platform-admin only). Falls back to the install's
  default org so single-tenant installs keep working unchanged.
  Defines the `OrgLookup` interface and `ErrOrgNotFound`
  sentinel. 16 unit tests covering every resolution path.

- **`tools/orgscope` CLI** (#141). Static helper that walks
  `internal/` looking for SQL statements targeting a scoped
  table without an `org_id` reference. Filters out gin's
  `c.Query("client_id")`-style false positives by checking that
  the string literal starts with a SQL keyword. Mirrors v36's
  scoped-table list (68 tables, with documented install-wide
  exclusions). Wired into Go CI as an **informational job**
  ("Org-scope lint") that posts findings to the run summary but
  never gates a PR — v1.7.0 will promote to `-fail` once the
  service-layer refactors complete. Baseline on current `main`:
  ~1096 findings, each a concrete v1.7.0 refactor target. 28
  unit + fixture tests.

- **`docs/v2-multitenancy-design.md`** (#135). The architectural
  design doc the v1.0 plan called out as a v2 prerequisite.
  Captures three approved decisions (tenant resolution model,
  app-layer + Postgres RLS defense-in-depth, automatic `'default'`
  org backfill for existing installs), the four-milestone delivery
  plan (v1.6 → v2.0), out-of-scope items, risk register, sizing.

### Changed (schema)

- **Migration v34** (#137) — `org_id UUID NULL` column +
  `idx_<table>_org_id` index added to ~55 tables that migration
  v25 didn't reach (api_keys, mfa_*, oauth_*_tokens, ziti_*,
  scim_*, directory_*, privacy_*, posture_*, governance tables,
  …). Idempotent via `IF NOT EXISTS`. Six tables explicitly **not**
  scoped because they are install-wide rather than tenant-data:
  `organizations`, `permissions`, `system_settings`,
  `ip_threat_list`, `posture_check_types`, `policy_sync_state`.

- **Migration v35** (#138) — Backfills the default organization
  UUID (`00000000-0000-0000-0000-000000000010`, created by v25)
  into every NULL `org_id` row across v34's scoped set. Idempotent
  via `WHERE org_id IS NULL` guards. Down is narrower: only
  reverses rows currently holding the default UUID, so multi-org
  installs (none today) stay intact.

- **Migration v36** (#139) — Final foundation migration. For each
  of the 68 scoped tables, applies `SET DEFAULT '<default-org-
  uuid>'` (preserves ship gate — INSERTs that omit `org_id`
  silently land in default), `SET NOT NULL`, `ADD CONSTRAINT
  fk_<t>_org … REFERENCES organizations(id) ON DELETE RESTRICT`,
  and `CREATE POLICY pol_<t>_org_scope … PERMISSIVE … USING
  (true)`. **RLS is NOT enabled** on the tables — v1.8.0 owns
  activation by `ALTER POLICY` to a real org filter + `ALTER TABLE
  … ENABLE ROW LEVEL SECURITY`. v1.7.0's final PR will `DROP
  DEFAULT` once every INSERT path is org-context-aware.

### Notes for operators

- **No operator action required.** Migrations are
  forward-only-idempotent and `default` org is created
  automatically. The install behaves as a single-tenant install
  did before, just with the multi-tenancy plumbing ready
  underneath.
- **Migration v36 caveat:** `SET NOT NULL` on a table with very
  many rows (audit_events, login_history at scale) runs a
  validation scan. v35 backfilled every existing row so the scan
  succeeds, but for the largest installs we recommend the
  migration runs during a maintenance window.
- `tools/orgscope` baseline (~1096 unscoped queries) is **not**
  a regression — it documents the surface v1.7.0 will refactor.
  The CI job posts the count informationally; PRs are not gated.

### What's NOT in this release

- No enforcement of org scoping. Service code still ignores
  `orgctx`. Queries do not filter by `org_id` yet. RLS is not
  enabled. (v1.7.0 owns the app-layer enforcement; v1.8.0 owns
  RLS.)
- No tenant signup UI, billing, hard quotas, per-tenant signing
  keys, schema/db-per-tenant — those are explicitly out of scope
  for the entire v2.0 epic; see the design doc.

## [1.5.0] - 2026-06-11

A docs-only release that closes the last open P2 backlog item from
the v1.0 plan. No code change; safe to skip if you're already on
v1.4.0 and don't need the new operator-facing docs.

### Added
- **`docs/SECURITY-HARDENING.md`** (#133). Production-readiness
  checklist where every "hard requirement" row maps to a check in
  `Config.ValidateProduction()` — the in-process blocking startup
  gate that already refuses to bring up a misconfigured production
  deploy. Covers the secrets / transport / CSRF-CORS-audit-stream /
  debug-knob sections the validator gates on, plus an "outside the
  validator" section for the operational items that aren't config
  flags. The policy at the bottom nails down validator-first,
  doc-update-in-the-same-PR.
- **`docs/SECURITY-TENANCY.md`** (#133). Explicit, prose statement
  of the single-tenant assumption the v1.0 plan made and the v1.x
  releases preserved. Describes what is shared (data layer,
  identity, authorization, audit), what we do support (federation
  across IdPs, per-app authz, per-customer deployments), and what
  we don't (row-level tenant isolation, per-tenant signing keys,
  per-tenant rate limits, per-tenant audit isolation) — and why
  each is intentional, not a gap.

### Changed
- **`SECURITY.md`** Deployment section trimmed (#133). The previous
  generic OWASP-ish bullet list duplicated marketing copy from the
  README and overlapped with the new hardening doc by 90%. Replaced
  with two pointers to `SECURITY-HARDENING.md` and
  `SECURITY-TENANCY.md` plus the lock-step policy. Vuln reporting
  and supported-versions sections are unchanged.
- **`README.md`** Overview (#133). Adds a prominent blockquote that
  states the single-tenant assumption in one sentence and links to
  `docs/SECURITY-TENANCY.md`. First-impression accuracy for readers
  who would otherwise spend time evaluating us against a multi-
  tenant SaaS use case we don't support.
- **`docs/GETTING-STARTED.md`** "Initialize Database" step (#133).
  The old step told operators to run `\i migrations/001_create_tables.sql`
  — a pre-historic flow. Replaced with the supported path: build
  `cmd/migrate`, run `migrate up`, verify with `migrate status`.
  Plus a top-of-doc callout pointing readers at the new hardening
  and tenancy docs before any production deploy.

### Notes
- v1.4.0 deployments upgrade in place. The release tags the v1.5.0
  binaries identically to v1.4.0; if you don't pull the docs, the
  upgrade is a no-op.

## [1.4.0] - 2026-06-11

A short, focused security-hardening release. Three independent P1/P2
items the v1.0 plan called out, each landed as its own commit with
defense-in-depth tests:

### Changed
- **Dynamic UPDATE builders now run behind a column allow-list**
  (#129). Both `updateSAMLServiceProvider`
  (`internal/oauth/saml_sp.go`) and the
  `/access/paths/:pathID/classification` handler
  (`internal/access/app_publish.go`) used to build their SQL with
  `fmt.Sprintf("col = $%d", argIdx)` scattered through one if-block
  per column. The literals were hardcoded so the pattern was not
  actively exploitable, but the blast radius was wide: one refactor
  wiring a request-derived string into a Sprintf would have introduced
  a real SQL-injection vector. The new `buildUpdateClause` helper
  takes a per-caller column allow-list, validates each candidate
  against both that map and a strict identifier regex
  (`^[a-z_][a-z0-9_]{0,62}$`), and refuses to build the query when
  anything else slips through. Unit tests pin the rejection paths.
- **Migration lock acquisition retries up to 30 s before giving up**
  (#130). Previously `acquireLock` returned instantly on conflict —
  fine for a single admin-driven `cmd/migrate up`, but it raced in
  containerized environments where the migrate job and the
  identity-service / oauth-service replicas were all coming up against
  the same database at startup. Whichever migrator won the race ran
  the migrations; every other process exited with "lock is already
  held" and the orchestrator restarted them in a crash loop. The lock
  now retries every 500 ms for up to 30 s before reporting failure.
  Stale-lock recovery (15 min) is unchanged. A real DB error (not
  `errLockBusy`) still surfaces on the first try — only conflicts
  retry. Six unit tests pin the new behavior including
  context-cancellation handling.
- **CSRF protection is on by default** (#131). The
  `csrf_enabled` default flipped from `false` to `true`. The
  production gate (`ValidateProduction`) caught the old default
  anyway, but every non-prod environment had to remember to opt in.
  Operators now opt out (`CSRF_ENABLED=false`) only when they know
  they need to.

### Fixed
- **`internal/access/ziti.go` was hardcoding
  `tls.Config{InsecureSkipVerify: true}` unconditionally** (#131).
  The line ran before the CA-loading branch, which then bolted a
  `RootCAs` pool onto the TLS config — but `InsecureSkipVerify=true`
  nullifies every CA after it, so the verification path was doing
  nothing for security and the connection was insecure regardless of
  the operator's intent. Replaced with:
  - Load `ZitiIdentityDir/ca.pem` → use it for proper validation
    (the desired path).
  - Missing CA + `ZitiInsecureSkipVerify=true` → log a warning and
    use `InsecureSkipVerify` (the dev-loop escape hatch).
  - Missing CA + `ZitiInsecureSkipVerify=false` → refuse to start
    with a hint pointing at both knobs (the production refusal).

### Security
- **`ValidateProduction()` now rejects two new misconfigurations**
  (#131):
  - `redis_tls_skip_verify=true`
  - `ziti_insecure_skip_verify=true`
  Both are dev-loop escape hatches against self-signed certs in a
  local docker stack; in production they silently erase the trust
  chain on the link they cover. The blocking startup gate
  (`security_check.ValidateProductionConfig`) now ensures production
  deploys can't ship with either flag on.

### Notes
- All v1.3.0 deployments upgrade in place. The CSRF default flip and
  the new skip-verify production gates are the only behavioral
  changes most operators will see; the SQL builder and migration lock
  refactors are internal.

## [1.3.0] - 2026-06-11

A focused follow-on release driven by the P1.5 backend-test sweep —
which surfaced (and made us fix) two real OAuth-flow bugs and one
missing schema migration that production deployments had been
silently broken on since the QR-login feature shipped.

### Added
- **Backend unit-test coverage on previously untested seams** (#122):
  - `internal/oauth/authorize_handler_test.go` — the methods on
    `*AuthorizeHandler` (`validateRedirectURI`, `validateResponseType`,
    `validateScope`, `validatePKCEParameters`, `parseAuthorizeRequest`)
    were 0% covered; new file takes them to 100% without bringing up
    a Service / Redis / DB.
  - `internal/common/netutil/ssrf_test.go` — entire package was
    untested. `DefaultSSRFConfig`, `ValidateURL` (scheme / localhost /
    private-IP / no-hostname / allowlist-miss branches),
    `domainMatches`, `isPrivateIP` (RFC 1918 + RFC 4193 boundaries),
    `isLocalhostIP`, `IsPrivateURL`, `KnownPublicAPIs` sanity. Uses
    literal IPs so the test stays off DNS. **Package coverage
    0 % → 66.2 %**.
  - `internal/common/events/bus_test.go` — entire package was
    untested. `Event` constructor + fluent setters + `JSON`,
    `MemoryBus` subscribe / wildcard / all / with-filter / unsubscribe /
    publish-returns-last-error / close-rejects-publish /
    `PublishAsync`-delivers, and the package-level global-bus wrappers.
    **Package coverage 0 % → 100 %**.
- **Integration coverage for stepup + passwordless** (#123, #126,
  #127). Two new test files (`test/integration/stepup_test.go`,
  `test/integration/passwordless_test.go`) exercise 13 routes /
  ~25 cases. The stepup happy-path round-trip and the QR-login
  create / poll happy paths are now part of the gating integration
  suite.
- **Database migration v33: `qr_login_sessions`** (#127). The table
  `internal/identity/passwordless.go` has been `INSERT`-ing into since
  the QR-login feature shipped — but which no migration ever created.
  Every `POST /oauth/qr-login/create` therefore 500'd at the first
  `INSERT` against "relation does not exist". Surfaced by PR #126's
  integration tests; was previously masked by the broken-session-id
  validator (see Fixed below). Schema mirrors the column set the
  package already reads/writes (id, unique session_token, qr_code_data,
  status enum, nullable user_id, JSONB device blobs, IP, four
  lifecycle timestamps) plus indexes on `(status, created_at)` and a
  partial `user_id` index for the post-scan lookups.

### Fixed
- **`/oauth/stepup-*` returned 401 for every valid bearer token**
  (#126, closes #124). The three step-up routes were registered
  against the bare `/oauth` group with no auth middleware in front of
  them. The handlers read `user_id` and `session_id` from the gin
  context — but nothing populated them, because no middleware ran the
  JWT parse. The fix wraps the routes with `authMiddleware` the same
  way the `/oauth/authorize` consent endpoint already does. As a
  defense-in-depth follow-on, `handleAuthorizationCodeGrant` also now
  falls back to a DB lookup for the user's most-recent active session
  when the Redis `authcode_session:<code>` bridge is empty, so the
  access token always carries a usable `sid` claim.
- **`isValidSessionID` rejected every real `login_session`** (#126,
  closes #125). The validator required a strict 36-character UUID,
  but `/oauth/authorize` produces `login_session` via
  `GenerateRandomToken(32)` — a 44-character padded base64url token.
  The mismatch broke QR login, MFA OTP, passkey, and magic-link-verify
  end to end against the actual auth flow. `isValidSessionID` now
  accepts either form: a 36-character UUID, OR a 32..128-character
  base64url token with optional `=` padding. Both still exclude `:`,
  `/`, whitespace, and control bytes — Redis-key injection / path
  traversal stays blocked. Unit tests expanded to 23 cases covering
  the UUID happy path, the base64url happy path with and without
  padding, length boundaries, and the full injection-shaped rejection
  set.

### Notes
- All v1.2.0 deployments upgrade in place. Migration v33 applies on
  startup through the standard migration runner; the table is empty
  on first use and the OAuth service starts populating it
  immediately.

## [1.2.0] - 2026-06-10

A follow-on minor release closing the rest of the P1 and P2 backlog items
queued behind v1.1.0, plus a full sweep through the admin-console test
suite. Every admin-console page is now covered.

### Added
- **GDPR DSAR processor.** `Service.ExecuteDSAR` now actually fulfills
  data-subject access requests instead of marking them "received":
  - `export` (Article 15) compiles 12 categories of subject data (profile,
    consents, sessions, audit events, roles, groups, app assignments,
    access requests, MFA TOTP, MFA WebAuthn, MFA push, prior DSARs).
  - `delete` (Article 17) erases the subject's records.
  - `restrict` (Article 18) flags the subject for restricted processing.
  A background processor (`StartDSARProcessor`) auto-executes new `export`
  requests; `delete` and `restrict` stay manual on purpose. Backed by
  schema migration v32 (privacy tables) (#118).
- **Outbound resilience.** New `internal/common/resilience` package wraps
  external OAuth / SAML / OIDC discovery calls behind a circuit breaker
  (`ResilientHTTPClient` + per-host `Registry`). Long IdP outages no
  longer drag the whole login path down (#117).
- **Frontend test coverage: 100%.** Every page under
  `web/admin-console/src/pages/` (87 in total) now has a vitest suite.
  Suite is 114 files / 684 tests. Patterns established for fixtures with
  TanStack Query, Radix listeners, fetch-direct pages, route params, and
  `useAuth` mocks (#120).

### Changed
- **Application access requests are fulfilled end-to-end.** Approving an
  access request whose `resource_type == application` now provisions the
  application binding through `internal/provisioning`. Prior to this it
  marked the request approved and warned (#117).
- **Certification reviews now enforce decisions.** Reviewing an item
  with `decision == revoke` (whether per-item or via the campaign's
  `revokeUnreviewedItems`) actually revokes the underlying role / group /
  app assignment instead of just recording the decision (#117).

### Fixed
- **Session-cleanup race-detector flake.** `TestSessionService_Session-`
  `ExpirationCleanup` no longer relies on `miniredis.FastForward`, which
  raced the cleanup goroutine when `-race` was on. The test uses a real
  1 s TTL plus a 1.1 s sleep; the helper also closes its Redis client
  via `t.Cleanup` so leaked goroutines don't carry across tests (#119).

### Notes
- v1.1.0 deployments upgrade in place. The new privacy tables (migration
  v32) apply on startup through the standard migration runner.

## [1.1.0] - 2026-06-09

The first minor release after v1.0.0 — three weeks of post-release hardening
focused on real security gaps that integration tests surfaced, plus the
infrastructure to keep them from coming back.

### Added
- **`POST /api/v1/identity/users/:id/set-password`** — direct admin
  password-set endpoint. Hashes via `Service.SetPassword` so password-history
  and policy enforcement apply. Closes the "admin onboards a non-SSO user"
  gap that previously had no API path (#112).
- **`GET /api/v1/identity/users/me/sessions`** — the self-access counterpart
  of the existing admin-only `/users/:id/sessions`. Sources user id from the
  JWT (#114).
- **`GET /api/v1/identity/users/me/mfa/status`** — self-service MFA status
  endpoint. Returns the user's enabled primary factors as an array, distinct
  from the admin-console toggle map at `/mfa/methods`. Backup recovery codes
  are intentionally excluded — they're not a primary factor on their own
  (#114).
- **Integration test suite is now mandatory in CI**. The full 24-test suite
  (Postgres + Redis ephemeral services, real identity + oauth-service
  binaries) runs on every PR; any regression in identity / OAuth / MFA /
  WebAuthn / session flows blocks the merge (#115).

### Changed
- **Token revocation is now enforced at `/oauth/userinfo`.** PR #82 made
  `internal/auth.ValidateToken` fail-closed on revocation, but the OAuth
  service had its own JWT-parse path that never consulted the revocation
  store — `/oauth/revoke`, `/oauth/logout`, and `/oauth/logout-all` were
  redirect-theater. Now backed by two Redis-keyed mechanisms:
  - Per-token blacklist keyed by `sha256(token)`, TTL = remaining token
    lifetime. Used by `/oauth/revoke` and single-session `/oauth/logout`
    (when called with a Bearer).
  - Per-user revocation cutoff (`oauth:user_tokens_revoked_at:<userID>`).
    Used by `/oauth/logout-all` and by OIDC RP-initiated `/oauth/logout`
    when no Bearer is supplied — every token whose `iat ≤ cutoff` is
    rejected by `/oauth/userinfo` (#112, #114).
- **Refresh-token rotation now happens on every `grant_type=refresh_token`
  exchange** (RFC 6749 §6 / RFC 6819 §5.2.2.3). A new random refresh token
  is issued, the old one is deleted *after* the new one's INSERT succeeds,
  and the response carries the rotated token. Clients that don't store the
  rotated token will get `invalid_grant` on the next refresh — this is the
  intended security improvement (#114).
- **`Service.CreateUser` now mirrors the generated UUID back to the
  caller's struct**, so `c.JSON(201, user)` returns a usable `id` and the
  downstream "user.created" webhook + email-verification token insert see a
  real value instead of an empty string (#112).
- **SCIM `active` field now properly maps to the database `enabled` column**
  in `FromUser`. Previously, SCIM-conformant clients posting
  `{"active": true}` silently created users with `enabled=false`, and every
  admin handler queried `WHERE enabled = true` (#112).
- `handleAdminSetPassword` validates `:id` as a UUID up-front (#112).
- `handleRevoke` now signature-verifies the access token before blacklisting
  it (closes a CodeQL "missing JWT signature check" finding) (#112).

### Database
- **Migration v30**: `ALTER TABLE user_roles ADD COLUMN expires_at TIMESTAMPTZ`.
  The column was already referenced by `GenerateJWT` and the role-expiry
  cleaner, but never existed in the v1 schema — every JWT issuance returned
  an empty `roles` claim, which then 403'd the post-#79 admin-API authz gate
  (#105).
- **Migration v31**: `ALTER TABLE oauth_refresh_tokens ADD COLUMN session_id
  UUID`. The column was added when session-bound rotation landed but never
  made it into the schema migrations. Postgres rejected every INSERT, the
  error was swallowed in `handleAuthorizationCodeGrant`, and clients got
  refresh tokens that were never persisted — every `grant_type=refresh_token`
  then 400'd with `invalid_grant` (#114).

### Fixed
- `audit-service` registers the Redis health check it had been silently
  missing — every other service in the fleet was already checking Redis (#109).
- SAML SP metadata: corrected SA5008 XML tag conflicts on
  `Organization{Name,DisplayName,URL}` (#99).
- `internal/oauth/service.go` and `internal/identity/service.go` cleared
  CodeQL "log entries from user input" findings introduced by the new admin
  endpoints (#112).
- Ratelimit test window flake (#98).
- Frontend type-check and test command scripts (#88, #89).
- Race-condition CI job added (#91).
- CVE bumps: Go toolchain 1.25.11, `go-jose/v4` 4.1.4 (#104, #97).

### Test coverage
- `internal/migrations` unit tests for `allMigrations()` integrity (versions
  contiguous, no gaps, no empty SQL) and `splitSQL` behavior pins (#111).
- `internal/oauth.generateStepUpToken` sign/verify round-trip + claim
  shape (#111).
- `internal/oauth.isValidSessionID` regex-gate locked down across 15 cases
  including path traversal, separator injection, newline injection (#111).
- Frontend smoke coverage on top admin pages (#101).

### Docs
- `docs/PRODUCTION-READINESS.md` — end-to-end "can I deploy this?"
  assessment, 35-item pre-deployment checklist, full feature inventory,
  known-gaps register, deployment paths for Docker Compose / Helm /
  Terraform-EKS (#113).

### Upgrade notes
- **OAuth clients** with refresh tokens: after upgrade, the first
  `grant_type=refresh_token` exchange rotates the token. Persist the new
  `refresh_token` from the response; the old one is invalidated. Clients
  that ignore the rotated token will fail at the *second* refresh, not the
  first — make sure your client code stores the new value.
- **Browser SPAs** relying on the legacy "access token survives logout"
  bug: after upgrade, RP-initiated logout actually kills the access token.
  This is the desired behavior; UI flows that depended on the old leak
  should be reviewed.
- **Database**: two new migrations (v30, v31). Both are
  `ALTER TABLE ADD COLUMN IF NOT EXISTS` with nullable columns — backward
  compatible, fast on production-sized tables, no downtime required.

## [1.0.0] - 2026-05-22

The first tagged release: a hardened, single-tenant, self-hostable v1.

### Added
- Production deployment runbook (`docs/DEPLOYMENT.md`) anchored to the
  `ValidateProduction()` startup gate.
- Observability stack wired into the canonical compose file (Prometheus,
  Alertmanager, Grafana with provisioned dashboards, Loki/Promtail, Jaeger).
- GHCR image pipeline: multi-arch (amd64/arm64) images published to
  `ghcr.io/mhmtgngr/openidx/<service>` on every `main` push and `vX.Y.Z` tag,
  now version-stamped (the tag or commit SHA) and surfaced at `/health`.
- Helm `values-prod.yaml` (pinned tags, autoscaling, NetworkPolicies, external
  secrets, managed datastores) and a Helm chart CI workflow.
- Terraform remote-state backend bootstrap (`deployments/terraform/bootstrap/`)
  and a Terraform fmt/validate CI workflow.
- Compile gate for the build-tagged integration test suite, plus an ephemeral
  Postgres/Redis integration-test CI job.
- Backup/restore: real S3 upload and restore-from-S3 wired through the
  `Storage` interface (the previously-unused `S3Storage` backend), with a
  corrected disaster-recovery runbook.

### Changed
- Project status / feature docs rewritten to reflect the real (much more
  complete) state of the codebase.
- Adopted golangci-lint v2 and cleared the lint backlog: enforced `gofmt`,
  `govet`, `ineffassign`, `unconvert`, `bodyclose`, `staticcheck` (SA bug-class)
  and `unused`; removed dead code. `errcheck` remains intentionally deferred
  (dominated by intentional fire-and-forget calls and optional request-body
  binds).

### Fixed
- Frontend `eslint` configuration repaired; 18 stale frontend tests fixed
  (full suite green).
- Security Scanning workflow no longer reports false-red (image-scan gating;
  Semgrep SARIF upload made non-blocking).
- Backup storage: removed misleading "not initialized" panic placeholders and
  added the package's first tests.
- Schema migrations recover a stale advisory lock (from a crashed holder)
  instead of deadlocking on startup.

### Security
- **Identity admin API now enforces authorization.** The `/api/v1/identity`
  routes are deny-by-default: self-service paths (`/users/me`, MFA enrollment,
  trusted browsers, risk assessment, resend-verification) remain available to
  the authenticated user, but every other identity route now requires the
  `admin`/`super_admin` role. Previously these routes were authenticated but
  not authorized.
- **Token revocation is now enforced.** `RevokeUserTokens` previously wrote a
  per-user revocation marker that was never consulted; tokens issued before a
  revocation are now rejected. Added opt-in fail-closed validation
  (`WithRevocationRequired`) for production.
- **Auth endpoints fail closed under load-shedding.** The distributed rate
  limiter now rejects auth-sensitive requests (login, token, OTP, magic-link,
  password-reset, step-up) when its Redis backend is unavailable, instead of
  silently failing open, and covers more sensitive paths.

### Known limitations (v1)
- **Single-tenant.** One organization per deployment; multi-tenant SaaS
  isolation is not implemented.
- OAuth token introspection does not yet reflect revocation; access-token
  revocation propagates within the access-token TTL (15 min).
- Several built-but-unwired features remain (flagged `TODO(unwired)` in code):
  session idle/absolute-timeout enforcement, SAML SLO session tracking,
  reverse-proxy hop-by-hop header stripping, and audit-stream SIEM config
  endpoints.


[Unreleased]: https://github.com/mhmtgngr/openidx/compare/v1.36.0...HEAD
[1.36.0]: https://github.com/mhmtgngr/openidx/compare/v1.35.0...v1.36.0
[1.35.0]: https://github.com/mhmtgngr/openidx/compare/v1.34.0...v1.35.0
[1.34.0]: https://github.com/mhmtgngr/openidx/compare/v1.33.3...v1.34.0
[1.33.3]: https://github.com/mhmtgngr/openidx/compare/v1.33.2...v1.33.3
[1.33.2]: https://github.com/mhmtgngr/openidx/compare/v1.33.1...v1.33.2
[1.33.1]: https://github.com/mhmtgngr/openidx/compare/v1.33.0...v1.33.1
[1.33.0]: https://github.com/mhmtgngr/openidx/compare/v1.32.0...v1.33.0
[1.32.0]: https://github.com/mhmtgngr/openidx/compare/v1.31.0...v1.32.0
[1.31.0]: https://github.com/mhmtgngr/openidx/compare/v1.29.0...v1.31.0
[1.29.0]: https://github.com/mhmtgngr/openidx/compare/v1.28.0...v1.29.0
[1.28.0]: https://github.com/mhmtgngr/openidx/compare/v1.27.0...v1.28.0
[1.27.0]: https://github.com/mhmtgngr/openidx/compare/v1.26.0...v1.27.0
[1.26.0]: https://github.com/mhmtgngr/openidx/compare/v1.25.0...v1.26.0
[1.25.0]: https://github.com/mhmtgngr/openidx/compare/v1.24.11...v1.25.0
[1.24.11]: https://github.com/mhmtgngr/openidx/compare/v1.24.9...v1.24.11
[1.24.9]: https://github.com/mhmtgngr/openidx/compare/v1.24.8...v1.24.9
[1.24.8]: https://github.com/mhmtgngr/openidx/compare/v1.24.7...v1.24.8
[1.24.7]: https://github.com/mhmtgngr/openidx/compare/v1.24.6...v1.24.7
[1.24.6]: https://github.com/mhmtgngr/openidx/compare/v1.24.5...v1.24.6
[1.24.5]: https://github.com/mhmtgngr/openidx/compare/v1.24.4...v1.24.5
[1.24.4]: https://github.com/mhmtgngr/openidx/compare/v1.24.3...v1.24.4
[1.24.3]: https://github.com/mhmtgngr/openidx/compare/v1.24.2...v1.24.3
[1.24.2]: https://github.com/mhmtgngr/openidx/compare/v1.24.1...v1.24.2
[1.24.1]: https://github.com/mhmtgngr/openidx/compare/v1.24.0...v1.24.1
[1.24.0]: https://github.com/mhmtgngr/openidx/compare/v1.23.5...v1.24.0
[1.23.5]: https://github.com/mhmtgngr/openidx/compare/v1.23.4...v1.23.5
[1.23.4]: https://github.com/mhmtgngr/openidx/compare/v1.23.3...v1.23.4
[1.23.3]: https://github.com/mhmtgngr/openidx/compare/v1.23.2...v1.23.3
[1.23.2]: https://github.com/mhmtgngr/openidx/compare/v1.23.1...v1.23.2
[1.23.1]: https://github.com/mhmtgngr/openidx/compare/v1.23.0...v1.23.1
[1.23.0]: https://github.com/mhmtgngr/openidx/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/mhmtgngr/openidx/compare/v1.21.1...v1.22.0
[1.21.1]: https://github.com/mhmtgngr/openidx/compare/v1.21.0...v1.21.1
[1.21.0]: https://github.com/mhmtgngr/openidx/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/mhmtgngr/openidx/compare/v1.19.0...v1.20.0
[1.19.0]: https://github.com/mhmtgngr/openidx/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/mhmtgngr/openidx/compare/v1.17.0...v1.18.0
[1.17.0]: https://github.com/mhmtgngr/openidx/compare/v1.16.1...v1.17.0
[1.16.1]: https://github.com/mhmtgngr/openidx/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/mhmtgngr/openidx/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/mhmtgngr/openidx/compare/v1.14.1...v1.15.0
[1.14.1]: https://github.com/mhmtgngr/openidx/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/mhmtgngr/openidx/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/mhmtgngr/openidx/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/mhmtgngr/openidx/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/mhmtgngr/openidx/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/mhmtgngr/openidx/compare/v1.10.1...v1.11.0
[1.10.1]: https://github.com/mhmtgngr/openidx/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/mhmtgngr/openidx/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/mhmtgngr/openidx/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/mhmtgngr/openidx/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/mhmtgngr/openidx/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/mhmtgngr/openidx/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/mhmtgngr/openidx/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/mhmtgngr/openidx/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/mhmtgngr/openidx/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/mhmtgngr/openidx/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/mhmtgngr/openidx/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/mhmtgngr/openidx/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/mhmtgngr/openidx/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mhmtgngr/openidx/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mhmtgngr/openidx/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mhmtgngr/openidx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mhmtgngr/openidx/releases/tag/v1.0.0

<!-- [1.24.10] has a section above but no v1.24.10 tag was ever pushed, so it has
     no compare link. Left as-is rather than invented. -->
