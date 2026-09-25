# §5.3 — the display == enforcement invariant

The invariant this whole programme exists to protect: **for each grant type,
the place a person sees it and the place the system enforces it must use the
same predicate.** When they diverge, the console shows a control that decides
nothing — which is worse than showing nothing, because someone will trust it.

Verify whenever access machinery changes, and at least once per release.
Every release runs the automated checks below on its own; see
[Every release](#every-release).
Each row's "Verify by" is a two-sided test on purpose: the positive half
proves the grant works, the negative half proves it is a *grant* rather than
decoration. Running only the positive half is how this class survives.

| Grant | Displayed at | Enforced at | Verify by |
|---|---|---|---|
| App assignment | My Apps & Network, Access 360 | `internal/appaccess` via the proxy, `/oauth/authorize`, Ziti dial policy | assignment report empty; dial as an assigned user, then as an unassigned one |
| Role / group | Users, Groups | JWT `roles` claim, route checks | probe an admin route as a member, then as a non-member |
| Vault / PAM grant | My Privileged Access, PAM pages | `pamEntryAllowed` at connect and at reveal | connect as a granted user, then as an ungranted one |
| Session | Sessions pages | The refresh grant checks the refresh token's own row (`revoked_at`) and the Redis `revoked_session:*` marker. Userinfo checks the per-token blacklist and the per-user cutoff instead (`internal/revocation`) | revoke, then refresh — the refresh must fail |
| MFA policy | MFA Management (required methods, grace period) and the sign-in page (the deadline notice) | `IsMFARequired` and `evaluateMFA` in the OAuth password login, and `mfa_policy_grace`. A policy with required methods accepts only those; a user with none of them signs in until their grace period ends, then only with a bypass code. With no methods it challenges every user with a factor. Conditions are refused (#990) | with a policy that requires TOTP, a user with TOTP and email OTP is offered TOTP alone; a user with only email OTP signs in inside the grace period, is told the deadline, and is refused after it. With the policy off, or with no methods, any factor satisfies it, and a user with no factor is not challenged |
| Device trust | My Devices, Access 360 | Ziti posture + the `#device-trusted` attribute | an untrusted device is denied the dial |
| **ABAC policy** | ABAC Policies (with its mode badge) | `internal/abac` at both PEPs — the token endpoint and the access proxy | in `observe`, a deny policy records `access.abac.would_deny` and still issues; in `enforce`, the same policy returns 403 and audits `access.abac.denied` |
| **JIT elevation** | User Access 360, portal dashboard ("active JIT grants") | `internal/jitgrant` over `access_requests` — the expiry sweep, the kill switch, the lifecycle sweep, deprovisioning | grant a time-boxed role, confirm it is listed and counted, then press the kill switch: the role must be gone, the request `expired`, and `pam_jit_grants_revoked` must be **1** rather than 0 |

**Anything that appears in an admin UI without a row in this table is a
defect: either wire it or remove it.** That rule is what retired the ABAC page
from decoration into the row above, and what removed the dashboard's
"refresh" and "metrics" endpoints rather than faking them.

## Automated checks

A row's "Verify by", as tests that run in CI with both halves. A row without
one is not verified automatically yet; #957 tracks closing that.

| Grant | Tests | Where they run |
|---|---|---|
| App assignment at `/oauth/authorize` | `TestEnforcedAssignmentDeniesAndAudits`, `TestSSOSessionIsSubjectToTheAssignmentGate` | the integration job; the unit job for `internal/oauth` |
| App assignment at the proxy | `TestProxyEnforcesApplicationAssignment`, through `handleProxy` with a session and a real upstream | the unit job for `internal/access`, against a migrated Postgres |
| App assignment at the Ziti dial, BrowZer routes | `TestZitiDialFollowsApplicationAssignment`: the Dial policy the reconciler writes, and the attributes the user sync builds | the unit job for `internal/access`, against a migrated Postgres and a fake controller |
| App assignment at the Ziti dial, identity-mode routes | `TestZitiDialKeepsTheAccessProxyOnIdentityModeRoutes`: under enforcement the Dial policy keeps the access proxy, named by id, while unassigned tunnelers are cut (#984) | the unit job for `internal/access`, against a migrated Postgres and a fake controller |
| ABAC policy | `TestEvaluateAgainstTheMigratedSchema` (the evaluator), `TestABACGateAtAuthorization` (the token endpoint), `TestABACGateAtTheProxy` (the proxy) | the unit jobs, against a migrated Postgres |
| Role at an admin route | `TestARealTokenOpensAnAdminRouteOnlyForAMember`. The issuer mints the token from `user_roles` and publishes its key at its JWKS. `middleware.Auth` verifies the token against that JWKS, and `RequireRoles` reads the claim. Covered: a member, a non-member, a lapsed time-bound role, a role removed before minting, and a forged token | the unit job for `internal/oauth`, against a migrated Postgres |
| Vault / PAM grant at reveal | `TestPrivilegedCredentialRevealIsGranted`, both halves | the integration job |
| Vault / PAM grant at connect | `TestPamConnectFollowsTheGrant`: for each user, the entry list beside the connect handler. It covers a user grant, a group grant, no grant, a lapsed grant and a view-only grant | the unit job for `internal/access`, against a migrated Postgres |
| JIT elevation | `TestJITElevationEndsAtTheKillSwitch`: the grant listed by User Access 360 and counted by the portal, then the kill switch through its route, with another user's elevation left alone | the unit job for `internal/access`, against a migrated Postgres |
| Device trust at the dial | `TestPostureDecidesWhoDialsTheAdminPlane`, with `POSTURE_DEVICE_TRUST_GATE=enforce` and the dark-service tiers on (both are off by default). A compliant posture report grants `#device-trusted` and the admin plane is dialable. A failing report removes it and the dial is denied, while Tier 1 stays. In `observe`, nothing changes | the unit job for `internal/access`, against a migrated Postgres and a fake controller |
| Session | `TestAnEndedSessionCannotRefresh`: a session is created the way login creates it and ended the way the Sessions page ends it (`identity.TerminateSession`). Its refresh then fails, with Redis up and with Redis down. The user's other session keeps refreshing | the unit job for `internal/oauth`, against a migrated Postgres and an in-memory Redis |
| MFA policy | `TestMFAPolicyRaisesTheLoginChallenge`: with a policy on, a user whose only factor is email OTP is challenged at login. With it off, or for a user with no factor, they are not | the unit job for `internal/oauth`, against a migrated Postgres |
| MFA policy, required methods and grace | `TestMFAPolicyRequiredMethodsAtTheLoginDecision`: the offered methods with and without the policy's methods, a remembered browser, the grace window's start, its end with and without a bypass code, a longer grace period reopening it, 0 hours, and the order policies are tried in. `TestMFAPolicyGraceAtTheLoginEndpoint`: the same through `POST /oauth/login`, with the audit rows. `TestMFAPolicyHandlersEnforceTheRules`: what the admin API accepts, and that only a new method set restarts the windows | the unit jobs for `internal/oauth` and `internal/admin`, against a migrated Postgres and an in-memory Redis |

The ABAC tests cover all three states. In `enforce`, a deny policy refuses
the subject it names with a 403 and records `access.abac.denied`. In
`observe`, that subject passes and `access.abac.would_deny` is recorded. A
subject no policy names passes in every mode and leaves no record.

The assignment tests do the same for the other gate. With enforcement on, an
assigned user reaches the application and an unassigned one is refused before
the upstream, or is left out of the Dial policy. With it off, the unassigned
user gets through and the gap is recorded. Each negative half in this table
was mutation-checked: removing the control turns it red.

The PAM test records one gap in the display. The entry list shows an entry held
under any action, and the Connections page offers Connect on it. A view-only
grant therefore shows a Connect button that answers 403. That is closed in the
safe direction, but the button should follow the grant.

The JIT test found a display defect on its first step (#988): on the migrated
schema User Access 360 answered 500 for every user, and had since v1.35.0.
The access map's own tests ran on tables they created by hand, where the
failing query was valid. The tests in this table run on the schema the product
migrates to for that reason.

Mapping two more rows found divergences, fixed with the tests above:

- **Session (#992).** A session a user ended from their Sessions page
  (`identity.TerminateSession`) lost its row but not its refresh tokens, so the
  signed-out device went on refreshing. Ending a session now revokes its
  refresh tokens and publishes the marker (#993).
- **MFA policy (#990).** The console showed required methods and a grace
  period that nothing enforced, and the API accepted only conditions no code
  reads. #991 refused what was not enforced. The methods and the grace period
  are now enforced at the password login, and the console offers them again;
  conditions are still refused.

## Every release

`.github/workflows/display-equals-enforcement.yml` runs on every release. It
runs each test the table above names, one package at a time, against a
migrated Postgres 16. A test that fails, skips or does not run fails the run.
A skip counts as a failure because these tests skip when they have no
database, and then they prove nothing.

The report lands in two places:

- on the GitHub release, as the asset `display-equals-enforcement-vX.Y.Z.md`;
- on the workflow run, as its summary, and in the artifact
  `display-equals-enforcement` with each package's `go test -v` log.

The report gives the date, the ref, the commit, the runner and the Postgres
version, and each test's result. The tests under `test/integration` need the
whole stack, so the release run leaves them to the integration job, and the
report says so.

`.github/workflows/release.yml` starts the run on the tag once the release
exists. It can also be started by hand from the Actions tab, on any branch,
tag or commit.

The table is the only list. The run reads the test names from it, so a test
added to the table runs on the next release. A pull request that renames or
removes a named test fails CI (`scripts/check-display-enforcement-tests.sh`)
until the table changes with it.

To run it yourself, point it at a scratch database. The tests drop and rebuild
its public schema.

```sh
OPENIDX_TEST_DATABASE_URL=postgres://… scripts/run-display-enforcement-tests.sh /tmp/evidence
```

## Runs

This table records runs by hand against a deployed install. The per-release
runs are not copied here: each release carries its own report. The first row
predates the per-release run. It is the automated checks, run by hand in a
development container.

| Date | Who | Rows verified | Divergence found | Output |
|---|---|---|---|---|
| 2026-09-23 | Automated: the tests named above, run against a migrated Postgres 16 in a development container, not against a deployed install | Every row. Session and MFA are covered in #993 and #991, and identity-mode dial routes in #987 | #984 (proxy dial, identity-mode routes), #988 (User Access 360 answered 500), #990 (MFA methods and grace shown, not enforced), #992 (an ended session kept refreshing). Also a view-only PAM grant is offered Connect | #982, #985, #987, #989, #991, #993 |

## Notes for whoever runs this next

- The **negative** half is the one that finds things. A grant that works is
  the expected case; a *revocation* that does not is the finding.
- ABAC's row has three states, not two. Check the console's mode badge first —
  a deny that does not deny is correct behaviour in `observe`, and a defect in
  `enforce`. A fresh install is in `observe` and stays there until an operator
  sets `enforce` (decided in #956), so on a new install the badge reads
  `observe`.
- A role removed from a user is missing from the next token they get. A token
  minted before the removal still carries the role until it expires, unless
  the path that removed it also cuts the user's tokens (see `TokenCarries` in
  `internal/jitgrant`).
- Session revocation has a latency floor: the marker is written synchronously,
  but a token already minted stays valid until its TTL. Verify the refresh
  path, not the access token.
