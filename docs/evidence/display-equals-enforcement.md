# §5.3 — the display == enforcement invariant

The invariant this whole programme exists to protect: **for each grant type,
the place a person sees it and the place the system enforces it must use the
same predicate.** When they diverge, the console shows a control that decides
nothing — which is worse than showing nothing, because someone will trust it.

Verify whenever access machinery changes, and at least once per release.
Each row's "Verify by" is a two-sided test on purpose: the positive half
proves the grant works, the negative half proves it is a *grant* rather than
decoration. Running only the positive half is how this class survives.

| Grant | Displayed at | Enforced at | Verify by |
|---|---|---|---|
| App assignment | My Apps & Network, Access 360 | `internal/appaccess` via the proxy, `/oauth/authorize`, Ziti dial policy | assignment report empty; dial as an assigned user, then as an unassigned one |
| Role / group | Users, Groups | JWT `roles` claim, route checks | probe an admin route as a member, then as a non-member |
| Vault / PAM grant | My Privileged Access, PAM pages | `pamEntryAllowed` at connect and at reveal | connect as a granted user, then as an ungranted one |
| Session | Sessions pages | Redis `revoked_session:*` at the refresh grant; userinfo checks the per-token blacklist and the per-user cutoff instead (`internal/revocation`) | revoke, then refresh — the refresh must fail |
| MFA policy | MFA Management | `IsMFARequired` in the OAuth login path | a policy user is challenged; an exempt user is not |
| Device trust | My Devices, Access 360 | Ziti posture + the `#device-trusted` attribute | an untrusted device is denied the dial |
| **ABAC policy** | ABAC Policies (with its mode badge) | `internal/abac` at both PEPs — the token endpoint and the access proxy | in `observe`, a deny policy records `abac.would_deny` and still issues; in `enforce`, the same policy returns 403 and audits `abac.denied` |
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
| App assignment at the Ziti dial, identity-mode routes | None. Under enforcement the access proxy loses its own dial on these routes (#984) | — |
| ABAC policy | `TestEvaluateAgainstTheMigratedSchema` (the evaluator), `TestABACGateAtAuthorization` (the token endpoint), `TestABACGateAtTheProxy` (the proxy) | the unit jobs, against a migrated Postgres |
| Role at an admin route | `TestARealTokenOpensAnAdminRouteOnlyForAMember`. The issuer mints the token from `user_roles` and publishes its key at its JWKS. `middleware.Auth` verifies the token against that JWKS, and `RequireRoles` reads the claim. Covered: a member, a non-member, a lapsed time-bound role, a role removed before minting, and a forged token | the unit job for `internal/oauth`, against a migrated Postgres |
| Vault / PAM grant at reveal | `TestPrivilegedCredentialRevealIsGranted`, both halves | the integration job |
| Vault / PAM grant at connect | `TestPamConnectFollowsTheGrant`: for each user, the entry list beside the connect handler. It covers a user grant, a group grant, no grant, a lapsed grant and a view-only grant | the unit job for `internal/access`, against a migrated Postgres |
| JIT elevation | `TestJITElevationEndsAtTheKillSwitch`: the grant listed by User Access 360 and counted by the portal, then the kill switch through its route, with another user's elevation left alone | the unit job for `internal/access`, against a migrated Postgres |
| Device trust at the dial | `TestPostureDecidesWhoDialsTheAdminPlane`, with `POSTURE_DEVICE_TRUST_GATE=enforce` and the dark-service tiers on (both are off by default). A compliant posture report grants `#device-trusted` and the admin plane is dialable. A failing report removes it and the dial is denied, while Tier 1 stays. In `observe`, nothing changes | the unit job for `internal/access`, against a migrated Postgres and a fake controller |
| Session, MFA policy | Covered in the PRs that fixed them; see below | — |

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

### The two rows whose tests arrive with their fixes

Mapping these rows found a divergence in each, so each row's two-sided test
ships in the PR that fixes it:

- **Session.** Revoking through the product found **#992**. A session a user
  ended from their Sessions page (`identity.TerminateSession`) lost its row but
  not its refresh tokens, so the signed-out device went on refreshing. The fix
  and the row's two-sided test (`TestAnEndedSessionCannotRefresh`) are in
  #993.
- **MFA policy.** Mapping this row found **#990**:
  - the console showed required methods and a grace period that nothing
    enforced;
  - the API accepted only conditions no code reads.

  #991 refuses what is not enforced. It also adds the row's two-sided test on
  the login path (`TestMFAPolicyRaisesTheLoginChallenge`): with a policy on, a
  user with a factor is challenged; with it off, or with no factor, they are
  not.

## Runs

| Date | Who | Rows verified | Divergence found | Output |
|---|---|---|---|---|
| 2026-09-23 | Automated: the tests named above, run against a migrated Postgres 16 in a development container, not against a deployed install | Every row. Session and MFA are covered in #993 and #991, and identity-mode dial routes in #987 | #984 (proxy dial, identity-mode routes), #988 (User Access 360 answered 500), #990 (MFA methods and grace shown, not enforced), #992 (an ended session kept refreshing). Also a view-only PAM grant is offered Connect | #982, #985, #987, #989, #991, #993 |

## Notes for whoever runs this next

- The **negative** half is the one that finds things. A grant that works is
  the expected case; a *revocation* that does not is the finding.
- ABAC's row has three states, not two. Check the console's mode badge first —
  a deny that does not deny is correct behaviour in `observe`, and a defect in
  `enforce`.
- A role removed from a user is missing from the next token they get. A token
  minted before the removal still carries the role until it expires, unless
  the path that removed it also cuts the user's tokens (see `TokenCarries` in
  `internal/jitgrant`).
- Session revocation has a latency floor: the marker is written synchronously,
  but a token already minted stays valid until its TTL. Verify the refresh
  path, not the access token.
