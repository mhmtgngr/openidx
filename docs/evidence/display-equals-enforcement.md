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
| JIT elevation | `TestJITElevationEndsAtTheKillSwitch`: the grant listed by User Access 360 and counted by the portal, then the kill switch through its route, with another user's elevation left alone | the unit job for `internal/access`, against a migrated Postgres |
| Role / group, Vault / PAM grant, Session, MFA policy, Device trust | Partly; see below | — |

The ABAC tests cover all three states. In `enforce`, a deny policy refuses
the subject it names with a 403 and records `access.abac.denied`. In
`observe`, that subject passes and `access.abac.would_deny` is recorded. A
subject no policy names passes in every mode and leaves no record.

The assignment tests do the same for the other gate. With enforcement on, an
assigned user reaches the application and an unassigned one is refused before
the upstream, or is left out of the Dial policy. With it off, the unassigned
user gets through and the gap is recorded. Each negative half in this table
was mutation-checked: removing the control turns it red.

The JIT test found a display defect on its first step (#988): on the migrated
schema User Access 360 answered 500 for every user, and had since v1.35.0.
The access map's own tests ran on tables they created by hand, where the
failing query was valid. The tests in this table run on the schema the product
migrates to for that reason.

### What the other five rows have today

Each of these rows has tests for its pieces, but none runs its "Verify by"
end to end with both halves. The gap is what #957 still has to close:

- **Role / group.** `TestAdminRouteGating`, `TestRequireAdminUnlessSelfService`
  and `TestRequireAdmin` check both halves at the gate, with roles put straight
  into the request context. No test logs in, gets a real token and probes an
  admin route as a member and then as a non-member. `RequirePermission` is not
  mounted in any test.
- **Vault / PAM grant.** `TestPrivilegedCredentialRevealIsGranted` (integration)
  has both halves at reveal. At connect, only the predicate is tested
  (`TestPamEntryAllowed_GroupGrant`); no connect handler is.
- **Session.** `TestRefreshTokenGrant` refuses a refresh when the marker is
  set, but it writes the marker by hand, and its success path has no session.
  No test revokes a session through the product and then refreshes it.
- **MFA policy.** `TestIsMFARequired` covers the evaluator, but its fixtures
  use `factor_enrolled`, a condition `IsMFARequired` does not read (it reads
  `groups`, `ip_ranges`, `time_windows` and `attributes`). So no test has a
  policy that exempts anyone, and nothing drives the login path with one.
- **Device trust.** The `device-trusted` attribute is tested on both sides
  (`TestAssembleAttributesDeviceTrustedGated`, `TestDeviceTrustAttrs`). Nothing
  shows an untrusted device being refused the dial.

## Runs

| Date | Who | Rows verified | Divergence found | Output |
|---|---|---|---|---|
| | | | | |

## Notes for whoever runs this next

- The **negative** half is the one that finds things. A grant that works is
  the expected case; a *revocation* that does not is the finding.
- ABAC's row has three states, not two. Check the console's mode badge first —
  a deny that does not deny is correct behaviour in `observe`, and a defect in
  `enforce`.
- Session revocation has a latency floor: the marker is written synchronously,
  but a token already minted stays valid until its TTL. Verify the refresh
  path, not the access token.
