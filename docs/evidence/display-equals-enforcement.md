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
| Session | Sessions pages | Redis `revoked_session:*` at refresh and userinfo | revoke, then refresh — the refresh must fail |
| MFA policy | MFA Management | `IsMFARequired` in the OAuth login path | a policy user is challenged; an exempt user is not |
| Device trust | My Devices, Access 360 | Ziti posture + the `#device-trusted` attribute | an untrusted device is denied the dial |
| **ABAC policy** | ABAC Policies (with its mode badge) | `internal/abac` at both PEPs — the token endpoint and the access proxy | in `observe`, a deny policy records `abac.would_deny` and still issues; in `enforce`, the same policy returns 403 and audits `abac.denied` |

**Anything that appears in an admin UI without a row in this table is a
defect: either wire it or remove it.** That rule is what retired the ABAC page
from decoration into the row above, and what removed the dashboard's
"refresh" and "metrics" endpoints rather than faking them.

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
