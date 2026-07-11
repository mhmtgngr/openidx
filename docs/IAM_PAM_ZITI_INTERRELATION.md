# IAM ⇄ PAM ⇄ Ziti — How the Three Pillars Interrelate

OpenIDX's three pillars — **IAM** (identity), **PAM** (privileged access), and
**Ziti** (zero-trust network) — live in one Postgres and one control plane.
This document describes the seams that tie them together: how state in one
pillar propagates to the others, and the correlation surfaces exposed to
admins and end users.

## The correlation model

```
                 ┌────────────────────────────────────────┐
                 │              users (IAM)               │
                 │  roles · groups · sessions · api keys  │
                 └───────┬───────────────────┬────────────┘
        principal_id     │                   │   user_id / group→attr sync
        (user | role)    ▼                   ▼
        ┌────────────────────────┐   ┌─────────────────────────┐
        │        PAM             │   │         Ziti            │
        │ vault_access_grants    │   │ ziti_identities         │
        │ vault_checkouts        │   │ ziti_service_policies   │
        │ jit_grants             │   │ enrolled_agents         │
        │ guacamole_sessions ────┼───► proxy_routes.ziti_enabled│
        └────────────────────────┘   └─────────────────────────┘
                 │                                 │
                 └───────────► unified_audit_events ◄─ (openidx · guacamole · ziti)
```

- **IAM → PAM**: vault grants and JIT elevations are keyed to IAM principals
  (`principal_type` = `user` | `role`); privileged sessions are keyed by
  `user_id`. Governance access-requests fulfill vault credential checkouts.
- **IAM → Ziti**: the user-sync poller (`internal/access/ziti_user_sync.go`,
  30s tick) mirrors enabled users into Ziti identities, group memberships into
  identity role attributes, and device trust into `#device-trusted`.
- **PAM ⇄ Ziti**: a privileged session's connection hangs off a `proxy_routes`
  row that may be Ziti-overlaid — the access map surfaces this as the
  session's `over_ziti` flag.
- **All → audit**: `unified_audit_events` collects openidx, guacamole, and
  ziti events keyed by `user_id`, so a user's cross-pillar trail is one query.

## Lifecycle propagation (disable/delete a user)

Three enforcement layers guarantee a disabled user loses access in every
pillar, regardless of which path disabled them:

| Layer | Path covered | Latency | What it severs |
|---|---|---|---|
| `identity.deprovisionUser` (`internal/identity/service.go`) | API disable / delete / offboard | inline | IAM sessions (+ Redis `revoked_session:` markers), API keys, **active vault checkouts, direct user vault grants, JIT elevations** |
| Lifecycle enforcement sweep (`internal/access/lifecycle_sweep.go`) | any path (SCIM, directory sync, lifecycle policies, direct DB) | ≤30s | same PAM state as above, plus **live Guacamole session termination** (only the access-service holds the Guacamole client) |
| Ziti deprovision sweep (`internal/access/ziti_user_sync.go`) | any path | ≤30s | the user's **Ziti identity** (controller + mirror row), which kills live circuits |

The sweeps are idempotent and reconcile-style: they only touch still-active
rows, and Guacamole session rows are marked `terminated` only after the
controller confirms the kill (no fabricated terminations).

## The admin kill switch (all pillars, synchronous)

`POST /api/v1/access/users/:id/kill-switch` (admin) severs one user's live
access across all three pillars in a single action:

1. **IAM** — revokes live sessions, publishes cross-service revocation
   markers; with `disable_user=true` also disables the account and revokes
   API keys.
2. **PAM** — revokes active vault checkouts, expires direct user vault
   grants, revokes JIT elevations, terminates live Guacamole sessions.
3. **Ziti** — deletes the identity's edge sessions **and** API sessions on
   the controller (severing circuits and forcing re-auth) for the user's
   identity and any device identities they enrolled; with `disable_user=true`
   the user's Ziti identity is deleted immediately.

Every step is best-effort — one pillar failing never stops the others — and
the response reports exactly what was severed, with warnings for anything
that couldn't be (e.g. Ziti controller offline). The action lands in
`unified_audit_events` as `user.kill_switch` with the full severance summary.

## Correlation surfaces

### Admin side — Access 360

`GET /api/v1/access/users/:id/access-map` (admin) returns one JSON document
correlating the user across pillars: IAM roles/groups/live counts; PAM vault
grants (annotated `via: user` or `via: role:<name>`), active checkouts, JIT
elevations, live privileged sessions with the `over_ziti` flag; Ziti identity,
attributes, enrolled devices, the Dial policies matching the identity and the
services they resolve to; and the recent unified audit trail.

Console: **Users → row menu → Access 360** (`/users/:id/access-360`), which
also hosts the kill-switch action.

### User side — My Access

`GET /api/v1/identity/portal/access-overview` now returns `privileged` (vault
grants, active checkouts, JIT elevations, live sessions, pending session
requests) and `network` (Ziti linked/enrolled, device count, device trust)
alongside the IAM roles/groups/apps — the **My Access** page shows all three
pillars with links into *My Privileged Access* and *My Devices*.

## Design rules these seams follow

- **One store, JOINs not integrations** — cross-pillar reads are scoped SQL
  in the shared Postgres; no service-to-service calls on the read path.
- **Honesty** — nothing is reported severed/terminated unless the controller
  call succeeded; unavailable subsystems produce explicit warnings.
- **Org scoping** — every query carries an explicit `org_id` predicate on top
  of the FORCE-RLS belt; install-wide sweeps run under the documented
  `orgscope:ignore` reconcile posture, same as the pre-existing Ziti sweep.
- **Idempotence** — kill switch and sweeps only touch still-active rows, so
  repeats and replica races are harmless.
