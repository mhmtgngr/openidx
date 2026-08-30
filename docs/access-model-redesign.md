# Access model: four parallel systems, and how to converge them

Status: **superseded by `access-and-login-convergence-design.md`**, which turns
this finding into an agreed design (assignment as the only grant, staged behind
a report-only flag) and adds the login and MFA-policy convergences alongside it.
This document stays as the record of what was found and why.

Nothing here is implemented. It is written down because the current model
surprises the people who configure it, and the surprise is structural rather
than a bug in any one place.

## What is true today

Four independent mechanisms decide what a user can reach. Only one of them
answers with the same data it enforces with.

| System | Decided by | Enforced where | Display == enforcement? |
|---|---|---|---|
| Portal app catalog | `user_application_assignments`, `group_application_assignments` | **nowhere** | n/a — it is a list, not a gate |
| Web / proxy routes | `proxy_routes.allowed_roles` + `.allowed_groups` | `handleProxy`, `internal/access/service.go` | yes, since the My Network listing was fixed to check both |
| Ziti overlay | Dial policies in `ziti_service_policies` matched against identity attributes | the Ziti controller, at circuit establishment | yes |
| PAM | `pam_entry_grants` | `pamEntryAllowed`, at connect and reveal | yes |

The gap is not *within* any row. It is that the rows do not talk to each other,
while the admin console presents them as one idea ("give this user access to
this app").

### Assigning an app grants no access

"Manage Access" on an application writes `user_application_assignments` /
`group_application_assignments`. Those tables are read by `GetMyApplications`
(the launcher tiles), `GetAccessOverview` (the counts), governance approval and
revocation, access reviews, attestation and the privacy export. They are read by
**no data path**. Whether the user can actually open the app is decided by the
proxy route's `allowed_roles` / `allowed_groups`, or by a Ziti Dial policy —
neither of which the assignment touches.

So both of these are normal today:

- an app appears in My Apps that the user cannot open, because the underlying
  route restricts by a group they are not in;
- a route is perfectly reachable, and never appears in My Apps, because no
  assignment row exists.

### A Ziti-enabled route is reachable by every enrolled user

When a `proxy_routes` row has `ziti_enabled = true` (App Publish sets this), the
reconciler provisions the service and a **default Dial policy** granting
`#access-proxy-clients` — or `#browzer-users` in router-hosted/BrowZer mode
(`ensurePolicies`, `internal/access/ziti_reconciler.go`). That grant is not
scoped by the route's own `allowed_roles` / `allowed_groups`, nor by any
application assignment. Every enrolled identity can dial it.

The manual "Add a resource" flow is better: it takes explicit `dial_roles`
(`handleCreateZitiService`, `internal/access/ziti_handlers.go`). But an admin who
publishes an app and ticks "expose over the zero-trust network" gets the broad
default, having just configured what looks like a per-user restriction next to it.

### The only IAM → Ziti bridge is group membership

`SyncUserToZiti` replaces an identity's attribute set wholesale with: the user's
IAM **group names**, `enrolled-users`, `device-trusted` when they have a trusted
device, and `browzer-users` when BrowZer is on
(`assembleAttributes`, `internal/access/ziti_user_sync.go`). Applications are not
an input. This is documented in `IAM_PAM_ZITI_INTERRELATION.md` and matches the
code; it is simply narrower than what the console implies.

## What to change

The goal is that **the thing an admin assigns is the thing that is enforced**,
without collapsing the four systems into one (they enforce at genuinely
different layers and should keep doing so).

1. **Make app assignment an input to Ziti attributes.** Extend
   `assembleAttributes` to emit a per-application attribute (`#app-<slug>`) for
   every application the user is assigned, directly or through a group. The
   existing 30s sync poller already re-syncs stale attributes, so the propagation
   path exists.
2. **Scope the auto-provisioned Dial policy.** When App Publish Ziti-enables a
   route that belongs to an application, `ensurePolicies` should grant
   `#app-<slug>` rather than `#access-proxy-clients` / `#browzer-users`. Keep the
   broad default only for routes with no application behind them, and make it an
   explicit, visible choice in the UI rather than an invisible fallback.
3. **Derive route role/group restrictions from the same assignment** where an
   application owns the route, so a single "who may use this app" edit reaches
   the proxy check too — or, at minimum, warn in the console when a route's
   restrictions and its application's assignments disagree.
4. **Show the truth.** The Access 360 / My Access surfaces should present, per
   resource, which mechanism grants it — assignment, route restriction, Ziti
   policy, PAM grant — so a disagreement is visible rather than inferred from a
   failed click.

Steps 1 and 2 change who can reach what on an existing deployment: any user
relying on the broad `#access-proxy-clients` grant loses it the moment policies
are narrowed. That needs a migration plan (report first, enforce later) and an
explicit decision, which is why this is a proposal and not a patch.

## Already fixed, for the record

Two reporting gaps that came out of the same trace are fixed and not part of
this proposal:

- My Network listed published web routes after checking `allowed_roles` only,
  while the proxy enforces roles **and** groups — a group-restricted route showed
  as "Ready" and then 403'd.
- `GetAccessOverview` counted only direct app assignments, so a user whose apps
  all came through a group was told they had none.

See also: `IAM_PAM_ZITI_INTERRELATION.md` (cross-pillar correlation),
`how-network-access-works.md` (the admin-facing resource flow),
`app-publishing.md` (publish → route → optional Ziti/BrowZer).
