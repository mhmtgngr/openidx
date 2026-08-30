# Access and login convergence

Design, 2026-08-30.

## Why

Three separate traces this week landed on the same shape: a knob an admin can
turn that nothing reads.

- Assigning an application to a user or group writes
  `user_application_assignments` / `group_application_assignments`. Those tables
  feed the launcher tiles, the My Access counts, governance and access reviews —
  and **no data path**. Whether the user can actually reach the app is decided
  elsewhere, by `proxy_routes.allowed_roles` / `.allowed_groups` and by Ziti Dial
  policies.
- A Ziti-enabled route provisioned through App Publish gets a Dial policy for
  `#access-proxy-clients` (or `#browzer-users` in router-hosted mode) —
  **every enrolled identity** — regardless of who the app is assigned to
  (`ensurePolicies`, `internal/access/ziti_reconciler.go:454`).
- `IsMFARequired` (`internal/identity/service.go:2529`) evaluates the
  `mfa_policies` table. It is called from nowhere but a test, while the admin
  console offers full CRUD over that table
  (`internal/admin/mfa_management.go`). Authoring an MFA policy today does
  nothing.

Two browser login implementations produced the rest. `/oauth/authorize` served a
server-rendered page to every public client while the console SPA posted JSON to
`/oauth/login`, and only the JSON path enforced MFA — the bypass closed in #873.
The same divergence also meant the server-rendered path created no session row
and wrote no `login_history` entry.

This design converges all three: one grant, one login, one MFA policy.

## Decisions taken

| Decision | Choice |
|---|---|
| Grant model | Assignment is the only knob. Route restrictions and Ziti dial policies are derived from it. |
| Migration posture | Report-only first, then enforce explicit assignments only. Current over-broad reach is reported, never backfilled into permanent grants. |
| Login UI | The SPA becomes the only login. The server-rendered page and its second-factor flow are deleted. |
| MFA rule | Policy-driven via the existing `mfa_policies` table, defaulting to today's behaviour. |
| Ziti propagation | Per-app identity attribute plus per-app dial policy, mirroring the existing per-org path. |
| OIDC assignment gate | Opt-in per client, default off. |

## Architecture

```
        ┌─────────────────────────────────────────────┐
GRANT   │ user_application_assignments                │  (existing tables,
        │ group_application_assignments               │   now the only knob)
        └───────────────────┬─────────────────────────┘
                            │
                  internal/appaccess  (one predicate)
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
 route-linked apps                        plain OIDC clients
 (applications.route_id set)              (route_id null)
        │                                       │
        ├── ziti identity attr  #app-<uuid>     └── gate at /oauth/authorize
        │   + policy openidx-appdial-<svc>          when require_assignment
        └── proxy forward-auth: same predicate
```

On the live deployment the split is clean: `Es-Dev`, `Netgraph`, `PSM`,
`SecOps`, `kibana-dev` are route-linked (all Ziti- and BrowZer-enabled);
`Admin Console`, `API Service`, `Sample SPA`, `TEST`, `securetask` are plain
OIDC clients. Fixing only the Ziti half would leave half the catalogue
unenforced, which is why there are two enforcement points.

## Section A — assignment drives reach

### A.1 One shared predicate

New package `internal/appaccess`:

- `Allowed(ctx, db, userID, appID) (bool, error)` — direct assignment OR
  assignment to a group the user belongs to.
- `AppsForUser(ctx, db, userID) ([]AppRef, error)` — the same predicate as a
  list; `AppRef` carries the application id, name and `RouteID`.
- `PrincipalsForApp(ctx, db, appID) (Principals, error)` — users and groups, for
  the reconciler.

It is a shared package because the enforcement points live in three services:
access (proxy, Ziti sync, reconciler), identity (portal), oauth (the authorize
gate). `GetMyApplications` and `GetAccessOverview`'s app count both collapse onto
`AppsForUser`, so the catalogue and the enforcement cannot drift again the way
they did in #874.

### A.2 Schema

Migration **v137** (the tree and the box are both at v136):

```sql
ALTER TABLE applications
  ADD COLUMN require_assignment boolean NOT NULL DEFAULT false;
```

That is the whole schema change. The grant tables already exist (v136).

### A.3 Staging flag and the report

`ACCESS_ASSIGNMENT_ENFORCE` (env, default `false`).

In report-only every enforcement point computes the decision and takes no
action. On a would-be denial it writes an audit event
`access.assignment.would_deny` carrying user id, application id, enforcement
point (`ziti` | `proxy` | `oidc`) and reason. Reusing `audit_logs` rather than
adding a report table inherits retention, RLS and the existing audit UI. A
console view aggregates the events into "who would lose what", grouped by
application.

### A.4 Ziti propagation

- `assembleAttributes` (`internal/access/ziti_user_sync.go:319`) additionally
  emits `#app-<application uuid>` for each **route-linked** application the user
  is assigned. Plain OIDC clients get no attribute — they are gated at
  `/oauth/authorize` instead.
- `ensurePolicies` (`internal/access/ziti_reconciler.go:454`) additionally
  emits `openidx-appdial-<service>` granting `#app-<uuid>`, mirroring the
  existing `openidx-orgdial-<service>` path line for line.
- Under enforcement, an app-backed service's Dial grant becomes the per-app
  attribute **instead of** `#access-proxy-clients` / `#browzer-users`. Routes
  with no application behind them keep the blanket grant untouched.

The attribute is keyed on the application **uuid**, not its name: the attribute
set is wholesale-replaced on every sync, so a rename would silently drop reach.
The console displays the uuid→name mapping for debugging.

Propagation is eventually consistent — the sync poller runs every 30s and
re-syncs stale attributes every 5 minutes. Immediate revocation remains the
kill switch, which revokes the Ziti identity outright.

### A.5 Proxy and OIDC enforcement

- `handleProxy` (`internal/access/service.go:2014`) consults `appaccess.Allowed`
  for routes that have an application behind them. Under enforcement the
  predicate **replaces** the `allowed_roles` / `allowed_groups` check for those
  routes — checking both would be the intersect model this design rejected, and
  the two cannot disagree once the fields are derived. Routes with no
  application keep the role and group checks exactly as they are. In report-only
  both are computed and any disagreement is logged, which is how the report
  surfaces routes whose restrictions and assignments diverge today.
- `/oauth/authorize` consults it for clients whose application row has
  `require_assignment = true`. Default false, so deploy one cannot lock anyone
  out of a first-party client such as the admin console.

### A.6 Console

"Manage Access" on an application becomes the single grant UI. For app-backed
routes, the `allowed_roles` / `allowed_groups` fields render read-only with a
link to it. Routes with no application keep authoring their own restrictions.

### A.7 Deliberately untouched

PAM grants (`pam_entry_grants`) already use the same predicate for display and
for enforcement, and the group→attribute sync stays: services that are not
applications still need it.

## Section B — one login front end

### B.1 The change

`/oauth/authorize` currently forks: render the hosted page for public clients, or
redirect to the **client's own** `redirect_uri?login_session=…` otherwise. That
second branch is why the hosted page had to exist — `openidx-mobile`, whose
redirect_uri is `openidx://oauth-callback`, cannot host a login page.

Both branches are replaced by one: always redirect to
`<issuer>/login?login_session=…`. The SPA already lives at the issuer origin and
already fetches tenant branding (`/api/v1/identity/branding?domain=`).

### B.2 Removed

`renderLoginPage`, `renderBrandedPage`, `handleAuthorizeCallback`, all of
`internal/oauth/hosted_mfa.go`, the routes `/oauth/authorize/callback` and
`/oauth/authorize/mfa*`, and their entries in `authPaths` / `pollPaths` — about
600 lines, including the hosted second-factor flow shipped in #873 and #876.
Those remain correct in the interim: they closed a live bypass, and this section
supersedes rather than reverts them.

### B.3 Retained

`evaluateMFA` stays as the single MFA policy (with one consumer instead of two),
along with `createMFASession` and `verifyStepUpFactor`. Session creation,
`login_history` recording and rate limiting are already on the JSON path.
`handleLogin` has its own country block (`internal/oauth/service.go:2046`) and
BrowZer device-trust gate (`:2085`), so deleting the hosted path loses neither.
Consent is already JSON-rendered by the SPA and is unaffected.

### B.4 Staging

`OAUTH_LOGIN_UI` (env, `server` | `spa`, default `server`). Flip after verifying
the three flows below; delete the server branch in a follow-up once the flip has
held. Rollback is one environment variable.

The flow least likely to work unchanged is BrowZer: it bootstraps its own OIDC
dance from `browzer.tdv.org`, so the cross-origin bounce to
`openidx.tdv.org/login` and back needs an explicit end-to-end check **before**
the flip, since there is no fallback UI once the server page is gone.

## Section C — MFA policy

### C.1 Wiring, not inventing

`evaluateMFA` calls `IsMFARequired`. "Require a second factor whenever one is
enrolled" becomes a policy row in `mfa_policies` rather than a hardcoded
condition.

### C.2 Condition allowlist

The `conditions` jsonb is validated against an explicit allowlist at write time
(the admin create/update handlers in `internal/admin/mfa_management.go`), and an
unknown key is rejected with an error. Supported initially:

| Key | Meaning |
|---|---|
| `factor_enrolled: true` | require MFA whenever the user has any enrolled primary factor |
| `min_risk_score: <int>` | require MFA at or above this risk score |
| `client_ids: [<string>]` | restrict the policy to these OAuth clients |

Silently ignoring unknown keys is how this table became decorative; rejecting
them is the fix.

### C.3 Precedence and the lockout guard

An enabled policy can only **raise** the requirement. A matching policy means
challenge, regardless of the risk engine's verdict. No matching policy means
today's rule, `Enabled && !SkipMFA && (RequireMFA || totpEnabled)`, unchanged.
With no policy rows present, behaviour is byte-for-byte what it is now — that is
what makes the default safe.

A policy raises the requirement only for a user who has a factor enrolled. A user
with none is not blocked; they appear in an enrollment-gap report. Requiring a
factor from someone who has none is a lockout with extra steps.

### C.4 Prerequisite

`IsMFARequired` has never executed in production. It gets its own tests —
condition matching, priority ordering, grace-period semantics — **before** it
gates a login, not after.

## Staging order

Each step is independently revertible, and the two that change behaviour come
last.

1. **A.1–A.4 in report-only.** Predicate, migration v137, attributes and the
   per-app dial policy provisioned alongside the blanket one. No behaviour
   change; the report starts filling.
2. **C wired, no policy rows.** Behaviour identical; `IsMFARequired` is now
   reachable and tested.
3. **B behind `OAUTH_LOGIN_UI=server`.** No behaviour change until flipped.
4. **Flip B to `spa`** after the three login flows verify. Delete the server
   branch once it holds.
5. **Review the A report, create the assignments you want, flip
   `ACCESS_ASSIGNMENT_ENFORCE=true`.** This is the step that removes access.
6. **Create the MFA policy** after confirming a push challenge can actually be
   approved on the device.

## Verification

**Automated.**

- `internal/appaccess`: direct assignment, group-derived assignment, both at
  once counted once, unassigned denied, disabled application denied.
- Portal: `GetMyApplications` and `GetAccessOverview`'s count return the same set
  the predicate does (the drift fixed in #874 cannot recur).
- Ziti: `assembleAttributes` emits `#app-<uuid>` for a route-linked assigned app
  and not for a plain OIDC client; `ensurePolicies` emits
  `openidx-appdial-<svc>`; under enforcement the blanket dial identity is absent
  for app-backed services and present for unlinked ones.
- Report mode: a would-be denial writes `access.assignment.would_deny` and
  returns allow.
- Authorize gate: `require_assignment=false` issues a code for an unassigned
  user; `true` refuses.
- Login: `/oauth/authorize` redirects to `<issuer>/login?login_session=` for a
  public, a confidential and a native client.
- MFA policy: condition matching, priority ordering, grace period, unknown
  condition key rejected at write time, no policy rows means the pre-existing
  rule.

**On the box.**

- After step 1: `GET /api/v1/access/my/ziti/services` is unchanged for
  `mehmet.gungor`, and `openidx-appdial-*` policies exist beside the blanket
  ones in the Ziti controller.
- After step 4: sign in through the console, the mobile client and BrowZer; each
  lands back at its own redirect_uri with a working code.
- After step 5: a user with no assignment to `Es-Dev` can no longer dial it, and
  the audit trail shows the denial at the `ziti` enforcement point.
- After step 6: a push-only account is challenged, and approving on the device
  completes the login.

## Alternatives rejected

- **Intersect assignment with route rules.** Safer to roll out, but leaves two
  knobs that can disagree — the condition this design exists to remove.
- **Derive the catalogue from enforcement** (show only what the route and Ziti
  already permit). Cheapest and zero lockout risk, but it keeps the blanket
  `#access-proxy-clients` dial grant, so the over-permission survives.
- **Pin identities in the dial policy** (`@<zitiId>` per user) instead of a
  per-app attribute. Immediate on assignment, but policies grow with user count
  and are rewritten on every membership change, abandoning the attribute idiom
  the rest of the system uses.
- **Enforce at the proxy only.** BrowZer's data path bypasses proxy
  forward-auth, so the blanket dial grant would still let a user reach the
  service.
- **Backfill current reach into explicit assignments.** Nobody loses access on
  day one, but every enrolled user gains a permanent grant to all five Ziti
  apps — today's over-permission, laundered into rows someone must prune by
  hand.
