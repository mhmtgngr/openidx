# Ziti policy/service mirror — implementation report

Branch content: 2 commits on top of `origin/main` (71cfaa3f).

- `2b435d29` fix(ziti): make the local policy/service mirror reflect the controller
- `bed09259` chore(ziti): drop an unused attribution-skip struct

**Branch-name note.** `fix/ziti-policy-mirror` already existed locally, checked out
in a leftover worktree (`/home/cmit/openidx/.claude/worktrees/ziti-mirror`) from the
blocked earlier attempt. That worktree has untracked files, so `git worktree remove`
refuses without `--force`, and git will not check the same branch out twice. I did
**not** force-remove someone else's worktree. I verified it holds no Go work (every
file carries the checkout mtime; the only untracked artifact is a `MIRROR-BRIEF.md`
at its root), worked on this worktree's own branch — cut from the identical commit —
and pushed it to origin as `fix/ziti-policy-mirror`. The pushed branch is exactly
`origin/main` + the two commits above.

---

## 1. How org attribution is resolved, and what happens when it cannot be

Mirror rows are org-scoped (`org_id` NOT NULL + FK to `organizations`); controller
policies are not. Attribution (R1) uses **only in-DB data**:

1. The policy's `serviceRoles` are turned into candidate service names:
   `#attr` → `attr` (every service OpenIDX provisions is tagged with its own name as
   a role attribute — `CreateService` / `ensureServiceAttr`), `@ref` → the controller
   service of that id if the listing knows it, else `ref` treated as a name.
   `#all` yields **no candidate at all** — a wildcard names no particular service.
2. Candidates are matched against `proxy_routes.ziti_service_name` (read install-wide
   with RLS bypassed, on purpose: attribution has to see every org's routes to be
   able to detect that two of them claim the same name).
3. The route's `org_id` is used **only when exactly one org matches**.

A policy is **skipped, counted, surfaced, and left alone** when:

- no candidate matches a ziti-enabled route (this is every genuinely platform-wide
  policy — the dark-tier `*-dial-enrolled-users` / `*-dial-device-trusted` policies,
  the agent bind/dial policies, `#ci-clients`, `#pam-broker-dialers`);
- candidates span more than one org;
- the only match is a route whose own `org_id` is NULL;
- the service roles are the `#all` wildcard;
- a service name is claimed by routes in two different orgs (that name is dropped
  from the attribution table entirely rather than resolving to whichever row was read
  last).

No policy **name** is ever parsed for an org, and `orgMarkerAttr` is not reversed —
`sanitizeAttr` is lossy, so a name is not evidence of ownership. Nothing is attached
to the default org, and nothing unattributable is deleted.

Surfacing: the skips are counted in `MirrorRefreshStats` (`policies_skipped_unattributed`,
`services_skipped_unattributed`, `write_through_skipped_no_org`) with up to 20 named
examples-with-reason, logged at WARN, and exposed as a `"mirror"` block on
`GET /ziti/reconciler/status`. The write-through path keeps its own cumulative
counter (`ZitiManager.MirrorWritesSkippedNoOrg`) for policies converged with no org.

**R2 gap, deliberately not closed here** (stated in a code comment): platform-wide
policies have no org at all, and `org_id` is NOT NULL with an FK, so there is nowhere
truthful to put them. Representing them properly needs a migration making `org_id`
nullable plus every reader matching `org_id = $1 OR org_id IS NULL`. That is a
follow-up PR, not this one.

**R3/R4.** Both controller listings complete *before any write*; a failed or
unpaginated listing returns an error and the mirror is untouched. Deletion runs only
against a complete listing, so a row whose `ziti_id` is absent is positively gone
rather than merely unseen; the row's own `org_id` is in-DB fact, so no guess is made.
`pruneMirrorPolicies` additionally refuses to run on an empty listing. A response
without `meta.pagination` is an error, never an empty success. The pager advances by
the number of rows it **received**, not by the `limit` it asked for, so a controller
that ignores `limit` cannot cause silent truncation.

## 2. What the refresh would attribute vs. skip

Measured read-only against the live box (`podman exec oidx-pg psql`, SELECTs only):

- `proxy_routes` has **5** ziti-enabled routes, each with a non-null `org_id`
  (all the default org): `openidx-Es-Dev`, `openidx-Netgraph`, `openidx-PSM`,
  `openidx-SecOps`, `openidx-kibana-dev`.
- `ziti_service_policies` holds the **4** known-stale rows
  (bind/dial for `openidx-Netgraph` and `openidx-PSM`), all in the default org.
- `ziti_services` holds **4** rows (`browzer-router-zt`, `openidx-Netgraph`,
  `openidx-PSM`, `secops`).

Combining that with the brief's controller figures (35 policies / 16 services), the
projected first refresh is:

- **Attributable: ~10 of 35** — the `openidx-bind-<svc>` / `openidx-dial-<svc>` pair
  for each of the 5 routed services (plus any `openidx-orgdial-<svc>` if the per-org
  flag is on). The 4 existing rows are **updated** (their
  `identity_roles: ["#access-proxy-clients"]` corrected to what the controller
  actually says), not deleted — this is the `DO NOTHING` regression the change fixes.
- **Skipped: ~25 of 35** — the platform-wide dark-tier and agent policies, the
  `#ci-clients` / `#pam-broker-dialers` policies, and any per-service policy whose
  service has no ziti-enabled route (the brief counts 7 `#browzer-users` Dial
  policies against only 5 routes, so at least 2 fall here).
- **Deleted: 0 expected**, unless the controller no longer holds one of the 4
  mirrored policy ids.
- Services: **~5 upserted** (the route-backed names), the remaining ~11 skipped.
  `secops` and `browzer-router-zt` are left exactly as they are.

I could not turn "~10 / ~25" into an exact count: that needs the controller's own
policy list, and the container's `ziti` CLI session has expired (401). Logging a new
admin session on the production controller was out of scope for this change, so the
split above is derived from measured DB state plus the brief's controller figures,
not measured end-to-end. **The first refresh in production will print the exact
numbers** in its WARN/INFO lines and on `/ziti/reconciler/status`.

## 3. Tests

**Changed existing tests: none.** Full `go test ./internal/access/ -count=1` is green
(295s, foreground) with no edits to any existing test. The brief allowed for
`/my/ziti/services` and access-map expectations to change; they did not need to,
because the existing cases assert on behavior that stayed correct:

- `TestResolveServiceRoles/"tag ref is kept as intent"` still passes: the new `#tag`
  resolution only fires when the mirror holds a service of that exact name, and that
  case's tag (`#web-apps`) names no service, so it is still surfaced verbatim.
- `TestMyZitiServices` drives a `#all`/`#all` policy, which is unaffected.

**New tests** (`internal/access/ziti_mirror_test.go`, all passing, DB-backed ones on
testcontainers Postgres):

| Test | What it pins |
|---|---|
| `TestEnsureServicePolicyWritesMirror` | write-through writes the row; a second converge with different identity roles **updates** it (the `DO NOTHING` regression) and does not add a second row |
| `TestEnsureServicePolicyWithoutOrgIsCountedNotStored` | R2 — a platform-wide policy is not stored and the skip is counted |
| `TestRefreshZitiMirrorConverges` | insert missing / update drifted / delete positively-absent, plus the service row taking host+port from the route's upstream |
| `TestRefreshSkipsUnattributablePolicies` | R1 — platform-wide, cross-org and `#all` policies are skipped with reasons; only the attributable one is stored |
| `TestRefreshDoesNotDeleteUnattributedRows` | R3 — an existing row for an unattributable policy that still exists on the controller survives untouched |
| `TestRefreshFailureLeavesMirrorUnchanged` (3 subtests) | R4 — controller 500, a listing with no `meta.pagination`, and a services-listing failure after a successful policy listing all leave the mirror byte-identical |
| `TestListAllEdgeEntitiesPaging` | a controller that ignores `limit` and serves 2 per page over `totalCount: 5` still yields all 5 |
| `TestListAllEdgeEntitiesRequiresPagination` | a response with no `meta.pagination` is an error, not an empty success |
| `TestRefreshThenCollectZitiPillar` | end-to-end: the box's exact broken state (identity carrying `browzer-users`, mirror row keyed to `#access-proxy-clients`) resolves **zero** services before the refresh and the real named service — enriched with its upstream host/port through `myZitiServices` — after it |

## 4. Judgment calls (not transcribed from the brief)

1. **`#tag` service roles now resolve to a same-named service.** The real Dial
   policies use `serviceRoles: ["#openidx-<app>"]`, and `resolveServiceRoles` returned
   that literal string as the "reachable service" — which then matched no
   `ziti_services` row, so `/my/ziti/services` would have listed an app called
   `#openidx-Netgraph` with no host or port. Every service OpenIDX provisions carries
   its own name as a role attribute, so name-equality is a sound resolution here.
   Storing the controller's actual `roleAttributes` would be stronger but needs a new
   column, i.e. a migration. A tag with no matching service is still surfaced verbatim,
   so nothing disappears.
2. **Services are upserted but never pruned.** The brief's delete rule is about the
   verdict-bearing policy table. `ziti_services` rows carry `route_id` linkage that
   teardown paths read, and no reach verdict depends on removing them, so I kept the
   blast radius smaller. Stale service rows can still exist; they are visible as
   "on controller: 16 / skipped: N" in the stats.
3. **Fixed the two `DO NOTHING` writers outside the reconciler too** — App Publish
   (`feature_manager.go`) and `SetupZitiForRoute` (`ziti.go`). The brief scoped item 1
   to the reconciler, but leaving those would have left two paths that still freeze a
   mirror row at whatever was written first. `SetupZitiForRoute` previously wrote the
   row with **no `org_id` at all**, which the column DEFAULT silently turned into "the
   default org" — exactly the attribution R2 forbids; it now resolves the org from the
   route (`routeOrgID`) and skips the mirror write when there is none.
4. **`EnsureServicePolicy` keeps its signature.** Rather than thread an org through
   ~10 call sites, I added `EnsureServicePolicyForOrg` and made the old function
   delegate with an empty org. Platform-wide callers therefore skip-and-count by
   construction, and no unrelated call site changed.
5. **The mirror is written even on the "already converged" branch.** The controller
   being right does not imply the mirror is — that is precisely today's defect.
6. **Refresh is throttled to once per 5 minutes** inside the 30s reconcile loop, and
   is also exposed as `(*ZitiReconciler).RefreshMirror` for the status endpoint/tests.
7. **Attribution deliberately ignores the `org-<uuid>` marker attribute.** The brief
   permits it as a secondary signal after an `organizations` lookup; the primary
   service-role rule already attributes every `openidx-orgdial-*` policy, so adding a
   name-derived signal would have bought nothing and widened the guessing surface.

## 5. Verification

- `go build ./...` — clean
- `go vet ./internal/access/` — clean
- `go test ./internal/access/ -count=1` — **ok, 295.8s**, foreground, no skips of the
  new DB tests (podman is available on this host)
- `golangci-lint run ./...` (the pinned scratchpad binary) — **0 issues**
- `go run ./tools/orgscope -fail ./internal` — **0 possible unscoped queries**

## 6. Concerns / follow-ups

- The `org_id IS NULL` migration for platform-wide policies is still owed; until then
  those policies are visible only as a count, and any reader that wants them must be
  updated at the same time.
- The projected 10-vs-25 attribution split is derived, not measured end-to-end (see
  §2). The first production refresh reports the true numbers.
- Deletion is enabled from the first pass. It is gated on a complete listing, and no
  deletions are expected on the box's current 4 rows, but it is the one destructive
  behavior in this change — worth watching the first `ziti mirror refreshed` log line
  after deploy.
- The mirror refresh adds two paged controller listings every 5 minutes per
  access-service instance.
