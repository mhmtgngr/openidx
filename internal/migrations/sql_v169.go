package migrations

// Migration v169 — the app-publish tables, and the guard a comment assumed.
//
// v73 gave `published_apps` and `discovered_paths` an org_id, a backfill, a
// NOT NULL and a foreign key, and then wrote down, in its own registration,
// why it stopped short of the belt:
//
//	Not RLS-belted (runAppDiscovery runs in a background goroutine with no
//	org ctx; the integrity doctor sweeps all orgs under bypass-RLS).
//
// Half of that reason had already expired and the other half was one line of
// plumbing.
//
// THE DOCTOR. It does sweep every org -- and it does it under
// orgctx.WithBypassRLS, which is the belt's own documented opt-out. A belted
// table is exactly as visible to it as an unbelted one. That half of the
// reason describes a path the belt was designed to permit.
//
// THE GOROUTINE. runAppDiscovery genuinely ran on context.Background(), so the
// pool set no app.org_id and every statement would have matched nothing once
// the belt landed. But its SQL was never the problem: every one of its six
// statements already carries `AND org_id = $N`, because the handler threads the
// org id in explicitly. What was missing was the org on the CONTEXT, which is
// orgctx.With(context.Background(), org) -- one line, in the same commit.
//
// A reason for skipping a control is a claim with a shelf life, and this is the
// second time this programme has found one that had expired: v71 skipped the
// belt on the temporary-access tables for a reason that stopped being true
// three batches before anyone looked.
//
// AND WHILE LOOKING AT THE DOCTOR: ITS TWO ROUTES CARRY NO ROLE GUARD.
//
//	api.GET("/health/relations", svc.handleHealthRelations)
//	api.POST("/health/fix/:checkId", svc.handleHealthFix)
//
// Every neighbouring app-publish route carries `adminOnly`, and the comment
// that introduces `adminOnly` forty lines above says why: a plain authenticated
// tenant user must not reach a surface that reconfigures the fabric. The
// doctor's own handler comment says the same thing in passing -- "an org-scoped
// ADMIN request must see all rows" -- while the route it guards requires no
// admin at all. The guard the comment assumes is the guard nobody applied.
//
// What that opened, for any authenticated user of any tenant:
//
//   - GET /health/relations returns an install-wide report naming every
//     tenant's published app names, public hosts, OAuth client_ids and Ziti
//     service names. It runs under bypass-RLS by design, so the belt this
//     migration adds could never have closed it.
//   - GET /health/relations?heal=safe applies every Safe fix across every
//     tenant in one request.
//   - POST /health/fix/:checkId applies one named fix -- including the two the
//     code itself labels RISKY: tearing a service off the Ziti controller, and
//     consolidating an app, which rewrites another tenant's proxy routes and
//     repoints their discovered_paths.
//
// FixOne re-detects before it fixes, so a subject has to be a real live
// finding; that bounds the reachable set, it does not scope it to the caller's
// tenant. Both routes now carry adminOnly, and a test walks the REAL route
// table -- RegisterRoutes on a stub service -- and asserts a non-admin gets 403
// where an admin gets through, so the next route added here cannot quietly skip
// the gate.
//
// The belt itself is short: v73 already did the column work, so this is the
// policy, ENABLE, FORCE and the grant.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var appPublishTenantBeltUp = `-- Migration 169: belt the app-publish tables v73 scoped but did not belt.

DROP POLICY IF EXISTS pol_published_apps_org_scope ON published_apps;
CREATE POLICY pol_published_apps_org_scope ON published_apps
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE published_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE published_apps FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_discovered_paths_org_scope ON discovered_paths;
CREATE POLICY pol_discovered_paths_org_scope ON discovered_paths
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE discovered_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovered_paths FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON published_apps   TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovered_paths TO openidx_app;
`

// Down returns both tables to v73's state: the columns, foreign keys and
// indexes stay, only the belt is lifted. Nothing here can fail on data.
var appPublishTenantBeltDown = `-- Rollback 169.

ALTER TABLE discovered_paths NO FORCE ROW LEVEL SECURITY;
ALTER TABLE discovered_paths DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_discovered_paths_org_scope ON discovered_paths;

ALTER TABLE published_apps NO FORCE ROW LEVEL SECURITY;
ALTER TABLE published_apps DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_published_apps_org_scope ON published_apps;
`
