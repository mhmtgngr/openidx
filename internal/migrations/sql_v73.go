package migrations

// Migration v73 — published_apps / discovered_paths tenant isolation.
//
// The access "App Publish" tables (published_apps + its child discovered_paths,
// created by v40) have no org_id. The app-publish handlers in
// internal/access/app_publish.go acted on rows by bare id with no org filter:
// any caller could list/enumerate, read (incl. internal target_url/spec_url),
// and delete every org's apps and paths — a cross-tenant IDOR. The authorization
// gate (admin-only on the /apps routes) is a separate change; this adds the
// per-tenant column so the handlers can scope every query by org, closing the
// residual cross-org admin IDOR too.
//
// Backfill: published_apps from its creator (created_by -> users.org_id), any
// orphan (created_by NULL/unknown — the register handler historically never set
// it) -> the oldest (primary) org so SET NOT NULL can't fail; discovered_paths
// from its parent app (FK-guaranteed to exist), any stray -> oldest org.
//
// Deliberately NOT placed under the v37 FORCE-RLS belt: runAppDiscovery runs in
// a background goroutine with context.Background() (no org context, so the
// app.org_id GUC would be unset) and the integrity doctor sweeps all orgs under
// bypass-RLS — so the handlers filter by org_id explicitly instead. Plain
// statements only — the runner's splitSQL cannot handle DO $$ blocks.
var publishedAppsOrgIsolationUp = `-- Migration 073: published_apps + discovered_paths tenant isolation.
ALTER TABLE published_apps ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill each app to its creator's org.
UPDATE published_apps p SET org_id = u.org_id FROM users u WHERE p.created_by = u.id AND p.org_id IS NULL;

-- Any orphan (created_by NULL/unknown) -> oldest (primary) org so SET NOT NULL can't fail.
UPDATE published_apps SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE published_apps ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_published_apps_org ON published_apps(org_id);

ALTER TABLE discovered_paths ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill each path from its parent app (FK-guaranteed non-NULL after the above).
UPDATE discovered_paths d SET org_id = p.org_id FROM published_apps p WHERE d.app_id = p.id AND d.org_id IS NULL;

-- Belt-and-suspenders for any stray path whose app somehow vanished.
UPDATE discovered_paths SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE discovered_paths ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_discovered_paths_org ON discovered_paths(org_id);
`

var publishedAppsOrgIsolationDown = `-- Migration 073 down.
DROP INDEX IF EXISTS idx_discovered_paths_org;
ALTER TABLE discovered_paths DROP COLUMN IF EXISTS org_id;
DROP INDEX IF EXISTS idx_published_apps_org;
ALTER TABLE published_apps DROP COLUMN IF EXISTS org_id;
`
