package migrations

// Migration v71 — temp_access_links tenant isolation. temp_access_links (PAM
// temporary vendor access to internal SSH/RDP/VNC hosts, created by v54) has no
// org_id, and internal/access/temp_access.go listed/read/revoked links by id
// with no org filter — any authenticated user in any org could enumerate, read
// (target_host, username, access URL) and revoke every other org's vendor
// access links (a cross-tenant IDOR). This adds org_id (backfilled from the
// creating user, NOT NULL, FK) + an index; the handlers add an org predicate
// and an admin gate.
//
// Deliberately NOT placed under the v37 FORCE-RLS belt: the public
// token-redemption path (GET /temp-access/:token -> handleUseTempAccess) runs
// with no authenticated org context, so FORCE RLS would fail-closed and break
// redemption for the vendor. That path is keyed by a unique unguessable secret
// token (not an enumerable id), and every management path is now org-filtered
// in code + admin-gated, so the belt would add no protection there. Plain
// statements only — the runner's splitSQL cannot handle DO $$ blocks.
var tempAccessOrgIsolationUp = `-- Migration 071: temp_access_links tenant isolation.
ALTER TABLE temp_access_links ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill each link to its creator's org.
UPDATE temp_access_links t SET org_id = u.org_id FROM users u WHERE t.created_by = u.id AND t.org_id IS NULL;

-- Any orphan (creator deleted/unknown) -> oldest (primary) org, so SET NOT NULL can't fail.
UPDATE temp_access_links SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE temp_access_links ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_temp_access_links_org ON temp_access_links(org_id);
`

var tempAccessOrgIsolationDown = `-- Migration 071 down.
DROP INDEX IF EXISTS idx_temp_access_links_org;
ALTER TABLE temp_access_links DROP COLUMN IF EXISTS org_id;
`
