package migrations

// Migration v61 — attestation tenant isolation. attestation_campaigns and
// attestation_items (created by v54) had no org_id, and internal/admin/attestation.go
// queried them without an org filter — any authenticated admin could read/act on other
// orgs' campaigns and items. This adds org_id (backfilled, NOT NULL, FK) to both tables
// and places them under the v37 FORCE-RLS belt (USING + WITH CHECK, so reads AND writes
// are org-scoped). Plain statements only — the runner's splitSQL cannot handle DO $$
// blocks (see the v56/v57 lesson). The same DDL is mirrored into init-db.sql so
// TestInitDBParity stays green.
var attestationOrgIsolationUp = `-- Migration 061: attestation tenant isolation.
-- Add org_id + FK idempotently (nullable first so existing rows are allowed).
ALTER TABLE attestation_campaigns ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE attestation_items     ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill: campaigns -> oldest (primary) org; items -> parent campaign's org;
-- any orphan items (parent already gone) -> oldest org, so SET NOT NULL can't fail.
UPDATE attestation_campaigns SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE attestation_items ai SET org_id = ac.org_id FROM attestation_campaigns ac WHERE ai.campaign_id = ac.id AND ai.org_id IS NULL;
UPDATE attestation_items SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE attestation_campaigns ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE attestation_items     ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_attestation_campaigns_org ON attestation_campaigns(org_id);
CREATE INDEX IF NOT EXISTS idx_attestation_items_org     ON attestation_items(org_id);

-- v37 FORCE-RLS belt. USING + explicit WITH CHECK so INSERT/UPDATE are org-enforced too.
DROP POLICY IF EXISTS pol_attestation_campaigns_org_scope ON attestation_campaigns;
CREATE POLICY pol_attestation_campaigns_org_scope ON attestation_campaigns
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE attestation_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_campaigns FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_attestation_items_org_scope ON attestation_items;
CREATE POLICY pol_attestation_items_org_scope ON attestation_items
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE attestation_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_items FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role. openidx_app is provisioned by v53 (which always
-- runs first) and its ALTER DEFAULT PRIVILEGES covers new tables — this explicit grant
-- is belt-and-suspenders. Plain GRANT (no DO/$$ block) per the splitSQL constraint.
GRANT SELECT, INSERT, UPDATE, DELETE ON attestation_campaigns, attestation_items TO openidx_app;
`

var attestationOrgIsolationDown = `-- Migration 061 down.
DROP POLICY IF EXISTS pol_attestation_items_org_scope ON attestation_items;
DROP POLICY IF EXISTS pol_attestation_campaigns_org_scope ON attestation_campaigns;
ALTER TABLE attestation_items     DISABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_campaigns DISABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_items     DROP COLUMN IF EXISTS org_id;
ALTER TABLE attestation_campaigns DROP COLUMN IF EXISTS org_id;
`
