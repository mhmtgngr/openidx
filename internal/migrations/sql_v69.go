package migrations

// Migration v69 — governance tenant isolation. certification_campaigns and
// abac_policies (created by v42) and campaign_runs had no org_id, and
// internal/governance queried/wrote them without an org filter — any
// authenticated tenant could read/act on other orgs' campaigns, runs and ABAC
// policies. This adds org_id (backfilled, NOT NULL, FK) to all three tables and
// places them under the v37 FORCE-RLS belt (USING + WITH CHECK, so reads AND
// writes are org-scoped). certification_campaigns is handled before campaign_runs
// because campaign_runs backfills its org_id from its parent campaign. Plain
// statements only — the runner's splitSQL cannot handle DO $$ blocks (see the
// v56/v57 lesson).
var governanceOrgIsolationUp = `-- Migration 069: governance tenant isolation.
-- Add org_id + FK idempotently (nullable first so existing rows are allowed).
ALTER TABLE certification_campaigns ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill campaigns -> oldest (primary) org.
UPDATE certification_campaigns SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE certification_campaigns ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_certification_campaigns_org ON certification_campaigns(org_id);

-- v37 FORCE-RLS belt. USING + explicit WITH CHECK so INSERT/UPDATE are org-enforced too.
DROP POLICY IF EXISTS pol_certification_campaigns_org_scope ON certification_campaigns;
CREATE POLICY pol_certification_campaigns_org_scope ON certification_campaigns
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE certification_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE certification_campaigns FORCE  ROW LEVEL SECURITY;

-- Add org_id + FK idempotently (nullable first so existing rows are allowed).
ALTER TABLE campaign_runs ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill: runs -> parent campaign's org; any orphan runs (parent already gone)
-- -> oldest org, so SET NOT NULL can't fail.
UPDATE campaign_runs cr SET org_id = cc.org_id FROM certification_campaigns cc WHERE cr.campaign_id = cc.id AND cr.org_id IS NULL;
UPDATE campaign_runs SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE campaign_runs ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_campaign_runs_org ON campaign_runs(org_id);

DROP POLICY IF EXISTS pol_campaign_runs_org_scope ON campaign_runs;
CREATE POLICY pol_campaign_runs_org_scope ON campaign_runs
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE campaign_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_runs FORCE  ROW LEVEL SECURITY;

-- Add org_id + FK idempotently (nullable first so existing rows are allowed).
ALTER TABLE abac_policies ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill policies -> oldest (primary) org.
UPDATE abac_policies SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE abac_policies ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_abac_policies_org ON abac_policies(org_id);

DROP POLICY IF EXISTS pol_abac_policies_org_scope ON abac_policies;
CREATE POLICY pol_abac_policies_org_scope ON abac_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE abac_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE abac_policies FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role. openidx_app is provisioned by v53 (which always
-- runs first) and its ALTER DEFAULT PRIVILEGES covers new tables — this explicit grant
-- is belt-and-suspenders. Plain GRANT (no DO/$$ block) per the splitSQL constraint.
GRANT SELECT, INSERT, UPDATE, DELETE ON certification_campaigns, campaign_runs, abac_policies TO openidx_app;
`

var governanceOrgIsolationDown = `-- Migration 069 down.
DROP POLICY IF EXISTS pol_abac_policies_org_scope ON abac_policies;
DROP POLICY IF EXISTS pol_campaign_runs_org_scope ON campaign_runs;
DROP POLICY IF EXISTS pol_certification_campaigns_org_scope ON certification_campaigns;
ALTER TABLE abac_policies           DISABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_runs           DISABLE ROW LEVEL SECURITY;
ALTER TABLE certification_campaigns DISABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_runs           DROP COLUMN IF EXISTS org_id;
ALTER TABLE certification_campaigns DROP COLUMN IF EXISTS org_id;
ALTER TABLE abac_policies           DROP COLUMN IF EXISTS org_id;
`
