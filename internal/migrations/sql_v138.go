package migrations

// Migration v138 — ISPM + AI tenant isolation.
//
// ispm_rules / ispm_findings / ispm_scores (v54), ai_agents (v42) with its
// three children ai_agent_credentials / ai_agent_permissions /
// ai_agent_activity (v43), and ai_recommendations / recommendation_history
// (v43) were created without org_id, and internal/admin read and wrote them
// by bare id: any tenant admin could list, dismiss, "remediate" and delete
// every other tenant's posture findings, disable every tenant's posture rules
// (check_type was globally UNIQUE — one row per check for the whole install),
// enumerate, modify and delete every tenant's AI agents (name was globally
// UNIQUE, so one tenant could squat another's), and act on every tenant's
// recommendations. ispm_scores carried UNIQUE(snapshot_date): one posture
// score per day for the whole install, overwritten by whichever tenant
// scanned last. These tables backed the /ispm, /ai-agents and
// /ai-recommendations console pages, so the exposure was reachable from the UI.
//
// Same shape as v69 (governance_org_isolation): add org_id nullable →
// backfill → SET NOT NULL → index → USING + WITH CHECK policy → ENABLE +
// FORCE ROW LEVEL SECURITY → GRANT. Children backfill from their parent row
// first, then any orphan falls back to the oldest (primary) org so SET NOT
// NULL cannot fail. No column DEFAULT, deliberately: a v1.33 binary rolled
// back over this schema must fail its INSERT loudly rather than mis-tenant
// rows into the primary org (the v76 lesson). Plain statements only — the
// runner's splitSQL cannot handle DO $$ blocks (the v56/v57 lesson).
//
// The two install-wide unique keys become per-tenant keys:
//
//	ispm_rules(check_type)      → (org_id, check_type)
//	ai_agents(name)             → (org_id, name)
//	ispm_scores(snapshot_date)  → (org_id, snapshot_date)
//
// The constraint names are the ones Postgres generates for an inline UNIQUE
// in the v54/v42 CREATE TABLE; DROP CONSTRAINT IF EXISTS keeps the migration
// idempotent on an install where they are already gone.
//
// Rows that existed before this migration are attributed to the oldest org.
// Findings and scores are regenerable (the next scan rebuilds them); agents
// and recommendations are not, so an operator with more than one org should
// review /ai-agents after upgrading (noted in the CHANGELOG).
var ispmAIOrgIsolationUp = `-- Migration 138: ISPM + AI tenant isolation.

-- ispm_rules ------------------------------------------------------------------
ALTER TABLE ispm_rules ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ispm_rules SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ispm_rules ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE ispm_rules DROP CONSTRAINT IF EXISTS ispm_rules_check_type_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_rules_org_check_type ON ispm_rules(org_id, check_type);

CREATE INDEX IF NOT EXISTS idx_ispm_rules_org ON ispm_rules(org_id);

DROP POLICY IF EXISTS pol_ispm_rules_org_scope ON ispm_rules;
CREATE POLICY pol_ispm_rules_org_scope ON ispm_rules
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ispm_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_rules FORCE  ROW LEVEL SECURITY;

-- ispm_findings ---------------------------------------------------------------
ALTER TABLE ispm_findings ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- A finding raised by a rule belongs to that rule's org; the rest (rule_id is
-- nullable, and the pre-v138 scanner never set it) go to the oldest org.
UPDATE ispm_findings f SET org_id = r.org_id FROM ispm_rules r WHERE f.rule_id = r.id AND f.org_id IS NULL;
UPDATE ispm_findings SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ispm_findings ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ispm_findings_org ON ispm_findings(org_id);

DROP POLICY IF EXISTS pol_ispm_findings_org_scope ON ispm_findings;
CREATE POLICY pol_ispm_findings_org_scope ON ispm_findings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ispm_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_findings FORCE  ROW LEVEL SECURITY;

-- ispm_scores -----------------------------------------------------------------
ALTER TABLE ispm_scores ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ispm_scores SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ispm_scores ALTER COLUMN org_id SET NOT NULL;

-- One snapshot per org per day, not one per install per day.
DROP INDEX IF EXISTS idx_ispm_scores_date;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_org_date ON ispm_scores(org_id, snapshot_date);

DROP POLICY IF EXISTS pol_ispm_scores_org_scope ON ispm_scores;
CREATE POLICY pol_ispm_scores_org_scope ON ispm_scores
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ispm_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_scores FORCE  ROW LEVEL SECURITY;

-- ai_agents -------------------------------------------------------------------
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- An agent belongs to its owner's org; ownerless agents go to the oldest org.
UPDATE ai_agents a SET org_id = u.org_id FROM users u WHERE a.owner_id = u.id AND a.org_id IS NULL;
UPDATE ai_agents SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ai_agents ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE ai_agents DROP CONSTRAINT IF EXISTS ai_agents_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_agents_org_name ON ai_agents(org_id, name);

CREATE INDEX IF NOT EXISTS idx_ai_agents_org ON ai_agents(org_id);

DROP POLICY IF EXISTS pol_ai_agents_org_scope ON ai_agents;
CREATE POLICY pol_ai_agents_org_scope ON ai_agents
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ai_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agents FORCE  ROW LEVEL SECURITY;

-- ai_agent_credentials (child of ai_agents) -----------------------------------
-- key_prefix was VARCHAR(12) while internal/admin writes the first 16
-- characters of the key ("oix_agent_" + 6 hex): every INSERT failed, the error
-- was swallowed, and "create agent" answered 201 with an api_key that was never
-- stored. Widened here because this is the migration that already rewrites the
-- table; the handler now fails the whole create if the credential cannot be
-- written. Not narrowed on the way down — the pre-v138 binary could never
-- write a row of that width anyway.
ALTER TABLE ai_agent_credentials ALTER COLUMN key_prefix TYPE VARCHAR(32);

ALTER TABLE ai_agent_credentials ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ai_agent_credentials c SET org_id = a.org_id FROM ai_agents a WHERE c.agent_id = a.id AND c.org_id IS NULL;
UPDATE ai_agent_credentials SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ai_agent_credentials ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_agent_credentials_org ON ai_agent_credentials(org_id);

DROP POLICY IF EXISTS pol_ai_agent_credentials_org_scope ON ai_agent_credentials;
CREATE POLICY pol_ai_agent_credentials_org_scope ON ai_agent_credentials
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ai_agent_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_credentials FORCE  ROW LEVEL SECURITY;

-- ai_agent_permissions (child of ai_agents) -----------------------------------
ALTER TABLE ai_agent_permissions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ai_agent_permissions p SET org_id = a.org_id FROM ai_agents a WHERE p.agent_id = a.id AND p.org_id IS NULL;
UPDATE ai_agent_permissions SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ai_agent_permissions ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_agent_permissions_org ON ai_agent_permissions(org_id);

DROP POLICY IF EXISTS pol_ai_agent_permissions_org_scope ON ai_agent_permissions;
CREATE POLICY pol_ai_agent_permissions_org_scope ON ai_agent_permissions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ai_agent_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_permissions FORCE  ROW LEVEL SECURITY;

-- ai_agent_activity (child of ai_agents) --------------------------------------
ALTER TABLE ai_agent_activity ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ai_agent_activity x SET org_id = a.org_id FROM ai_agents a WHERE x.agent_id = a.id AND x.org_id IS NULL;
UPDATE ai_agent_activity SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ai_agent_activity ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_agent_activity_org ON ai_agent_activity(org_id);

DROP POLICY IF EXISTS pol_ai_agent_activity_org_scope ON ai_agent_activity;
CREATE POLICY pol_ai_agent_activity_org_scope ON ai_agent_activity
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ai_agent_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_activity FORCE  ROW LEVEL SECURITY;

-- ai_recommendations ----------------------------------------------------------
ALTER TABLE ai_recommendations ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE ai_recommendations SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE ai_recommendations ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ai_recommendations_org ON ai_recommendations(org_id);

DROP POLICY IF EXISTS pol_ai_recommendations_org_scope ON ai_recommendations;
CREATE POLICY pol_ai_recommendations_org_scope ON ai_recommendations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE ai_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_recommendations FORCE  ROW LEVEL SECURITY;

-- recommendation_history (child of ai_recommendations) ------------------------
ALTER TABLE recommendation_history ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE recommendation_history h SET org_id = r.org_id FROM ai_recommendations r WHERE h.recommendation_id = r.id AND h.org_id IS NULL;
UPDATE recommendation_history SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE recommendation_history ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_recommendation_history_org ON recommendation_history(org_id);

DROP POLICY IF EXISTS pol_recommendation_history_org_scope ON recommendation_history;
CREATE POLICY pol_recommendation_history_org_scope ON recommendation_history
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE recommendation_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendation_history FORCE  ROW LEVEL SECURITY;

-- Runtime app role. openidx_app is provisioned by v53 and its ALTER DEFAULT
-- PRIVILEGES already covers these tables; the explicit grant is belt-and-braces
-- (plain GRANT, no DO block, per the splitSQL constraint).
GRANT SELECT, INSERT, UPDATE, DELETE ON ispm_rules, ispm_findings, ispm_scores, ai_agents, ai_agent_credentials, ai_agent_permissions, ai_agent_activity, ai_recommendations, recommendation_history TO openidx_app;
`

// Down restores the pre-v138 shape. Re-adding the install-wide unique keys
// fails if tenants have since created rows that collide (two orgs with an
// agent of the same name, two orgs' scores on one day); that failure is the
// right signal — silently dropping the uniqueness would corrupt the rollback
// target's invariants — so it is not wrapped in IF EXISTS-style softening.
var ispmAIOrgIsolationDown = `-- Migration 138 down.
DROP POLICY IF EXISTS pol_recommendation_history_org_scope ON recommendation_history;
DROP POLICY IF EXISTS pol_ai_recommendations_org_scope ON ai_recommendations;
DROP POLICY IF EXISTS pol_ai_agent_activity_org_scope ON ai_agent_activity;
DROP POLICY IF EXISTS pol_ai_agent_permissions_org_scope ON ai_agent_permissions;
DROP POLICY IF EXISTS pol_ai_agent_credentials_org_scope ON ai_agent_credentials;
DROP POLICY IF EXISTS pol_ai_agents_org_scope ON ai_agents;
DROP POLICY IF EXISTS pol_ispm_scores_org_scope ON ispm_scores;
DROP POLICY IF EXISTS pol_ispm_findings_org_scope ON ispm_findings;
DROP POLICY IF EXISTS pol_ispm_rules_org_scope ON ispm_rules;
ALTER TABLE recommendation_history  DISABLE ROW LEVEL SECURITY;
ALTER TABLE ai_recommendations      DISABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_activity       DISABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_permissions    DISABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_credentials    DISABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agents               DISABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_scores             DISABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_findings           DISABLE ROW LEVEL SECURITY;
ALTER TABLE ispm_rules              DISABLE ROW LEVEL SECURITY;
DROP INDEX IF EXISTS idx_ispm_scores_org_date;
DROP INDEX IF EXISTS idx_ai_agents_org_name;
DROP INDEX IF EXISTS idx_ispm_rules_org_check_type;
ALTER TABLE recommendation_history  DROP COLUMN IF EXISTS org_id;
ALTER TABLE ai_recommendations      DROP COLUMN IF EXISTS org_id;
ALTER TABLE ai_agent_activity       DROP COLUMN IF EXISTS org_id;
ALTER TABLE ai_agent_permissions    DROP COLUMN IF EXISTS org_id;
ALTER TABLE ai_agent_credentials    DROP COLUMN IF EXISTS org_id;
ALTER TABLE ai_agents               DROP COLUMN IF EXISTS org_id;
ALTER TABLE ispm_scores             DROP COLUMN IF EXISTS org_id;
ALTER TABLE ispm_findings           DROP COLUMN IF EXISTS org_id;
ALTER TABLE ispm_rules              DROP COLUMN IF EXISTS org_id;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ispm_scores_date ON ispm_scores(snapshot_date);
ALTER TABLE ai_agents ADD CONSTRAINT ai_agents_name_key UNIQUE (name);
ALTER TABLE ispm_rules ADD CONSTRAINT ispm_rules_check_type_key UNIQUE (check_type);
`
