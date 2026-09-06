package migrations

// Migration v159 — v44's four tables: two get a tenant, two go.
//
// v44 was a reconcile pass. It lifted four tables out of loose SQL files into
// the versioned migration set so managed-Postgres installs would stop 500ing,
// and its own note records the choice it deferred: "Not org-scoped (matches
// source + handlers), consistent with v42/v43." Two of the four have a live
// consumer and get the tenant column; the other two do not, and their consumer
// was deleted from this repository.
//
// A DEVICE LOCKDOWN POLICY ANY ADMINISTRATOR COULD LIST, EDIT AND DELETE. A
// kiosk_policies row puts a managed device into single-app or multi-app lock
// task mode: which packages may run, which activity is pinned to the screen,
// the branding shown, and the hash of the PIN required to leave. The admin list
// carries the finding in its own doc comment —
//
//	// HandleListPolicies returns every kiosk policy (admin view, no filtering).
//
// — and get, update and delete address a policy by bare id. So one tenant's
// administrator could read another's lockdown configuration, disable it, or
// delete it, and nothing on the owning console would say the control had
// stopped existing.
//
// THE ASSIGNMENT IS THE SHARPER HALF. HandleAssignPolicy takes the policy id
// from the URL and target_id from the body, checks neither, and writes the row.
// target_id is a plain VARCHAR(128) naming an agent, and
// resolveEffectiveKioskPolicy matches it against the agent asking for its
// configuration. So one tenant could aim their own lockdown policy at another
// tenant's enrolled device: the device is put into single-app mode with an exit
// PIN only the other tenant knows. This migration scopes the policy and the
// assignment, and both handlers now verify the policy belongs to the caller.
//
// What it does NOT close is the target itself. enrolled_agents has no org_id by
// a decision recorded in three separate comments in internal/access, so an
// agent id names a device without naming a tenant, and there is no tenant term
// to put on target_id. Closing that is a product decision about whether the
// fleet is per-tenant, and it is named in the readiness guide rather than
// settled here.
//
// THE BELT AND THE AGENT PATH. /agent/config resolves the effective policy for
// a device that authenticates with an agent token and carries no user, so it
// has no organization on its context. Under the belt that read returns nothing,
// and the caller treats resolution failure as "no policy applies" and omits the
// block — a device that should be locked down would quietly stop being locked
// down. resolveEffectiveKioskPolicy therefore runs under
// orgctx.WithBypassRLS, the same explicit opt-out the SAML and SSF pre-tenant
// paths use, and it is the one read of these tables that does.
//
// TWO TABLES WHOSE ONLY CONSUMER WAS DELETED. v44 created
// policy_recommendations and compliance_gaps for, in its own words, the "AI
// policy suggestion / compliance-gap endpoints
// (internal/admin/ai_policy_recommendations.go)". That file is gone: commit
// 7f8d189e, "fix(admin): remove dead AI policy-recommendations route (WS-05)",
// removed it from this repository. A search of the tree finds both table names
// in the migrations and in the orgscope register and nowhere else — no handler,
// no worker, no seed, no console call.
//
// So they are dropped rather than scoped, for the reason v157 dropped
// auth_contexts: giving org_id and a policy to a table with no reader and no
// writer moves a name off a register and changes nothing. Nothing can have
// written a row, so nothing is lost, and the down migration recreates both
// exactly as v44 declared them.
//
// BACKFILL. A kiosk policy goes to the organization of its author through v44's
// own created_by FK to users; an assignment follows its policy through an
// enforced FK. Anything unattributed — a policy whose author has been deleted —
// goes to the oldest organization.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var kioskScopeUp = `-- Migration 159: scope the kiosk lockdown policies; drop v44's two orphans.

ALTER TABLE kiosk_policies            ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE kiosk_policy_assignments  ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- A policy goes to its author's organization; an assignment follows its policy.
UPDATE kiosk_policies p SET org_id = u.org_id FROM users u WHERE u.id = p.created_by AND p.org_id IS NULL;
UPDATE kiosk_policies SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE kiosk_policy_assignments a SET org_id = p.org_id FROM kiosk_policies p WHERE p.id = a.policy_id AND a.org_id IS NULL;
UPDATE kiosk_policy_assignments SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE kiosk_policies           ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE kiosk_policy_assignments ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_kiosk_policies_org        ON kiosk_policies(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_kiosk_assignments_org_pol ON kiosk_policy_assignments(org_id, policy_id);

DROP POLICY IF EXISTS pol_kiosk_policies_org_scope ON kiosk_policies;
CREATE POLICY pol_kiosk_policies_org_scope ON kiosk_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE kiosk_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE kiosk_policies FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_kiosk_policy_assignments_org_scope ON kiosk_policy_assignments;
CREATE POLICY pol_kiosk_policy_assignments_org_scope ON kiosk_policy_assignments
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE kiosk_policy_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE kiosk_policy_assignments FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON kiosk_policies           TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON kiosk_policy_assignments TO openidx_app;

-- v44 created these for internal/admin/ai_policy_recommendations.go, which
-- commit 7f8d189e removed as a dead route. Nothing has read or written either
-- table since, so nothing is lost.
DROP TABLE IF EXISTS policy_recommendations;
DROP TABLE IF EXISTS compliance_gaps;
`

// Down recreates v44's two orphans verbatim (empty, which is the state they
// have always been in) and lifts the belt from the kiosk tables. v44 gave
// neither kiosk table an install-wide unique key — kiosk_policy_assignments'
// UNIQUE (policy_id, target_kind, target_id) is keyed on the policy, which
// carries the tenant — so, like v158, this rollback cannot fail on data.
var kioskScopeDown = `-- Rollback 159.

CREATE TABLE IF NOT EXISTS policy_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(100) NOT NULL,
    priority VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    estimated_effort VARCHAR(50),
    confidence FLOAT NOT NULL,
    reasoning JSONB,
    affected_users INT DEFAULT 0,
    affected_roles INT DEFAULT 0,
    affected_resources JSONB,
    metadata JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    implemented_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_status   ON policy_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_priority ON policy_recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_type     ON policy_recommendations(type);

CREATE TABLE IF NOT EXISTS compliance_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    standard VARCHAR(100) NOT NULL,
    control_id VARCHAR(255) NOT NULL,
    control_name TEXT NOT NULL,
    current_state TEXT,
    desired_state TEXT,
    gap_description TEXT,
    remediation_plan TEXT,
    priority VARCHAR(50) NOT NULL,
    estimated_effort INT DEFAULT 0,
    due_date DATE,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_standard ON compliance_gaps(standard);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_status   ON compliance_gaps(status);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_priority ON compliance_gaps(priority);

GRANT SELECT, INSERT, UPDATE, DELETE ON policy_recommendations, compliance_gaps TO openidx_app;

ALTER TABLE kiosk_policy_assignments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE kiosk_policy_assignments DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_kiosk_policy_assignments_org_scope ON kiosk_policy_assignments;

ALTER TABLE kiosk_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE kiosk_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_kiosk_policies_org_scope ON kiosk_policies;

DROP INDEX IF EXISTS idx_kiosk_assignments_org_pol;
DROP INDEX IF EXISTS idx_kiosk_policies_org;

ALTER TABLE kiosk_policy_assignments DROP COLUMN IF EXISTS org_id;
ALTER TABLE kiosk_policies           DROP COLUMN IF EXISTS org_id;
`
