package migrations

// Migration v154 — joiner/mover/leaver automation.
//
// Four tables, one subsystem, one defect. `lifecycle_workflows` and
// `lifecycle_policies` are the RULES that decide which accounts get roles
// added, groups removed, sessions revoked, passwords forced, accounts
// disabled, or accounts DELETED. `lifecycle_executions` and
// `lifecycle_policy_executions` are the logs of what those rules did.
// v54 and v55 created all four with no tenant column.
//
// THE ACTIONS WERE SCOPED. THE RULE THAT AIMS THEM WAS NOT. Every mutation
// this subsystem performs is carefully org-scoped, in both packages:
//
//	UPDATE users SET enabled = false ... WHERE id = $1 AND org_id = $2
//	DELETE FROM users                    WHERE id = $1 AND org_id = $2
//	DELETE FROM user_roles        WHERE user_id = $1 AND role_id = $2 AND org_id = $3
//	DELETE FROM sessions          WHERE user_id = $1 AND org_id = $2
//
// and `findAffectedUsers` selects its candidates with `AND org_id = $N` in
// all four policy types. internal/admin/deprovisioning.go even carries a
// comment recording an earlier fix in this programme — the org has to travel
// on the CONTEXT because `users` is behind the FORCE-RLS belt, or the leaver
// disable matches its predicate and affects nobody. Someone thought hard
// about the blast radius of the actions.
//
// Nobody scoped the rule. Every handler over these four tables addresses them
// by bare id:
//
//	SELECT ... FROM lifecycle_policies ORDER BY name            -- every tenant's
//	UPDATE lifecycle_policies SET %s WHERE id = $N              -- any tenant's
//	DELETE FROM lifecycle_policies WHERE id = $1                -- any tenant's
//	DELETE FROM lifecycle_workflows WHERE id = $1               -- any tenant's
//	SELECT ... FROM lifecycle_policy_executions WHERE policy_id = $1
//
// So a second organization's administrator could open the first's leaver
// policy, change `conditions` to {"inactive_days": 0} and `actions` to
// {"action": "delete"}, and hand it back. The owning administrator then runs
// what their console still labels "Stale account disable — 90 days" and it
// deletes their directory. The action never leaves the owner's tenant, which
// is exactly why the org predicate on the DELETE does not help: the rows
// destroyed are the owner's own. A control that another tenant can re-aim is
// armed by its owner and pointed by someone else.
//
// The other three directions are the same defect seen from different sides.
// DELETE removes another tenant's offboarding rule outright — the leaver
// control stops existing, silently, and nothing on the owner's console says
// so. Execute loads any tenant's policy by bare id and runs it against the
// caller's own users, so a rule one organization wrote governs another's
// accounts. And the execution logs are a plain cross-tenant read of personal
// data: `actions_taken` records, per affected account,
//
//	{"user_id":..., "username":..., "action":"delete", "reason":"No login for 90+ days"}
//
// so listing another tenant's runs returns their users' names, the action
// taken against each, and why. That is a directory dump with a justification
// column, reachable by anyone who can guess or list a policy id — and listing
// them was itself unscoped.
//
// BACKFILL, NARROWING FROM THE MOST SPECIFIC ATTRIBUTION. The rules go to
// their author's organization (`created_by` -> users.org_id). A workflow
// execution goes to the organization of the USER IT ACTED ON: the row names
// that person and the log belongs where they do; only if that user is gone
// does it fall back to the workflow's organization. A policy execution has no
// user column, so it follows its policy. Anything still unattributed goes to
// the oldest organization, where an operator can see it.
//
// One consequence for a multi-organization install, and the CHANGELOG says it
// in these words: a rule that has been visible to every administrator becomes
// visible to one. If a second organization was relying on a rule the first
// authored — which it was never entitled to — it must author its own.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var lifecycleScopeUp = `-- Migration 154: scope and belt the lifecycle automation.

ALTER TABLE lifecycle_workflows          ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE lifecycle_policies           ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE lifecycle_executions         ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE lifecycle_policy_executions  ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- The rules go to whoever wrote them.
UPDATE lifecycle_workflows w SET org_id = u.org_id FROM users u WHERE u.id = w.created_by AND w.org_id IS NULL;
UPDATE lifecycle_policies  p SET org_id = u.org_id FROM users u WHERE u.id = p.created_by AND p.org_id IS NULL;

UPDATE lifecycle_workflows SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE lifecycle_policies  SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

-- A workflow execution names the account it acted on: the log belongs where
-- that person does. Only a deleted user falls back to the rule's own tenant.
UPDATE lifecycle_executions e SET org_id = u.org_id FROM users u WHERE u.id = e.user_id AND e.org_id IS NULL;
UPDATE lifecycle_executions e SET org_id = w.org_id FROM lifecycle_workflows w WHERE w.id = e.workflow_id AND e.org_id IS NULL;

-- A policy execution has no user column; it follows its policy.
UPDATE lifecycle_policy_executions x SET org_id = p.org_id FROM lifecycle_policies p WHERE p.id = x.policy_id AND x.org_id IS NULL;

UPDATE lifecycle_executions        SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE lifecycle_policy_executions SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE lifecycle_workflows         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE lifecycle_policies          ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE lifecycle_executions        ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE lifecycle_policy_executions ALTER COLUMN org_id SET NOT NULL;

-- Each index is the read the scoped handler now makes. v54's single-column
-- indexes are the same reads without their tenant term; they are left alone.
CREATE INDEX IF NOT EXISTS idx_lifecycle_workflows_org_event ON lifecycle_workflows(org_id, event_type);
CREATE INDEX IF NOT EXISTS idx_lifecycle_policies_org_name   ON lifecycle_policies(org_id, name);
CREATE INDEX IF NOT EXISTS idx_lifecycle_executions_org      ON lifecycle_executions(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lifecycle_policy_exec_org     ON lifecycle_policy_executions(org_id, policy_id, started_at DESC);

DROP POLICY IF EXISTS pol_lifecycle_workflows_org_scope ON lifecycle_workflows;
CREATE POLICY pol_lifecycle_workflows_org_scope ON lifecycle_workflows
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE lifecycle_workflows ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_workflows FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_lifecycle_policies_org_scope ON lifecycle_policies;
CREATE POLICY pol_lifecycle_policies_org_scope ON lifecycle_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE lifecycle_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_policies FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_lifecycle_executions_org_scope ON lifecycle_executions;
CREATE POLICY pol_lifecycle_executions_org_scope ON lifecycle_executions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE lifecycle_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_executions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_lifecycle_policy_executions_org_scope ON lifecycle_policy_executions;
CREATE POLICY pol_lifecycle_policy_executions_org_scope ON lifecycle_policy_executions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE lifecycle_policy_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_policy_executions FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON lifecycle_workflows         TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON lifecycle_policies          TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON lifecycle_executions        TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON lifecycle_policy_executions TO openidx_app;
`

// Down lifts the belt and drops the columns. v54's and v55's own indexes are
// left in place: they are not this migration's, and a rolled-back binary reads
// these tables without a tenant term again, which is what they serve.
var lifecycleScopeDown = `-- Rollback 154.

ALTER TABLE lifecycle_policy_executions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_policy_executions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_lifecycle_policy_executions_org_scope ON lifecycle_policy_executions;

ALTER TABLE lifecycle_executions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_executions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_lifecycle_executions_org_scope ON lifecycle_executions;

ALTER TABLE lifecycle_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_lifecycle_policies_org_scope ON lifecycle_policies;

ALTER TABLE lifecycle_workflows NO FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle_workflows DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_lifecycle_workflows_org_scope ON lifecycle_workflows;

DROP INDEX IF EXISTS idx_lifecycle_policy_exec_org;
DROP INDEX IF EXISTS idx_lifecycle_executions_org;
DROP INDEX IF EXISTS idx_lifecycle_policies_org_name;
DROP INDEX IF EXISTS idx_lifecycle_workflows_org_event;

ALTER TABLE lifecycle_policy_executions DROP COLUMN IF EXISTS org_id;
ALTER TABLE lifecycle_executions        DROP COLUMN IF EXISTS org_id;
ALTER TABLE lifecycle_policies          DROP COLUMN IF EXISTS org_id;
ALTER TABLE lifecycle_workflows         DROP COLUMN IF EXISTS org_id;
`
