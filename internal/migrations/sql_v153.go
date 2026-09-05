package migrations

// Migration v153 — the login risk policies.
//
// A `risk_policies` row is a rule the login path consults: "when this condition
// holds, require MFA / require step-up / deny / allow these factors." v39
// created it with no tenant column, and the read that matters has no predicate
// either:
//
//	SELECT id, name, ... FROM risk_policies
//	 WHERE enabled = true
//	 ORDER BY priority ASC
//
// That is `GetEnabledRiskPolicies`, and `AssessLoginRisk` applies EVERY row it
// returns that matches:
//
//	for _, policy := range policies {
//	    if s.evaluateRiskPolicy(lc, assessment, &policy) {
//	        s.applyRiskPolicyActions(assessment, &policy)
//	    }
//	}
//
// So every organization's enabled policies were evaluated against every
// organization's logins.
//
// THE DIRECTION IS TOWARD WEAKER, WHICH IS WHAT MAKES IT SHARP. Look at what
// an action can do, in applyRiskPolicyActions:
//
//	if methods, ok := actions["mfa_methods"].([]interface{}); ok {
//	    assessment.AllowedMethods = make([]string, 0)   // REPLACES, not merges
//	    ... "any" -> {"totp","push","webauthn","sms","email"}
//	}
//
// At high risk the assessment restricts the second factor to WebAuthn and push
// — the phishing-resistant ones. A policy belonging to another organization
// with `mfa_methods: ["any"]` overwrites that list with one that includes SMS
// and email. And the matching condition need not be clever: `risk_score_min: 0`
// is `assessment.Score >= 0`, true on every login ever assessed. One row in one
// tenant, and every tenant's step-up admits an SMS code. `deny: true` on the
// same condition is the other end of it: every login refused, everywhere.
//
// A control that one organization can weaken for all of them is not a control,
// and it is the same finding as v151's require_approval — a PAM gate another
// tenant could turn off — arriving this time on the authentication path.
//
// AND THE COMMENT SAID IT WAS ALREADY SCOPED. internal/risk/policy.go, on the
// create request's TenantID field:
//
//	// TenantID is optional. The policy is org-scoped by the request context;
//	// the admin console does not send a tenant_id ...
//
// It was not org-scoped by anything. There was no column and no predicate.
// `CreateRiskPolicy` even ends with `if req.TenantID != "" { p.TenantID =
// req.TenantID }` — assigning the tenant to the RESPONSE STRUCT and never to
// the row, so an API caller who supplied one was handed it back as though it
// had been recorded. This is the third comment in three batches asserting a
// tenant scoping that does not exist (v151 credited an RLS belt that was never
// applied; v152 copied a predicate's justification without the predicate).
//
// The whole CRUD went with it: list, get, update, delete and toggle all
// addressed policies by bare id, so any tenant's administrator could author,
// re-point, disable or delete any other tenant's login rules.
//
// BACKFILL, AND WHY IT NEEDS AN OPERATOR. This table has no user, no route, no
// parent of any kind — nothing to attribute a row through. Every existing
// policy therefore goes to the oldest organization. That is the honest choice
// and it is not a neutral one: a policy that has been applying to every tenant
// will, after this migration, apply to one. That is the correct direction (no
// tenant was ever entitled to have another's rule applied to its logins), but
// installs with more than one organization should re-create the policies they
// meant to have. The CHANGELOG says so in those words.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var riskPolicyScopeUp = `-- Migration 153: scope and belt risk_policies.

ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Nothing on this row names a tenant, so there is no narrower attribution to
-- make: every existing policy goes where an operator can see and re-create it.
UPDATE risk_policies SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE risk_policies ALTER COLUMN org_id SET NOT NULL;

-- The login path reads (org_id, enabled) ordered by priority; v39's index was
-- (enabled, priority), which is the same read without its tenant term.
CREATE INDEX IF NOT EXISTS idx_risk_policies_org_enabled ON risk_policies(org_id, enabled, priority);

DROP POLICY IF EXISTS pol_risk_policies_org_scope ON risk_policies;
CREATE POLICY pol_risk_policies_org_scope ON risk_policies
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE risk_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_policies FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON risk_policies TO openidx_app;
`

// Down lifts the belt and drops the column. v39's (enabled, priority) index is
// left in place: it is not this migration's, and a rolled-back binary reads the
// table without a tenant term again, which is exactly the index it wants.
var riskPolicyScopeDown = `-- Rollback 153.

ALTER TABLE risk_policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_policies DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_risk_policies_org_scope ON risk_policies;
DROP INDEX IF EXISTS idx_risk_policies_org_enabled;
ALTER TABLE risk_policies DROP COLUMN IF EXISTS org_id;
`
