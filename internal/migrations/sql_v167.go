package migrations

// Migration v167 — the group→application assignment: ENABLE is not the belt.
//
// v136 created `group_application_assignments` and gave it, in its own words,
// "Org isolation: rows are visible only within their org unless a trusted
// caller sets app.bypass_rls (mirrors user_application_assignments, migration
// v37)." It wrote `org_id UUID NOT NULL`, `ENABLE ROW LEVEL SECURITY`, and the
// same USING/WITH CHECK policy every other belted table has.
//
// It did not write FORCE.
//
// ENABLE applies a policy to every role EXCEPT the table's owner. FORCE is what
// applies it to the owner too. So this table's isolation holds only while the
// role that ran the migration and the role the application connects as are
// different roles. On the reference deployment they are — deployments/docker's
// bootstrap.sql creates openidx_app as NOSUPERUSER NOBYPASSRLS and the Helm
// values note that "migrations connect as the database OWNER" — so this is not
// a live hole there, and this says so rather than overstating it. On any
// install where those roles coincide (a single-role Postgres, a managed service
// whose application user owns the schema, a developer's local database), the
// policy silently stops applying to the application, on this table alone.
//
// AND THE PROXY'S OWN COMMENT ASSERTS OTHERWISE. proxy_assignment_cache.go
// explains why the data plane re-applies orgctx.WithBypassRLS, and its reason is
//
//	`applications` / `user_application_assignments` / `group_memberships` /
//	`group_application_assignments` are all FORCE ROW LEVEL SECURITY.
//
// Three of those four are. Checked against a migrated database:
//
//	applications                  relrowsecurity=t  relforcerowsecurity=t
//	user_application_assignments  relrowsecurity=t  relforcerowsecurity=t
//	group_memberships             relrowsecurity=t  relforcerowsecurity=t
//	group_application_assignments relrowsecurity=t  relforcerowsecurity=f
//
// The group half of the app-assignment pair is the one that is not, which is
// the fourth time this programme has found a pair guarded on one side and not
// the other -- after v154's lifecycle, v158's biometric rules, v161's bulk
// operations and v162's feature switch. The comment is corrected in the same
// commit as the migration, because a comment that certifies a property nothing
// checks is how the property goes missing.
//
// The queries are already clean -- appaccess's assignedPredicate carries
// `gaa.org_id = $2`, PrincipalsFor carries `AND org_id = $2`, and the portal's
// three handlers each carry their own term -- which is why this table sat on
// the needsBelt register rather than needing a scoping batch. This migration is
// the one statement that was missing, plus the policy re-stated in the
// programme's canonical form so the two are never again out of step.
//
// A regression guard lands with it: an integration case that asserts EVERY
// table carrying an RLS policy also carries FORCE. The existing belt suite
// could not catch this, because requireForceRLS SKIPS a table that is not
// forced rather than failing it -- a guard that steps aside for exactly the
// condition it exists to detect.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var groupAppAssignmentsForceUp = `-- Migration 167: FORCE the belt v136 only enabled.

DROP POLICY IF EXISTS pol_group_app_assignments_org_scope ON group_application_assignments;
CREATE POLICY pol_group_app_assignments_org_scope ON group_application_assignments
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE group_application_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_application_assignments FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON group_application_assignments TO openidx_app;
`

// Down returns the table to v136's state: the policy stays and RLS stays
// enabled, only FORCE is lifted. Nothing here can fail on data.
var groupAppAssignmentsForceDown = `-- Rollback 167.

ALTER TABLE group_application_assignments NO FORCE ROW LEVEL SECURITY;
`
