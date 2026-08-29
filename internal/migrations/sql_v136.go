package migrations

// Migration v136 — group→application assignments (group-based app access).
//
// SSO/OIDC app access was user-only (user_application_assignments). This adds a
// parallel group→app table so assigning an application to a group grants it to
// every member — the access model admins expect. GetMyApplications returns the
// UNION of user- and group-assigned apps. Additive + nullable; the existing
// user-assignment path is unaffected. Org-scoped via RLS to match the security
// posture of user_application_assignments (v37).
var groupAppAssignmentsUp = `-- Migration 136: group→application assignments.
CREATE TABLE IF NOT EXISTS group_application_assignments (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id       UUID NOT NULL,
    application_id UUID NOT NULL,
    org_id         UUID NOT NULL,
    assigned_by    UUID,
    assigned_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_group_app_assignments_group ON group_application_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_group_app_assignments_app   ON group_application_assignments(application_id);
CREATE INDEX IF NOT EXISTS idx_group_app_assignments_org   ON group_application_assignments(org_id);

-- Org isolation: rows are visible only within their org unless a trusted caller
-- sets app.bypass_rls (mirrors user_application_assignments, migration v37).
ALTER TABLE group_application_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY pol_group_app_assignments_org_scope ON group_application_assignments
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON group_application_assignments TO openidx_app;
`

var groupAppAssignmentsDown = `-- Rollback migration 136.
DROP TABLE IF EXISTS group_application_assignments CASCADE;
`
