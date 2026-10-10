package migrations

// Migration 228: per-organization privileged-session policy.
//
// Until now the rules around a privileged session were spread between a
// constant and column defaults. externalid.MaxPamSession (8 h) was the only
// duration limit and applied to external users alone; the launch-approval
// window was time.Hour in pam_launch.go; and pam_entries.require_approval /
// record_session defaulted to false, so an internal user's session was
// neither approved nor recorded unless someone set it on each entry.
//
// org_pam_policy holds those rules per organization. A missing row means the
// secure defaults in internal/access/pam_policy.go: every session capped at
// 8 h, internal sessions recorded, approval not required, a 60-minute
// approval window. Every organization that exists at migration time gets a
// row carrying its behaviour as it was (no cap for internal users, no
// recording by default), so nothing changes under it until an administrator
// changes the policy from the PAM dashboard; a new organization starts
// secure. External users keep the 8-hour ceiling whatever the policy says.
//
// idle_timeout_minutes is stored but not yet enforced: the broker reports no
// per-session activity (docs/docs/guide/privileged-access.md). The column is
// here so the policy is complete when it does.
var orgPamPolicyUp = `-- Migration 228: per-organization PAM policy.
CREATE TABLE IF NOT EXISTS org_pam_policy (
  org_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  max_session_hours INTEGER NOT NULL DEFAULT 8 CHECK (max_session_hours >= 0 AND max_session_hours <= 168),
  idle_timeout_minutes INTEGER NOT NULL DEFAULT 0 CHECK (idle_timeout_minutes >= 0 AND idle_timeout_minutes <= 1440),
  require_approval_internal BOOLEAN NOT NULL DEFAULT false,
  record_internal BOOLEAN NOT NULL DEFAULT true,
  launch_approval_window_minutes INTEGER NOT NULL DEFAULT 60 CHECK (launch_approval_window_minutes >= 5 AND launch_approval_window_minutes <= 1440),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID
);

-- Organizations that exist today keep the behaviour they had.
INSERT INTO org_pam_policy (org_id, max_session_hours, idle_timeout_minutes, require_approval_internal, record_internal, launch_approval_window_minutes)
SELECT id, 0, 0, false, false, 60 FROM organizations
ON CONFLICT (org_id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON org_pam_policy TO openidx_app;

DROP POLICY IF EXISTS pol_org_pam_policy_org_scope ON org_pam_policy;
CREATE POLICY pol_org_pam_policy_org_scope ON org_pam_policy
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE org_pam_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_pam_policy FORCE  ROW LEVEL SECURITY;
`

var orgPamPolicyDown = `-- Migration 228 down: the constants and column defaults rule again.
DROP TABLE IF EXISTS org_pam_policy;
`
