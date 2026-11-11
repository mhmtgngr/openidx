package migrations

// Migration 252: per-organization agent settings.
//
// org_agent_settings is the one settings row an organization has for its
// agent fleet. This migration brings claim_mode, how a device enrolled with
// a fleet token (which names no one) gets an owner:
//
//	login            (default) the person who signs in on the tray claims it
//	                 through POST /agent/claim.
//	logged_on_user   additionally, the agent's report names the Windows
//	                 session user, and the server makes an unowned device
//	                 theirs when that name matches a directory- or
//	                 federation-sourced user of the organization.
//
// Update-ring columns (B8.5) join this row later. Migration 251 is reserved
// for agent identity continuity on another branch. No row means the defaults.

var orgAgentSettingsUp = `-- Migration 252: org agent settings.
CREATE TABLE IF NOT EXISTS org_agent_settings (
    org_id     UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    claim_mode VARCHAR(32) NOT NULL DEFAULT 'login'
               CHECK (claim_mode IN ('login', 'logged_on_user')),
    updated_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_agent_settings TO openidx_app;
DROP POLICY IF EXISTS pol_org_agent_settings_org_scope ON org_agent_settings;
CREATE POLICY pol_org_agent_settings_org_scope ON org_agent_settings
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE org_agent_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_agent_settings FORCE  ROW LEVEL SECURITY;
`

var orgAgentSettingsDown = `-- Rollback migration 252.
DROP TABLE IF EXISTS org_agent_settings;
`
