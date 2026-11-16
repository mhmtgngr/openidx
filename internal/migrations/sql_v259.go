package migrations

// Migration 259: how far the platform may act on its own.
//
// org_agentic_settings holds one row per organization: the autonomy mode
// (off, observe, tier0, tier1) and a kill switch. A missing row means the
// default, observe: findings are recorded and nothing is done. The mode is
// also capped by the AGENTIC_MODE environment variable, so an operator of the
// deployment can hold every organization lower than its admins chose.
//
// agentic_actions is the ledger of what the platform did, or would have done,
// to a device: one row per fix. It is also the memory behind the anti-flap
// rule (the same fix is not applied to a device more than twice a day), so it
// is read on the hot path of every diagnostic. Rows expire after 30 days.

var agenticSettingsUp = `-- Migration 259: agentic settings and action ledger.
CREATE TABLE IF NOT EXISTS org_agentic_settings (
    org_id      UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    mode        VARCHAR(16) NOT NULL DEFAULT 'observe'
                CHECK (mode IN ('off', 'observe', 'tier0', 'tier1')),
    kill_switch BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by  UUID,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_agentic_settings TO openidx_app;
DROP POLICY IF EXISTS pol_org_agentic_settings_org_scope ON org_agentic_settings;
CREATE POLICY pol_org_agentic_settings_org_scope ON org_agentic_settings
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE org_agentic_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_agentic_settings FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS agentic_actions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id      VARCHAR(255) NOT NULL,
    action        VARCHAR(64) NOT NULL,
    cause         VARCHAR(64) NOT NULL,
    mode          VARCHAR(16) NOT NULL,
    outcome       VARCHAR(16) NOT NULL
                  CHECK (outcome IN ('observed', 'applied', 'suppressed')),
    reason        VARCHAR(64) NOT NULL DEFAULT '',
    command_id    UUID,
    diagnostic_id UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX IF NOT EXISTS idx_agentic_actions_agent ON agentic_actions (org_id, agent_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_actions_recent ON agentic_actions (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_actions_expiry ON agentic_actions (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON agentic_actions TO openidx_app;
DROP POLICY IF EXISTS pol_agentic_actions_org_scope ON agentic_actions;
CREATE POLICY pol_agentic_actions_org_scope ON agentic_actions
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agentic_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_actions FORCE  ROW LEVEL SECURITY;
`

var agenticSettingsDown = `-- Rollback migration 259.
DROP TABLE IF EXISTS agentic_actions;
DROP TABLE IF EXISTS org_agentic_settings;
`
