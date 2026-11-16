package migrations

// Migration 257: diagnostic bundles.
//
// agent_diagnostics keeps what a device's own doctor found when it could not
// connect: the bundle as the device sent it (bounded and stripped of unknown
// fields before it is stored), the leading cause the rule engine drew from
// it, and when it was collected. A row is evidence for a person or an
// operator asking "why can't this device connect"; it is not a log, so it
// expires after 30 days and each device keeps only its most recent few.
//
// The bundle carries no token, key or proxy password by construction
// (agent/internal/doctor). Its free text is device-supplied and is treated
// as untrusted wherever it is shown.

var agentDiagnosticsUp = `-- Migration 257: agent diagnostics.
CREATE TABLE IF NOT EXISTS agent_diagnostics (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id      VARCHAR(255) NOT NULL,
    source        VARCHAR(16) NOT NULL DEFAULT 'agent'
                  CHECK (source IN ('agent', 'command')),
    bundle        JSONB NOT NULL CHECK (octet_length(bundle::text) <= 131072),
    primary_cause VARCHAR(64),
    collected_at  TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX IF NOT EXISTS idx_agent_diagnostics_agent ON agent_diagnostics (org_id, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_diagnostics_expiry ON agent_diagnostics (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_diagnostics TO openidx_app;
DROP POLICY IF EXISTS pol_agent_diagnostics_org_scope ON agent_diagnostics;
CREATE POLICY pol_agent_diagnostics_org_scope ON agent_diagnostics
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agent_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_diagnostics FORCE  ROW LEVEL SECURITY;
`

var agentDiagnosticsDown = `-- Rollback migration 257.
DROP TABLE IF EXISTS agent_diagnostics;
`
