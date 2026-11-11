package migrations

// Migration 254: remote fleet commands (Faz B8.6).
//
// agent_commands is the queue an administrator fills and a device drains.
// A command is queued, handed to its device once in /agent/config
// (delivered), and finished by the device's result (done or failed). One
// nobody picked up in 24 hours expires; an administrator may cancel one
// that is still queued. collect_logs returns an artifact, a tar.gz of at
// most 8 MiB, kept with its name and SHA-256.
//
// Org-scoped under FORCE RLS like every fleet table.

var agentCommandsUp = `-- Migration 254: agent commands.
CREATE TABLE IF NOT EXISTS agent_commands (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        VARCHAR(255) NOT NULL,
    kind            VARCHAR(32) NOT NULL
                    CHECK (kind IN ('restart', 'collect_logs', 'reenroll', 'set_options', 'update_now', 'uninstall')),
    args            JSONB NOT NULL DEFAULT '{}',
    status          VARCHAR(16) NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'delivered', 'done', 'failed', 'expired', 'cancelled')),
    reason          TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    result          JSONB,
    artifact        BYTEA CHECK (artifact IS NULL OR octet_length(artifact) <= 8388608),
    artifact_name   VARCHAR(255),
    artifact_sha256 VARCHAR(64)
);
CREATE INDEX IF NOT EXISTS idx_agent_commands_agent_status ON agent_commands (org_id, agent_id, status);
CREATE INDEX IF NOT EXISTS idx_agent_commands_expiry ON agent_commands (expires_at) WHERE status IN ('queued', 'delivered');
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_commands TO openidx_app;
DROP POLICY IF EXISTS pol_agent_commands_org_scope ON agent_commands;
CREATE POLICY pol_agent_commands_org_scope ON agent_commands
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_commands FORCE  ROW LEVEL SECURITY;
`

var agentCommandsDown = `-- Rollback migration 254.
DROP TABLE IF EXISTS agent_commands;
`
