package migrations

// Migration 261: assistant conversations.
//
// agentic_sessions and agentic_messages keep what a person and the assistant
// said, server-side, so a conversation can continue and an operator can see
// what the assistant told someone. They are server-side on purpose: a
// transcript the browser sent back could carry forged assistant or tool turns,
// which is exactly how a model is talked into things. Text is stored as it
// was sent to the model (already masked). Rows expire after 30 days.

var agenticChatUp = `-- Migration 261: assistant conversations.
CREATE TABLE IF NOT EXISTS agentic_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL,
    agent_id   VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
);
CREATE INDEX IF NOT EXISTS idx_agentic_sessions_user ON agentic_sessions (org_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_sessions_expiry ON agentic_sessions (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON agentic_sessions TO openidx_app;
DROP POLICY IF EXISTS pol_agentic_sessions_org_scope ON agentic_sessions;
CREATE POLICY pol_agentic_sessions_org_scope ON agentic_sessions
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agentic_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_sessions FORCE  ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS agentic_messages (
    id         BIGSERIAL PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES agentic_sessions(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    role       VARCHAR(16) NOT NULL CHECK (role IN ('user', 'assistant')),
    blocks     JSONB NOT NULL CHECK (octet_length(blocks::text) <= 65536),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_agentic_messages_user_recent ON agentic_messages (org_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON agentic_messages TO openidx_app;
GRANT USAGE, SELECT ON SEQUENCE agentic_messages_id_seq TO openidx_app;
DROP POLICY IF EXISTS pol_agentic_messages_org_scope ON agentic_messages;
CREATE POLICY pol_agentic_messages_org_scope ON agentic_messages
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agentic_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_messages FORCE  ROW LEVEL SECURITY;
`

var agenticChatDown = `-- Rollback migration 261.
DROP TABLE IF EXISTS agentic_messages;
DROP TABLE IF EXISTS agentic_sessions;
`
