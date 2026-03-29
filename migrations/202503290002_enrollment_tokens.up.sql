CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  VARCHAR(128) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_by  VARCHAR(255),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by_agent VARCHAR(64),
    revoked     BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON agent_enrollment_tokens(token_hash);
