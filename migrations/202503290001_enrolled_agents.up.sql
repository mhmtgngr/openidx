-- Agent enrollment and posture tracking tables
CREATE TABLE IF NOT EXISTS enrolled_agents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          VARCHAR(64) UNIQUE NOT NULL,
    device_id         VARCHAR(64) NOT NULL,
    ziti_identity_id  VARCHAR(255),
    status            VARCHAR(20) DEFAULT 'pending' NOT NULL,
    auth_token_hash   VARCHAR(128) NOT NULL,
    enrolled_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ,
    last_report_at    TIMESTAMPTZ,
    compliance_status VARCHAR(20) DEFAULT 'unknown' NOT NULL,
    compliance_score  FLOAT DEFAULT 0.0,
    metadata          JSONB DEFAULT '{}',
    created_by        VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_status ON enrolled_agents(status);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_last_seen ON enrolled_agents(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_agent_id ON enrolled_agents(agent_id);

CREATE TABLE IF NOT EXISTS agent_posture_results (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           VARCHAR(64) NOT NULL,
    check_type         VARCHAR(64) NOT NULL,
    status             VARCHAR(10) NOT NULL,
    score              FLOAT DEFAULT 0.0,
    severity           VARCHAR(10) NOT NULL,
    details            JSONB DEFAULT '{}',
    message            TEXT,
    reported_at        TIMESTAMPTZ DEFAULT NOW(),
    expires_at         TIMESTAMPTZ,
    enforced           BOOLEAN DEFAULT FALSE,
    enforcement_action VARCHAR(20)
);

CREATE INDEX IF NOT EXISTS idx_agent_posture_agent ON agent_posture_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_posture_reported ON agent_posture_results(reported_at);
