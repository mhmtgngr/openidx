package migrations

// Migration v43 — reconcile the Agent Fleet / AI Recommendations / Notification
// Digest tables into the versioned migration set (same class as v38–v42).
//
// These admin pages 500'd on managed-RDS/Helm/`migrate` installs because the
// tables their handlers query existed only outside the Go migration runner:
//   - enrolled_agents (+ agent_posture_results, agent_enrollment_tokens) lived in
//     loose, un-runnered files under migrations/ (202503290001/2, 202605150001,
//     202605200001). Agent Fleet → GET /api/v1/access/agents.
//   - ai_recommendations + recommendation_history, and the ai_agents children
//     ai_agent_credentials/permissions/activity (v42 created ai_agents but not its
//     children), lived only in deployments/docker/init-db.sql.
//     AI Recommendations → GET /api/v1/recommendations.
//   - notification_digests lived only in init-db.sql.
//     Notification Center digest → GET /api/v1/notifications/digest.
//
// (Issue #184 originally called these "unimplemented features" — that was a
// mis-read: it used the route/feature name, not the table name. The schema
// existed in source all along; this is the init-db↔migrations gap.)
//
// DDL is lifted verbatim from those sources (enrolled_agents is consolidated to
// its final post-ALTER shape; the source backfill UPDATEs are upgrade-only and a
// no-op on a fresh create, so they are omitted). All statements are idempotent
// (IF NOT EXISTS), so this is a no-op on docker-compose installs. None of these
// tables are org-scoped in source and their handlers don't filter org_id, so they
// are created without org_id to match the deployed schema; org-scoping them is a
// separate effort.
var agentRecoDigestUp = `-- Migration 043: agent fleet + AI recommendations + notification digest tables.

-- Agent fleet ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrolled_agents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            VARCHAR(64) UNIQUE NOT NULL,
    device_id           VARCHAR(64) NOT NULL,
    ziti_identity_id    VARCHAR(255),
    status              VARCHAR(20) DEFAULT 'pending' NOT NULL,
    auth_token_hash     VARCHAR(128) NOT NULL,
    enrolled_at         TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ,
    last_report_at      TIMESTAMPTZ,
    compliance_status   VARCHAR(20) DEFAULT 'unknown' NOT NULL,
    compliance_score    FLOAT DEFAULT 0.0,
    metadata            JSONB DEFAULT '{}',
    created_by          VARCHAR(255),
    platform            VARCHAR(32),
    form_factor         VARCHAR(32),
    is_device_owner     BOOLEAN NOT NULL DEFAULT FALSE,
    enrollment_method   VARCHAR(32),
    enrolled_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    management_mode     VARCHAR(32)
);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_status ON enrolled_agents(status);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_last_seen ON enrolled_agents(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_agent_id ON enrolled_agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_platform ON enrolled_agents(platform);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_enrolled_by_user ON enrolled_agents(enrolled_by_user_id);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_management_mode ON enrolled_agents(management_mode);

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

CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    VARCHAR(128) UNIQUE NOT NULL,
    description   VARCHAR(255),
    created_by    VARCHAR(255),
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    used_by_agent VARCHAR(64),
    revoked       BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON agent_enrollment_tokens(token_hash);

-- AI agent children (complete the cluster v42 left half-created) -------------
CREATE TABLE IF NOT EXISTS ai_agent_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'api_key',
    key_prefix VARCHAR(12),
    key_hash VARCHAR(128) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    rotated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_agent_creds_agent ON ai_agent_credentials(agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_creds_hash ON ai_agent_credentials(key_hash);

CREATE TABLE IF NOT EXISTS ai_agent_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    actions TEXT[] NOT NULL DEFAULT '{}',
    conditions JSONB DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_agent_perms_agent ON ai_agent_permissions(agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_agent_perms_resource ON ai_agent_permissions(resource_type, resource_id);

CREATE TABLE IF NOT EXISTS ai_agent_activity (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    outcome VARCHAR(50) NOT NULL DEFAULT 'success',
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(45),
    duration_ms INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_agent_activity_agent ON ai_agent_activity(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_agent_activity_time ON ai_agent_activity(created_at DESC);

-- AI recommendations --------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_type VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    impact VARCHAR(20) NOT NULL DEFAULT 'medium',
    effort VARCHAR(20) NOT NULL DEFAULT 'medium',
    affected_entities JSONB DEFAULT '[]',
    suggested_action JSONB DEFAULT '{}',
    supporting_data JSONB DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    dismissed_reason TEXT,
    applied_at TIMESTAMP WITH TIME ZONE,
    applied_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_status ON ai_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_category ON ai_recommendations(category);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_impact ON ai_recommendations(impact);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_created ON ai_recommendations(created_at DESC);

CREATE TABLE IF NOT EXISTS recommendation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id UUID NOT NULL REFERENCES ai_recommendations(id) ON DELETE CASCADE,
    previous_status VARCHAR(50),
    new_status VARCHAR(50) NOT NULL,
    changed_by UUID REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recommendation_history_rec ON recommendation_history(recommendation_id, created_at DESC);

-- Notification digests ------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_digests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    digest_type VARCHAR(50) NOT NULL DEFAULT 'daily',
    channel VARCHAR(50) NOT NULL DEFAULT 'email',
    last_sent_at TIMESTAMP WITH TIME ZONE,
    next_scheduled_at TIMESTAMP WITH TIME ZONE,
    notification_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, digest_type, channel)
);
CREATE INDEX IF NOT EXISTS idx_digests_user ON notification_digests(user_id);
CREATE INDEX IF NOT EXISTS idx_digests_next ON notification_digests(next_scheduled_at, enabled);
`

var agentRecoDigestDown = `-- Migration 043 down.
DROP TABLE IF EXISTS notification_digests;
DROP TABLE IF EXISTS recommendation_history;
DROP TABLE IF EXISTS ai_recommendations;
DROP TABLE IF EXISTS ai_agent_activity;
DROP TABLE IF EXISTS ai_agent_permissions;
DROP TABLE IF EXISTS ai_agent_credentials;
DROP TABLE IF EXISTS agent_enrollment_tokens;
DROP TABLE IF EXISTS agent_posture_results;
DROP TABLE IF EXISTS enrolled_agents;
`
