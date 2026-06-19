package migrations

// Migration v42 — reconcile more init-db.sql-only / loose-SQL tables into the
// versioned migration set (same class as v38/v39/v40).
//
// On managed-RDS / Helm / `migrate` installs these tables were never created
// because their DDL lived only in deployments/docker/init-db.sql (abac_policies,
// ai_agents, certification_campaigns) or in loose, un-runnered files under
// migrations/ (saml_sessions in 010_add_saml_idp_tables.sql, remote_support_sessions
// in 202605150004_remote_support.up.sql). The result was 500s on the
// ABAC Policies, AI Agents, Certification Campaigns and Remote Support admin
// pages, plus continuous "relation saml_sessions does not exist" errors from the
// OAuth session-expiry worker. DDL is lifted verbatim from those authoritative
// sources; all statements are idempotent (IF NOT EXISTS), so this is a no-op on
// docker-compose installs.
//
// certification_campaigns additionally gains started_at/completed_at/total_items:
// the certification run code (internal/governance/certification.go) writes those
// columns but neither init-db.sql nor any migration ever created them, so a
// campaign "Run" 500'd everywhere. Added here as ADD COLUMN IF NOT EXISTS.
//
// Still NOT covered (no schema exists anywhere in the repo — genuinely
// unimplemented, tracked separately): agents (/api/v1/access/agents),
// recommendations (/api/v1/recommendations), notification_digest_settings.
var tableGapV42Up = `-- Migration 042: reconcile init-db.sql-only + loose-SQL tables.

-- Governance: ABAC policies -------------------------------------------------
CREATE TABLE IF NOT EXISTS abac_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    conditions JSONB NOT NULL DEFAULT '[]',
    effect VARCHAR(10) NOT NULL DEFAULT 'deny',
    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_abac_policies_resource ON abac_policies(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_abac_policies_enabled ON abac_policies(enabled);

-- Governance: certification campaigns ---------------------------------------
CREATE TABLE IF NOT EXISTS certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    reviewer_strategy VARCHAR(50) NOT NULL,
    reviewer_id UUID,
    reviewer_role VARCHAR(100),
    auto_revoke BOOLEAN DEFAULT false,
    grace_period_days INTEGER DEFAULT 7,
    duration_days INTEGER DEFAULT 30,
    status VARCHAR(50) DEFAULT 'active',
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_certification_campaigns_status ON certification_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_certification_campaigns_next_run ON certification_campaigns(next_run_at);
-- Columns the certification run code writes but no source ever created:
ALTER TABLE certification_campaigns ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE certification_campaigns ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE certification_campaigns ADD COLUMN IF NOT EXISTS total_items INTEGER DEFAULT 0;

-- AI agents -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    agent_type VARCHAR(50) NOT NULL DEFAULT 'assistant',
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    capabilities JSONB DEFAULT '[]',
    trust_level VARCHAR(20) NOT NULL DEFAULT 'low',
    rate_limits JSONB DEFAULT '{"requests_per_minute": 60, "requests_per_hour": 1000}',
    allowed_scopes TEXT[] DEFAULT '{}',
    ip_allowlist TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    last_active_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_agents_status ON ai_agents(status);
CREATE INDEX IF NOT EXISTS idx_ai_agents_owner ON ai_agents(owner_id);
CREATE INDEX IF NOT EXISTS idx_ai_agents_type ON ai_agents(agent_type);

-- OAuth: SAML SLO session tracking (loose file 010_add_saml_idp_tables.sql) --
CREATE TABLE IF NOT EXISTS saml_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL,
    sp_entity_id VARCHAR(500) NOT NULL,
    session_index VARCHAR(255) NOT NULL,
    name_id VARCHAR(500) NOT NULL,
    name_id_format VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(user_id, sp_entity_id, session_index)
);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_user_id ON saml_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_sp_entity_id ON saml_sessions(sp_entity_id);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_session_index ON saml_sessions(session_index);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_expires_at ON saml_sessions(expires_at);

-- Access: remote-support sessions (loose file 202605150004_remote_support) ---
CREATE TABLE IF NOT EXISTS remote_support_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           VARCHAR(64) NOT NULL,
    admin_user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    status             VARCHAR(16) NOT NULL DEFAULT 'pending',
    mode               VARCHAR(16) NOT NULL DEFAULT 'interactive',
    ice_servers        JSONB NOT NULL DEFAULT '[]'::jsonb,
    end_reason         VARCHAR(255),
    recording_url      VARCHAR(512),
    started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at        TIMESTAMPTZ,
    ended_at           TIMESTAMPTZ,
    notes              TEXT,
    last_activity_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_agent ON remote_support_sessions(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_admin ON remote_support_sessions(admin_user_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_active ON remote_support_sessions(status) WHERE status IN ('pending', 'active');
-- Recording columns (loose file 202605180001_remote_support_recording.up.sql),
-- SELECTed by the session list query.
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_storage_key VARCHAR(255);
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_size_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_chunk_count INT NOT NULL DEFAULT 0;
ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_finalized_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_remote_support_recordings_finalized ON remote_support_sessions(recording_finalized_at DESC) WHERE recording_finalized_at IS NOT NULL;

-- Recording legal holds (loose file 202605180003_recording_legal_hold.up.sql),
-- referenced by the remote-support session list query.
CREATE TABLE IF NOT EXISTS recording_legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL,
    reason          TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    placed_by       UUID,
    released_at     TIMESTAMPTZ,
    released_by     UUID,
    released_reason TEXT,
    CONSTRAINT recording_legal_holds_session_fk
        FOREIGN KEY (session_id) REFERENCES remote_support_sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_recording_legal_holds_lookup ON recording_legal_holds(session_id) WHERE released_at IS NULL;
`

var tableGapV42Down = `-- Migration 042 down.
DROP TABLE IF EXISTS recording_legal_holds;
DROP TABLE IF EXISTS remote_support_sessions;
DROP TABLE IF EXISTS saml_sessions;
DROP TABLE IF EXISTS ai_agents;
DROP TABLE IF EXISTS abac_policies;
ALTER TABLE certification_campaigns
    DROP COLUMN IF EXISTS started_at,
    DROP COLUMN IF EXISTS completed_at,
    DROP COLUMN IF EXISTS total_items;
DROP TABLE IF EXISTS certification_campaigns;
`
