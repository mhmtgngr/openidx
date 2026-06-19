package migrations

// Migration v44 — reconcile the Kiosk-policy and AI policy-recommendation /
// compliance-gap tables into the versioned migration set (final pass of the
// init-db↔migrations gap class, after v38–v43).
//
// Missing on managed-RDS/Helm/`migrate` installs because their DDL lived only
// outside the Go migration runner:
//   - kiosk_policies + kiosk_policy_assignments → loose file
//     migrations/202605150003_kiosk_policies.up.sql. Kiosk Policies page →
//     GET /api/v1/access/kiosk/policies (was 500ing).
//   - policy_recommendations + compliance_gaps → loose file
//     migrations/017_add_genai_and_advanced_auth_tables.up.sql. AI policy
//     suggestion / compliance-gap endpoints (internal/admin/ai_policy_recommendations.go).
//
// DDL is lifted verbatim from those sources; index DDL is made IF NOT EXISTS for
// idempotency. All statements are idempotent, so this is a no-op on docker-compose
// installs. Not org-scoped (matches source + handlers), consistent with v42/v43.
var kioskPolicyV44Up = `-- Migration 044: kiosk-policy + AI policy-recommendation / compliance-gap tables.

-- Kiosk policies ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kiosk_policies (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               VARCHAR(128) NOT NULL,
    description        TEXT,
    mode               VARCHAR(16) NOT NULL DEFAULT 'multi_app',
    allowed_packages   JSONB NOT NULL DEFAULT '[]'::jsonb,
    primary_activity   VARCHAR(255),
    lock_task_features JSONB NOT NULL DEFAULT '[]'::jsonb,
    branding           JSONB NOT NULL DEFAULT '{}'::jsonb,
    exit_pin_hash      VARCHAR(128),
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_kiosk_policies_enabled ON kiosk_policies(enabled) WHERE enabled = TRUE;

CREATE TABLE IF NOT EXISTS kiosk_policy_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID NOT NULL REFERENCES kiosk_policies(id) ON DELETE CASCADE,
    target_kind VARCHAR(16) NOT NULL,
    target_id   VARCHAR(128) NOT NULL,
    priority    INT NOT NULL DEFAULT 100,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (policy_id, target_kind, target_id)
);
CREATE INDEX IF NOT EXISTS idx_kiosk_assignments_target ON kiosk_policy_assignments(target_kind, target_id);

-- AI policy recommendations -------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(100) NOT NULL,
    priority VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    estimated_effort VARCHAR(50),
    confidence FLOAT NOT NULL,
    reasoning JSONB,
    affected_users INT DEFAULT 0,
    affected_roles INT DEFAULT 0,
    affected_resources JSONB,
    metadata JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    implemented_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_status ON policy_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_priority ON policy_recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_policy_recommendation_type ON policy_recommendations(type);

-- Compliance gaps -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS compliance_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    standard VARCHAR(100) NOT NULL,
    control_id VARCHAR(255) NOT NULL,
    control_name TEXT NOT NULL,
    current_state TEXT,
    desired_state TEXT,
    gap_description TEXT,
    remediation_plan TEXT,
    priority VARCHAR(50) NOT NULL,
    estimated_effort INT DEFAULT 0,
    due_date DATE,
    status VARCHAR(50) DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_standard ON compliance_gaps(standard);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_status ON compliance_gaps(status);
CREATE INDEX IF NOT EXISTS idx_compliance_gap_priority ON compliance_gaps(priority);
`

var kioskPolicyV44Down = `-- Migration 044 down.
DROP TABLE IF EXISTS compliance_gaps;
DROP TABLE IF EXISTS policy_recommendations;
DROP TABLE IF EXISTS kiosk_policy_assignments;
DROP TABLE IF EXISTS kiosk_policies;
`
