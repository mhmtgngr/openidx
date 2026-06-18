package migrations

// Migration v39 — device-trust, trusted-browser and risk-policy tables.
//
// These four tables back the device-trust approval flow (device_trust_requests,
// device_trust_settings), the "trusted browsers" self-service feature
// (trusted_browsers), and risk policy management (risk_policies). Their handlers
// in internal/identity returned HTTP 500 on any managed-RDS/Helm/`migrate`
// deploy because the tables existed only in deployments/docker/init-db.sql
// (docker-compose), never in the versioned Go migration set — the same gap class
// that migration v38 closed for the tenant_* tables.
//
// DDL mirrors init-db.sql and is idempotent (CREATE TABLE/INDEX IF NOT EXISTS),
// so it is a no-op on clusters bootstrapped from init-db.sql.
//
// NOTE: a wider audit found ~70 further tables that live only in init-db.sql and
// not in the migrations; closing that whole gap (and reconciling init-db.sql's
// own internal inconsistencies, e.g. a duplicated lifecycle_executions
// definition) is tracked as separate follow-up work. This migration fixes the
// tables behind the 500s observed in the admin console.
var deviceTrustRiskUp = `-- Migration 039: device-trust / trusted-browser / risk-policy tables.
CREATE TABLE IF NOT EXISTS device_trust_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    justification TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,
    auto_expire_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_trust_requests_user ON device_trust_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_requests_status ON device_trust_requests(status);
CREATE INDEX IF NOT EXISTS idx_trust_requests_pending ON device_trust_requests(status) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS device_trust_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    require_approval BOOLEAN DEFAULT false,
    auto_approve_known_ips BOOLEAN DEFAULT false,
    auto_approve_corporate_devices BOOLEAN DEFAULT false,
    request_expiry_hours INTEGER DEFAULT 72,
    notify_admins BOOLEAN DEFAULT true,
    notify_user_on_decision BOOLEAN DEFAULT true,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trusted_browsers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_hash VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    trusted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    UNIQUE(user_id, browser_hash)
);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_user_id ON trusted_browsers(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_hash ON trusted_browsers(browser_hash);
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_active ON trusted_browsers(user_id, revoked, expires_at);

CREATE TABLE IF NOT EXISTS risk_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    conditions JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risk_policies_enabled ON risk_policies(enabled, priority);
`

var deviceTrustRiskDown = `-- Migration 039 down.
DROP TABLE IF EXISTS device_trust_requests;
DROP TABLE IF EXISTS device_trust_settings;
DROP TABLE IF EXISTS trusted_browsers;
DROP TABLE IF EXISTS risk_policies;
`
