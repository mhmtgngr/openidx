-- Migration 029: OpenZiti Enhanced Features

-- Device posture check types
CREATE TABLE IF NOT EXISTS posture_check_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Posture checks linked to Ziti
CREATE TABLE IF NOT EXISTS posture_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE,
    name VARCHAR(255) NOT NULL,
    check_type VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(50) DEFAULT 'medium',
    remediation_hint TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device posture results
CREATE TABLE IF NOT EXISTS device_posture_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID,
    check_id UUID,
    passed BOOLEAN NOT NULL,
    details JSONB DEFAULT '{}',
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_posture_results_identity ON device_posture_results(identity_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_results_check ON device_posture_results(check_id);

-- Policy sync state between governance and Ziti
CREATE TABLE IF NOT EXISTS policy_sync_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    governance_policy_id UUID NOT NULL,
    ziti_policy_id VARCHAR(255),
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    last_synced_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_sync_governance ON policy_sync_state(governance_policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_sync_status ON policy_sync_state(status);

-- Ziti certificate management
CREATE TABLE IF NOT EXISTS ziti_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    cert_data TEXT NOT NULL,
    private_key_encrypted TEXT,
    ca_chain TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    identity_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_certificates_identity ON ziti_certificates(identity_id);
CREATE INDEX IF NOT EXISTS idx_ziti_certificates_expires ON ziti_certificates(expires_at);
