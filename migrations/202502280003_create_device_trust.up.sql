-- Migration: Device Trust Assessment Table
-- Description: Creates table for tracking trusted devices (FR-M008)
--              Supports device trust scoring for risk-based authentication

CREATE TABLE IF NOT EXISTS device_trust (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    trust_score INTEGER DEFAULT 50 CHECK (trust_score BETWEEN 0 AND 100),
    is_trusted BOOLEAN DEFAULT false,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_ip VARCHAR(45),
    authentication_count INTEGER DEFAULT 0,
    failed_auth_count INTEGER DEFAULT 0,
    suspicious_activity_count INTEGER DEFAULT 0,
    attributes JSONB DEFAULT '{}'::jsonb,
    UNIQUE(user_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_device_trust_user_id ON device_trust(user_id);
CREATE INDEX IF NOT EXISTS idx_device_trust_fingerprint ON device_trust(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_device_trust_is_trusted ON device_trust(is_trusted) WHERE is_trusted = true;

COMMENT ON TABLE device_trust IS 'Device trust assessment for risk-based authentication (FR-M008)';
COMMENT ON COLUMN device_trust.trust_score IS 'Trust score 0-100, higher is more trusted';
