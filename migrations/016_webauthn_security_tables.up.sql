-- Migration: WebAuthn Security Hardening
-- Description: Creates proper WebAuthn tables for security-hardened credential management
--              This migration addresses critical security vulnerabilities by adding:
--              1. Proper WebAuthn credentials table with all required fields
--              2. WebAuthn session storage for challenge management
--              3. Audit trail for WebAuthn operations
--              4. Device binding for additional security

-- ============================================================================
-- WebAuthn Credentials Table (Primary table for FIDO2/Passkey credentials)
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id TEXT UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL DEFAULT 'none',
    aaguid BYTEA NOT NULL DEFAULT ('\x00000000000000000000000000000000'::BYTEA),
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT[] DEFAULT '{}',
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_handle BYTEA NOT NULL,
    friendly_name VARCHAR(255) DEFAULT 'Security Key',
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    -- Security columns for tracking and audit
    registration_ip VARCHAR(45),
    registration_user_agent TEXT,
    device_fingerprint VARCHAR(255),
    is_passkey BOOLEAN DEFAULT false,
    -- Soft delete support
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255),
    UNIQUE(user_id, credential_id)
);

-- Indexes for performance and security queries
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_aaguid ON webauthn_credentials(aaguid);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_handle ON webauthn_credentials(user_handle);

-- ============================================================================
-- WebAuthn Session Storage (Challenge management)
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_sessions (
    session_key TEXT PRIMARY KEY,
    session_data JSONB NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- Security tracking
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at);

-- ============================================================================
-- WebAuthn Audit Log (Security event tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT,
    event_type VARCHAR(50) NOT NULL, -- registration, login, deletion, rename, suspicious_activity
    event_status VARCHAR(20) NOT NULL, -- success, failure, blocked
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_audit_user_id ON webauthn_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_audit_event_type ON webauthn_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_webauthn_audit_created_at ON webauthn_audit_log(created_at);

-- ============================================================================
-- Security: Failed authentication attempt tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_failed_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    failure_reason VARCHAR(100) NOT NULL,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_failed_user_id ON webauthn_failed_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_failed_ip_address ON webauthn_failed_attempts(ip_address);

-- ============================================================================
-- Views for security monitoring
-- ============================================================================

-- Active credentials per user (excludes revoked)
CREATE OR REPLACE VIEW active_webauthn_credentials AS
SELECT
    id,
    user_id,
    credential_id,
    friendly_name,
    attestation_type,
    is_passkey,
    backup_eligible,
    backup_state,
    created_at,
    last_used_at
FROM webauthn_credentials
WHERE revoked_at IS NULL
ORDER BY created_at DESC;

-- WebAuthn security summary per user
CREATE OR REPLACE VIEW user_webauthn_security_summary AS
SELECT
    u.id AS user_id,
    u.username,
    u.email,
    COUNT(wc.id) AS total_credentials,
    COUNT(wc.id) FILTER (WHERE wc.is_passkey = true) AS passkey_count,
    COUNT(wc.id) FILTER (WHERE wc.is_passkey = false) AS security_key_count,
    MAX(wc.last_used_at) AS last_used_at,
    COUNT(DISTINCT wc.registration_ip) AS distinct_registration_ips,
    COUNT(fa.id) AS recent_failed_attempts
FROM users u
LEFT JOIN webauthn_credentials wc ON u.id = wc.user_id AND wc.revoked_at IS NULL
LEFT JOIN webauthn_failed_attempts fa ON u.id = fa.user_id AND fa.attempted_at > NOW() - INTERVAL '1 hour'
GROUP BY u.id, u.username, u.email;

-- Suspicious activity detection view
CREATE OR REPLACE VIEW webauthn_suspicious_activity AS
SELECT
    user_id,
    ip_address,
    COUNT(*) AS failed_count,
    MAX(attempted_at) AS last_attempt
FROM webauthn_failed_attempts
WHERE attempted_at > NOW() - INTERVAL '24 hours'
GROUP BY user_id, ip_address
HAVING COUNT(*) >= 5;

-- ============================================================================
-- Comments for documentation
-- ============================================================================
COMMENT ON TABLE webauthn_credentials IS 'FIDO2/WebAuthn credentials with security audit fields';
COMMENT ON TABLE webauthn_sessions IS 'WebAuthn ceremony session data (challenges) with expiration';
COMMENT ON TABLE webauthn_audit_log IS 'Audit trail for all WebAuthn security events';
COMMENT ON TABLE webauthn_failed_attempts IS 'Failed WebAuthn authentication attempts for rate limiting and anomaly detection';

COMMENT ON COLUMN webauthn_credentials.device_fingerprint IS 'Device fingerprint for additional security validation';
COMMENT ON COLUMN webauthn_credentials.is_passkey IS 'Indicates if this is a passkey (syncable) vs security key';
COMMENT ON COLUMN webauthn_credentials.revoked_at IS 'Soft delete timestamp - credentials are kept for audit';
COMMENT ON COLUMN webauthn_audit_log.event_type IS 'Type of event: registration, authentication, deletion, rename, suspicious_activity';
COMMENT ON COLUMN webauthn_audit_log.event_status IS 'Status: success, failure, blocked';

-- ============================================================================
-- Trigger for automatic audit logging on credential changes
-- ============================================================================
CREATE OR REPLACE FUNCTION webauthn_audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO webauthn_audit_log (user_id, credential_id, event_type, event_status, ip_address, user_agent, device_fingerprint)
        VALUES (NEW.user_id, NEW.credential_id, 'registration', 'success', NEW.registration_ip, NEW.registration_user_agent, NEW.device_fingerprint);
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
            INSERT INTO webauthn_audit_log (user_id, credential_id, event_type, event_status, details)
            VALUES (NEW.user_id, NEW.credential_id, 'deletion', 'success', jsonb_build_object('reason', NEW.revoked_reason));
        ELSIF OLD.friendly_name != NEW.friendly_name THEN
            INSERT INTO webauthn_audit_log (user_id, credential_id, event_type, event_status, details)
            VALUES (NEW.user_id, NEW.credential_id, 'rename', 'success', jsonb_build_object('old_name', OLD.friendly_name, 'new_name', NEW.friendly_name));
        END IF;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER webauthn_audit_trigger
    AFTER INSERT OR UPDATE ON webauthn_credentials
    FOR EACH ROW EXECUTE FUNCTION webauthn_audit_trigger_func();
