-- Migration: WebAuthn Credentials Table (for passwordless authentication)
-- Description: Creates table for storing FIDO2/WebAuthn credentials for passwordless authentication
--              This is for the market feature FR-M006

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
    registration_ip VARCHAR(45),
    registration_user_agent TEXT,
    device_fingerprint VARCHAR(255),
    is_passkey BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255),
    UNIQUE(user_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_aaguid ON webauthn_credentials(aaguid);

COMMENT ON TABLE webauthn_credentials IS 'FIDO2/WebAuthn credentials for passwordless authentication (FR-M006)';
