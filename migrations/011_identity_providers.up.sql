-- Migration 011: External Identity Providers (OIDC/SAML)

CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    issuer_url VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    scopes JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identity_providers_name ON identity_providers(name);
CREATE INDEX IF NOT EXISTS idx_identity_providers_provider_type ON identity_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_identity_providers_issuer_url ON identity_providers(issuer_url);

-- Add IdP columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_user_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_idp_id ON users(idp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id_idp_id ON users(idp_id, external_user_id) WHERE idp_id IS NOT NULL;

COMMENT ON TABLE identity_providers IS 'Configuration for external OIDC/SAML identity providers for SSO';
COMMENT ON COLUMN users.idp_id IS 'Foreign key to the identity provider that provisioned this user';
COMMENT ON COLUMN users.external_user_id IS 'The user''s unique ID from the external identity provider';
