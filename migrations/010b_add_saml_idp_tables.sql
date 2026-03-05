-- OpenIDX SAML 2.0 IdP Tables Migration
-- Version: 010
-- Description: Tables for SAML 2.0 Identity Provider functionality

-- ============================================================================
-- SAML SERVICE PROVIDERS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS saml_service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    entity_id VARCHAR(500) UNIQUE NOT NULL,
    acs_url VARCHAR(500) NOT NULL,
    slo_url VARCHAR(500),
    metadata_url VARCHAR(500),
    metadata_xml TEXT,
    certificate TEXT,
    name_id_format VARCHAR(255) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mappings JSONB,
    want_assertions_signed BOOLEAN DEFAULT false,
    encryption_enabled BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

-- ============================================================================
-- SAML SESSIONS TABLE
-- ============================================================================

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

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- SP indexes
CREATE INDEX IF NOT EXISTS idx_saml_service_providers_entity_id ON saml_service_providers(entity_id);
CREATE INDEX IF NOT EXISTS idx_saml_service_providers_enabled ON saml_service_providers(enabled);
CREATE INDEX IF NOT EXISTS idx_saml_service_providers_name ON saml_service_providers(name);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_saml_sessions_user_id ON saml_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_sp_entity_id ON saml_sessions(sp_entity_id);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_session_index ON saml_sessions(session_index);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_expires_at ON saml_sessions(expires_at);

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE saml_service_providers IS 'Registered SAML 2.0 Service Providers for the IdP';
COMMENT ON TABLE saml_sessions IS 'Active SAML sessions for single logout tracking';

COMMENT ON COLUMN saml_service_providers.entity_id IS 'The unique SAML entity ID of the service provider';
COMMENT ON COLUMN saml_service_providers.acs_url IS 'Assertion Consumer Service URL where SAML responses are sent';
COMMENT ON COLUMN saml_service_providers.slo_url IS 'Single Logout Service URL (optional)';
COMMENT ON COLUMN saml_service_providers.certificate IS 'X.509 certificate used by the SP for signature verification';
COMMENT ON COLUMN saml_service_providers.attribute_mappings IS 'Custom mapping of user attributes to SAML attributes';
COMMENT ON COLUMN saml_service_providers.want_assertions_signed IS 'Whether the SP requires signed assertions';

COMMENT ON COLUMN saml_sessions.session_index IS 'Unique session identifier for SAML logout';
COMMENT ON COLUMN saml_sessions.name_id IS 'The NameID value for the user in this session';
COMMENT ON COLUMN saml_sessions.name_id_format IS 'The format of the NameID (email, persistent, transient)';
