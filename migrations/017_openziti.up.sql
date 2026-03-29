-- Migration 017: OpenZiti Integration

ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_enabled BOOLEAN DEFAULT false;
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_service_name VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_proxy_routes_ziti_enabled ON proxy_routes(ziti_enabled);

CREATE TABLE IF NOT EXISTS ziti_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    protocol VARCHAR(20) DEFAULT 'tcp',
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    route_id UUID,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) UNIQUE NOT NULL,
    identity_type VARCHAR(50) DEFAULT 'Device',
    user_id UUID,
    enrollment_jwt TEXT,
    enrolled BOOLEAN DEFAULT false,
    attributes JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(10) NOT NULL,
    service_roles JSONB DEFAULT '[]',
    identity_roles JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ziti_services_name ON ziti_services(name);
CREATE INDEX IF NOT EXISTS idx_ziti_services_route_id ON ziti_services(route_id);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_user_id ON ziti_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_ziti_identities_name ON ziti_identities(name);

-- Seed: Register access-proxy as an OAuth client
INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
VALUES (
    'access-proxy',
    '',
    'Zero Trust Access Proxy',
    'public',
    '["http://localhost:8007/access/.auth/callback", "http://localhost:8088/access/.auth/callback", "http://demo.localtest.me:8088/access/.auth/callback"]'::jsonb,
    '["authorization_code", "refresh_token"]'::jsonb,
    '["code"]'::jsonb,
    '["openid", "profile", "email"]'::jsonb,
    true
) ON CONFLICT (client_id) DO NOTHING;
