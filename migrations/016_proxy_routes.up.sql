-- Migration 016: Zero Trust Access Proxy Routes

CREATE TABLE IF NOT EXISTS proxy_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    from_url VARCHAR(500) NOT NULL,
    to_url VARCHAR(500) NOT NULL,
    preserve_host BOOLEAN DEFAULT false,
    require_auth BOOLEAN DEFAULT true,
    allowed_roles JSONB,
    allowed_groups JSONB,
    policy_ids JSONB,
    idle_timeout INTEGER DEFAULT 900,
    absolute_timeout INTEGER DEFAULT 43200,
    cors_allowed_origins JSONB,
    custom_headers JSONB,
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxy_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    route_id UUID,
    session_token VARCHAR(500) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_proxy_routes_from_url ON proxy_routes(from_url);
CREATE INDEX IF NOT EXISTS idx_proxy_routes_enabled ON proxy_routes(enabled);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_user ON proxy_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_token ON proxy_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_proxy_sessions_expires ON proxy_sessions(expires_at);
