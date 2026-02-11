-- Temporary Access Links for support/vendor access
-- Allows creating time-limited, secure access URLs

CREATE TABLE IF NOT EXISTS temp_access_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc')),
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    username VARCHAR(255),
    created_by UUID NOT NULL,
    created_by_email VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 0,
    current_uses INTEGER DEFAULT 0,
    allowed_ips TEXT[],
    require_mfa BOOLEAN DEFAULT FALSE,
    notify_on_use BOOLEAN DEFAULT FALSE,
    notify_email VARCHAR(255),
    route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
    guacamole_connection_id VARCHAR(255),
    access_url TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'used')),
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for token lookup (used when accessing the link)
CREATE INDEX IF NOT EXISTS idx_temp_access_token ON temp_access_links(token);

-- Index for status filtering
CREATE INDEX IF NOT EXISTS idx_temp_access_status ON temp_access_links(status);

-- Index for expiration cleanup
CREATE INDEX IF NOT EXISTS idx_temp_access_expires ON temp_access_links(expires_at);

-- Index for created_by (user's links)
CREATE INDEX IF NOT EXISTS idx_temp_access_created_by ON temp_access_links(created_by);


-- Temp Access Usage tracking
CREATE TABLE IF NOT EXISTS temp_access_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id UUID NOT NULL REFERENCES temp_access_links(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE
);

-- Index for link usage history
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_link ON temp_access_usage(link_id);

-- Index for usage time range queries
CREATE INDEX IF NOT EXISTS idx_temp_access_usage_time ON temp_access_usage(connected_at);


-- Function to auto-expire links
CREATE OR REPLACE FUNCTION expire_temp_access_links()
RETURNS void AS $$
BEGIN
    UPDATE temp_access_links
    SET status = 'expired', updated_at = CURRENT_TIMESTAMP
    WHERE status = 'active' AND expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Comment for documentation
COMMENT ON TABLE temp_access_links IS 'Temporary access links for support/vendor access with time limits and usage tracking';
COMMENT ON TABLE temp_access_usage IS 'Usage history for temporary access links';
