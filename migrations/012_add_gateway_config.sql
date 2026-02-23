-- Migration: Add gateway configuration and rate limiting
-- Description: Creates tables for API gateway configuration and rate limiting
-- Version: 012

-- Create gateway_services table for service discovery
CREATE TABLE IF NOT EXISTS gateway_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    base_url VARCHAR(500) NOT NULL,
    health_check_url VARCHAR(500),
    timeout_seconds INTEGER DEFAULT 30,
    retry_attempts INTEGER DEFAULT 3,
    circuit_breaker_threshold INTEGER DEFAULT 5,
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Create index on service name
CREATE INDEX IF NOT EXISTS idx_gateway_services_name ON gateway_services(name);
CREATE INDEX IF NOT EXISTS idx_gateway_services_is_active ON gateway_services(is_active);

-- Create gateway_routes table for route configuration
CREATE TABLE IF NOT EXISTS gateway_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id UUID REFERENCES gateway_services(id) ON DELETE CASCADE,
    path_pattern VARCHAR(500) NOT NULL,
    methods VARCHAR(50)[] NOT NULL DEFAULT ARRAY['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    require_auth BOOLEAN DEFAULT true NOT NULL,
    require_mfa BOOLEAN DEFAULT false NOT NULL,
    rate_limit_enabled BOOLEAN DEFAULT true NOT NULL,
    rate_limit_per_minute INTEGER DEFAULT 100,
    allowed_roles VARCHAR(100)[],
    strip_prefix BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create indexes for route lookups
CREATE INDEX IF NOT EXISTS idx_gateway_routes_service_id ON gateway_routes(service_id);
CREATE INDEX IF NOT EXISTS idx_gateway_routes_path_pattern ON gateway_routes(path_pattern);
CREATE INDEX IF NOT EXISTS idx_gateway_routes_methods ON gateway_routes USING GIN(methods);

-- Create gateway_rate_limits table for rate limiting tracking
CREATE TABLE IF NOT EXISTS gateway_rate_limits (
    id BIGSERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    request_count INTEGER DEFAULT 1 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create index for rate limit lookups
CREATE INDEX IF NOT EXISTS idx_gateway_rate_limits_identifier ON gateway_rate_limits(identifier, service_name, window_start);
CREATE INDEX IF NOT EXISTS idx_gateway_rate_limits_window_start ON gateway_rate_limits(window_start);

-- Create gateway_api_keys table for API key authentication
CREATE TABLE IF NOT EXISTS gateway_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    user_id UUID,
    service_account_id UUID,
    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_active BOOLEAN DEFAULT true NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    created_by UUID REFERENCES admin_users(id) ON DELETE SET NULL
);

-- Create indexes for API key lookups
CREATE INDEX IF NOT EXISTS idx_gateway_api_keys_key_hash ON gateway_api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_gateway_api_keys_key_prefix ON gateway_api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_gateway_api_keys_user_id ON gateway_api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_gateway_api_keys_service_account_id ON gateway_api_keys(service_account_id);
CREATE INDEX IF NOT EXISTS idx_gateway_api_keys_is_active ON gateway_api_keys(is_active, expires_at);

-- Create gateway_access_logs table for access logging
CREATE TABLE IF NOT EXISTS gateway_access_logs (
    id BIGSERIAL PRIMARY KEY,
    correlation_id VARCHAR(100),
    request_id VARCHAR(100),
    service_name VARCHAR(100),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(500) NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER,
    client_ip INET,
    user_id UUID,
    user_agent TEXT,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create indexes for log queries and partitioning
CREATE INDEX IF NOT EXISTS idx_gateway_access_logs_correlation_id ON gateway_access_logs(correlation_id);
CREATE INDEX IF NOT EXISTS idx_gateway_access_logs_service_name ON gateway_access_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_gateway_access_logs_status_code ON gateway_access_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_gateway_access_logs_created_at ON gateway_access_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_access_logs_user_id ON gateway_access_logs(user_id);

-- Create gateway_cache_config table for response caching
CREATE TABLE IF NOT EXISTS gateway_cache_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id UUID REFERENCES gateway_services(id) ON DELETE CASCADE,
    path_pattern VARCHAR(500) NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    cache_by_user BOOLEAN DEFAULT false,
    cache_by_headers TEXT[],
    allowed_methods VARCHAR(50)[] DEFAULT ARRAY['GET'],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

-- Create index for cache config lookups
CREATE INDEX IF NOT EXISTS idx_gateway_cache_config_service_id ON gateway_cache_config(service_id);
CREATE INDEX IF NOT EXISTS idx_gateway_cache_config_path_pattern ON gateway_cache_config(path_pattern);

-- Create function to clean up old rate limit records
CREATE OR REPLACE FUNCTION cleanup_old_rate_limits()
RETURNS void AS $$
BEGIN
    DELETE FROM gateway_rate_limits
    WHERE window_start < NOW() - INTERVAL '1 hour';
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up old access logs (optional, for retention)
CREATE OR REPLACE FUNCTION cleanup_old_access_logs(retention_days INTEGER DEFAULT 30)
RETURNS void AS $$
BEGIN
    DELETE FROM gateway_access_logs
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
END;
$$ LANGUAGE plpgsql;

-- Insert default gateway services
INSERT INTO gateway_services (name, base_url, health_check_url) VALUES
    ('identity', 'http://identity-service:8501', '/health'),
    ('oauth', 'http://oauth-service:8502', '/health'),
    ('governance', 'http://governance-service:8503', '/health'),
    ('audit', 'http://audit-service:8504', '/health'),
    ('admin', 'http://admin-api:8505', '/health'),
    ('risk', 'http://risk-service:8506', '/health')
ON CONFLICT (name) DO NOTHING;

-- Insert default gateway routes
INSERT INTO gateway_routes (service_id, path_pattern, methods, require_auth)
SELECT
    s.id,
    CASE s.name
        WHEN 'identity' THEN '/api/v1/identity'
        WHEN 'oauth' THEN '/api/v1/oauth'
        WHEN 'governance' THEN '/api/v1/governance'
        WHEN 'audit' THEN '/api/v1/audit'
        WHEN 'admin' THEN '/api/v1/admin'
        WHEN 'risk' THEN '/api/v1/risk'
    END,
    ARRAY['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    CASE s.name
        WHEN 'oauth' THEN false  -- OAuth has public endpoints
        ELSE true
    END
FROM gateway_services s
WHERE s.is_active = true
ON CONFLICT DO NOTHING;

-- Create views for common queries
CREATE OR REPLACE VIEW gateway_services_with_health AS
SELECT
    s.id,
    s.name,
    s.base_url,
    s.health_check_url,
    s.is_active,
    s.timeout_seconds,
    s.retry_attempts,
    COUNT(DISTINCT r.id) as route_count
FROM gateway_services s
LEFT JOIN gateway_routes r ON r.service_id = s.id
GROUP BY s.id;

CREATE OR REPLACE VIEW gateway_rate_limit_stats AS
SELECT
    service_name,
    window_start,
    COUNT(*) as total_requests,
    COUNT(DISTINCT identifier) as unique_identifiers,
    MAX(request_count) as max_requests_per_identifier
FROM gateway_rate_limits
WHERE window_start > NOW() - INTERVAL '1 hour'
GROUP BY service_name, window_start
ORDER BY window_start DESC;

-- Add comments for documentation
COMMENT ON TABLE gateway_services IS 'Configuration for backend services that the gateway proxies to';
COMMENT ON TABLE gateway_routes IS 'Route configuration for API endpoints';
COMMENT ON TABLE gateway_rate_limits IS 'Rate limiting tracking data (sliding window)';
COMMENT ON TABLE gateway_api_keys IS 'API keys for service-to-service authentication';
COMMENT ON TABLE gateway_access_logs IS 'Access logs for all requests through the gateway';
COMMENT ON TABLE gateway_cache_config IS 'Cache configuration for gateway responses';

-- Enable automatic cleanup of old rate limit data (run via cron/scheduler)
-- SELECT cleanup_old_rate_limits();
