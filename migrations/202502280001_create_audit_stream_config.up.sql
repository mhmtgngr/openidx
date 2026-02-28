-- Migration: Audit Stream Configuration
-- Description: Creates tables for managing audit stream WebSocket configuration and security
--
-- This migration adds support for:
-- 1. Audit stream configuration storage (allowed origins, logging, max clients)
-- 2. WebSocket session tracking
-- 3. Security event logging for rejected connections

-- ============================================================================
-- Audit Stream Configuration Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_stream_config (
    id TEXT PRIMARY KEY,
    config_data JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default configuration
INSERT INTO audit_stream_config (id, config_data, updated_at, created_at)
VALUES (
    'default',
    '{
        "allowed_origins": [],
        "enable_logging": true,
        "max_clients": 100
    }'::jsonb,
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Audit Stream Sessions Table (Active WebSocket connections)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_stream_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id TEXT NOT NULL UNIQUE,
    client_id TEXT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    connected BOOLEAN DEFAULT true,
    origin TEXT,
    remote_addr TEXT,
    user_agent TEXT,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    disconnected_at TIMESTAMP WITH TIME ZONE,
    disconnect_reason TEXT,
    filters JSONB
);

-- Indexes for session queries
CREATE INDEX IF NOT EXISTS idx_audit_stream_sessions_connected ON audit_stream_sessions(connected) WHERE connected = true;
CREATE INDEX IF NOT EXISTS idx_audit_stream_sessions_user_id ON audit_stream_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_stream_sessions_origin ON audit_stream_sessions(origin);
CREATE INDEX IF NOT EXISTS idx_audit_stream_sessions_connected_at ON audit_stream_sessions(connected_at DESC);

-- ============================================================================
-- Audit Stream Security Events Table (Rejected connections, suspicious activity)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_stream_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL, -- connection_rejected, suspicious_activity, rate_limit_exceeded
    origin TEXT,
    remote_addr TEXT,
    real_ip TEXT, -- The real IP from X-Forwarded-For or X-Real-IP
    user_agent TEXT,
    request_uri TEXT,
    reason TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for security monitoring
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_event_type ON audit_stream_security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_created_at ON audit_stream_security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_origin ON audit_stream_security_events(origin);
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_real_ip ON audit_stream_security_events(real_ip);

-- Index for detecting rapid connection attempts from same IP
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_ip_time ON audit_stream_security_events(real_ip, created_at DESC);

-- ============================================================================
-- Comments for documentation
-- ============================================================================
COMMENT ON TABLE audit_stream_config IS 'Configuration for audit stream WebSocket connections (allowed origins, logging settings)';
COMMENT ON TABLE audit_stream_sessions IS 'Active and historical WebSocket session connections to the audit stream';
COMMENT ON TABLE audit_stream_security_events IS 'Security events related to audit stream (rejected connections, suspicious activity)';

COMMENT ON COLUMN audit_stream_sessions.filters IS 'Event filters applied to this stream session';
COMMENT ON COLUMN audit_stream_security_events.real_ip IS 'The real client IP extracted from X-Forwarded-For or X-Real-IP headers';
COMMENT ON COLUMN audit_stream_security_events.event_type IS 'Type of security event: connection_rejected, suspicious_activity, rate_limit_exceeded';

-- ============================================================================
-- View: Active WebSocket Sessions Summary
-- ============================================================================
CREATE OR REPLACE VIEW active_audit_stream_sessions AS
SELECT
    id,
    session_id,
    client_id,
    user_id,
    origin,
    remote_addr,
    connected_at,
    EXTRACT(EPOCH FROM (NOW() - connected_at)) / 60 AS session_minutes
FROM audit_stream_sessions
WHERE connected = true
ORDER BY connected_at DESC;

COMMENT ON VIEW active_audit_stream_sessions IS 'Summary of currently active WebSocket stream connections';

-- ============================================================================
-- View: Security Events Summary (last 24 hours)
-- ============================================================================
CREATE OR REPLACE VIEW audit_stream_security_summary AS
SELECT
    event_type,
    COUNT(*) AS event_count,
    COUNT(DISTINCT real_ip) AS unique_ips,
    MAX(created_at) AS last_event_at
FROM audit_stream_security_events
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY event_count DESC;

COMMENT ON VIEW audit_stream_security_summary IS 'Summary of security events in the last 24 hours';

-- ============================================================================
-- Trigger: Clean up old security events (older than 90 days)
-- ============================================================================
CREATE OR REPLACE FUNCTION cleanup_old_audit_stream_security_events()
RETURNS void AS $$
BEGIN
    DELETE FROM audit_stream_security_events
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Note: Schedule this function to run periodically via pg_cron or similar
COMMENT ON FUNCTION cleanup_old_audit_stream_security_events() IS 'Cleans up security events older than 90 days';
