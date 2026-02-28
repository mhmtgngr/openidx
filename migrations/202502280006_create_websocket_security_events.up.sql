-- Migration: WebSocket Security Events Extended
-- Description: Extends security event tracking for WebSocket connections
--              This is a continuation of the first migration for backward compatibility

-- Note: The main audit_stream_security_events table was created in migration 202502280001
-- This migration adds additional columns for enhanced security monitoring

-- Add enhanced security columns if they don't exist
DO $$
BEGIN
    -- Check if column exists before adding
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'threat_level'
    ) THEN
        ALTER TABLE audit_stream_security_events
        ADD COLUMN threat_level VARCHAR(20) DEFAULT 'low'; -- low, medium, high, critical
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'blocked'
    ) THEN
        ALTER TABLE audit_stream_security_events
        ADD COLUMN blocked BOOLEAN DEFAULT false;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'headers_snapshot'
    ) THEN
        ALTER TABLE audit_stream_security_events
        ADD COLUMN headers_snapshot JSONB;
    END IF;
END $$;

-- Create index for threat level queries
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_threat_level
ON audit_stream_security_events(threat_level) WHERE threat_level IN ('high', 'critical');

-- Create index for blocked events
CREATE INDEX IF NOT EXISTS idx_audit_stream_security_events_blocked
ON audit_stream_security_events(blocked, created_at DESC) WHERE blocked = true;

COMMENT ON COLUMN audit_stream_security_events.threat_level IS 'Threat level assessment: low, medium, high, critical';
COMMENT ON COLUMN audit_stream_security_events.blocked IS 'Whether the connection was blocked';
COMMENT ON COLUMN audit_stream_security_events.headers_snapshot IS 'Snapshot of request headers for forensic analysis';
