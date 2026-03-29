-- Rollback: WebSocket Security Events Extended
-- Description: Removes extended columns from audit_stream_security_events

DO $$
BEGIN
    -- Drop columns that were added in the up migration
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'threat_level'
    ) THEN
        ALTER TABLE audit_stream_security_events DROP COLUMN threat_level;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'blocked'
    ) THEN
        ALTER TABLE audit_stream_security_events DROP COLUMN blocked;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_stream_security_events'
        AND column_name = 'headers_snapshot'
    ) THEN
        ALTER TABLE audit_stream_security_events DROP COLUMN headers_snapshot;
    END IF;
END $$;

-- Drop indexes
DROP INDEX IF EXISTS idx_audit_stream_security_events_threat_level;
DROP INDEX IF EXISTS idx_audit_stream_security_events_blocked;
