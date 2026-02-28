-- Rollback: Audit Stream Configuration
-- Description: Removes tables created for audit stream WebSocket configuration

DROP VIEW IF EXISTS audit_stream_security_summary CASCADE;
DROP VIEW IF EXISTS active_audit_stream_sessions CASCADE;
DROP FUNCTION IF EXISTS cleanup_old_audit_stream_security_events() CASCADE;

DROP TABLE IF EXISTS audit_stream_security_events CASCADE;
DROP TABLE IF EXISTS audit_stream_sessions CASCADE;
DROP TABLE IF EXISTS audit_stream_config CASCADE;
