-- Rollback 022: Security Alerts and Anomaly Detection

DELETE FROM audit_events WHERE details->>'username' = 'admin';
DROP INDEX IF EXISTS idx_ip_threat_list_ip;
DROP INDEX IF EXISTS idx_security_alerts_created;
DROP INDEX IF EXISTS idx_security_alerts_severity;
DROP INDEX IF EXISTS idx_security_alerts_status;
DROP INDEX IF EXISTS idx_security_alerts_user;
DROP TABLE IF EXISTS ip_threat_list;
DROP TABLE IF EXISTS security_alerts;
