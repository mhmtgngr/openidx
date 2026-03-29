-- Rollback 008: Audit and Compliance Tables

DROP TABLE IF EXISTS compliance_reports CASCADE;
DROP TABLE IF NOT EXISTS audit_events CASCADE;
