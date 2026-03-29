-- Rollback 026: Advanced Reporting Tables

DROP INDEX IF EXISTS idx_scheduled_reports_org;
DROP INDEX IF EXISTS idx_report_exports_org;
DROP TABLE IF EXISTS report_exports;
DROP TABLE IF EXISTS scheduled_reports;
