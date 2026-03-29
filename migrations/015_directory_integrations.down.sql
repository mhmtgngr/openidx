-- Rollback 015: Directory Integrations

DROP INDEX IF EXISTS idx_directory_integrations_type;
DROP TABLE IF EXISTS directory_integrations;
