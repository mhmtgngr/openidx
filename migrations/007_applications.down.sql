-- Rollback 007: Application Management Tables

DROP TABLE IF EXISTS application_sso_settings CASCADE;
DROP TABLE IF NOT EXISTS applications CASCADE;
