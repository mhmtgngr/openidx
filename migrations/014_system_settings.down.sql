-- Rollback 014: System Settings

DELETE FROM system_settings WHERE key IN ('system', 'mfa_methods', 'browzer_domain_config');
DROP TABLE IF EXISTS system_settings;
