-- Rollback 012: Provisioning Rules and Password Reset Tokens

DROP INDEX IF EXISTS idx_password_reset_tokens_user_id;
DROP INDEX IF EXISTS idx_password_reset_tokens_token;
DROP TABLE IF EXISTS password_reset_tokens;
DROP INDEX IF EXISTS idx_provisioning_rules_priority;
DROP INDEX IF EXISTS idx_provisioning_rules_enabled;
DROP INDEX IF EXISTS idx_provisioning_rules_trigger;
DROP TABLE IF EXISTS provisioning_rules;
