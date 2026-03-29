-- Rollback 020: API Keys, Webhooks, Email Verification, Invitations

ALTER TABLE users DROP COLUMN IF EXISTS onboarding_completed;
DROP INDEX IF EXISTS idx_invitations_email;
DROP INDEX IF EXISTS idx_invitations_token;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS email_verification_tokens;
DROP INDEX IF EXISTS idx_webhook_deliveries_sub;
DROP INDEX IF EXISTS idx_webhook_deliveries_status;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_subscriptions;
DROP INDEX IF EXISTS idx_api_keys_sa;
DROP INDEX IF EXISTS idx_api_keys_user;
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS service_accounts;
