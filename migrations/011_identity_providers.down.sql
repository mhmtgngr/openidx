-- Rollback 011: External Identity Providers

DROP INDEX IF EXISTS idx_users_external_id_idp_id;
DROP INDEX IF EXISTS idx_users_idp_id;
ALTER TABLE users DROP COLUMN IF EXISTS external_user_id;
ALTER TABLE users DROP COLUMN IF EXISTS idp_id;
DROP INDEX IF EXISTS idx_identity_providers_issuer_url;
DROP INDEX IF EXISTS idx_identity_providers_provider_type;
DROP INDEX IF EXISTS idx_identity_providers_name;
DROP TABLE IF EXISTS identity_providers;
