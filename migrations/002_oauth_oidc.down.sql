-- Rollback 002: OAuth 2.0 / OIDC Tables

DROP TABLE IF EXISTS oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS oauth_access_tokens CASCADE;
DROP TABLE IF EXISTS oauth_authorization_codes CASCADE;
DROP TABLE IF EXISTS oauth_clients CASCADE;
