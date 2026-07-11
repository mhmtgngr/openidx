package migrations

// Migration v79 — oauth_signing_keys for DB-backed signing key rotation.
//
// Until now the OAuth service held exactly one RSA signing key (a
// system_settings row) hardcoded to kid "openidx-key-1", so keys could never
// be rotated without instantly invalidating every outstanding token. This
// table holds one active signing key plus retired keys that stay servable
// from JWKS until their not_after verification grace expires.
//
// Install-wide like system_settings (no org_id) — the signing key mints
// tokens for every tenant. private_key_pem is encrypted at rest by
// internal/signingkeys with the ENCRYPTION_KEY cipher. The partial unique
// index guarantees at most one active key and gives EnsureActive a race-safe
// ON CONFLICT target. Plain statements only — the runner's splitSQL cannot
// handle DO $$ blocks.
var oauthSigningKeysUp = `-- Migration 079: oauth_signing_keys (rotatable token signing keys).
CREATE TABLE IF NOT EXISTS oauth_signing_keys (
    kid VARCHAR(255) PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'retired')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMP WITH TIME ZONE,
    retired_at TIMESTAMP WITH TIME ZONE,
    not_after TIMESTAMP WITH TIME ZONE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_signing_keys_active ON oauth_signing_keys (status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_oauth_signing_keys_status ON oauth_signing_keys (status, not_after);`

var oauthSigningKeysDown = `-- Rollback 079
DROP TABLE IF EXISTS oauth_signing_keys;`
