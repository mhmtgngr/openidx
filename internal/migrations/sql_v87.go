package migrations

// Migration v87 — per-user Guacamole identities (PAM broker hardening).
//
// Today every PAM session is brokered through the shared Guacamole admin account,
// and the browser receives that admin token — a user could lift it from DevTools
// and drive the Guacamole admin API. This adds standing NON-admin Guacamole
// accounts (one per OpenIDX user per broker) so the browser token is scoped to a
// single connection. guac_password_enc holds the account's random password,
// AES-256-GCM encrypted via secretcrypt (encv1: tag; plaintext passthrough when
// no key). pam_entry_sessions.guac_username records which per-user account
// brokered each session so its READ grant can be revoked at session end.
// Additive/idempotent; RLS org-scope belt mirrors pam_entry_sessions (v37 style).
var guacPerUserUp = `-- Migration 087: per-user Guacamole identities.
CREATE TABLE IF NOT EXISTS guacamole_users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    user_id           UUID NOT NULL,
    broker            VARCHAR(32) NOT NULL,
    guac_username     VARCHAR(255) NOT NULL,
    guac_password_enc TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (broker, user_id)
);
CREATE INDEX IF NOT EXISTS idx_guacamole_users_user ON guacamole_users(user_id);

DROP POLICY IF EXISTS pol_guacamole_users_org_scope ON guacamole_users;
CREATE POLICY pol_guacamole_users_org_scope ON guacamole_users
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE guacamole_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_users FORCE  ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_users TO openidx_app;

ALTER TABLE pam_entry_sessions ADD COLUMN IF NOT EXISTS guac_username VARCHAR(255);`

var guacPerUserDown = `-- Rollback 087.
ALTER TABLE pam_entry_sessions DROP COLUMN IF EXISTS guac_username;
DROP TABLE IF EXISTS guacamole_users CASCADE;`
