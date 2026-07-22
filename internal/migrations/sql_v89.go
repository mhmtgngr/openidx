package migrations

// Migration v89 — OAuth per-application user consent records.
//
// application_sso_settings.require_consent has existed as an admin-configurable
// flag but was never enforced: the authorization endpoint issued codes without
// ever showing a consent screen. This adds oauth_user_consents to record a
// user's grant of a set of scopes to a client, so consent can be enforced at
// authorization time and remembered across logins (re-prompt only when the
// requested scopes exceed what was previously granted). Org-scoped under the
// FORCE-RLS belt (v37 style). Additive/idempotent.
var oauthUserConsentsUp = `-- Migration 089: OAuth per-application user consent.
CREATE TABLE IF NOT EXISTS oauth_user_consents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    user_id     UUID NOT NULL,
    client_id   VARCHAR(255) NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, user_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_user_consents_user ON oauth_user_consents(user_id);

DROP POLICY IF EXISTS pol_oauth_user_consents_org_scope ON oauth_user_consents;
CREATE POLICY pol_oauth_user_consents_org_scope ON oauth_user_consents
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE oauth_user_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_user_consents FORCE  ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_user_consents TO openidx_app;`

var oauthUserConsentsDown = `-- Rollback 089.
DROP TABLE IF EXISTS oauth_user_consents;`
