package migrations

// Migration v156 — the developer portal.
//
// Two tables. `developer_settings` holds the limits an administrator sets for
// API keys, webhooks, CORS and rate limiting. `oauth_playground_sessions` holds
// the PKCE material for the console's "try an OAuth flow" tool. v54 created
// both with no tenant column.
//
// ONE ROW FOR THE WHOLE INSTALLATION, KEYED ON A STRING LITERAL. The settings
// read and write are these, in full:
//
//	SELECT setting_value FROM developer_settings WHERE setting_key = 'global'
//
//	INSERT INTO developer_settings (setting_key, setting_value, updated_at)
//	VALUES ('global', $1, NOW())
//	ON CONFLICT (setting_key) DO UPDATE SET setting_value = $1, updated_at = NOW()
//
// `setting_key VARCHAR(100) UNIQUE NOT NULL`, and the key is the constant
// `'global'`. So there is exactly one settings row on the installation and
// every organization's administrators share it: the last one to press Save
// decides, for everybody, the maximum API keys per user, which scopes an API
// key may carry (the defaults include `write:users`, `write:applications` and
// `write:provisioning`), the webhook IP allowlist, the CORS allowed origins,
// the default rate limit, and whether sandbox mode is on. This is the third
// install-wide unique key this programme has found in two batches, after v155's
// `federation_rules.email_domain` and `identity_providers.issuer_url`, and the
// second time the key itself — not a missing predicate — was the whole defect.
// Re-scoped to (org_id, setting_key).
//
// AND NOTHING READS IT. A search of the tree finds `developer_settings` in its
// own two handlers, in this migration, and nowhere else. No API-key mint checks
// `APIKeyMaxPerUser` or `APIKeyAllowedScopes`; no CORS middleware consults
// `CORSAllowedOrigins`; no limiter reads `RateLimitDefault`. Which means the
// page presents six security limits, saves them, reads them back, and
// constrains nothing at all — and the cross-tenant write above is only as
// harmful as the settings are effective, which is not at all. That is the same
// shape as v155's `custom_claims_mappings`, and it is recorded rather than
// fixed here for the same reason: giving these values a consumer is a feature,
// and a scoping batch is the wrong place to smuggle one in.
//
// THE PLAYGROUND SESSION HOLDS THE SECRETS OF AN OAUTH FLOW. Its columns are
// `code_verifier` (the PKCE secret), `authorization_code`, `access_token` and
// `id_token`. The execute handler loads one by bare id:
//
//	SELECT id, state, code_verifier, ... FROM oauth_playground_sessions WHERE id = $1
//
// and neither playground handler calls `requireAdmin`, though every other
// handler in that file does. So a session's PKCE verifier — the thing that lets
// its authorization code be redeemed — was retrievable by id alone, with no
// tenant term, no owner term and no role check.
//
// The schema shows what was meant. v54 gave the table
// `user_id UUID REFERENCES users(id) ON DELETE CASCADE` and an index on it,
// `idx_playground_user`. The insert has never set that column and no read has
// ever used it: an index on a column that is always NULL, which is what an
// intention looks like after the code that would have honoured it was not
// written. Both handlers now set and check the owner as well as the tenant.
//
// BACKFILL. Settings rows go to the organization of whoever last updated them
// (`updated_by` -> users.org_id); playground sessions to their `user_id`'s
// organization, which in practice is nobody's, since the column was never
// written — those fall to the oldest organization, and they expire in fifteen
// minutes regardless.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var developerPortalScopeUp = `-- Migration 156: scope and belt the developer portal.

ALTER TABLE developer_settings        ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE oauth_playground_sessions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE developer_settings d SET org_id = u.org_id FROM users u WHERE u.id = d.updated_by AND d.org_id IS NULL;
UPDATE oauth_playground_sessions p SET org_id = u.org_id FROM users u WHERE u.id = p.user_id AND p.org_id IS NULL;

UPDATE developer_settings        SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE oauth_playground_sessions SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE developer_settings        ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE oauth_playground_sessions ALTER COLUMN org_id SET NOT NULL;

-- One settings row per installation becomes one per organization. The name is
-- the one Postgres generates for v54's inline UNIQUE.
ALTER TABLE developer_settings DROP CONSTRAINT IF EXISTS developer_settings_setting_key_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_developer_settings_org_key ON developer_settings(org_id, setting_key);

CREATE INDEX IF NOT EXISTS idx_playground_org_expiry ON oauth_playground_sessions(org_id, expires_at);

DROP POLICY IF EXISTS pol_developer_settings_org_scope ON developer_settings;
CREATE POLICY pol_developer_settings_org_scope ON developer_settings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE developer_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE developer_settings FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_oauth_playground_sessions_org_scope ON oauth_playground_sessions;
CREATE POLICY pol_oauth_playground_sessions_org_scope ON oauth_playground_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE oauth_playground_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_playground_sessions FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON developer_settings        TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_playground_sessions TO openidx_app;
`

// Down lifts the belt, drops the columns and restores v54's install-wide UNIQUE
// on setting_key. That restore is the statement that can fail: once more than
// one organization has saved developer settings — the point of the migration —
// there are several rows keyed 'global' and the single-column constraint cannot
// come back. Refusing is better than deleting somebody's settings to make a
// rollback succeed; the same trade v138 and v155 made.
var developerPortalScopeDown = `-- Rollback 156.

ALTER TABLE oauth_playground_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_playground_sessions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_oauth_playground_sessions_org_scope ON oauth_playground_sessions;

ALTER TABLE developer_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE developer_settings DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_developer_settings_org_scope ON developer_settings;

DROP INDEX IF EXISTS idx_playground_org_expiry;
DROP INDEX IF EXISTS idx_developer_settings_org_key;

ALTER TABLE oauth_playground_sessions DROP COLUMN IF EXISTS org_id;
ALTER TABLE developer_settings        DROP COLUMN IF EXISTS org_id;

ALTER TABLE developer_settings ADD CONSTRAINT developer_settings_setting_key_key UNIQUE (setting_key);
`
