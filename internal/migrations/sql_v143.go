package migrations

// Migration v143 — the sign-in tables: social providers and four per-user
// authentication records.
//
// `social_providers` is the live hole, and its list query is worth reading
// twice:
//
//	FROM social_providers sp
//	LEFT JOIN identity_providers ip ON sp.provider_id = ip.id AND ip.org_id = $1
//	ORDER BY sp.sort_order
//
// That names the caller's org, so it reads as scoped. It is not: the predicate
// sits inside a LEFT JOIN's ON clause, where it decides only whether the joined
// row contributes — it filters nothing on the driving table. Every tenant's
// social providers were listed to every tenant; all the org check did was blank
// out the `idp_name` column for the ones that belonged to somebody else. Get,
// update and delete then took a bare id with no org at all, so one tenant's
// admin could read another's provider configuration, edit it, or delete it —
// and `internal/oauth/social_policy.go` reads this table on the login path, so
// that changes which buttons another tenant's users see and which e-mail
// domains are allowed to auto-provision.
//
// `provider_key` was globally UNIQUE, the same shape as v138's
// `ispm_rules.check_type` and `ai_agents.name`: the first tenant to register
// `google` took the name for the whole install, and everybody else's create
// failed with a duplicate-key error they could do nothing about. It becomes
// UNIQUE(org_id, provider_key).
//
// The other four are per-user records that were already keyed by user_id, which
// is itself org-scoped — so this is depth, not a live hole, with two exceptions
// worth naming: trusted_browsers is updated by BARE id at two sites
// (`SET expires_at`, `SET last_used_at`), and phone_call_challenges.user_id is
// nullable, so a challenge with no user was in nobody's scope at all. Under the
// belt, both become impossible rather than merely unlikely.
//
// BACKFILL. social_providers derives its org from the identity provider it
// extends, falling back to the oldest org — provider_id was NOT NULL in the
// original v54 shape but v127 made it nullable, because the console's create
// flow supplies only a provider_key, so a row with no identity provider to
// inherit from is the normal case now, not an edge one. The per-user tables
// derive from their user, with the same fallback on the two whose user_id is
// nullable. No column DEFAULT anywhere.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var signinTenantScopeUp = `-- Migration 143: org_id + FORCE RLS on the sign-in tables.

-- social_providers ---------------------------------------------------------
ALTER TABLE social_providers ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- A social provider belongs to the org of the identity provider it extends.
UPDATE social_providers sp SET org_id = ip.org_id FROM identity_providers ip WHERE sp.provider_id = ip.id AND sp.org_id IS NULL;
-- An identity provider that has itself lost its org (pre-v69 rows).
UPDATE social_providers SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE social_providers ALTER COLUMN org_id SET NOT NULL;

-- provider_key was UNIQUE install-wide: the first tenant to register 'google'
-- took it from everybody else. The constraint name is the one Postgres
-- generates for the inline UNIQUE in the v54 CREATE TABLE.
ALTER TABLE social_providers DROP CONSTRAINT IF EXISTS social_providers_provider_key_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_social_providers_org_key ON social_providers(org_id, provider_key);
CREATE INDEX IF NOT EXISTS idx_social_providers_org ON social_providers(org_id);

DROP POLICY IF EXISTS pol_social_providers_org_scope ON social_providers;
CREATE POLICY pol_social_providers_org_scope ON social_providers
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE social_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE social_providers FORCE  ROW LEVEL SECURITY;

-- trusted_browsers ---------------------------------------------------------
ALTER TABLE trusted_browsers ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE trusted_browsers t SET org_id = u.org_id FROM users u WHERE t.user_id = u.id AND t.org_id IS NULL;

ALTER TABLE trusted_browsers ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_trusted_browsers_org ON trusted_browsers(org_id, user_id);

DROP POLICY IF EXISTS pol_trusted_browsers_org_scope ON trusted_browsers;
CREATE POLICY pol_trusted_browsers_org_scope ON trusted_browsers
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE trusted_browsers ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_browsers FORCE  ROW LEVEL SECURITY;

-- passwordless_preferences -------------------------------------------------
ALTER TABLE passwordless_preferences ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE passwordless_preferences p SET org_id = u.org_id FROM users u WHERE p.user_id = u.id AND p.org_id IS NULL;
-- user_id is nullable on this table; a preference row with no user belongs to
-- nobody and would keep a NULL org, which SET NOT NULL would reject.
UPDATE passwordless_preferences SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE passwordless_preferences ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_passwordless_prefs_org ON passwordless_preferences(org_id, user_id);

DROP POLICY IF EXISTS pol_passwordless_preferences_org_scope ON passwordless_preferences;
CREATE POLICY pol_passwordless_preferences_org_scope ON passwordless_preferences
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE passwordless_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE passwordless_preferences FORCE  ROW LEVEL SECURITY;

-- user_risk_baselines ------------------------------------------------------
ALTER TABLE user_risk_baselines ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE user_risk_baselines b SET org_id = u.org_id FROM users u WHERE b.user_id = u.id AND b.org_id IS NULL;

ALTER TABLE user_risk_baselines ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_user_risk_baselines_org ON user_risk_baselines(org_id);

DROP POLICY IF EXISTS pol_user_risk_baselines_org_scope ON user_risk_baselines;
CREATE POLICY pol_user_risk_baselines_org_scope ON user_risk_baselines
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE user_risk_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_risk_baselines FORCE  ROW LEVEL SECURITY;

-- phone_call_challenges ----------------------------------------------------
ALTER TABLE phone_call_challenges ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE phone_call_challenges c SET org_id = u.org_id FROM users u WHERE c.user_id = u.id AND c.org_id IS NULL;
-- user_id is nullable here: a challenge raised before the user is resolved had
-- no owner at all, which is precisely why it needed a tenant of its own.
UPDATE phone_call_challenges SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE phone_call_challenges ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_phone_challenges_org ON phone_call_challenges(org_id, user_id);

DROP POLICY IF EXISTS pol_phone_call_challenges_org_scope ON phone_call_challenges;
CREATE POLICY pol_phone_call_challenges_org_scope ON phone_call_challenges
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE phone_call_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE phone_call_challenges FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON social_providers, trusted_browsers, passwordless_preferences, user_risk_baselines, phone_call_challenges TO openidx_app;
`

// Down drops the belt and the column, and restores the install-wide
// provider_key uniqueness so a rolled-back binary sees the constraint it was
// written against. The backfill is not reversed: the rows it attributed had no
// org before, and a re-apply cannot reconstruct an attribution once the user or
// identity provider it was derived from is gone.
var signinTenantScopeDown = `-- Rollback 143.

ALTER TABLE social_providers          NO FORCE ROW LEVEL SECURITY;
ALTER TABLE social_providers          DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_social_providers_org_scope ON social_providers;
DROP INDEX IF EXISTS idx_social_providers_org_key;
DROP INDEX IF EXISTS idx_social_providers_org;
ALTER TABLE social_providers          DROP COLUMN IF EXISTS org_id;
ALTER TABLE social_providers          ADD CONSTRAINT social_providers_provider_key_key UNIQUE (provider_key);

ALTER TABLE trusted_browsers          NO FORCE ROW LEVEL SECURITY;
ALTER TABLE trusted_browsers          DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_trusted_browsers_org_scope ON trusted_browsers;
DROP INDEX IF EXISTS idx_trusted_browsers_org;
ALTER TABLE trusted_browsers          DROP COLUMN IF EXISTS org_id;

ALTER TABLE passwordless_preferences  NO FORCE ROW LEVEL SECURITY;
ALTER TABLE passwordless_preferences  DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_passwordless_preferences_org_scope ON passwordless_preferences;
DROP INDEX IF EXISTS idx_passwordless_prefs_org;
ALTER TABLE passwordless_preferences  DROP COLUMN IF EXISTS org_id;

ALTER TABLE user_risk_baselines       NO FORCE ROW LEVEL SECURITY;
ALTER TABLE user_risk_baselines       DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_user_risk_baselines_org_scope ON user_risk_baselines;
DROP INDEX IF EXISTS idx_user_risk_baselines_org;
ALTER TABLE user_risk_baselines       DROP COLUMN IF EXISTS org_id;

ALTER TABLE phone_call_challenges     NO FORCE ROW LEVEL SECURITY;
ALTER TABLE phone_call_challenges     DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_phone_call_challenges_org_scope ON phone_call_challenges;
DROP INDEX IF EXISTS idx_phone_challenges_org;
ALTER TABLE phone_call_challenges     DROP COLUMN IF EXISTS org_id;
`
