package migrations

// Migration v157 — the admin console's own settings, and a risk engine reading
// a table nobody writes.
//
// Both tables here are from v62, which created four tables the Go code
// referenced and no migration had ever created, so their endpoints 500ed. Its
// own note says what it left undone: "Not under the v37 FORCE-RLS belt: the
// code does not org-scope these (no org_id in any query) ... org_id/RLS is a
// separate hardening follow-up." The other two of the four, breach_incidents
// and breach_alerts, were scoped in an earlier batch. These are the unkept half
// of a written-down promise.
//
// THE KEY WAS THE PRIMARY KEY. admin_console_settings is
//
//	key        TEXT PRIMARY KEY,
//	value      JSONB NOT NULL DEFAULT '{}',
//	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//	updated_by TEXT
//
// and the handler writes exactly four keys: 'general', 'security',
// 'authentication', 'branding'. So the installation has four settings rows in
// total, and every organization's administrators share them. The read has no
// predicate of any kind --
//
//	SELECT key, value, updated_at, updated_by FROM admin_console_settings ORDER BY key
//
// -- and the write is an upsert ON CONFLICT (key). This is the sixth
// install-wide key this programme has found, after v138's ispm_rules.check_type
// and ai_agents.name, v155's federation_rules.email_domain and
// identity_providers.issuer_url, and v156's developer_settings.setting_key. It
// is the most severe of the six because the key is the PRIMARY KEY rather than
// a UNIQUE constraint beside one, and because of what the four rows hold: the
// 'security' row carries the password policy (minimum length, character
// classes, forbidden words, maximum age, history depth), the MFA settings
// (whether MFA is enabled, whether it is REQUIRED, which methods are allowed,
// the WebAuthn relying party) and the session settings; 'authentication'
// carries the allowed email domains. One administrator lowering their password
// minimum to eight, or turning "MFA required" off, or adding a domain to the
// allow list, did it for every tenant on the installation -- and the console
// page that displays those values was showing each of them whatever the last
// administrator anywhere had saved.
//
// Unlike v156's developer_settings, this one has a consumer. getPasswordPolicy
// reads `WHERE key = 'security'` and POST /api/v1/settings/validate-password
// answers from it, so the shared row is not merely displayed: it is the policy
// a password is checked against. Re-scoped to a (org_id, key) primary key. No
// separate index on org_id -- the new primary key leads with it.
//
// A RISK ENGINE WHOSE ONLY INPUT TABLE HAS NO WRITER. auth_contexts is read in
// three places in internal/admin/continuous_auth.go and written in none. Not by
// a handler, not by the login path, not by a seed, not by a migration: a search
// of the tree finds SELECT at two sites, one UPDATE, and nothing else. The
// UPDATE is the whole of "update the authentication score", so it updates no
// rows and returns success. The SELECT is the first statement of
// CalculateSessionRisk, so that function returns "failed to get auth context:
// no rows in result set" for every session that has ever existed, and all three
// registered routes -- GET /continuous-auth/risk, POST /continuous-auth/check,
// POST /continuous-auth/update -- have only ever returned 500.
//
// The scan proves it was never once executed against a row: the query selects
// the TEXT column `location` into &authCtx.Location, and AuthContext.Location
// is *GeoLocation, so the destination is a **GeoLocation. Had a row existed the
// scan would have failed on type, every time. Nothing about this table has run.
//
// So there is nothing here to scope. Adding org_id and a policy to a table with
// no rows and no writer would move a name off a register and change nothing --
// the ceremony this programme exists to stop. What the engine needs is the data
// it was written to read, and that data already exists, already carries org_id,
// and is already behind the belt:
//
//	sessions       (v37 belted, written by identity/session_repository.go with
//	                org_id) holds user_id, ip_address, user_agent, started_at,
//	                auth_methods, device_name, device_type, location, revoked
//	session_risks  (v77, org_id NOT NULL) holds the risk score history that
//	                CalculateSessionRisk already writes to and reads back
//
// auth_contexts was a shadow of both, and the shadow is what got read. The
// engine now reads sessions and session_risks under the caller's organization,
// and this migration drops the phantom. Every other factor in the engine
// already resolves orgctx and scopes its own query -- known_devices, audit_events,
// risk_factors, session_risks all carry AND org_id = $N -- so the tenant term
// was missing at exactly one place: the input.
//
// Dropping rather than scoping is safe in a way that is worth stating: no code
// path can have written a row, so there is no data to lose. The down migration
// recreates the table exactly as v62 declared it.
//
// BACKFILL. Settings rows go to the organization of whoever last saved them
// (updated_by holds a user id as TEXT), and anything unattributed -- the
// handler writes the literal "unknown" when the request carries no user -- to
// the oldest organization. One consequence for a multi-organization install:
// the four rows land in one organization and every other organization falls
// back to the compiled-in defaults until an administrator saves once. Those
// defaults are the stricter setting in each case (minimum length 12 against the
// validator's floor of 8), so no tenant's policy loosens on upgrade.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var adminConsoleScopeUp = `-- Migration 157: scope the console's settings; drop the phantom auth context.

ALTER TABLE admin_console_settings ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE admin_console_settings s SET org_id = u.org_id FROM users u WHERE u.id::text = s.updated_by AND s.org_id IS NULL;
UPDATE admin_console_settings SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE admin_console_settings ALTER COLUMN org_id SET NOT NULL;

-- Four rows for the installation become four per organization. v62 made key
-- the PRIMARY KEY, so this is a primary-key change, not a spare UNIQUE: the
-- name is the one Postgres generates.
ALTER TABLE admin_console_settings DROP CONSTRAINT IF EXISTS admin_console_settings_pkey;
ALTER TABLE admin_console_settings ADD  CONSTRAINT admin_console_settings_pkey PRIMARY KEY (org_id, key);

DROP POLICY IF EXISTS pol_admin_console_settings_org_scope ON admin_console_settings;
CREATE POLICY pol_admin_console_settings_org_scope ON admin_console_settings
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE admin_console_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_console_settings FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_console_settings TO openidx_app;

-- The continuous-auth engine now reads sessions and session_risks, both of
-- which carry org_id and are behind the belt. Nothing has ever written a row
-- here, so nothing is lost.
DROP TABLE IF EXISTS auth_contexts;
`

// Down restores v62's auth_contexts verbatim (it comes back empty, which is the
// state it has always been in) and lifts the belt from the settings table.
//
// The statement that can fail is the last one: restoring `key` as the primary
// key needs the keys to be unique across the installation again, and once a
// second organization has saved its console settings -- the point of the
// migration -- there are two rows keyed 'security' and the constraint cannot
// come back. The rollback stops there rather than deleting an organization's
// password policy to make itself succeed. Same trade as v138, v155 and v156.
var adminConsoleScopeDown = `-- Rollback 157.

CREATE TABLE IF NOT EXISTS auth_contexts (
    session_id         UUID PRIMARY KEY,
    user_id            UUID,
    auth_time          TIMESTAMPTZ,
    auth_method        TEXT,
    auth_strength      TEXT,
    current_risk_score DOUBLE PRECISION,
    device_fingerprint TEXT,
    ip_address         TEXT,
    location           TEXT,
    user_agent         TEXT,
    metadata           JSONB NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_contexts TO openidx_app;

ALTER TABLE admin_console_settings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE admin_console_settings DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_admin_console_settings_org_scope ON admin_console_settings;

ALTER TABLE admin_console_settings DROP CONSTRAINT IF EXISTS admin_console_settings_pkey;
ALTER TABLE admin_console_settings DROP COLUMN IF EXISTS org_id;
ALTER TABLE admin_console_settings ADD  CONSTRAINT admin_console_settings_pkey PRIMARY KEY (key);
`
