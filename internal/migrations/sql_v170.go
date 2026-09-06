package migrations

// Migration v170 — the DCR registration tokens and the device codes: a column
// nothing wrote, and the belt that would have broken the feature.
//
// THE REGISTER'S CHECK PASSES, for both tables. Its note against
// oauth_device_codes said to confirm the pre-tenant path before belting: a
// device code is redeemed by the SHA-256 of the code the device holds, and a
// device polling /oauth/token is about as close to tenantless as this product
// gets. It is not tenantless. tenantSkipPaths carries five entries -- /health,
// /metrics, /ready, /live and the login-branding bootstrap -- and no OAuth path
// is among them, so every one of these requests is resolved by TenantResolver
// or refused with 400 before a handler runs. loadDeviceCodeByHash, resolveUserCode
// and decideDeviceCode already carry `AND org_id = $2`, and handleDeviceCodeGrant
// refuses a request with no organization. The belt here is the database
// enforcing what the application already does.
//
// A COLUMN NOTHING WROTE, AND THE TRAP IT SET. v97 gave
// oauth_registration_tokens an `org_id UUID` -- nullable, no foreign key, no
// belt -- and then nothing in the tree ever wrote it. The one INSERT names
// (client_id, token_hash, created_at). So every row on every installation
// carries a NULL tenant.
//
// The register said to belt this table. BELTING IT AS IT STOOD WOULD HAVE
// BROKEN RFC 7592 CLIENT MANAGEMENT OUTRIGHT. Under FORCE ROW LEVEL SECURITY a
// NULL-org row matches no scoped read, so registrationTokenValid would have
// found no stored hash for any client, and every
//
//	GET    /oauth/register/{client_id}
//	PUT    /oauth/register/{client_id}
//	DELETE /oauth/register/{client_id}
//
// would have answered `401 invalid registration access token` -- for every
// client, on every install, with the credential the caller holds being
// perfectly correct. The column had to be FILLED before it could be ENFORCED,
// and that ordering is the whole content of this migration.
//
// It is the exact inverse of v169, where a recorded reason for SKIPPING a
// control had quietly expired. Here a recorded instruction to APPLY one would
// have caused an outage. A register entry is a note, not a verdict; both of
// them wanted reading before they were acted on.
//
// BACKFILL, AND WHY ORPHANS ARE DELETED RATHER THAN ATTRIBUTED. A registration
// token belongs to exactly one client: oauth_clients.client_id is UNIQUE across
// the installation and oauth_clients.org_id has been NOT NULL with a foreign
// key since v25, so the join is exact and there is nothing to guess. A row whose
// client no longer exists is a different matter -- it cannot be validated by
// anything (the handlers read the client immediately after the token check, and
// that read is org-scoped), and attributing it to the oldest organization would
// file another tenant's dead credential under theirs. Those rows are deleted.
// This is the first backfill in the programme that removes rows rather than
// attributing them, and it does so because the alternative is to invent an
// owner for a credential.
//
// NOT A LIVE CROSS-TENANT HOLE, and this says so rather than overstating it.
// The three unscoped DCR queries key on client_id, which is unique across the
// installation, so they were never ambiguous; and both management handlers read
// the client through the belted, org-scoped oauth_clients immediately after the
// token check, so a caller in another tenant already got 404 there. What the
// tenant term adds is that the queries stop depending on the uniqueness of a
// column in a different table, and keep working under an explicit bypass.
//
// The device-code updates are the same shape: all four take a row id off a
// record that loadDeviceCodeByHash or resolveUserCode has already fetched WITH
// the tenant, so they were bounded by the read that preceded them. They now
// carry it themselves.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var oauthDcrDeviceBeltUp = `-- Migration 170: fill the DCR token tenant, then belt it and the device codes.

UPDATE oauth_registration_tokens t SET org_id = c.org_id
  FROM oauth_clients c WHERE c.client_id = t.client_id AND t.org_id IS NULL;

DELETE FROM oauth_registration_tokens WHERE org_id IS NULL;

ALTER TABLE oauth_registration_tokens ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE oauth_registration_tokens DROP CONSTRAINT IF EXISTS fk_oauth_registration_tokens_org;
ALTER TABLE oauth_registration_tokens ADD  CONSTRAINT fk_oauth_registration_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_oauth_registration_tokens_org ON oauth_registration_tokens(org_id);

DROP POLICY IF EXISTS pol_oauth_registration_tokens_org_scope ON oauth_registration_tokens;
CREATE POLICY pol_oauth_registration_tokens_org_scope ON oauth_registration_tokens
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE oauth_registration_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_registration_tokens FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_oauth_device_codes_org_scope ON oauth_device_codes;
CREATE POLICY pol_oauth_device_codes_org_scope ON oauth_device_codes
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE oauth_device_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_device_codes FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_registration_tokens TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_device_codes        TO openidx_app;
`

// Down lifts both belts, drops the index and the foreign key, and returns
// oauth_registration_tokens.org_id to nullable. The deleted orphans do not come
// back -- a registration token whose client is gone was already unusable -- and
// nothing else here can fail on data.
var oauthDcrDeviceBeltDown = `-- Rollback 170.

ALTER TABLE oauth_device_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_device_codes DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_oauth_device_codes_org_scope ON oauth_device_codes;

ALTER TABLE oauth_registration_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_registration_tokens DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_oauth_registration_tokens_org_scope ON oauth_registration_tokens;

DROP INDEX IF EXISTS idx_oauth_registration_tokens_org;
ALTER TABLE oauth_registration_tokens DROP CONSTRAINT IF EXISTS fk_oauth_registration_tokens_org;
ALTER TABLE oauth_registration_tokens ALTER COLUMN org_id DROP NOT NULL;
`
