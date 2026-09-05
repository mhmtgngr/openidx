package migrations

// Migration v145 — the credentials that stand in for a password.
//
// Five tables from v54, every one of them a way to authenticate WITHOUT the
// password, and not one of them carried a tenant.
//
// `hardware_tokens` is the worst of the batch and the clearest. It is an
// inventory of physical tokens — serial number, model, and the HOTP/TOTP
// `secret_key` — and internal/identity/hardware_token.go read and wrote it
// install-wide at every single call site. ListHardwareTokens had NO predicate
// beyond an optional status filter, so one tenant's administrator saw every
// other tenant's inventory; get, revoke and report-lost took a bare id; and
// AssignHardwareToken took a bare token id AND a bare user id, so an admin of
// tenant A could take a token sitting available in tenant B's inventory and
// bind it to one of their own users. That is not disclosure of a credential,
// it is transfer of one.
//
// `mfa_bypass_codes` is the break-glass code an administrator issues to get a
// user past MFA. ListBypassCodes was already scoped, through a join on the
// target user's org — but RevokeBypassCode took a bare code id, and
// RevokeAllBypassCodes a bare user id, so one tenant could destroy another's
// break-glass at the moment it was needed. `mfa_bypass_audit`, the record of
// who issued and who used one, was read by GetBypassAuditLog through an
// OPTIONAL user filter — and the console calls it with no user, which returned
// every tenant's bypass history in the install.
//
// `magic_links` are single-use sign-in links. Creation was already scoped to
// the caller's org; the admin statistics counted every tenant's links.
//
// THE BACKFILL HAS TO NARROW, AND FOR hardware_tokens IT CANNOT ALWAYS REACH.
// The per-user tables take their org from their user. hardware_tokens rows
// exist BEFORE any user is attached — that is the point of an inventory — so
// an unassigned token has nothing on it that names a tenant. Those rows go to
// the oldest org, the v141/v144 rule: put the remainder somewhere an operator
// can see and re-file it, rather than leaving rows nobody can read. That is
// also why the column is stamped at creation from the caller's org rather than
// derived from a user at write time, unlike v143's per-user tables.
//
// SERIAL_NUMBER MOVES TO (org_id, serial_number), and the contrast with v144
// is the point. v144 kept saml_service_providers.entity_id UNIQUE install-wide
// because the entity id is what RESOLVES the tenant on an inbound request:
// make it per-org and the lookup becomes ambiguous. A hardware token's serial
// resolves nothing — verification finds the token through `assigned_to`, never
// through the serial. What the install-wide constraint did do was hand the
// first tenant to register a serial a veto over everybody else (v143's
// provider_key shape) and answer "does this serial exist somewhere in the
// install?" to anyone who tried, which is a cross-tenant oracle over hardware
// somebody else owns. Two tenants recording the same serial is a bookkeeping
// error with no security consequence: each row carries its own secret_key and
// its own assignment.
//
// Order matters below: hardware_token_events derives from hardware_tokens and
// mfa_bypass_audit from mfa_bypass_codes, so the parents are filled first.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var credentialTenantScopeUp = `-- Migration 145: org_id + FORCE RLS on the password-substitute credentials.

-- hardware_tokens -----------------------------------------------------------
ALTER TABLE hardware_tokens ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Narrow from the strongest attribution: the user holding the token, then the
-- administrator who assigned it, then the remainder.
UPDATE hardware_tokens t SET org_id = u.org_id FROM users u WHERE t.assigned_to = u.id AND t.org_id IS NULL;
UPDATE hardware_tokens t SET org_id = u.org_id FROM users u WHERE t.assigned_by = u.id AND t.org_id IS NULL;
UPDATE hardware_tokens SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE hardware_tokens ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hardware_tokens_org ON hardware_tokens(org_id);

-- serial_number was UNIQUE install-wide, which gave the first tenant to
-- register a serial a veto over every other tenant and answered "does this
-- exist somewhere?" to anyone who asked. It resolves no tenant. See the file
-- comment for why this is the opposite call from v144's entity_id.
ALTER TABLE hardware_tokens DROP CONSTRAINT IF EXISTS hardware_tokens_serial_number_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_tokens_org_serial ON hardware_tokens(org_id, serial_number);

DROP POLICY IF EXISTS pol_hardware_tokens_org_scope ON hardware_tokens;
CREATE POLICY pol_hardware_tokens_org_scope ON hardware_tokens
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE hardware_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_tokens FORCE  ROW LEVEL SECURITY;

-- hardware_token_events -----------------------------------------------------
ALTER TABLE hardware_token_events ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE hardware_token_events e SET org_id = t.org_id FROM hardware_tokens t WHERE e.token_id = t.id AND e.org_id IS NULL;
UPDATE hardware_token_events e SET org_id = u.org_id FROM users u WHERE e.user_id = u.id AND e.org_id IS NULL;
UPDATE hardware_token_events SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE hardware_token_events ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hardware_token_events_org ON hardware_token_events(org_id, token_id);

DROP POLICY IF EXISTS pol_hardware_token_events_org_scope ON hardware_token_events;
CREATE POLICY pol_hardware_token_events_org_scope ON hardware_token_events
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE hardware_token_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_token_events FORCE  ROW LEVEL SECURITY;

-- mfa_bypass_codes ----------------------------------------------------------
ALTER TABLE mfa_bypass_codes ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- user_id is nullable in the v54 shape; generated_by is not, so it is the
-- second-best attribution rather than a last resort.
UPDATE mfa_bypass_codes c SET org_id = u.org_id FROM users u WHERE c.user_id = u.id AND c.org_id IS NULL;
UPDATE mfa_bypass_codes c SET org_id = u.org_id FROM users u WHERE c.generated_by = u.id AND c.org_id IS NULL;
UPDATE mfa_bypass_codes SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_bypass_codes ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_bypass_codes_org ON mfa_bypass_codes(org_id, user_id);

DROP POLICY IF EXISTS pol_mfa_bypass_codes_org_scope ON mfa_bypass_codes;
CREATE POLICY pol_mfa_bypass_codes_org_scope ON mfa_bypass_codes
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_bypass_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_bypass_codes FORCE  ROW LEVEL SECURITY;

-- mfa_bypass_audit ----------------------------------------------------------
ALTER TABLE mfa_bypass_audit ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE mfa_bypass_audit a SET org_id = c.org_id FROM mfa_bypass_codes c WHERE a.bypass_code_id = c.id AND a.org_id IS NULL;
UPDATE mfa_bypass_audit a SET org_id = u.org_id FROM users u WHERE a.user_id = u.id AND a.org_id IS NULL;
UPDATE mfa_bypass_audit a SET org_id = u.org_id FROM users u WHERE a.performed_by = u.id AND a.org_id IS NULL;
UPDATE mfa_bypass_audit SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_bypass_audit ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_bypass_audit_org ON mfa_bypass_audit(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_mfa_bypass_audit_org_scope ON mfa_bypass_audit;
CREATE POLICY pol_mfa_bypass_audit_org_scope ON mfa_bypass_audit
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_bypass_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_bypass_audit FORCE  ROW LEVEL SECURITY;

-- magic_links ---------------------------------------------------------------
ALTER TABLE magic_links ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE magic_links m SET org_id = u.org_id FROM users u WHERE m.user_id = u.id AND m.org_id IS NULL;
UPDATE magic_links SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE magic_links ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_magic_links_org ON magic_links(org_id, status);

DROP POLICY IF EXISTS pol_magic_links_org_scope ON magic_links;
CREATE POLICY pol_magic_links_org_scope ON magic_links
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE magic_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_links FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON hardware_tokens, hardware_token_events, mfa_bypass_codes, mfa_bypass_audit, magic_links TO openidx_app;
`

// Down drops the belt and the columns, and restores serial_number's install-wide
// uniqueness so a rolled-back binary sees the constraint it was written against.
// The backfill is not reversed: the rows it attributed had no org before, and a
// re-apply cannot reconstruct an attribution once the user it was derived from
// is gone.
//
// The restore can fail, and should. If two tenants registered the same serial
// while v145 was applied, re-adding a UNIQUE over the whole install is exactly
// the wrong thing to do quietly — the rollback stops and names the duplicate
// rather than deciding for an operator which tenant loses its token.
var credentialTenantScopeDown = `-- Rollback 145.

ALTER TABLE magic_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE magic_links DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_magic_links_org_scope ON magic_links;
DROP INDEX IF EXISTS idx_magic_links_org;
ALTER TABLE magic_links DROP COLUMN IF EXISTS org_id;

ALTER TABLE mfa_bypass_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_bypass_audit DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_bypass_audit_org_scope ON mfa_bypass_audit;
DROP INDEX IF EXISTS idx_mfa_bypass_audit_org;
ALTER TABLE mfa_bypass_audit DROP COLUMN IF EXISTS org_id;

ALTER TABLE mfa_bypass_codes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_bypass_codes DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_bypass_codes_org_scope ON mfa_bypass_codes;
DROP INDEX IF EXISTS idx_mfa_bypass_codes_org;
ALTER TABLE mfa_bypass_codes DROP COLUMN IF EXISTS org_id;

ALTER TABLE hardware_token_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE hardware_token_events DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_hardware_token_events_org_scope ON hardware_token_events;
DROP INDEX IF EXISTS idx_hardware_token_events_org;
ALTER TABLE hardware_token_events DROP COLUMN IF EXISTS org_id;

ALTER TABLE hardware_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE hardware_tokens DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_hardware_tokens_org_scope ON hardware_tokens;
DROP INDEX IF EXISTS idx_hardware_tokens_org_serial;
DROP INDEX IF EXISTS idx_hardware_tokens_org;
ALTER TABLE hardware_tokens DROP COLUMN IF EXISTS org_id;
ALTER TABLE hardware_tokens ADD CONSTRAINT hardware_tokens_serial_number_key UNIQUE (serial_number);
`
