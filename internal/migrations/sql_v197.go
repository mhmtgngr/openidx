package migrations

// Migration v197 — the device fleet is per-tenant.
//
// THE DECISION THIS WAITED ON. Three tables from v43 -- enrolled_agents (the
// devices), agent_posture_results (what each device reported) and
// agent_enrollment_tokens (what admits a device) -- carried no org_id, by a
// decision written into three separate comments in internal/access: the fleet
// was install-wide, and an agent id named a device without naming a tenant.
// They were the last three tables on the orgscope needsScoping register, held
// there since v138 behind one product question the lint could not answer: is
// the fleet per-tenant?
//
// It is. Decided 2026-09-17. Every consequence of the old shape was already
// measured and recorded, and each one is what this migration closes:
//
//   - v159: kiosk lockdown assignments could TARGET another tenant's device,
//     because there was no tenant term to put on the agent match;
//   - the admin fleet list (HandleListAgents) and the token list were the
//     installation's, not the organization's -- one tenant's administrator
//     saw every device and every enrolment token on the install;
//   - plan 4.5's "N enrolments per tenant per hour" could not be enforced on a
//     token table that did not know which tenant a token belonged to;
//   - a device's tenant had to be inferred through its enrolling user on every
//     read, so a token-enrolled device with no user (fleet/MDM bootstrap) had
//     no tenant at all.
//
// WHERE A DEVICE'S TENANT COMES FROM. The token admits the device, so the
// token's tenant is the device's tenant: agent_enrollment_tokens.org_id is set
// by the administrator or user who minted the token (from their own resolved
// organization), enrolled_agents.org_id is copied from the token (or the
// enrollment session) at redemption, and agent_posture_results.org_id from the
// agent at report time. The public redemption path -- an agent arriving with a
// token and no tenant -- reads the token under an explicit RLS bypass keyed by
// the token's SHA-256, exactly as v171 did for enrollment_sessions, and carries
// the tenant it finds there into everything after it.
//
// BACKFILL, most exact source first, then the next, then the oldest
// organization for anything nothing can attribute (the v157–v172 convention):
//
//	tokens:  created_by is the minting user's id on the session and QR paths
//	         (matched as text against users.id, never cast, because the admin
//	         path stored free text there) → that user's organization;
//	agents:  the enrolling user → the token that admitted it (used_by_agent)
//	         → the linked known device (v80) → oldest organization;
//	posture: the agent it belongs to → oldest organization.
//
// THE FINGERPRINT KEY BECOMES PER-TENANT. v93's unique index on
// device_fingerprint was install-wide: one physical machine could enrol into
// one tenant on the whole installation. Two tenants that both manage a
// contractor's laptop is a real case, and (org_id, device_fingerprint) is the
// key the stable-identity re-enrolment actually wants -- it looks the
// fingerprint up within the tenant the token names.
//
// token_hash stays UNIQUE install-wide on purpose: it is the key the public
// redemption path looks a token up by BEFORE any tenant is known.
//
// No column DEFAULT, so a binary rolled back to before this migration fails
// loudly on INSERT instead of silently filing devices under one tenant.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var fleetPerTenantUp = `-- Migration 197: the device fleet is per-tenant.

ALTER TABLE agent_enrollment_tokens ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE enrolled_agents         ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE agent_posture_results   ADD COLUMN IF NOT EXISTS org_id UUID;

-- Tokens: the minting user's organization, where created_by is a user id.
UPDATE agent_enrollment_tokens t SET org_id = u.org_id FROM users u
  WHERE t.org_id IS NULL AND u.id::text = t.created_by;
UPDATE agent_enrollment_tokens SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;

-- Agents: the enrolling user, then the token that admitted the device, then
-- the linked known device, then the oldest organization.
UPDATE enrolled_agents a SET org_id = u.org_id FROM users u
  WHERE a.org_id IS NULL AND a.enrolled_by_user_id = u.id;
UPDATE enrolled_agents a SET org_id = t.org_id FROM agent_enrollment_tokens t
  WHERE a.org_id IS NULL AND t.used_by_agent = a.agent_id;
UPDATE enrolled_agents a SET org_id = kd.org_id FROM known_devices kd
  WHERE a.org_id IS NULL AND a.known_device_id = kd.id;
UPDATE enrolled_agents SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;

-- Posture: the agent it belongs to, then the oldest organization.
UPDATE agent_posture_results p SET org_id = a.org_id FROM enrolled_agents a
  WHERE p.org_id IS NULL AND p.agent_id = a.agent_id;
UPDATE agent_posture_results SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1)
  WHERE org_id IS NULL;

ALTER TABLE agent_enrollment_tokens ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE enrolled_agents         ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE agent_posture_results   ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE agent_enrollment_tokens DROP CONSTRAINT IF EXISTS fk_agent_enrollment_tokens_org;
ALTER TABLE agent_enrollment_tokens ADD  CONSTRAINT fk_agent_enrollment_tokens_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE enrolled_agents DROP CONSTRAINT IF EXISTS fk_enrolled_agents_org;
ALTER TABLE enrolled_agents ADD  CONSTRAINT fk_enrolled_agents_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE agent_posture_results DROP CONSTRAINT IF EXISTS fk_agent_posture_results_org;
ALTER TABLE agent_posture_results ADD  CONSTRAINT fk_agent_posture_results_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_agent_enrollment_tokens_org ON agent_enrollment_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_org         ON enrolled_agents(org_id);
CREATE INDEX IF NOT EXISTS idx_agent_posture_results_org   ON agent_posture_results(org_id, agent_id);

-- The stable-identity key is per-tenant now (was install-wide, v93).
DROP INDEX IF EXISTS enrolled_agents_device_fingerprint_key;
CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_org_device_fingerprint_key
    ON enrolled_agents (org_id, device_fingerprint)
    WHERE device_fingerprint IS NOT NULL;

DROP POLICY IF EXISTS pol_agent_enrollment_tokens_org_scope ON agent_enrollment_tokens;
CREATE POLICY pol_agent_enrollment_tokens_org_scope ON agent_enrollment_tokens
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agent_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_enrollment_tokens FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_enrolled_agents_org_scope ON enrolled_agents;
CREATE POLICY pol_enrolled_agents_org_scope ON enrolled_agents
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE enrolled_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrolled_agents FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_agent_posture_results_org_scope ON agent_posture_results;
CREATE POLICY pol_agent_posture_results_org_scope ON agent_posture_results
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE agent_posture_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_posture_results FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_enrollment_tokens TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON enrolled_agents         TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_posture_results   TO openidx_app;
`

// Down lifts the three belts, drops the tenant columns and restores v93's
// install-wide fingerprint key. That last step can fail on data: if two
// tenants have enrolled the same fingerprint since this migration, the
// install-wide key cannot be recreated, which is the correct refusal -- the
// rows are two devices to two tenants and the old schema cannot hold that.
var fleetPerTenantDown = `-- Rollback 197.

ALTER TABLE agent_posture_results NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_posture_results DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_agent_posture_results_org_scope ON agent_posture_results;

ALTER TABLE enrolled_agents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE enrolled_agents DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_enrolled_agents_org_scope ON enrolled_agents;

ALTER TABLE agent_enrollment_tokens NO FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_enrollment_tokens DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_agent_enrollment_tokens_org_scope ON agent_enrollment_tokens;

DROP INDEX IF EXISTS enrolled_agents_org_device_fingerprint_key;
CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_device_fingerprint_key
    ON enrolled_agents (device_fingerprint)
    WHERE device_fingerprint IS NOT NULL;

DROP INDEX IF EXISTS idx_agent_posture_results_org;
DROP INDEX IF EXISTS idx_enrolled_agents_org;
DROP INDEX IF EXISTS idx_agent_enrollment_tokens_org;

ALTER TABLE agent_posture_results   DROP COLUMN IF EXISTS org_id;
ALTER TABLE enrolled_agents         DROP COLUMN IF EXISTS org_id;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS org_id;
`
