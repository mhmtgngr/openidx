package migrations

// Migration v149 — the legal holds.
//
// A legal hold marks a session recording as evidence: while one is active, the
// retention sweep must not purge the recording. There are two hold tables,
// because there are two kinds of recorded session — `recording_legal_holds`
// (v42, remote support) and `guacamole_recording_legal_holds` (v68, PAM) — and
// neither carried an organization.
//
// THIS ONE DESTROYS RATHER THAN DISCLOSES, which is the first time in this
// programme that has been the primary consequence. `sweepExpiredRecordings`
// selects recordings to purge with `AND NOT EXISTS (SELECT 1 FROM
// recording_legal_holds WHERE session_id = s.id AND released_at IS NULL)`. So
// releasing a hold is not a status change; it is what lets the next sweep
// delete the recording. `HandleReleaseLegalHold` took a BARE session id:
//
//	UPDATE recording_legal_holds
//	   SET released_at = NOW(), ...
//	 WHERE session_id = $1::uuid AND released_at IS NULL
//
// An administrator of one tenant, naming another tenant's session id, released
// that tenant's litigation hold — and the recording it was protecting was gone
// at the next sweep. Nothing about that is reversible, and nothing about it is
// visible to the tenant that placed the hold: their hold row simply reads
// released, by a user id that is not in their organization. Place and list were
// equally bare, so the reasons — free text describing an investigation — were
// readable across tenants too.
//
// THE TWIN WAS GUARDED, WHICH IS HOW THE GAP IS LEGIBLE. The Guacamole hold
// handlers in internal/access/guacamole_legal_hold.go do the identical job and
// every one of them calls guacSessionVisible first. Two implementations of one
// control, side by side, one gated and one not — the shape v146 found in
// mfa_management.go's six-factor SELECT.
//
// The guard is also thinner than it looks, and this migration fixes that too.
// guacSessionVisible is `SELECT EXISTS(SELECT 1 FROM guacamole_sessions WHERE
// id=$1)` with no tenant term at all; its comment says the scope comes from
// "RLS on guacamole_sessions". That is true on a correctly configured
// connection and false on any connection with BYPASSRLS — which is what every
// test pool in this repo is, and what an operator gets by pointing the app at a
// superuser DSN. A control whose only defence is a database setting has no
// defence in the code, so the check now carries the organization itself and the
// belt is the second layer rather than the only one.
//
// THE SWEEPS STAY INSTALL-WIDE, and they already say so: both run under
// orgctx.WithBypassRLS set by StartRecordingRetentionEnforcer. Retention is a
// per-session policy evaluated from each row's own org_id, so a sweep that
// iterated organizations would be slower and no more correct. The belt does not
// change them.
//
// BACKFILL. Each hold takes its session's organization. Both session tables
// allow a NULL org_id on old rows (the sweeps COALESCE it), so the oldest-org
// fallback is load-bearing here rather than a formality.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var legalHoldTenantScopeUp = `-- Migration 149: org_id + FORCE RLS on the two legal-hold tables.

-- recording_legal_holds (v42, remote support) --------------------------------
ALTER TABLE recording_legal_holds ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE recording_legal_holds h SET org_id = s.org_id FROM remote_support_sessions s
 WHERE h.session_id = s.id AND h.org_id IS NULL AND s.org_id IS NOT NULL;
UPDATE recording_legal_holds SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE recording_legal_holds ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_recording_legal_holds_org ON recording_legal_holds(org_id, session_id);

DROP POLICY IF EXISTS pol_recording_legal_holds_org_scope ON recording_legal_holds;
CREATE POLICY pol_recording_legal_holds_org_scope ON recording_legal_holds
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE recording_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE recording_legal_holds FORCE  ROW LEVEL SECURITY;

-- guacamole_recording_legal_holds (v68, PAM) ---------------------------------
ALTER TABLE guacamole_recording_legal_holds ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE guacamole_recording_legal_holds h SET org_id = s.org_id FROM guacamole_sessions s
 WHERE h.session_id = s.id AND h.org_id IS NULL AND s.org_id IS NOT NULL;
UPDATE guacamole_recording_legal_holds SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE guacamole_recording_legal_holds ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_guac_recording_legal_holds_org ON guacamole_recording_legal_holds(org_id, session_id);

DROP POLICY IF EXISTS pol_guacamole_recording_legal_holds_org_scope ON guacamole_recording_legal_holds;
CREATE POLICY pol_guacamole_recording_legal_holds_org_scope ON guacamole_recording_legal_holds
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE guacamole_recording_legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_recording_legal_holds FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON recording_legal_holds, guacamole_recording_legal_holds TO openidx_app;
`

// Down drops the belt and the columns. The active-hold partial unique indexes
// both migrations created are untouched in either direction: they key on
// session_id, which already determines the organization, so re-scoping them
// would let one session carry two active holds — the v146 UNIQUE(user_id)
// judgement, reached the same way and for the same reason.
var legalHoldTenantScopeDown = `-- Rollback 149.

ALTER TABLE guacamole_recording_legal_holds NO FORCE ROW LEVEL SECURITY;
ALTER TABLE guacamole_recording_legal_holds DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_guacamole_recording_legal_holds_org_scope ON guacamole_recording_legal_holds;
DROP INDEX IF EXISTS idx_guac_recording_legal_holds_org;
ALTER TABLE guacamole_recording_legal_holds DROP COLUMN IF EXISTS org_id;

ALTER TABLE recording_legal_holds NO FORCE ROW LEVEL SECURITY;
ALTER TABLE recording_legal_holds DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_recording_legal_holds_org_scope ON recording_legal_holds;
DROP INDEX IF EXISTS idx_recording_legal_holds_org;
ALTER TABLE recording_legal_holds DROP COLUMN IF EXISTS org_id;
`
