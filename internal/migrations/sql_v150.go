package migrations

// Migration v150 — remote support sessions.
//
// A remote support session is an administrator watching or driving an end
// user's screen. The row records which agent (device), which admin, the
// consent state, and where the recording of that screen is stored.
//
// `remote_support_sessions` has carried org_id since v92 and never got the
// belt. It sat on the needsBelt register with the largest count in that
// register — FOURTEEN unscoped queries — and the register entry was right:
//
//	HandleListSessions:
//	    SELECT s.id, s.agent_id, ... FROM remote_support_sessions s
//	     ORDER BY s.started_at DESC LIMIT 200
//
// No WHERE clause at all. Every tenant's remote support history — which of
// their people had their screen taken over, by which administrator, when, for
// how long, and whether a recording exists — on any tenant's console, with no
// belt behind it to catch the omission. v149 fixed the legal holds that hang
// off this table and deliberately did not claim this; this is that work.
//
// THE COLUMN IS NULLABLE, AND THAT IS THE HAZARD. v92 added `org_id UUID` with
// no NOT NULL, and HandleStartSession writes whatever getOrgID(c) returns —
// NULL when the caller has no organization resolved. The retention sweeps say
// so out loud: they select the column through COALESCE to an empty string.
//
// Belting a nullable tenant column does not scope those rows; it HIDES them.
// A NULL-org session becomes invisible to every org-scoped query at once, which
// for this table means the administrator who started the session cannot list
// it, cannot end it, and cannot revoke the recording — while the session itself
// keeps running, because the broker holds it in memory and does not consult the
// database to keep a peer connected. The needsBelt register already carries
// this exact warning against edr_device_mappings; it applies here and it is why
// the backfill and the NOT NULL come before the policy rather than after.
//
// The handler is fixed in the same commit: a session with no organization is
// refused at the door instead of written as NULL and discovered later.
//
// THREE KINDS OF QUERY, and they get three different answers — the same split
// v148 and v149 arrived at:
//
//   - The ADMIN paths (list, start, supersede, fetch-by-id, finalize
//     recording, chunk tally) take an explicit org predicate. These are the
//     ones that leaked.
//   - The DEVICE paths (consent grant/deny, the agent's own active-session
//     lookup, markActive, touchSession, endSession) run on a request that has
//     no organization: the agent authenticates as a device, not as a member of
//     a tenant. They keep the session id or agent id as the key and run
//     bypassed, exactly like v145's magic-link redemption and v148's
//     token-redemption path. Belting them without the bypass would break
//     consent — and consent failing closed here means the session never starts,
//     which is safe, but the agent's active-session poll failing closed means a
//     device that can never be helped.
//   - expireOrphanSessions is a background sweep and stays install-wide: a
//     stalled session the sweep cannot see is one that never ages out.
//
// BACKFILL. A session names the administrator who started it, so admin_user_id
// -> users.org_id is the attribution. Sessions started before v92, or by an
// admin since deleted, go to the oldest organization where an operator can see
// them.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var remoteSupportSessionScopeUp = `-- Migration 150: backfill, pin and belt remote_support_sessions.org_id.

-- Attribute each session to the administrator who started it.
UPDATE remote_support_sessions s SET org_id = u.org_id FROM users u
 WHERE s.admin_user_id = u.id AND s.org_id IS NULL AND u.org_id IS NOT NULL;
UPDATE remote_support_sessions SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

-- The belt hides NULL-org rows rather than scoping them, so the column is
-- pinned NOT NULL first. v92 added it nullable and the handler wrote NULL
-- whenever the caller had no organization resolved.
ALTER TABLE remote_support_sessions ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE remote_support_sessions ADD CONSTRAINT fk_remote_support_sessions_org
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_remote_support_sessions_org ON remote_support_sessions(org_id, started_at DESC);

DROP POLICY IF EXISTS pol_remote_support_sessions_org_scope ON remote_support_sessions;
CREATE POLICY pol_remote_support_sessions_org_scope ON remote_support_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE remote_support_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_support_sessions FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON remote_support_sessions TO openidx_app;
`

// Down removes the belt and the constraints this migration added. org_id
// itself stays: it is v92's column, and the rows this migration attributed
// keep their attribution — dropping the NOT NULL is enough to let a rolled-back
// binary write NULL again.
var remoteSupportSessionScopeDown = `-- Rollback 150.

ALTER TABLE remote_support_sessions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE remote_support_sessions DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_remote_support_sessions_org_scope ON remote_support_sessions;
DROP INDEX IF EXISTS idx_remote_support_sessions_org;
ALTER TABLE remote_support_sessions DROP CONSTRAINT IF EXISTS fk_remote_support_sessions_org;
ALTER TABLE remote_support_sessions ALTER COLUMN org_id DROP NOT NULL;
`
