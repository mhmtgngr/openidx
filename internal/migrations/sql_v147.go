package migrations

// Migration v147 — the breach response surface.
//
// `breach_incidents` and `breach_alerts` are the Identity Breach Detection and
// Response record: what was detected, which users and sessions it affected,
// what containment was applied. Neither carried an organization, and
// internal/admin/ibdr.go read both install-wide:
//
//   - `handleIBDRIncidents`, the console's incident list, is `SELECT ... FROM
//     breach_incidents ORDER BY first_detected_at DESC LIMIT 100` with no
//     predicate at all. Every tenant's incident titles, descriptions,
//     severities and quarantine actions, to any tenant's administrator.
//   - `GetBreachAlerts` is `WHERE acknowledged = $1 OR $1 = true` — a filter
//     that is not a tenant filter. Each alert names a user_id, a session_id
//     and an IP address.
//   - `AnalyzeBreachPatterns` aggregates the whole install.
//
// THE SHARPEST PART IS THE CONTAINMENT, and it is this branch's defect class
// arriving from a direction the earlier batches did not cover.
// `TriggerIncidentResponse` takes a BARE incident id, reads the incident,
// flips it to 'investigating', and executes quarantine. The quarantine actions
// are already org-scoped — `executeFullQuarantine` and `revokeUserSessions`
// both call orgctx.From and write `... WHERE id = $1 AND org_id = $2`. So an
// administrator of one tenant triggering response on another tenant's incident
// does not damage that tenant: the user-disable and the session-revoke match
// zero rows. They also do nothing at all, while the incident is marked
// investigated and a list of containment steps is recorded against it.
//
// That is a containment action that reports success and contains nothing, and
// it is worse than either half alone. Scoping the ACTION without scoping the
// RECORD IT ACTS ON converted a cross-tenant write into a silent no-op instead
// of a refusal — and left the owning tenant's real incident marked as handled.
// The fix has to scope the record, so the trigger REFUSES rather than
// no-ops.
//
// A third file had already written the gap down as a property:
// internal/admin/ai_intelligence.go says "Breach incidents are install-wide (no
// org_id); affected_user_ids carries users.id values so scoping happens
// implicitly via the org's user set." Implicit scoping through a joined set is
// the v143 social_providers shape — it holds until the query changes, and
// nothing makes it hold.
//
// BACKFILL. An incident names its users in `affected_user_ids`, a TEXT[] of
// users.id values, so the first element attributes the row; an alert takes its
// incident's organization, then its own user_id. Anything left — an incident
// detected against a user since deleted — goes to the oldest organization,
// where an operator can see and re-file it.
//
// AND THE CONTAINMENT RECORD ITSELF WAS NEVER WRITTEN. TriggerIncidentResponse
// ends in `UPDATE breach_incidents SET containment_steps = $1,
// quarantine_action = $2 ...`. There is no containment_steps column: v62's
// CREATE TABLE does not have one and no later migration adds one. (The legacy
// standalone tree at migrations/017_*.up.sql declares it, which is why the code
// was written against it, but internal/migrations is the schema every service
// and every test actually runs.) So that UPDATE errored on every call since
// v62, the error was discarded by `_, _ =`, and quarantine_action went with it
// — the console's incident list has been reading 'none' for incidents that were
// fully quarantined. The column is added here, and the write now reports.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var breachResponseTenantScopeUp = `-- Migration 147: org_id + FORCE RLS on the breach response tables.

-- breach_incidents ----------------------------------------------------------
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- The record of what containment was applied. Written since v62, never present.
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS containment_steps JSONB;

-- affected_user_ids is TEXT[] of users.id values; the first names the tenant.
UPDATE breach_incidents i SET org_id = u.org_id FROM users u
 WHERE i.org_id IS NULL AND array_length(i.affected_user_ids, 1) >= 1
   AND u.id::text = i.affected_user_ids[1];
UPDATE breach_incidents SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE breach_incidents ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_breach_incidents_org ON breach_incidents(org_id, first_detected_at DESC);

DROP POLICY IF EXISTS pol_breach_incidents_org_scope ON breach_incidents;
CREATE POLICY pol_breach_incidents_org_scope ON breach_incidents
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE breach_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_incidents FORCE  ROW LEVEL SECURITY;

-- breach_alerts -------------------------------------------------------------
-- Filled after breach_incidents is complete, so an alert inherits a column
-- that is already set rather than falling through to the oldest organization.
ALTER TABLE breach_alerts ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE breach_alerts a SET org_id = i.org_id FROM breach_incidents i WHERE a.incident_id = i.id AND a.org_id IS NULL;
UPDATE breach_alerts a SET org_id = u.org_id FROM users u WHERE a.user_id = u.id AND a.org_id IS NULL;
UPDATE breach_alerts SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE breach_alerts ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_breach_alerts_org ON breach_alerts(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_breach_alerts_org_scope ON breach_alerts;
CREATE POLICY pol_breach_alerts_org_scope ON breach_alerts
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE breach_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_alerts FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON breach_incidents, breach_alerts TO openidx_app;
`

// Down drops the belt and the columns. The backfill is not reversed: the rows
// it attributed had no organization before, and a re-apply cannot reconstruct
// an attribution once the user it was derived from is gone. containment_steps
// goes with it, which loses the containment records written while v147 was
// applied — a faithful inverse of a column that did not exist before it.
var breachResponseTenantScopeDown = `-- Rollback 147.

ALTER TABLE breach_alerts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE breach_alerts DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_breach_alerts_org_scope ON breach_alerts;
DROP INDEX IF EXISTS idx_breach_alerts_org;
ALTER TABLE breach_alerts DROP COLUMN IF EXISTS org_id;

ALTER TABLE breach_incidents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE breach_incidents DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_breach_incidents_org_scope ON breach_incidents;
DROP INDEX IF EXISTS idx_breach_incidents_org;
ALTER TABLE breach_incidents DROP COLUMN IF EXISTS containment_steps;
ALTER TABLE breach_incidents DROP COLUMN IF EXISTS org_id;
`
