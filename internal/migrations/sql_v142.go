package migrations

// Migration v142 — give the unified audit stream a tenant.
//
// `unified_audit_events` is the table behind the console's Unified Audit page,
// the assignment- and ABAC-gate decision records, the agent lifecycle log, the
// MCP gateway's tool-call log, the Ziti and Guacamole sync, and the usage
// metering rollup. It is the busiest audit surface in the product, and it had
// no org_id at all. `UnifiedAuditService.QueryEvents` opened `WHERE 1=1`, so
// every tenant's admin read every tenant's audit trail — the enforcement
// decisions taken on other tenants' applications, the IP addresses of their
// users, the names of their routes, and via the JOIN their users' e-mail
// addresses. The summary endpoint counted install-wide the same way.
//
// The absence was not an oversight anybody had missed; it had been WRITTEN DOWN
// as a design property. Three files carried variations of "unified_audit_events
// has no org_id column by design (that is why it accepts these writes at all)",
// and the assignment gate chose this table over the org-scoped audit_events
// precisely because audit_events was rejecting its inserts. That rejection was
// a bug — a detached context.Background() left app.org_id empty, so RLS refused
// the write (fixed in the same series) — and the workaround outlived it. A
// missing tenant column is not a design; it is a cross-tenant read with a
// comment on it.
//
// BACKFILL, in three passes, most specific first:
//  1. from the event's own user (unified_audit_events.user_id -> users.org_id);
//  2. from the route it names (route_id -> proxy_routes.org_id), which covers
//     the Ziti and Guacamole sync rows — they carry a route but never a user;
//  3. the oldest org for the remainder: controller-level fabric events that
//     matched no route, and agent-lifecycle rows that carry neither. Those are
//     install infrastructure; parking them in the primary org keeps them
//     visible to somebody rather than leaving rows nobody can see.
//
// No column DEFAULT: a rolled-back binary that still writes this table must
// fail loudly rather than file new rows into whichever org a default happened
// to name. Every writer is updated in the same commit, and the FORCE belt makes
// a writer that forgets fail its WITH CHECK instead of writing an unattributed
// row.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var unifiedAuditOrgScopeUp = `-- Migration 142: org_id + FORCE RLS on unified_audit_events.

ALTER TABLE unified_audit_events ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- 1. The event's own user is the most specific attribution available.
UPDATE unified_audit_events e SET org_id = u.org_id FROM users u WHERE e.user_id = u.id AND e.org_id IS NULL;
-- 2. Ziti and Guacamole sync rows carry a route and no user.
UPDATE unified_audit_events e SET org_id = r.org_id FROM proxy_routes r WHERE e.route_id = r.id AND e.org_id IS NULL;
-- 3. Fabric events that matched no route and agent-lifecycle rows with neither.
UPDATE unified_audit_events SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE unified_audit_events ALTER COLUMN org_id SET NOT NULL;

-- The page reads newest-first within one org, and the metering worker walks
-- (created_at, id) within one org; both are served by this index.
CREATE INDEX IF NOT EXISTS idx_unified_audit_org ON unified_audit_events(org_id, created_at DESC);

DROP POLICY IF EXISTS pol_unified_audit_events_org_scope ON unified_audit_events;
CREATE POLICY pol_unified_audit_events_org_scope ON unified_audit_events
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE unified_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE unified_audit_events FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT ON unified_audit_events TO openidx_app;
`

// Down drops the belt and the column. The backfill is not reversed: the rows it
// attributed had no org before, and a re-apply cannot reconstruct an
// attribution once the user or route it was derived from is gone.
var unifiedAuditOrgScopeDown = `-- Rollback 142.

ALTER TABLE unified_audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE unified_audit_events DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_unified_audit_events_org_scope ON unified_audit_events;
DROP INDEX IF EXISTS idx_unified_audit_org;
ALTER TABLE unified_audit_events DROP COLUMN IF EXISTS org_id;
`
