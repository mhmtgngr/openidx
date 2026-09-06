package migrations

// Migration v166 — the network grant and revocation queues: the belt, and a
// revocation that reported done when it had done nothing.
//
// v100 created `network_revocation_queue` and v101 `network_grant_queue`. They
// are the hand-off between two services: governance decides, and the
// access-service — which owns the Ziti manager — applies. A grant row adds a
// time-bound role attribute to a user's overlay identity, which is what opens
// the dial; a revocation row removes an attribute and severs the user's live
// circuits. Both carry a nullable `org_id` with no foreign key and neither got
// FORCE ROW LEVEL SECURITY.
//
// THE REGISTER'S CHECK PASSES. Its note says to confirm the reconciler's scope
// before belting these, and both workers already run their drain loop under
// `orgctx.WithBypassRLS`: one worker serves the whole installation, claims by
// `state='pending'` and never by tenant, and the tenant travels on each claimed
// row. The same shape as the SSF outbox on beltExempt and the SCIM outbox belted
// in v164. Neither queue has a request-path reader at all, so there is no
// cross-tenant read surface here — the belt is the database enforcing what the
// application already does.
//
// A REVOCATION THAT REPORTED DONE WHEN IT HAD DONE NOTHING. This is the finding,
// and it is the organising defect of this whole programme pointed at the
// direction that matters most. drainNetworkRevocations called
// removeUserZitiAttribute, which returns nothing at all, and
// severUserZitiCircuits, which logs a termination failure and carries on — and
// then wrote
//
//	UPDATE network_revocation_queue SET state='done' ... WHERE id=$1
//
// unconditionally. So an access review revoked a user, governance recorded the
// revocation, and the queue recorded the circuit severance as done even when the
// Ziti call failed or the controller was unreachable. The user's live circuit
// stayed open and every record said it had been cut.
//
// ITS OWN SIBLING GOT THIS RIGHT. drainNetworkGrants, in the file next to it,
// checks the error and writes `state='failed', last_error=...`. One direction of
// the same pair recorded its failures and the other did not — the shape v162
// found in the feature switch, guarded on the way on and open on the way off,
// here as recorded on the way in and silent on the way out.
//
// AND `failed` HAD NO READER, AND NO RETRY. Nothing in the tree reads `state` or
// `last_error` from either queue: no handler, no console page, no alert. So even
// the grant worker's honest failure was a row nobody would ever see — an
// administrator approves a network access request, the console says granted, the
// attribute was never added because one Ziti call failed, and there is no
// surface that says so. Both queues also carry an `attempts` column that neither
// worker has ever incremented: the column was authored for a retry that was
// never written, so a single transient controller error lost the grant or the
// revocation permanently.
//
// Fixed rather than recorded, because a revoke that reports success without
// revoking is a control and not a missing feature: a failed item is now retried
// against the `attempts` column that already existed, and an item that exhausts
// its attempts is dead-lettered AND written to audit_events under the queue
// row's own organization — which is what gives `failed` a reader, on a surface
// that is already org-scoped and already belted.
//
// BACKFILL. Neither queue has an attribution column beyond the tenant the
// enqueuer wrote, and all four enqueue sites pass an organization they have
// already resolved from a scoped row, so a NULL is only produced when that
// organization is empty. Any such row goes to the oldest organization. The
// enqueuers now write the tenant directly rather than through NULLIF, so no new
// row can be tenantless.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var networkQueueBeltUp = `-- Migration 166: belt the network grant/revocation queues and make their tenant real.

UPDATE network_revocation_queue SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE network_grant_queue      SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE network_revocation_queue ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE network_grant_queue      ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE network_revocation_queue DROP CONSTRAINT IF EXISTS fk_network_revocation_queue_org;
ALTER TABLE network_revocation_queue ADD  CONSTRAINT fk_network_revocation_queue_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE network_grant_queue      DROP CONSTRAINT IF EXISTS fk_network_grant_queue_org;
ALTER TABLE network_grant_queue      ADD  CONSTRAINT fk_network_grant_queue_org      FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_net_revoke_org_state ON network_revocation_queue(org_id, state);
CREATE INDEX IF NOT EXISTS idx_net_grant_org_state  ON network_grant_queue(org_id, state);

DROP POLICY IF EXISTS pol_network_revocation_queue_org_scope ON network_revocation_queue;
CREATE POLICY pol_network_revocation_queue_org_scope ON network_revocation_queue
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE network_revocation_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_revocation_queue FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_network_grant_queue_org_scope ON network_grant_queue;
CREATE POLICY pol_network_grant_queue_org_scope ON network_grant_queue
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE network_grant_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_grant_queue FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON network_revocation_queue TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON network_grant_queue      TO openidx_app;
GRANT USAGE, SELECT ON SEQUENCE network_revocation_queue_id_seq  TO openidx_app;
GRANT USAGE, SELECT ON SEQUENCE network_grant_queue_id_seq       TO openidx_app;
`

// Down lifts the belt, drops the indexes and the foreign keys, and returns
// org_id to nullable. The columns themselves stay -- v100 and v101 created them
// -- so this rollback cannot fail on data.
var networkQueueBeltDown = `-- Rollback 166.

ALTER TABLE network_grant_queue NO FORCE ROW LEVEL SECURITY;
ALTER TABLE network_grant_queue DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_network_grant_queue_org_scope ON network_grant_queue;

ALTER TABLE network_revocation_queue NO FORCE ROW LEVEL SECURITY;
ALTER TABLE network_revocation_queue DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_network_revocation_queue_org_scope ON network_revocation_queue;

DROP INDEX IF EXISTS idx_net_grant_org_state;
DROP INDEX IF EXISTS idx_net_revoke_org_state;

ALTER TABLE network_grant_queue      DROP CONSTRAINT IF EXISTS fk_network_grant_queue_org;
ALTER TABLE network_revocation_queue DROP CONSTRAINT IF EXISTS fk_network_revocation_queue_org;

ALTER TABLE network_grant_queue      ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE network_revocation_queue ALTER COLUMN org_id DROP NOT NULL;
`
