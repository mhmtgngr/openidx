package migrations

// Migration v164 — outbound SCIM: the belt v95 said it had, and a predicate
// that carried its own bypass.
//
// v95 created `scim_target_apps`, `scim_provisioning_records` and
// `scim_provisioning_queue` for outbound provisioning: OpenIDX as a SCIM 2.0
// CLIENT, pushing users and groups out to Okta, Entra, Slack and the rest. Its
// own registry description says, in full, "Org-scoped for RLS." Each table got
// an `org_id UUID` column and none of them got the belt -- no FORCE ROW LEVEL
// SECURITY, no policy, and no NOT NULL or foreign key on the column either.
// This is the clearest instance of the shape the needsBelt register names: a
// migration that says org-scoped for RLS while the belt was never applied.
//
// WHAT IS LIVE. `org_id UUID` with no NOT NULL, written through
// `nullIfEmpty(orgID)`, means a row can be stored with a NULL tenant. A NULL-org
// row is invisible to every org-scoped read once the belt lands -- it does not
// leak, it DISAPPEARS -- and for a target app that means the console stops
// showing a provisioning connection that is still running, and for a queue row
// it means an operation the worker still drains but no operator can see. That
// is the hazard the register records against edr_device_mappings, and it is why
// the column is made NOT NULL here rather than merely belted.
//
// WHAT IS LATENT, AND WORTH FIXING ANYWAY. Every "org-scoped" query in the
// store carries its own escape hatch:
//
//	WHERE id = $1 AND (org_id::text = $2 OR $2 = '')
//
// -- on get, list, update and delete, and again on the two INSERT..SELECT fan-
// outs, where it decides which USERS are enqueued. An empty organization means
// "every organization". Reached with "", `ListTargetApps` returns every
// tenant's SCIM connections, `DeleteTargetApp` removes any of them (and, by
// ON DELETE CASCADE, their provisioning records and queued operations), and
// `EnqueueFullSync` pushes the WHOLE INSTALLATION'S directory -- every username,
// email and name -- into one tenant's downstream SaaS.
//
// It is not reachable through the mounted routes today, and this says so rather
// than overstating it: the provisioning service runs TenantResolver in front of
// every route, no provisioning path is on the resolver's skip list, and the
// resolver either attaches an organization or aborts the request, so
// `orgIDFromRequest` cannot in fact return "". The bypass is one middleware
// change, one skip-path entry, or one in-process caller away from being live,
// and the store methods are exported precisely so identity's SCIM write paths
// can call them.
//
// THE BYPASS WAS FOR THE TESTS. Every production caller of the fan-out passes a
// resolved `org.ID` -- service.go does so at all three inbound SCIM write
// paths. The only callers in the tree that pass "" are the package's own tests.
// The escape hatch existed to make a test convenient and left the production
// code carrying a wildcard.
//
// It also directly contradicts the belt: under FORCE ROW LEVEL SECURITY a query
// with no `app.org_id` set returns nothing, so an OR-empty-string escape hatch
// cannot mean "every
// organization" any more -- it means "no rows", silently. The predicate and the
// belt now agree, and the handlers require an organization instead of treating
// its absence as a wildcard.
//
// THE WORKER KEEPS ITS BYPASS, and it already had one: StartOutboundWorker runs
// its loop under `orgctx.WithBypassRLS`, so the outbox drain -- which is
// deliberately cross-tenant, one worker for the whole install, the same shape
// as the SSF outbox on the beltExempt register -- is unaffected by the belt.
// That is the check the register asked for before belting this queue, and it
// passes: the drain claims by `state` and `next_attempt_at`, never by tenant,
// and the tenant travels on each claimed row.
//
// BACKFILL. A provisioning record and a queued operation follow their target
// through v95's enforced foreign key, which is exact. A target app carries no
// attribution column of any kind -- no created_by -- so a target whose org_id
// was written NULL goes to the oldest organization, and an operator with more
// than one must re-check which connection belongs to whom before the next sync.
// Stated in the CHANGELOG rather than left to be discovered.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var outboundScimBeltUp = `-- Migration 164: belt the outbound SCIM tables and make their tenant column real.

UPDATE scim_provisioning_records r SET org_id = t.org_id FROM scim_target_apps t
  WHERE t.id = r.target_id AND r.org_id IS NULL AND t.org_id IS NOT NULL;
UPDATE scim_provisioning_queue q SET org_id = t.org_id FROM scim_target_apps t
  WHERE t.id = q.target_id AND q.org_id IS NULL AND t.org_id IS NOT NULL;

UPDATE scim_target_apps          SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE scim_provisioning_records SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;
UPDATE scim_provisioning_queue   SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE scim_target_apps          ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE scim_provisioning_records ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE scim_provisioning_queue   ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE scim_target_apps          DROP CONSTRAINT IF EXISTS fk_scim_target_apps_org;
ALTER TABLE scim_target_apps          ADD  CONSTRAINT fk_scim_target_apps_org          FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE scim_provisioning_records DROP CONSTRAINT IF EXISTS fk_scim_prov_records_org;
ALTER TABLE scim_provisioning_records ADD  CONSTRAINT fk_scim_prov_records_org         FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE scim_provisioning_queue   DROP CONSTRAINT IF EXISTS fk_scim_prov_queue_org;
ALTER TABLE scim_provisioning_queue   ADD  CONSTRAINT fk_scim_prov_queue_org           FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_scim_prov_records_org_target ON scim_provisioning_records(org_id, target_id);
CREATE INDEX IF NOT EXISTS idx_scim_prov_queue_org_target   ON scim_provisioning_queue(org_id, target_id);

DROP POLICY IF EXISTS pol_scim_target_apps_org_scope ON scim_target_apps;
CREATE POLICY pol_scim_target_apps_org_scope ON scim_target_apps
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE scim_target_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_target_apps FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_scim_provisioning_records_org_scope ON scim_provisioning_records;
CREATE POLICY pol_scim_provisioning_records_org_scope ON scim_provisioning_records
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE scim_provisioning_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_provisioning_records FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_scim_provisioning_queue_org_scope ON scim_provisioning_queue;
CREATE POLICY pol_scim_provisioning_queue_org_scope ON scim_provisioning_queue
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE scim_provisioning_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_provisioning_queue FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_target_apps          TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_provisioning_records TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_provisioning_queue   TO openidx_app;
GRANT USAGE, SELECT ON SEQUENCE scim_provisioning_queue_id_seq    TO openidx_app;
`

// Down lifts the belt, drops the indexes and the foreign keys, and returns
// org_id to nullable. The column itself stays -- v95 created it, not this
// migration -- so this rollback cannot fail on data.
var outboundScimBeltDown = `-- Rollback 164.

ALTER TABLE scim_provisioning_queue NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_provisioning_queue DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_scim_provisioning_queue_org_scope ON scim_provisioning_queue;

ALTER TABLE scim_provisioning_records NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_provisioning_records DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_scim_provisioning_records_org_scope ON scim_provisioning_records;

ALTER TABLE scim_target_apps NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scim_target_apps DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_scim_target_apps_org_scope ON scim_target_apps;

DROP INDEX IF EXISTS idx_scim_prov_queue_org_target;
DROP INDEX IF EXISTS idx_scim_prov_records_org_target;

ALTER TABLE scim_provisioning_queue   DROP CONSTRAINT IF EXISTS fk_scim_prov_queue_org;
ALTER TABLE scim_provisioning_records DROP CONSTRAINT IF EXISTS fk_scim_prov_records_org;
ALTER TABLE scim_target_apps          DROP CONSTRAINT IF EXISTS fk_scim_target_apps_org;

ALTER TABLE scim_provisioning_queue   ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE scim_provisioning_records ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE scim_target_apps          ALTER COLUMN org_id DROP NOT NULL;
`
