package migrations

// Migration v161 — the bulk user operations, and the record of what they did.
//
// v54 created `bulk_operations` and `bulk_operation_items` with no tenant
// column. A bulk operation is the console's "do this to these fifty accounts"
// control: enable, disable, DELETE, assign or remove a role, add to or remove
// from a group, force a password change.
//
// THE ACTIONS WERE SCOPED AND THE RECORD OF THEM WAS NOT. This is the third
// time this programme has found that exact shape, after v154's lifecycle
// policies and v158's biometric rules, and here the evidence is at its most
// explicit. Every statement in executeBulkOperation carries a tenant term --
//
//	UPDATE users SET enabled = false ... WHERE id = $1 AND org_id = $2
//	DELETE FROM users                    WHERE id = $1 AND org_id = $2
//	DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3
//
// -- and the function opens with a comment recording an earlier fix in this
// same programme, that the organization has to travel on the CONTEXT because
// the tables are behind the belt and the pool reads app.org_id at checkout.
// Somebody thought carefully about the blast radius of the actions. Nobody
// scoped the record.
//
// So the list read `FROM bulk_operations ORDER BY created_at DESC LIMIT 50`
// with no predicate at all: one administrator saw every organization's bulk
// runs, their type ("delete_users"), their counts, and their parameters -- the
// role id or group id the run applied. And the detail view is worse, because
// bulk_operation_items stores `entity_name`, which is the USERNAME the item
// acted on. Opening another organization's run returned their directory, one
// row per account, with what was done to it and why it failed. That is the same
// cross-tenant read of personal data v154 found in the lifecycle run logs.
//
// Cancel addressed a run by bare id, so one administrator could cancel
// another's import mid-flight.
//
// AND CANCEL WAS A LIE ANYWAY -- fixed here rather than recorded, because it is
// a control rather than a missing feature. handleCancelBulkOperation sets
// status = 'cancelled' on the row, and executeBulkOperation never reads that
// column: it walks every id it was given regardless, and then writes
// status = 'completed' unconditionally at the end. So pressing Cancel on a
// running bulk DELETE did not stop a single deletion, and the row it had just
// marked cancelled was overwritten with "completed" -- the administrator was
// left with no sign their cancel had been ignored. The loop now checks for a
// cancellation before each account and stops, and the final write no longer
// clobbers a cancelled run.
//
// A SUCCESS THAT TOUCHED NOBODY, also fixed here. `UPDATE users SET enabled =
// false WHERE id = $1 AND org_id = $2` against an id outside the caller's
// organization matches no row and returns NO ERROR, so errMsg stayed empty and
// the item was recorded 'success'. A bulk disable over fifty ids from somebody
// else's tenant reported fifty successes and changed nothing. The same shape as
// v154's ExecuteLifecycleWorkflow, and the fix is the same: an action that
// matched no row is an error.
//
// BACKFILL. A run goes to the organization of whoever started it, through v54's
// created_by foreign key to users; an item follows its run through an enforced
// foreign key. Anything unattributed goes to the oldest organization.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var bulkOpsScopeUp = `-- Migration 161: scope and belt the bulk operations and their items.

ALTER TABLE bulk_operations      ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE bulk_operation_items ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE bulk_operations o SET org_id = u.org_id FROM users u WHERE u.id = o.created_by AND o.org_id IS NULL;
UPDATE bulk_operations SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

UPDATE bulk_operation_items i SET org_id = o.org_id FROM bulk_operations o WHERE o.id = i.operation_id AND i.org_id IS NULL;
UPDATE bulk_operation_items SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE bulk_operations      ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE bulk_operation_items ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_bulk_operations_org_created ON bulk_operations(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bulk_items_org_operation    ON bulk_operation_items(org_id, operation_id);

DROP POLICY IF EXISTS pol_bulk_operations_org_scope ON bulk_operations;
CREATE POLICY pol_bulk_operations_org_scope ON bulk_operations
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE bulk_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulk_operations FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_bulk_operation_items_org_scope ON bulk_operation_items;
CREATE POLICY pol_bulk_operation_items_org_scope ON bulk_operation_items
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE bulk_operation_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulk_operation_items FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON bulk_operations      TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON bulk_operation_items TO openidx_app;
`

// Down lifts the belt, drops the indexes and drops the columns. v54 gave
// neither table a unique key beyond its primary key, so -- like v158 and v159 --
// this rollback cannot fail on data.
var bulkOpsScopeDown = `-- Rollback 161.

ALTER TABLE bulk_operation_items NO FORCE ROW LEVEL SECURITY;
ALTER TABLE bulk_operation_items DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_bulk_operation_items_org_scope ON bulk_operation_items;

ALTER TABLE bulk_operations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE bulk_operations DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_bulk_operations_org_scope ON bulk_operations;

DROP INDEX IF EXISTS idx_bulk_items_org_operation;
DROP INDEX IF EXISTS idx_bulk_operations_org_created;

ALTER TABLE bulk_operation_items DROP COLUMN IF EXISTS org_id;
ALTER TABLE bulk_operations      DROP COLUMN IF EXISTS org_id;
`
