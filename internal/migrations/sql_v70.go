package migrations

// Migration v70 — manager-based reviewer resolution. Access certification
// campaigns whose reviewer strategy is "manager" route each item to the item
// owner's manager: resolveReviewer (internal/governance/certification.go) runs
// `SELECT manager_id FROM users WHERE id = $1 AND org_id = $2`. But no migration
// ever added users.manager_id, so that query errored on every install and the
// resolver silently fell back to the system admin — "manager" campaigns looked
// configured but were never actually reviewed by managers (a hollow governance
// control). This adds the self-referential manager_id column plus an index.
//
// Nullable (no backfill — an unknown manager is a legitimate NULL). ON DELETE
// SET NULL so deleting a manager nulls their reports' pointer instead of
// cascade-deleting the reports. The column is populated from the SCIM 2.0
// enterprise-extension manager.value on provisioning (internal/provisioning).
// users is already under the v37 FORCE-RLS belt, so no policy change is needed;
// PostgreSQL referential-integrity checks always bypass RLS, so the self-FK
// resolves regardless of the per-request app.org_id GUC. Plain statements only —
// the runner's splitSQL cannot handle DO $$ blocks (see the v56/v57 lesson).
var usersManagerIDUp = `-- Migration 070: manager-based reviewer resolution.
ALTER TABLE users ADD COLUMN IF NOT EXISTS manager_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_users_manager_id ON users(manager_id);
`

var usersManagerIDDown = `-- Migration 070 down.
DROP INDEX IF EXISTS idx_users_manager_id;
ALTER TABLE users DROP COLUMN IF EXISTS manager_id;
`
