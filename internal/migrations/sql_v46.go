package migrations

// Migration v46 — ziti_identities.group_attrs_synced_at (init-db↔migrations gap).
//
// The Ziti user-sync engine stamps group_attrs_synced_at on every identity it
// creates/reconciles and the stale-attribute resync filters on it. The column
// is added by deployments/docker/init-db.sql (ALTER ... ADD COLUMN IF NOT
// EXISTS) but no migration ever added it, so migrated/managed installs were
// missing it: SyncUserToZiti's INSERT failed with "column group_attrs_synced_at
// does not exist", which in turn blocked BrowZer identity provisioning (the
// externalId + auth-policy wiring runs after the persist). Same gap pattern as
// v42–v45. Idempotent.
var zitiIdentitiesGroupSyncUp = `-- Migration 046: ziti_identities.group_attrs_synced_at.
ALTER TABLE ziti_identities ADD COLUMN IF NOT EXISTS group_attrs_synced_at TIMESTAMPTZ;
`

var zitiIdentitiesGroupSyncDown = `-- Migration 046 down.
ALTER TABLE ziti_identities DROP COLUMN IF EXISTS group_attrs_synced_at;
`
