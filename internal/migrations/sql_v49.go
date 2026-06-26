package migrations

// Migration v49 — applications referential integrity (sub-project 2).
//
// applications.client_id is overloaded with no FK: it is either a real
// oauth_clients.client_id (OIDC apps) or "proxy-app-<routeID>" (proxy launcher
// tiles). With no referential integrity, deleting a route or an oauth_client
// silently orphans its applications row. Add explicit FK columns with ON DELETE
// CASCADE so a tile/app row can never outlive the thing it represents, and
// backfill them from the existing string conventions. client_id is kept intact
// (legacy/display + UNIQUE). Non-destructive + idempotent: existing orphan
// tiles (no matching route) are left with route_id NULL for the doctor to heal.
var appReferentialIntegrityUp = `-- Migration 049: applications referential integrity.
ALTER TABLE applications ADD COLUMN IF NOT EXISTS route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE;
ALTER TABLE applications ADD COLUMN IF NOT EXISTS oauth_client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_applications_route_id ON applications(route_id);
CREATE INDEX IF NOT EXISTS idx_applications_oauth_client_id ON applications(oauth_client_id);
UPDATE applications a
   SET route_id = substring(a.client_id from 'proxy-app-(.*)')::uuid
 WHERE a.route_id IS NULL AND a.client_id LIKE 'proxy-app-%'
   AND EXISTS (SELECT 1 FROM proxy_routes r WHERE r.id::text = substring(a.client_id from 'proxy-app-(.*)'));
UPDATE applications a
   SET oauth_client_id = oc.id
  FROM oauth_clients oc
 WHERE a.oauth_client_id IS NULL AND a.client_id NOT LIKE 'proxy-app-%' AND oc.client_id = a.client_id;
`

var appReferentialIntegrityDown = `-- Migration 049 down.
ALTER TABLE applications DROP COLUMN IF EXISTS route_id;
ALTER TABLE applications DROP COLUMN IF EXISTS oauth_client_id;
`
