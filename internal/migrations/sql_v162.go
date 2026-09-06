package migrations

// Migration v162 — the route's feature switches, and the connectivity tests
// that probe behind them.
//
// v40 created `service_features` and v54 created `connection_tests`, both keyed
// on proxy_routes and neither given a tenant column. A service_features row is
// the per-route ZTNA switch: whether Ziti, BrowZer or Guacamole is on for that
// route, the Ziti service name and Guacamole connection id it provisioned, and
// the health verdict the console shows beside it. A connection_tests row is the
// stored result of the "Test connection" button.
//
// THE SWITCH WAS GUARDED ON THE WAY ON AND OPEN ON THE WAY OFF. EnableFeature
// opens with validateFeatureDependencies and validateRouteTypeCompatibility,
// and the second of those resolves orgctx and reads
//
//	SELECT COALESCE(route_type,'http') FROM proxy_routes WHERE id = $1 AND org_id = $2
//
// so enabling a feature on another organization's route already failed with
// "route not found". DisableFeature had no such lookup anywhere in its path:
// getDependentFeatures, getFeature, deprovisionFeature and the
// `UPDATE service_features SET enabled = false ... WHERE id = $2` that follows
// all addressed the row by route id alone. One administrator could therefore
// turn off another organization's ZTNA overlay for a route by naming its id --
// the same control, guarded in one direction and open in the other.
//
// AND THE TEARDOWN RAN BEFORE THE WRITE. deprovisionFeature for the Ziti
// feature reads ziti_service_id out of the row it was just handed and calls
// DeleteService against the controller, so on an install where the reconciler
// does not own teardown the foreign organization's overlay SERVICE was deleted,
// not merely marked off. What did not happen is the part that would have shown
// on their console: syncRouteFlags -- the one statement in DisableFeature that
// does carry `AND org_id = $N` -- matched no row, so proxy_routes.ziti_enabled
// stayed true. The owning tenant was left with a route the console reports as
// Ziti-protected, whose Ziti service no longer exists. A control that displays
// without enforcing, arrived at from the other side.
//
// THE TEST HISTORY IS INTERNAL TOPOLOGY. handleGetConnectionTestHistory read
// `FROM connection_tests WHERE route_id = $1` with no tenant term and no check
// that the route belongs to the caller, and the `details` JSONB it returns is
// the whole per-test result map: `url` is the route's upstream to_url, `address`
// is the "host:port" a TCP probe dialled, `service_name` and `service_id` are
// the overlay service, and error_message is the raw dial error, which names the
// host it failed to reach. So a route id was enough to read another
// organization's internal hostnames and ports out of the product -- the class
// this repository has a dedicated CI guard for on its public surfaces, sitting
// unscoped behind an admin one. handleTestConnection, by contrast, went through
// getRouteByID, which applies the tenant filter WHEN the context carries an
// organization and silently drops it when it does not; on a request path that
// is the wrong direction for a failure, so the handler now requires one.
//
// A MEASUREMENT THAT WAS TAKEN AND THROWN AWAY. UpdateFeatureHealth is the only
// writer of service_features.health_status in the tree and has no caller: not a
// worker, not a handler, not the health engine. So the coloured dot beside each
// feature on the Zero Trust page, and the badge on the route's feature panel,
// have read 'unknown' for every feature on every route since v40 -- honest, but
// unable to be anything else. The verdict they want already exists: the
// connection test in this same batch dials the upstream, resolves the Ziti
// service and validates the Guacamole connection, and then stored its answer in
// connection_tests and nowhere else. The test now also records each feature's
// outcome through UpdateFeatureHealth, so the dot means "the last connectivity
// test said this" and stays 'unknown' until one has run. No new probe: the
// measurement was already being taken.
//
// BACKFILL. Both tables carry `route_id UUID NOT NULL REFERENCES
// proxy_routes(id) ON DELETE CASCADE`, and proxy_routes.org_id is itself NOT
// NULL with an enforced foreign key, so every row's tenant is exact rather than
// inferred. The oldest-organization fallback below cannot fire; it is kept so
// that on an installation whose constraints were dropped by hand the statement
// that fails is not SET NOT NULL.
//
// Plain statements only -- the runner's splitSQL cannot handle DO $$ blocks.
var routeFeaturesScopeUp = `-- Migration 162: scope and belt the per-route feature switches and their tests.

ALTER TABLE service_features  ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE connection_tests  ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE service_features f SET org_id = r.org_id FROM proxy_routes r WHERE r.id = f.route_id AND f.org_id IS NULL;
UPDATE service_features SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

UPDATE connection_tests t SET org_id = r.org_id FROM proxy_routes r WHERE r.id = t.route_id AND t.org_id IS NULL;
UPDATE connection_tests SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE service_features ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE connection_tests ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_service_features_org_route ON service_features(org_id, route_id);
CREATE INDEX IF NOT EXISTS idx_connection_tests_org_route ON connection_tests(org_id, route_id, tested_at DESC);

DROP POLICY IF EXISTS pol_service_features_org_scope ON service_features;
CREATE POLICY pol_service_features_org_scope ON service_features
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE service_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_features FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_connection_tests_org_scope ON connection_tests;
CREATE POLICY pol_connection_tests_org_scope ON connection_tests
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE connection_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_tests FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON service_features TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON connection_tests TO openidx_app;
`

// Down lifts the belt, drops the indexes and drops the columns. Neither table's
// unique key names the tenant -- service_features is UNIQUE (route_id,
// feature_name) and connection_tests has none beyond its primary key -- and
// route_id carries the organization through an enforced foreign key, so both
// stay correct in either direction and this rollback cannot fail on data.
var routeFeaturesScopeDown = `-- Rollback 162.

ALTER TABLE connection_tests NO FORCE ROW LEVEL SECURITY;
ALTER TABLE connection_tests DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_connection_tests_org_scope ON connection_tests;

ALTER TABLE service_features NO FORCE ROW LEVEL SECURITY;
ALTER TABLE service_features DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_service_features_org_scope ON service_features;

DROP INDEX IF EXISTS idx_connection_tests_org_route;
DROP INDEX IF EXISTS idx_service_features_org_route;

ALTER TABLE connection_tests DROP COLUMN IF EXISTS org_id;
ALTER TABLE service_features DROP COLUMN IF EXISTS org_id;
`
