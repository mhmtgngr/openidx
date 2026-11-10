package migrations

// Migration 245: service tokens on proxied applications.
//
// proxy_route_service_accounts lists the service accounts a route admits. An
// API key (api_keys, already hashed, shown once, revocable and expiring) that
// belongs to a listed, active service account of the route's organization
// reaches the route without a person signing in. A route lists none by
// default, so no route changes on upgrade, and a route that requires
// anything only a person has (a trusted device, a reason, assignment to an
// application) never admits one.

var routeServiceAccountsUp = `-- Migration 245: route service accounts.
CREATE TABLE IF NOT EXISTS proxy_route_service_accounts (
    route_id           UUID NOT NULL REFERENCES proxy_routes(id) ON DELETE CASCADE,
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    org_id             UUID NOT NULL,
    created_by         UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (route_id, service_account_id)
);
CREATE INDEX IF NOT EXISTS idx_proxy_route_service_accounts_sa ON proxy_route_service_accounts (service_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON proxy_route_service_accounts TO openidx_app;
DROP POLICY IF EXISTS pol_proxy_route_service_accounts_org_scope ON proxy_route_service_accounts;
CREATE POLICY pol_proxy_route_service_accounts_org_scope ON proxy_route_service_accounts
  USING (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE proxy_route_service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE proxy_route_service_accounts FORCE  ROW LEVEL SECURITY;
`

var routeServiceAccountsDown = `-- Rollback migration 245.
DROP TABLE IF EXISTS proxy_route_service_accounts;
`
