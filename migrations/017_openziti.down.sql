-- Rollback 017: OpenZiti Integration

DELETE FROM oauth_clients WHERE client_id = 'access-proxy';
DROP INDEX IF EXISTS idx_ziti_identities_name;
DROP INDEX IF EXISTS idx_ziti_identities_user_id;
DROP INDEX IF EXISTS idx_ziti_services_route_id;
DROP INDEX IF EXISTS idx_ziti_services_name;
DROP TABLE IF EXISTS ziti_service_policies;
DROP TABLE IF EXISTS ziti_identities;
DROP TABLE IF EXISTS ziti_services;
DROP INDEX IF EXISTS idx_proxy_routes_ziti_enabled;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_service_name;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS ziti_enabled;
