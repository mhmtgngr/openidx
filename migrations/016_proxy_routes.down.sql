-- Rollback 016: Zero Trust Access Proxy Routes

DROP INDEX IF EXISTS idx_proxy_sessions_expires;
DROP INDEX IF EXISTS idx_proxy_sessions_token;
DROP INDEX IF EXISTS idx_proxy_sessions_user;
DROP INDEX IF EXISTS idx_proxy_routes_enabled;
DROP INDEX IF EXISTS idx_proxy_routes_from_url;
DROP TABLE IF EXISTS proxy_sessions;
DROP TABLE IF EXISTS proxy_routes;
