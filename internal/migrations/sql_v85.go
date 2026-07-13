package migrations

// Migration v85 — seed the native desktop (Windows) OAuth client.
//
// The OpenIDX Windows client is a public (PKCE) OAuth client. Unlike the mobile
// client (custom-scheme redirect), a desktop app uses an RFC 8252 loopback
// redirect; OpenIDX validates redirect_uri by exact match, so a fixed loopback
// port is registered. Refresh tokens enabled for background refresh. Idempotent.
var desktopClientUp = `-- Migration 085: openidx-desktop public OAuth client (PKCE, loopback redirect).
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000005', 'openidx-desktop', NULL, 'OpenIDX Desktop', 'OpenIDX Windows client (native/public PKCE client)', 'public',
 '["http://127.0.0.1:47600/callback", "http://localhost:47600/callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 2592000)
ON CONFLICT (id) DO NOTHING;`

var desktopClientDown = `-- Rollback 085.
DELETE FROM oauth_clients WHERE id = '80000000-0000-0000-0000-000000000005';`
