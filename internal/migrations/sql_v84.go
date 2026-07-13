package migrations

// Migration v84 — seed the native mobile OAuth client.
//
// The OpenIDX mobile app is a public (PKCE) OAuth client. Seeding it here (like
// the admin-console public client in migration v10) means every install can run
// the mobile login out of the box. Custom-scheme redirect `openidx://oauth-callback`
// for the native app; refresh tokens enabled for background token refresh.
// Idempotent via ON CONFLICT DO NOTHING.
var mobileClientUp = `-- Migration 084: openidx-mobile public OAuth client (PKCE, native redirect).
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000004', 'openidx-mobile', NULL, 'OpenIDX Mobile', 'OpenIDX companion mobile app (native/public PKCE client)', 'public',
 '["openidx://oauth-callback"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "email", "offline_access"]'::jsonb,
 true, true, 3600, 2592000)
ON CONFLICT (id) DO NOTHING;`

var mobileClientDown = `-- Rollback 084.
DELETE FROM oauth_clients WHERE id = '80000000-0000-0000-0000-000000000004';`
