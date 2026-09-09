package migrations

// v184 — seed the openidx-agent-android public OAuth client.
//
// The native Android agent's first screen is "Sign in with your work email to
// enroll this device" (agent-android/.../ui/EnrollmentActivity.kt). It runs an
// AppAuth PKCE flow as client_id "openidx-agent-android", redirect
// com.openidx.agent://oauth/redirect, requesting the scopes
//
//	openid profile offline_access agent.enroll
//
// and then POSTs the access token to /agent/enroll/oauth. No migration ever
// seeded that client: the native clients on every install were openidx-mobile
// (v84, the companion app) and openidx-desktop (v85, the Windows agent), and
// internal/oauth's scopeAllowedForClient refuses a scope the client is not
// registered for. So the button every Android user sees first has answered
// invalid_client since the day it was written, on every server this
// repository can build. The QR / enrollment-token path beside it works, which
// is why nobody noticed: the device could always be enrolled, just not the way
// the screen said.
//
// The scope is the point, not a courtesy. /agent/enroll/oauth now requires
// agent.enroll in the token, so a console session token -- which no seeded
// browser client can obtain this scope for -- can no longer enroll a device by
// accident. Only a client registered here, or by an operator on purpose, can.
//
// v184_test.go pins this row AND derives the check that found it: every
// client_id, redirect URI and requested scope hardcoded in a shipped client
// (agent/internal/sso/sso.go and the Kotlin OAuthEnrollmentFlow) must be
// registered by some migration, so the next client a developer names in
// source is refused at build time rather than at a user's first sign-in.
//
// Same shape as v84/v85: public, PKCE, refresh tokens, idempotent. org_id is
// left to its default (the default organization, NOT NULL since v?? with a
// DEFAULT), exactly where the v84/v85 rows landed after the tenant backfill.

var androidAgentClientUp = `-- Migration 184: openidx-agent-android public OAuth client (PKCE, custom-scheme redirect).
INSERT INTO oauth_clients (id, client_id, client_secret, name, description, type, redirect_uris, grant_types, response_types, scopes, pkce_required, allow_refresh_token, access_token_lifetime, refresh_token_lifetime) VALUES
('80000000-0000-0000-0000-000000000007', 'openidx-agent-android', NULL, 'OpenIDX Android Agent', 'OpenIDX endpoint agent for Android (native/public PKCE client; enrolls the device it runs on)', 'public',
 '["com.openidx.agent://oauth/redirect"]'::jsonb,
 '["authorization_code", "refresh_token"]'::jsonb,
 '["code"]'::jsonb,
 '["openid", "profile", "offline_access", "agent.enroll"]'::jsonb,
 true, true, 3600, 2592000)
ON CONFLICT (id) DO NOTHING;`

var androidAgentClientDown = `-- Rollback 184.
DELETE FROM oauth_clients WHERE id = '80000000-0000-0000-0000-000000000007';`
