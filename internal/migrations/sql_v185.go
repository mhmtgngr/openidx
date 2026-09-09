package migrations

// Migration v185 — bind refresh-token families to the enrolled device.
//
// Revoking a device did not revoke its tokens. executeDeviceRevoke
// (internal/access/user_devices.go) deletes the Ziti identity, terminates the
// Ziti sessions and untrusts the known device -- and touched no OAuth session
// or refresh token, because nothing recorded which device a token was issued
// to. sessions carry client_id, ip_address and user_agent; oauth_refresh_tokens
// carried client_id, user_id, session_id and family_id. The native clients
// hold a 30-day refresh token (v84/v85, refresh_token_lifetime = 2592000), so
// after an admin revoked a phone, that phone could not dial the overlay and
// could still act as the user on every HTTP surface for up to a month.
//
// agent_id is the enrolled_agents.agent_id the token family belongs to. It is
// written in two places:
//
//   - the authorization-code grant, when a native client that is already
//     enrolled sends agent_id with its code exchange (agent/internal/sso);
//   - /agent/enroll/oauth, which binds the enrolling bearer's session -- the
//     Android agent signs in first and enrols second, so its family exists
//     before the agent does.
//
// Rotation carries agent_id forward exactly as it carries family_id, so the
// binding survives however many refreshes. executeDeviceRevoke then revokes
// every family with this agent_id and every session those families ran under.
//
// Nullable, no backfill: a token issued before this migration has no device to
// be bound to, and a NULL simply means "not bound" -- the pre-migration state.
// The partial index serves the one query that reads by agent_id, the revoke,
// which sits on the security path.

var refreshTokenAgentBindingUp = `-- Migration 185: bind refresh-token families to the enrolled device.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS agent_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_agent
    ON oauth_refresh_tokens (agent_id) WHERE agent_id IS NOT NULL;`

var refreshTokenAgentBindingDown = `-- Rollback 185.
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_agent;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS agent_id;`
