package migrations

// Migration v59 — PAM M3 session injection: adds four credential/approval/recording
// columns to guacamole_connections (vault_secret_id, inject_username, require_approval,
// record_session) and creates two new org-scoped tables:
//   - guacamole_session_requests  (pre-session approval lifecycle)
//   - guacamole_sessions          (active/ended session tracking + recording ledger)
//
// Both new tables are placed under the v37 FORCE-RLS belt with the standard
// pol_<t>_org_scope predicate. guacamole_connections is NOT belted (only ALTERed).
// Idempotent. Mirrored into deployments/docker/init-db.sql so TestInitDBParity stays green.
var guacSessionsUp = `-- Migration 059: PAM M3 session injection — guacamole columns + session tables.

-- Add credential-injection / approval / recording columns to guacamole_connections.
-- guacamole_connections already exists (created in v54 reconcile / init-db).
ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS vault_secret_id  UUID REFERENCES vault_secrets(id) ON DELETE SET NULL;
ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS inject_username  VARCHAR(255);
ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS record_session   BOOLEAN NOT NULL DEFAULT false;

-- Pre-session approval requests (one row per user request to open a connection).
CREATE TABLE IF NOT EXISTS guacamole_session_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    connection_id UUID NOT NULL,
    requester_id  UUID NOT NULL,
    reason        TEXT,
    status        VARCHAR(16) NOT NULL DEFAULT 'pending',
    approver_id   UUID,
    decided_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_guac_session_requests_lookup
    ON guacamole_session_requests(connection_id, requester_id, status);

-- Active/ended session tracking + recording ledger.
CREATE TABLE IF NOT EXISTS guacamole_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL,
    connection_id       UUID NOT NULL,
    user_id             UUID,
    guac_session_uuid   VARCHAR(255),
    recording_path      TEXT,
    recording_purged_at TIMESTAMPTZ,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMPTZ,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_guac_sessions_connection
    ON guacamole_sessions(connection_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_guac_sessions_status
    ON guacamole_sessions(status);

-- v37-style RLS belt for guacamole_session_requests.
DROP POLICY IF EXISTS pol_guacamole_session_requests_org_scope ON guacamole_session_requests;
CREATE POLICY pol_guacamole_session_requests_org_scope ON guacamole_session_requests
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE guacamole_session_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_session_requests FORCE  ROW LEVEL SECURITY;

-- v37-style RLS belt for guacamole_sessions.
DROP POLICY IF EXISTS pol_guacamole_sessions_org_scope ON guacamole_sessions;
CREATE POLICY pol_guacamole_sessions_org_scope ON guacamole_sessions
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE guacamole_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_sessions FORCE  ROW LEVEL SECURITY;

-- Grant DML to the runtime app role. Plain GRANT (no DO $$ block) — the migration
-- runner's splitSQL only recognises $$ at the start of a line, so a DO block would
-- be split at the inner semicolon and fail (same lesson as v56/v57).
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_session_requests, guacamole_sessions TO openidx_app;
`

var guacSessionsDown = `-- Migration 059 down.
DROP TABLE IF EXISTS guacamole_sessions CASCADE;
DROP TABLE IF EXISTS guacamole_session_requests CASCADE;
`
