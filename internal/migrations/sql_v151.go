package migrations

// Migration v151 — the PAM broker's connection registry.
//
// A `guacamole_connections` row is the definition of a privileged session
// target: which host, which port, which protocol, which vault secret gets
// injected into the session, and whether the session needs an approval, a
// moderator, or a recording. It is the most consequential row in the PAM
// surface, and it has never carried a tenant.
//
// v59 said so and moved on. Its own header:
//
//	Both new tables are placed under the v37 FORCE-RLS belt with the standard
//	pol_<t>_org_scope predicate. guacamole_connections is NOT belted (only ALTERed).
//
// That migration added `vault_secret_id` to this table — the column that
// decides which credential is injected — belted the two tables it created
// alongside it, and left the one holding the credential pointer unbelted with
// no reason given. This migration gives it org_id and the belt.
//
// WHAT WAS REACHABLE. `POST /guacamole/connections/:routeId/connect` carries
// no admin gate: any authenticated user may call it. The handler resolves the
// caller's organization, refuses when there is none — and then loads the
// target row by route id alone:
//
//	SELECT id, guacamole_connection_id, protocol, hostname, port,
//	       COALESCE(vault_secret_id::text,''), ...
//	  FROM guacamole_connections WHERE route_id=$1
//
// The organization it just insisted on is never used. What follows is not a
// disclosure but an escalation: the handler reads that row's vault secret
// under orgctx.WithBypassRLS — deliberately, because the credential must be
// legible to the server that injects it — pushes the credential into the
// broker as connection parameters, and returns a connect URL. A user of one
// tenant, holding nothing but another tenant's route id, gets a live RDP, SSH
// or VNC session onto that tenant's host with that tenant's credential typed
// in for them. The vault belt is intact and irrelevant: it was bypassed on
// purpose, and the connection row was the thing that decided which secret to
// bypass it for.
//
// THE GATES DID NOT GATE. Both pre-session controls key on the connection:
//
//	checkAndConsumeApproval:  WHERE connection_id = $1 AND requester_id = $2 AND status = 'approved'
//	checkModerationActive:    WHERE connection_id = $1 AND requester_id = $2 AND status = 'active'
//
// `guacamole_session_requests` and `guacamole_moderation_sessions` are both
// belted, so each query sees only the caller's own organization's rows — and
// that is precisely why the gates cannot help. The caller opens the request
// against the other tenant's connection id, an administrator of the CALLER's
// tenant approves it, and the gate passes on a row that never left home. A
// four-eyes control satisfied entirely inside the attacker's own tenant is a
// control guarding the door of a room they are already standing in. Scoping
// the connection is what gives those two queries something to mean.
//
// The list endpoint is the plain read of the same defect: `SELECT ... FROM
// guacamole_connections ORDER BY created_at DESC`, no WHERE clause, no admin
// gate — every tenant's hostnames, ports, protocols and connection parameters.
// The route table registers app publishing next to it with the comment
// "Without it any authenticated user could register/discover/publish/delete
// apps"; the same sentence was true here and was not written.
//
// A COMMENT THAT HAD IT BACKWARDS. handleListMyGuacConnections carried:
//
//	RLS scopes guacamole_connections via the request context; the explicit
//	pr.org_id predicate is defence in depth.
//
// Inverted. There was no org_id on the table and no policy over it, so the
// predicate it calls defence in depth was the entire defence, and the belt it
// credits did not exist. After this migration the sentence is true, which is
// the only honest way to fix it.
//
// BACKFILL. `route_id` FKs proxy_routes ON DELETE CASCADE, and a route belongs
// to exactly one organization, so the route is the attribution. The column is
// nullable, so a row written without one falls back to the oldest organization
// where an operator can see it. UNIQUE(route_id) is left alone: the route
// already determines the org, so the key cannot span tenants — the same case
// as v144's entity_id and v149's active-hold indexes, unlike v143's provider
// key which had to be re-scoped.
//
// AND ONE TABLE LEAVES BY BEING DELETED. `guacamole_connection_pool` was on
// the register as "live connection tokens per user". It holds none, and never
// has:
//
//   - GetPooledConnection and CleanupExpiredConnections have no callers.
//   - Nothing anywhere SELECTs the table; the comment on the token column says
//     it is write-only.
//   - The write itself cannot succeed. savePooledConnection ends in
//     ON CONFLICT (connection_id), and connection_id has only a plain index —
//     no unique constraint exists on this table, so Postgres rejects the
//     statement at plan time with 42P10, every time, into a logger.Warn.
//
// v67 widened its token column so the tokens it stores would be encrypted at
// rest. It stores none. Three layers of care over a table that has been empty
// on every install since v54; scoping it would have been a fourth. It is
// dropped instead, and the census in tools/orgscope reads DROP TABLE, so it
// leaves the register by leaving the schema.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var guacConnectionScopeUp = `-- Migration 151: scope and belt guacamole_connections; drop the dead pool table.

ALTER TABLE guacamole_connections ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- A brokered connection fronts exactly one route, and a route belongs to
-- exactly one organization.
UPDATE guacamole_connections gc SET org_id = pr.org_id FROM proxy_routes pr
 WHERE pr.id = gc.route_id AND gc.org_id IS NULL AND pr.org_id IS NOT NULL;

-- route_id is nullable, so a row can be orphaned only by having been written
-- without one. Those go where an operator can still find them.
UPDATE guacamole_connections SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE guacamole_connections ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_guacamole_connections_org ON guacamole_connections(org_id);

DROP POLICY IF EXISTS pol_guacamole_connections_org_scope ON guacamole_connections;
CREATE POLICY pol_guacamole_connections_org_scope ON guacamole_connections
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE guacamole_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_connections FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_connections TO openidx_app;

-- Never written to, never read from, and its only INSERT names a constraint
-- that does not exist. See the header.
DROP TABLE IF EXISTS guacamole_connection_pool CASCADE;
`

// Down lifts the belt and drops the column this migration added, and puts the
// pool table back in the shape v67 left it (token TEXT) so a rollback past v67
// still finds the column it means to narrow.
var guacConnectionScopeDown = `-- Rollback 151.

ALTER TABLE guacamole_connections NO FORCE ROW LEVEL SECURITY;
ALTER TABLE guacamole_connections DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_guacamole_connections_org_scope ON guacamole_connections;
DROP INDEX IF EXISTS idx_guacamole_connections_org;
ALTER TABLE guacamole_connections DROP COLUMN IF EXISTS org_id;

CREATE TABLE IF NOT EXISTS guacamole_connection_pool (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id VARCHAR(255) NOT NULL,
    token TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ DEFAULT NOW(),
    use_count INTEGER DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guac_pool_connection ON guacamole_connection_pool(connection_id);
CREATE INDEX IF NOT EXISTS idx_guac_pool_user ON guacamole_connection_pool(user_id);
CREATE INDEX IF NOT EXISTS idx_guac_pool_expires ON guacamole_connection_pool(expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_connection_pool TO openidx_app;
`
