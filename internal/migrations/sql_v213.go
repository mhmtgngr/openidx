package migrations

// Migration v213 -- pam_entries.proxy_route_id: a proxy route's brokered
// connection is a PAM entry.
//
// A remote-access route (rdp, ssh, vnc, telnet) is provisioned a Guacamole
// connection, recorded in guacamole_connections, and any authenticated user of
// the organization could launch it through POST
// /guacamole/connections/:routeId/connect: the handler read the row, consumed a
// session approval when the connection asked for one, and injected the
// connection's vault secret. It asked nothing about the caller. The PAM entry
// path (POST /pam/entries/:id/connect) asks everything: a connect grant held
// directly, through a role or through a group (pam_entry_grants), a single-use
// approval on the entry, the overlay check, a fresh second factor, and a ledger
// row in pam_entry_sessions. Two launch paths onto the same hosts with two
// sets of controls is how the weaker one stays reachable, so the route-based
// launch now goes through the entry path, and for that every brokered route
// needs an entry.
//
// This column links them: a pam_entries row with proxy_route_id set stands
// for that route's brokered connection, and the route's connect handler
// resolves it and hands over. The partial unique index keeps it to one entry
// per route. ON DELETE CASCADE, because the entry describes the route's
// target and nothing else: guacamole_connections.route_id cascades the same
// way (v54), and an entry outliving its route would be a credential-bearing
// record nothing brokers.
//
// BACKFILL. Every existing brokered connection gets its entry, copying what
// the route's connection record holds: the target, the injected username and
// vault secret, the provisioned Guacamole connection id, require_approval and
// record_session. Reach mode is direct, which is what the route path always
// was. The entry carries no grants: nobody held a grant on these connections
// before, because nothing checked one, and inventing grants for every user of
// the organization would preserve the hole this closes. Until an administrator
// grants connect on the entry (or the caller is an administrator), the route's
// Connect refuses, and My Privileged Access no longer lists it, so what the
// list shows is what connect does.
//
// Down drops the index and the column. The entries stay: they are entries an
// administrator could have made, and the code that runs at v212 reads them as
// such.

var pamEntriesProxyRouteUp = `-- Migration 213: a brokered proxy route is a PAM entry.
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS proxy_route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pam_entries_proxy_route ON pam_entries(proxy_route_id) WHERE proxy_route_id IS NOT NULL;
INSERT INTO pam_entries (org_id, proxy_route_id, name, entry_type, description, hostname, port, username,
                         vault_secret_id, guacamole_connection_id, require_approval, record_session, reach_mode,
                         created_at, updated_at)
SELECT gc.org_id, gc.route_id, pr.name, gc.protocol,
       'Brokered connection of proxy route ' || pr.name,
       gc.hostname, gc.port, NULLIF(gc.inject_username, ''),
       gc.vault_secret_id, gc.guacamole_connection_id, gc.require_approval, gc.record_session, 'direct',
       COALESCE(gc.created_at, NOW()), NOW()
  FROM guacamole_connections gc
  JOIN proxy_routes pr ON pr.id = gc.route_id AND pr.org_id = gc.org_id
 WHERE gc.protocol IN ('rdp', 'ssh', 'vnc', 'telnet')
   AND NOT EXISTS (SELECT 1 FROM pam_entries pe WHERE pe.proxy_route_id = gc.route_id);
`

var pamEntriesProxyRouteDown = `-- Migration 213 down: unlink the entries from their routes; the entries stay.
DROP INDEX IF EXISTS idx_pam_entries_proxy_route;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS proxy_route_id;
`
