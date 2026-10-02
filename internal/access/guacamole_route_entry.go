// Package access — the PAM entry behind a proxy route's brokered connection.
//
// A remote-access proxy route (rdp, ssh, vnc, telnet) is provisioned a
// Guacamole connection and recorded in guacamole_connections. Its launch,
// POST /guacamole/connections/:routeId/connect, used to be its own path: it
// read that row, consumed a session approval when the row asked for one,
// injected the row's vault secret and returned a connect URL — and asked
// nothing about who was calling. The PAM entry path asks everything (a connect
// grant, a single-use approval on the entry, the overlay check, a fresh second
// factor, a ledger row), so the route launch now resolves the entry that
// stands for the route and hands over to it (connectPamEntry).
//
// The entry mirrors the connection record: name, target, injected username,
// vault secret, provisioned connection id, require_approval and
// record_session are copied from guacamole_connections whenever the route is
// provisioned or its credential settings saved, and on first use if the entry
// is missing (an install whose v213 backfill predates a route made by a path
// this file does not know). The grants are the entry's own: nothing on the
// route ever said who may launch it, and that is the gap this closes.
package access

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// errRouteNotBrokered is returned when a route has no brokered connection in
// the caller's organization, which the route handlers answer as 404 exactly as
// they did before the entry existed.
var errRouteNotBrokered = errors.New("no Guacamole connection found for this route")

// syncRouteEntry makes or refreshes the PAM entry standing for routeID's
// brokered connection and returns its id. It is an upsert keyed on
// proxy_route_id (one entry per route, v213), copying the connection record
// as the backfill did, so a credential or flag saved on the route is what the
// entry path enforces on the next launch. Grants, folder, reach mode and
// anything else administrators set on the entry itself are left alone.
//
// orgID is a parameter, not a context read, and is on both the connection
// row and the route: the connect handler's whole tenant isolation is that a
// route id from another organization resolves nothing here.
func (s *Service) syncRouteEntry(ctx context.Context, orgID, routeID string) (string, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entries (org_id, proxy_route_id, name, entry_type, description, hostname, port, username,
		                         vault_secret_id, guacamole_connection_id, require_approval, record_session, reach_mode)
		SELECT gc.org_id, gc.route_id, pr.name, gc.protocol,
		       'Brokered connection of proxy route ' || pr.name,
		       gc.hostname, gc.port, NULLIF(gc.inject_username, ''),
		       gc.vault_secret_id, gc.guacamole_connection_id, gc.require_approval, gc.record_session, 'direct'
		  FROM guacamole_connections gc
		  JOIN proxy_routes pr ON pr.id = gc.route_id AND pr.org_id = gc.org_id
		 WHERE gc.route_id = $1 AND gc.org_id = $2
		   AND gc.protocol IN ('rdp', 'ssh', 'vnc', 'telnet')
		ON CONFLICT (proxy_route_id) WHERE proxy_route_id IS NOT NULL DO UPDATE SET
		   name                    = EXCLUDED.name,
		   entry_type              = EXCLUDED.entry_type,
		   hostname                = EXCLUDED.hostname,
		   port                    = EXCLUDED.port,
		   username                = EXCLUDED.username,
		   vault_secret_id         = EXCLUDED.vault_secret_id,
		   guacamole_connection_id = EXCLUDED.guacamole_connection_id,
		   require_approval        = EXCLUDED.require_approval,
		   record_session          = EXCLUDED.record_session,
		   updated_at              = NOW()
		 WHERE pam_entries.org_id = $2
		RETURNING id::text`, routeID, orgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errRouteNotBrokered
	}
	return id, err
}

// routeConnection is what the route handlers still need from the connection
// record itself once the entry path decides the rest: the row's own id, which
// the moderation table keys on, and whether a moderator must be watching.
type routeConnection struct {
	ID               string
	EntryID          string
	RequireModerator bool
}

// resolveRouteConnection finds routeID's brokered connection in orgID and the
// entry standing for it, making the entry if it is missing.
func (s *Service) resolveRouteConnection(ctx context.Context, orgID, routeID string) (routeConnection, error) {
	var rc routeConnection
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id::text, require_moderator FROM guacamole_connections WHERE route_id = $1 AND org_id = $2`,
		routeID, orgID).Scan(&rc.ID, &rc.RequireModerator)
	if errors.Is(err, pgx.ErrNoRows) {
		return rc, errRouteNotBrokered
	}
	if err != nil {
		return rc, err
	}
	rc.EntryID, err = s.syncRouteEntry(ctx, orgID, routeID)
	return rc, err
}
