// Package sessionend is how a path that ends a session in another binary tells
// oauth-service to announce it to the relying parties.
//
// Back-channel logout (internal/oauth/backchannel_logout.go) mints a logout
// token with the issuer's signing key and POSTs it to every relying party a
// session reached. oauth-service does that from its own revocation funnel and
// nowhere else can: the identity service's session pages, password change,
// offboarding, lifecycle actions and deprovisioning, the admin console's
// revoke-session and revoke-all, the breach responder, the DSAR delete and
// restrict, the risk engine's remediation, the device-revoke and kill-switch
// paths in access and the SCIM deprovisioner all end sessions with a raw
// UPDATE or DELETE on the sessions table, in five binaries, with no key.
//
// This package is the seam, the same one ssfsignal is for the SSF transmitter:
// a severing path calls it on the handle it already holds -- a transaction if
// it has one, the pool if not -- BEFORE its own statement, and one row per
// session that is still live and reached at least one client lands in
// backchannel_logout_pending (migration v198). oauth-service's drainer resolves
// the captured clients against the tenant's registered back_channel_logout_uri
// values and delivers.
//
// BEFORE, NOT AFTER, because six of those paths DELETE the row and a DSAR
// erasure deletes it on purpose: the tenant, the user, the session id the
// relying party saw as sid and the clients holding refresh tokens bound to the
// session are all gone once the sever has run. The capture is a single
// INSERT ... SELECT, so its atomicity is exactly the atomicity of the handle
// it is given; a caller inside a transaction gets the capture committed or
// rolled back with the sever.
//
// ONLY LIVE SESSIONS ARE CAPTURED. A session oauth-service already revoked was
// already announced from the funnel; capturing it again would tell the relying
// party twice. A session no client ever reached (no login client, no refresh
// token) is not captured: there is nobody to tell.
//
// This package imports no service and no signing code, so every severing path
// in the tree can import it without a cycle.
package sessionend

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is the one method this package needs from a database handle.
// *pgxpool.Pool, pgx.Tx and the scoped pool wrapper all satisfy it.
type Execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// ErrNoTenant is returned for an empty org id: a capture that names no
// tenant would be refused by the table's belt anyway, and refusing it here
// says why.
var ErrNoTenant = errors.New("sessionend: refusing to capture sessions without a tenant")

// ErrNoSubject is returned when neither a user nor a session is named.
var ErrNoSubject = errors.New("sessionend: refusing to capture sessions without a user or a session")

// captureColumns is the SELECT half every capture shares: the session's
// tenant, id and user, and the distinct non-empty set of its login client and
// every client holding a refresh token bound to it. Rows whose set is empty
// are filtered here and, belt and braces, refused by the table's CHECK.
const captureColumns = `
	INSERT INTO backchannel_logout_pending (org_id, session_id, user_id, client_ids)
	SELECT s.org_id, s.id, s.user_id,
	       ARRAY(SELECT DISTINCT c FROM (
	                 SELECT s.client_id AS c
	                 UNION ALL
	                 SELECT r.client_id FROM oauth_refresh_tokens r
	                  WHERE r.session_id = s.id AND r.org_id = s.org_id) x
	              WHERE COALESCE(c, '') <> '')
	  FROM sessions s
	 WHERE s.org_id = $1
	   AND (s.revoked IS NULL OR s.revoked = false)
	   AND EXISTS (SELECT 1 FROM (
	                 SELECT s.client_id AS c
	                 UNION ALL
	                 SELECT r.client_id FROM oauth_refresh_tokens r
	                  WHERE r.session_id = s.id AND r.org_id = s.org_id) y
	              WHERE COALESCE(c, '') <> '')`

// ForUser captures every live session of userID in orgID. Call it before the
// statement that revokes or deletes them.
func ForUser(ctx context.Context, exec Execer, orgID, userID string) error {
	if orgID == "" {
		return ErrNoTenant
	}
	if userID == "" {
		return ErrNoSubject
	}
	if _, err := exec.Exec(ctx, captureColumns+` AND s.user_id = $2`, orgID, userID); err != nil {
		return fmt.Errorf("sessionend: capture user sessions: %w", err)
	}
	return nil
}

// ForSession captures one live session. Call it before the statement that
// revokes or deletes it.
func ForSession(ctx context.Context, exec Execer, orgID, sessionID string) error {
	if sessionID == "" {
		return ErrNoSubject
	}
	return ForSessions(ctx, exec, orgID, []string{sessionID})
}

// ForSessions captures the live sessions among sessionIDs. Call it before the
// statement that revokes or deletes them. An empty list captures nothing and
// is not an error: a caller that computed "no sessions" has nothing to say.
func ForSessions(ctx context.Context, exec Execer, orgID string, sessionIDs []string) error {
	if orgID == "" {
		return ErrNoTenant
	}
	if len(sessionIDs) == 0 {
		return nil
	}
	if _, err := exec.Exec(ctx, captureColumns+` AND s.id::text = ANY($2)`, orgID, sessionIDs); err != nil {
		return fmt.Errorf("sessionend: capture sessions: %w", err)
	}
	return nil
}
