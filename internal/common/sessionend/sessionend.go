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
// AND WHAT THE SESSION CAN STILL MINT. Telling the relying parties stops
// nothing. The refresh grant refuses a refresh token when its own row is
// revoked (revoked_at), when the revoked_session:<id> marker in Redis names
// its session, or when its session's row is gone, revoked or expired; it
// never reads this package's table. A path that ends a session revokes the
// refresh tokens bound to it with RevokeRefreshTokens or
// RevokeUserRefreshTokens, which holds with Redis in any state.
//
// The grant's reading of the session row is the net under that, not a
// substitute for it. It catches a session ended before these helpers existed,
// a session a future path ends and forgets, and a rotation that was already in
// flight when the rows were revoked. It answers only for tokens bound to a
// session: a refresh token the device authorization grant issued is bound to
// none, and revoking its row is the only thing that ends it.
//
// Until that read was added, the grant decided on the token's row and the
// marker alone, and a path that ended a session and left its refresh tokens
// alone left every device they were issued to minting access tokens: at once
// if it wrote no marker, from the moment the marker expired if it wrote one,
// and whenever Redis was down or came back empty.
//
// This package imports no service and no signing code, so every severing path
// in the tree can import it without a cycle.
package sessionend

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
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

// RevokeRefreshTokens revokes, in orgID, every refresh token bound to one of
// sessionIDs, and reports how many it revoked. Call it when those sessions
// end, before the statement that ends them or in the same transaction.
//
// An id that is not a UUID is skipped rather than refused: session_id is a
// uuid column, so no refresh token can be bound to one, and a caller handed
// such an id from a request has nothing here to revoke.
func RevokeRefreshTokens(ctx context.Context, exec Execer, orgID string, sessionIDs []string) (int64, error) {
	if orgID == "" {
		return 0, ErrNoTenant
	}
	ids := make([]string, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		if _, err := uuid.Parse(id); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := exec.Exec(ctx, `
		UPDATE oauth_refresh_tokens SET revoked_at = NOW()
		 WHERE org_id = $1 AND session_id = ANY($2::text[]::uuid[]) AND revoked_at IS NULL`,
		orgID, ids)
	if err != nil {
		return 0, fmt.Errorf("sessionend: revoke the sessions' refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeUserRefreshTokens revokes every refresh token userID holds in orgID,
// whichever session it is bound to and whether it is bound to one at all: a
// token issued by the device authorization grant carries no session, and is a
// signed-in device all the same. keepSessionID, when it is not empty, names
// the one session whose tokens are left alone: a user who changes their own
// password keeps the session they changed it from.
func RevokeUserRefreshTokens(ctx context.Context, exec Execer, orgID, userID, keepSessionID string) (int64, error) {
	if orgID == "" {
		return 0, ErrNoTenant
	}
	if userID == "" {
		return 0, ErrNoSubject
	}
	tag, err := exec.Exec(ctx, `
		UPDATE oauth_refresh_tokens SET revoked_at = NOW()
		 WHERE org_id = $1 AND user_id = $2 AND revoked_at IS NULL
		   AND ($3::text = '' OR session_id IS NULL OR session_id::text <> $3::text)`,
		orgID, userID, keepSessionID)
	if err != nil {
		return 0, fmt.Errorf("sessionend: revoke the user's refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
