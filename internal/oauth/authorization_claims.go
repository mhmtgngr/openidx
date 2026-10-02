package oauth

import (
	"context"
	"errors"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// authorizationClaims reads the authorization facts a token issued now carries
// for the user: the names of their roles (a time-bound assignment only while
// its window lasts), the names of their groups, and the permissions their
// roles give.
//
// It is the one place both answers come from: the access token and the ID
// token are built from it (GenerateJWT, GenerateIDToken), and so is the
// token-claims-change event the SSF drainer signs when a role or a group
// begins or ends (ssf_signal_drain.go). Two copies would let the event tell a
// receiver one set of roles while the next token says another.
//
// Each list is read on its own, and a read that fails leaves its list short
// and is reported in err, after the other lists are read. A token builder
// ignores err, as it always has: the token then asserts less, never more. The
// drainer does not sign on an error, because an event saying "no roles" that
// only means "the read failed" would be a false statement to every receiver.
func (s *Service) authorizationClaims(ctx context.Context, userID, orgID string) (roles, groups, permissions []string, err error) {
	roles, groups, permissions = make([]string, 0), make([]string, 0), make([]string, 0)
	if userID == "" {
		return roles, groups, permissions, nil
	}
	var errs []error
	read := func(into *[]string, sql string) {
		rows, qerr := s.db.Pool.Query(ctx, sql, userID, orgID)
		if qerr != nil {
			errs = append(errs, qerr)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil {
				*into = append(*into, v)
			}
		}
		if rerr := rows.Err(); rerr != nil {
			errs = append(errs, rerr)
		}
	}
	read(&roles, `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`)
	read(&groups, `
		SELECT g.name FROM groups g
		JOIN group_memberships gm ON g.id = gm.group_id
		WHERE gm.user_id = $1 AND gm.org_id = $2
	`)
	read(&permissions, `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`)
	return roles, groups, permissions, errors.Join(errs...)
}

// accessTokenLifetime is how long a token issued now for the user lives, in
// seconds: the client's lifetime, cut to the end of the earliest window among
// the time-bound roles the token carries. Section 6.5 of the third-party
// access framework: a token that carries an elevation does not outlive it.
//
// The role leaves a token issued after its window (authorizationClaims reads
// only live assignments), and the role-expiry sweep cuts the tokens that still
// carry it within a minute -- through the revocation marker, which lives in
// Redis. This makes the token itself say when it ends, so a resource server
// that verifies the signature offline, or one that reads no marker, stops
// accepting the role at the window's end as well. The token endpoint reports
// the same lifetime in expires_in, and the client refreshes then; the token
// it gets carries what is still live.
//
// A token with no user (client credentials) and a read that fails keep the
// client's lifetime: the read that fails is the one the token builder makes
// too, and a token built without the role has no window to end with.
func (s *Service) accessTokenLifetime(ctx context.Context, userID string, configured int) int {
	if userID == "" {
		return configured
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return configured
	}
	var left *float64
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM MIN(ur.expires_at) - NOW())::float8
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2
		AND ur.expires_at IS NOT NULL AND ur.expires_at > NOW()
	`, userID, org.ID).Scan(&left); err != nil || left == nil {
		return configured
	}
	secs := int(*left)
	if secs < 1 {
		secs = 1
	}
	if secs < configured {
		return secs
	}
	return configured
}
