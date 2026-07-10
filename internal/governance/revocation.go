package governance

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// sanitizeForLog strips CR/LF from user-supplied values before they are written
// to logs, preventing forged or split log entries (CWE-117 log injection).
func sanitizeForLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// revocationExecer is satisfied by both *pgxpool.Pool and pgx.Tx, so the shared
// revocation can run standalone (background sweeps that have no surrounding
// transaction) or inside a caller's transaction (the reviewer decision path,
// where recording the decision and enforcing it must commit together).
type revocationExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// revokeResourceAssignment removes a single (user, resource) grant from the
// underlying access table for the given governance resource type. This is the
// one place role / group / application revocations live — shared by the
// access-review decision path (SubmitReviewDecision / BatchSubmitDecisions), the
// certification reviewer path, and the auto-revoke-after-deadline sweep — so
// "revoke" removes the same access everywhere and a new resource type is wired
// in exactly one spot.
//
// An empty orgID skips the org filter (used by background sweeps that run
// without request org context); user_id is globally unique to one org so the
// (user_id, resource_id) key stays org-bounded either way.
//
// An unknown resource type returns an error rather than silently succeeding: a
// review item marked "revoked" while the access survives is precisely the
// silent hole access reviews exist to close, so callers must fail loudly and
// (in the transactional paths) roll the decision back.
func revokeResourceAssignment(ctx context.Context, q revocationExecer, resourceType, userID, resourceID, orgID string) error {
	filter := ""
	args := []any{userID, resourceID}
	if orgID != "" {
		filter = " AND org_id = $3"
		args = append(args, orgID)
	}

	switch resourceType {
	case "role", "privileged_role":
		// privileged_role review items point at a plain user_roles assignment;
		// the "privileged" flavor only reflects which rows the review surfaced.
		if _, err := q.Exec(ctx,
			`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`+filter, args...); err != nil {
			return fmt.Errorf("revoke role: %w", err)
		}
	case "group":
		if _, err := q.Exec(ctx,
			`DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2`+filter, args...); err != nil {
			return fmt.Errorf("revoke group: %w", err)
		}
	case "application":
		if _, err := q.Exec(ctx,
			`DELETE FROM user_application_assignments WHERE user_id = $1 AND application_id = $2`+filter, args...); err != nil {
			return fmt.Errorf("revoke application: %w", err)
		}
	default:
		return fmt.Errorf("unsupported revocation resource type %q", resourceType)
	}
	return nil
}
