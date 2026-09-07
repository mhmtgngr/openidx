// Package jitgrant is the one place that knows what a time-bound elevation is
// and how to end one.
//
// THE SHAPE IT REPLACES. The product had two representations of a JIT
// elevation. The live one is an access_requests row: resource_type 'role',
// 'group' or 'application', status 'fulfilled', expires_at set -- created by
// governance's approval workflow, which inserts the assignment
// (user_roles / group_memberships / user_application_assignments), and ended by
// its expiry sweep, which removes it again. The other was the jit_grants table,
// written only by internal/governance/jit.go, which no binary could reach.
//
// So jit_grants has been empty on every install ever run, and five live paths
// aimed at it:
//
//   - internal/access/kill_switch.go revoked jit_grants when an account is
//     compromised, and reported pam_jit_grants_revoked. Zero, every time,
//     while the user kept every time-bound role the product had actually
//     granted them. The emergency control did not sever the elevation, and
//     said "0" in a way that reads as "there were none".
//   - internal/access/lifecycle_sweep.go revoked the elevations of disabled
//     users. Nothing.
//   - internal/identity deprovisioning revoked a leaver's elevations. Nothing.
//   - internal/access/user_access_map.go listed a user's active elevations on
//     User Access 360. Always empty.
//   - internal/portal/service.go counted them on the end user's dashboard.
//     Always 0.
//
// Every one of those now goes through this package, against the rows the
// product has. jit_grants and its unreachable service are deleted in the same
// commit (migration v183).
//
// WHY A LEAF PACKAGE. internal/access, internal/identity, internal/portal and
// internal/governance all need this and none should import another: the shared
// revocation used to live unexported in internal/governance, which is exactly
// why the other three wrote their own SQL against the wrong table. A resource
// type wired in here is wired in everywhere, and there is no second place for
// the next one to be forgotten.
package jitgrant

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is satisfied by both *pgxpool.Pool and pgx.Tx, so a caller can run
// this standalone (a background sweep with no surrounding transaction) or
// inside their own transaction (the reviewer decision path, where recording the
// decision and enforcing it must commit together).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Querier adds the read half, for the calls that have to find the elevations
// before ending them.
type Querier interface {
	Execer
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Elevation is one time-bound grant a principal currently holds.
type Elevation struct {
	RequestID    string
	ResourceType string
	ResourceID   string
	ResourceName string
	OrgID        string
}

// Revoke removes a single (user, resource) grant from the underlying access
// table. This is the one place role / group / application revocations live --
// shared by the access-review decision path, the certification reviewer path,
// the auto-revoke-after-deadline sweep, the JIT expiry sweep, the kill switch,
// the lifecycle sweep and deprovisioning -- so "revoke" removes the same access
// everywhere and a new resource type is wired in exactly one spot.
//
// An empty orgID skips the org filter (used by background sweeps that run
// without request org context); user_id is globally unique to one org so the
// (user_id, resource_id) key stays org-bounded either way.
//
// An unknown resource type returns an error rather than silently succeeding: a
// review item marked "revoked" while the access survives is precisely the
// silent hole access reviews exist to close, so callers must fail loudly and
// (in the transactional paths) roll the decision back.
func Revoke(ctx context.Context, q Execer, resourceType, userID, resourceID, orgID string) error {
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

// activeForUser is the definition of "a time-bound elevation this user holds":
// a fulfilled access request with an expiry that has not passed. vault
// credentials are deliberately excluded -- their authorization is the vault
// grant's own expires_at, there is no assignment row to delete, and the callers
// that care about them (the kill switch, deprovisioning) already expire
// vault_access_grants directly.
const activeForUser = `SELECT id, resource_type, resource_id, COALESCE(resource_name, ''), org_id
	  FROM access_requests
	 WHERE requester_id = $1 AND org_id = $2
	   AND status = 'fulfilled'
	   AND expires_at IS NOT NULL AND expires_at > NOW()
	   AND resource_type <> 'vault_credential'`

// ListActiveForUser returns the elevations a user currently holds, soonest
// expiry first.
func ListActiveForUser(ctx context.Context, q Querier, userID, orgID string) ([]Elevation, error) {
	rows, err := q.Query(ctx, activeForUser+` ORDER BY expires_at`, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("list active elevations: %w", err)
	}
	defer rows.Close()
	var out []Elevation
	for rows.Next() {
		var e Elevation
		if err := rows.Scan(&e.RequestID, &e.ResourceType, &e.ResourceID, &e.ResourceName, &e.OrgID); err != nil {
			return nil, fmt.Errorf("scan elevation: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active elevations: %w", err)
	}
	return out, nil
}

// EndAllForUser removes every time-bound elevation a user holds and marks the
// requests that granted them expired. It returns how many it ended.
//
// The count is the number of elevations actually ended, and it is what callers
// report. That matters: the kill switch published this number as
// pam_jit_grants_revoked against a table nothing wrote, so it was always 0 --
// and 0 on that response reads as "this user held none", which is the opposite
// of what an incident responder needs to know.
//
// A failure to remove one assignment stops the run rather than continuing: the
// request must not be marked expired while the access it granted survives,
// which is the same rule the expiry sweep and the review decision path hold to.
func EndAllForUser(ctx context.Context, q Querier, userID, orgID string) (int64, error) {
	elevations, err := ListActiveForUser(ctx, q, userID, orgID)
	if err != nil {
		return 0, err
	}
	var ended int64
	for _, e := range elevations {
		if err := Revoke(ctx, q, e.ResourceType, userID, e.ResourceID, e.OrgID); err != nil {
			return ended, fmt.Errorf("end elevation %s: %w", e.RequestID, err)
		}
		if _, err := q.Exec(ctx,
			`UPDATE access_requests SET status = 'expired', updated_at = NOW()
			  WHERE id = $1 AND org_id = $2`, e.RequestID, e.OrgID); err != nil {
			return ended, fmt.Errorf("mark elevation %s expired: %w", e.RequestID, err)
		}
		ended++
	}
	return ended, nil
}

// EndAllForDisabledUsers is the install-wide reconcile: every time-bound
// elevation still held by a disabled user, ended. It runs under bypass-RLS from
// the lifecycle sweep, so it takes no org and derives each write's org from the
// row it came from.
func EndAllForDisabledUsers(ctx context.Context, q Querier) (int64, error) {
	rows, err := q.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep; each write below is scoped to the org of the row it came from
		`SELECT r.id, r.requester_id, r.resource_type, r.resource_id, r.org_id
		   FROM access_requests r
		   JOIN users u ON u.id = r.requester_id
		  WHERE r.status = 'fulfilled'
		    AND r.expires_at IS NOT NULL AND r.expires_at > NOW()
		    AND r.resource_type <> 'vault_credential'
		    AND u.enabled = false`)
	if err != nil {
		return 0, fmt.Errorf("list elevations of disabled users: %w", err)
	}
	type row struct{ id, user, rtype, rid, org string }
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.user, &r.rtype, &r.rid, &r.org); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan elevation: %w", err)
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("list elevations of disabled users: %w", err)
	}

	var ended int64
	for _, r := range pending {
		if err := Revoke(ctx, q, r.rtype, r.user, r.rid, r.org); err != nil {
			return ended, fmt.Errorf("end elevation %s: %w", r.id, err)
		}
		if _, err := q.Exec(ctx,
			`UPDATE access_requests SET status = 'expired', updated_at = NOW()
			  WHERE id = $1 AND org_id = $2`, r.id, r.org); err != nil {
			return ended, fmt.Errorf("mark elevation %s expired: %w", r.id, err)
		}
		ended++
	}
	return ended, nil
}

// ActiveForUserPredicate is the WHERE clause that identifies a user's live
// elevations, for the one caller that has to embed it in a larger query: the
// portal dashboard reads six privileged-access counters in a single round trip
// and a Go-side helper would cost five more. It carries no parameters, so the
// caller supplies its own `requester_id = $n AND org_id = $m` alongside it --
// and it is a constant here so the definition of "active elevation" cannot
// drift between the dashboard and the controls that end one.
const ActiveForUserPredicate = `status = 'fulfilled'
	   AND expires_at IS NOT NULL AND expires_at > NOW()
	   AND resource_type <> 'vault_credential'`
