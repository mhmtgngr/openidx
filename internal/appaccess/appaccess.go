// Package appaccess owns the single question "may this principal reach this
// application?".
//
// It exists because that question used to be answered in several places with
// different SQL: the portal catalogue counted only direct assignments, the
// proxy checked route roles, and the Ziti dial policy granted every enrolled
// identity. Those answers disagreed, so an app could be listed and unreachable
// or reachable and unlisted. Every enforcement point now calls this package.
//
// orgID is an explicit parameter rather than read from orgctx: this package is
// consumed by three services with different context plumbing, and an explicit
// scope is also what makes it testable.
package appaccess

import (
	"context"
	"fmt"

	"github.com/openidx/openidx/internal/common/database"
)

// AppRef is an application the caller may reach. RouteID is empty when the
// application has no published route — those are gated at /oauth/authorize
// instead of on the overlay.
type AppRef struct {
	ID      string
	Name    string
	RouteID string
}

// Principals are the grant holders for one application.
type Principals struct {
	UserIDs  []string
	GroupIDs []string
}

// assignedPredicate matches an application assigned to the user directly OR
// through a group they belong to. $1 = user id, $2 = org id.
const assignedPredicate = `(
	EXISTS (SELECT 1 FROM user_application_assignments uaa
	         WHERE uaa.application_id = a.id AND uaa.user_id = $1 AND uaa.org_id = $2)
	OR EXISTS (SELECT 1 FROM group_application_assignments gaa
	            JOIN group_memberships gm ON gm.group_id = gaa.group_id
	           WHERE gaa.application_id = a.id AND gm.user_id = $1 AND gaa.org_id = $2)
)`

// Allowed reports whether the user may reach the application. A disabled
// application is never reachable, however it is assigned.
func Allowed(ctx context.Context, db *database.PostgresDB, userID, orgID, appID string) (bool, error) {
	if userID == "" || orgID == "" || appID == "" {
		return false, nil
	}
	var ok bool
	err := db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM applications a
			 WHERE a.id = $3 AND a.enabled = true AND a.org_id = $2
			   AND `+assignedPredicate+`
		)`, userID, orgID, appID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("appaccess: allowed: %w", err)
	}
	return ok, nil
}

// AppsForUser lists every application the user may reach, deduped.
func AppsForUser(ctx context.Context, db *database.PostgresDB, userID, orgID string) ([]AppRef, error) {
	if userID == "" || orgID == "" {
		return nil, nil
	}
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT a.id, a.name, COALESCE(a.route_id::text, '')
		  FROM applications a
		 WHERE a.enabled = true AND a.org_id = $2
		   AND `+assignedPredicate+`
		 ORDER BY a.name`, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("appaccess: apps for user: %w", err)
	}
	defer rows.Close()

	out := []AppRef{}
	for rows.Next() {
		var a AppRef
		if err := rows.Scan(&a.ID, &a.Name, &a.RouteID); err != nil {
			return nil, fmt.Errorf("appaccess: scan app: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PrincipalsForApp returns the users and groups granted an application. The
// reconciler uses it to decide which identities a per-app dial policy covers.
func PrincipalsForApp(ctx context.Context, db *database.PostgresDB, appID, orgID string) (Principals, error) {
	var p Principals
	if appID == "" || orgID == "" {
		return p, nil
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT user_id FROM user_application_assignments WHERE application_id = $1 AND org_id = $2`,
		appID, orgID)
	if err != nil {
		return p, fmt.Errorf("appaccess: principals (users): %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return p, fmt.Errorf("appaccess: scan user principal: %w", err)
		}
		p.UserIDs = append(p.UserIDs, id)
	}
	rows.Close()

	rows, err = db.Pool.Query(ctx,
		`SELECT group_id FROM group_application_assignments WHERE application_id = $1 AND org_id = $2`,
		appID, orgID)
	if err != nil {
		return p, fmt.Errorf("appaccess: principals (groups): %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return p, fmt.Errorf("appaccess: scan group principal: %w", err)
		}
		p.GroupIDs = append(p.GroupIDs, id)
	}
	return p, rows.Err()
}
