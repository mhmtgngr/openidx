package abac

import (
	"context"

	"github.com/openidx/openidx/internal/common/database"
)

// SubjectAttributes builds the attribute map a policy is evaluated against.
//
// The attributes are the ones this schema actually stores. That matters: a
// policy written against an attribute nothing populates matches nothing, and
// before ABAC enforced anything there was no reason for anyone to notice which
// attributes those were. internal/identity's User struct carries an
// `Attributes map[string]string` field with a `db:"attributes"` tag for a
// column the users table does not have, so it is deliberately NOT a source
// here -- reading it would give every subject an empty bag and every policy a
// silent non-match.
//
// Keys:
//
//	user_id, username, email, department, job_title, employment_status,
//	enabled  — from the users row
//	roles    — role names, as a list; `in` / `not_in` match any member
//	groups   — group names, as a list
//
// A missing column value becomes an empty string rather than being absent, so
// `neq` on an unset department behaves like a comparison against "" instead of
// silently failing the condition.
func SubjectAttributes(ctx context.Context, db *database.PostgresDB, userID, orgID string) (map[string]interface{}, error) {
	attrs := map[string]interface{}{
		"user_id": userID,
		"roles":   []string{},
		"groups":  []string{},
	}
	if db == nil || db.Pool == nil || userID == "" || orgID == "" {
		return attrs, nil
	}

	var username, email, department, jobTitle, employmentStatus string
	var enabled bool
	err := db.Pool.QueryRow(ctx, `
		SELECT COALESCE(username, ''), COALESCE(email, ''), COALESCE(department, ''),
		       COALESCE(job_title, ''), COALESCE(employment_status, ''), enabled
		FROM users WHERE id = $1 AND org_id = $2`, userID, orgID,
	).Scan(&username, &email, &department, &jobTitle, &employmentStatus, &enabled)
	if err != nil {
		return attrs, err
	}
	attrs["username"] = username
	attrs["email"] = email
	attrs["department"] = department
	attrs["job_title"] = jobTitle
	attrs["employment_status"] = employmentStatus
	attrs["enabled"] = enabled

	roles, err := stringColumn(ctx, db, `
		SELECT r.name FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id AND r.org_id = ur.org_id
		WHERE ur.user_id = $1 AND ur.org_id = $2`, userID, orgID)
	if err != nil {
		return attrs, err
	}
	attrs["roles"] = roles

	groups, err := stringColumn(ctx, db, `
		SELECT g.name FROM group_memberships gm
		JOIN groups g ON g.id = gm.group_id AND g.org_id = gm.org_id
		WHERE gm.user_id = $1 AND gm.org_id = $2`, userID, orgID)
	if err != nil {
		return attrs, err
	}
	attrs["groups"] = groups

	return attrs, nil
}

func stringColumn(ctx context.Context, db *database.PostgresDB, query, userID, orgID string) ([]string, error) {
	rows, err := db.Pool.Query(ctx, query, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
