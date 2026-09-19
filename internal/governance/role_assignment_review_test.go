package governance

import (
	"context"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestRoleAssignmentReviewNamesTheReach is the regression test for the
// role-assignment review that was a copy of the user-access review. It is
// DB-backed because the defect is a query: whether composite_roles is walked
// at all, and whether the walk stops.
//
// Fixture: platform_admin -> auditor -> reader, and reader -> platform_admin
// (a cycle, so the walk has to terminate and must not list the root as its
// own reach). operator stands alone. An enabled user holds platform_admin and
// operator; a disabled user holds platform_admin and must produce nothing.
func TestRoleAssignmentReviewNamesTheReach(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000020"
	const otherOrg = "00000000-0000-0000-0000-000000000021"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true);
		CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(255) NOT NULL, org_id UUID NOT NULL);
		CREATE TABLE user_roles (user_id UUID NOT NULL, role_id UUID NOT NULL, org_id UUID NOT NULL, PRIMARY KEY (user_id, role_id));
		CREATE TABLE composite_roles (parent_role_id UUID NOT NULL, child_role_id UUID NOT NULL, org_id UUID NOT NULL, PRIMARY KEY (parent_role_id, child_role_id));
		CREATE TABLE review_items (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			review_id UUID,
			user_id UUID,
			resource_type VARCHAR(100) NOT NULL,
			resource_id VARCHAR(255) NOT NULL,
			resource_name VARCHAR(255),
			decision VARCHAR(50) DEFAULT 'pending',
			decided_by UUID,
			decided_at TIMESTAMPTZ,
			comments TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	const (
		enabledUser  = "bbbbbbbb-0000-0000-0000-000000000001"
		disabledUser = "bbbbbbbb-0000-0000-0000-000000000002"
		foreignUser  = "bbbbbbbb-0000-0000-0000-000000000003"
		platformAdm  = "aaaaaaaa-0000-0000-0000-000000000001"
		auditor      = "aaaaaaaa-0000-0000-0000-000000000002"
		reader       = "aaaaaaaa-0000-0000-0000-000000000003"
		operator     = "aaaaaaaa-0000-0000-0000-000000000004"
		foreignRole  = "aaaaaaaa-0000-0000-0000-000000000005"
	)
	seed := []string{
		`INSERT INTO users VALUES ('` + enabledUser + `','` + orgID + `',true), ('` + disabledUser + `','` + orgID + `',false), ('` + foreignUser + `','` + otherOrg + `',true)`,
		`INSERT INTO roles VALUES ('` + platformAdm + `','platform_admin','` + orgID + `'), ('` + auditor + `','auditor','` + orgID + `'),
		                          ('` + reader + `','reader','` + orgID + `'), ('` + operator + `','operator','` + orgID + `'),
		                          ('` + foreignRole + `','platform_admin','` + otherOrg + `')`,
		`INSERT INTO composite_roles VALUES ('` + platformAdm + `','` + auditor + `','` + orgID + `'), ('` + auditor + `','` + reader + `','` + orgID + `'),
		                                    ('` + reader + `','` + platformAdm + `','` + orgID + `')`,
		`INSERT INTO user_roles VALUES ('` + enabledUser + `','` + platformAdm + `','` + orgID + `'), ('` + enabledUser + `','` + operator + `','` + orgID + `'),
		                               ('` + disabledUser + `','` + platformAdm + `','` + orgID + `'), ('` + foreignUser + `','` + foreignRole + `','` + otherOrg + `')`,
	}
	for _, q := range seed {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}

	s := &Service{db: db, logger: zaptest.NewLogger(t)}

	populate := func(reviewID string, typ ReviewType) {
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := s.populateReviewItems(ctx, tx, &AccessReview{ID: reviewID, Type: typ}); err != nil {
			t.Fatalf("populate %s: %v", typ, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	type item struct{ user, typ, resource, name string }
	items := func(reviewID string) []item {
		rows, err := db.Pool.Query(ctx, `SELECT user_id, resource_type, resource_id, resource_name FROM review_items WHERE review_id = $1 ORDER BY user_id, resource_name`, reviewID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.user, &it.typ, &it.resource, &it.name); err != nil {
				t.Fatal(err)
			}
			out = append(out, it)
		}
		return out
	}

	const roleReview = "dddddddd-0000-0000-0000-000000000001"
	populate(roleReview, ReviewTypeRoleAssignment)
	got := items(roleReview)
	want := []item{
		{enabledUser, "role_assignment", operator, "operator"},
		{enabledUser, "role_assignment", platformAdm, "platform_admin (also grants: auditor, reader)"},
	}
	sort.Slice(got, func(i, j int) bool { return got[i].name < got[j].name })
	if len(got) != len(want) {
		t.Fatalf("role_assignment review produced %d item(s), want %d:\n%+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}

	// Control, and the difference this review exists for: the user-access
	// review of the same data names the role and nothing else.
	const userReview = "dddddddd-0000-0000-0000-000000000002"
	populate(userReview, ReviewTypeUserAccess)
	for _, it := range items(userReview) {
		if it.typ != "role" || strings.Contains(it.name, "also grants") {
			t.Errorf("user_access item should be a plain role: %+v", it)
		}
	}

	// A revoke on the new type removes the direct assignment, and only that
	// one: operator stays.
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := revokeResourceAssignment(ctx, tx, "role_assignment", enabledUser, platformAdm, orgID); err != nil {
		t.Fatalf("revoke role_assignment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var left []string
	rows, err := db.Pool.Query(ctx, `SELECT role_id FROM user_roles WHERE user_id = $1 AND org_id = $2 ORDER BY role_id`, enabledUser, orgID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r string
		_ = rows.Scan(&r)
		left = append(left, r)
	}
	rows.Close()
	if len(left) != 1 || left[0] != operator {
		t.Fatalf("after revoking platform_admin the user should hold only operator, holds %v", left)
	}
}

func TestRoleAssignmentItemNameFitsTheColumn(t *testing.T) {
	if got := roleAssignmentItemName("operator", ""); got != "operator" {
		t.Errorf("plain role: %q", got)
	}
	if got := roleAssignmentItemName("platform_admin", "auditor, reader"); got != "platform_admin (also grants: auditor, reader)" {
		t.Errorf("with reach: %q", got)
	}
	long := roleAssignmentItemName("r", strings.Repeat("x, ", 200))
	if n := len([]rune(long)); n != 255 || !strings.HasSuffix(long, "…") {
		t.Errorf("a long reach must be cut to the column's 255 characters with an ellipsis; got %d runes, suffix %q", n, long[len(long)-3:])
	}
}
