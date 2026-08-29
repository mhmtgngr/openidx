package portal

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// appAccessSchema creates the minimal tables the app-access queries touch.
func appAccessSchema(t *testing.T, s *Service) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`CREATE TABLE applications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			description TEXT,
			base_url TEXT,
			protocol VARCHAR(64),
			enabled BOOLEAN DEFAULT true,
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username VARCHAR(255),
			email VARCHAR(255),
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE group_memberships (
			group_id UUID NOT NULL,
			user_id UUID NOT NULL,
			joined_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL
		)`,
		`CREATE TABLE user_application_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			application_id UUID NOT NULL,
			org_id UUID NOT NULL,
			assigned_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(user_id, application_id)
		)`,
		`CREATE TABLE group_application_assignments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			group_id UUID NOT NULL,
			application_id UUID NOT NULL,
			org_id UUID NOT NULL,
			assigned_by UUID,
			assigned_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(group_id, application_id)
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
}

// TestGetMyApplications_GroupAndUserUnion proves group membership grants app
// access: a user sees apps assigned directly AND apps assigned to any group
// they belong to, de-duplicated, and not apps assigned to unrelated groups.
func TestGetMyApplications_GroupAndUserUnion(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	s := &Service{db: db, logger: zap.NewNop()}
	appAccessSchema(t, s)
	ctx := context.Background()

	const (
		org      = "00000000-0000-0000-0000-000000000010"
		user     = "11111111-1111-1111-1111-111111111111"
		grp      = "22222222-2222-2222-2222-222222222222"
		otherGrp = "33333333-3333-3333-3333-333333333333"
		appUser  = "aaaaaaaa-0000-0000-0000-000000000001"
		appGroup = "aaaaaaaa-0000-0000-0000-000000000002"
		appOther = "aaaaaaaa-0000-0000-0000-000000000003"
		appBoth  = "aaaaaaaa-0000-0000-0000-000000000004"
	)

	mustExec(t, s, `INSERT INTO users (id, username, email, org_id) VALUES ($1,'u','u@x',$2)`, user, org)
	mustExec(t, s, `INSERT INTO groups (id, name, org_id) VALUES ($1,'g',$2),($3,'other',$2)`, grp, org, otherGrp)
	mustExec(t, s, `INSERT INTO group_memberships (group_id, user_id, org_id) VALUES ($1,$2,$3)`, grp, user, org)
	for _, id := range []string{appUser, appGroup, appOther, appBoth} {
		mustExec(t, s, `INSERT INTO applications (id, name, enabled, org_id) VALUES ($1,$2,true,$3)`, id, id, org)
	}
	// appUser → user directly; appGroup → user's group; appOther → unrelated
	// group; appBoth → both user and group (must appear once).
	mustExec(t, s, `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1,$2,$3),($1,$4,$3)`, user, appUser, org, appBoth)
	mustExec(t, s, `INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES ($1,$2,$3),($1,$4,$3),($5,$6,$3)`,
		grp, appGroup, org, appBoth, otherGrp, appOther)

	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	apps, err := s.GetMyApplications(octx, user)
	if err != nil {
		t.Fatalf("GetMyApplications: %v", err)
	}

	got := map[string]int{}
	for _, a := range apps {
		got[a.ID]++
	}
	if got[appUser] != 1 {
		t.Errorf("user-assigned app missing (count=%d)", got[appUser])
	}
	if got[appGroup] != 1 {
		t.Errorf("group-assigned app missing (count=%d)", got[appGroup])
	}
	if got[appBoth] != 1 {
		t.Errorf("dual-assigned app should appear exactly once (count=%d)", got[appBoth])
	}
	if got[appOther] != 0 {
		t.Errorf("unrelated-group app should NOT appear (count=%d)", got[appOther])
	}
}

// TestCreateAndListAppAssignment covers the one-click grant path for both user
// and group principals, idempotency, validation, and revoke.
func TestCreateAndListAppAssignment(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	s := &Service{db: db, logger: zap.NewNop()}
	appAccessSchema(t, s)
	ctx := context.Background()

	const (
		org     = "00000000-0000-0000-0000-000000000010"
		admin   = "99999999-9999-9999-9999-999999999999"
		user    = "11111111-1111-1111-1111-111111111111"
		grp     = "22222222-2222-2222-2222-222222222222"
		app     = "aaaaaaaa-0000-0000-0000-000000000001"
		ghost   = "44444444-4444-4444-4444-444444444444"
		ghostAp = "aaaaaaaa-0000-0000-0000-00000000dead"
	)
	mustExec(t, s, `INSERT INTO users (id, username, email, org_id) VALUES ($1,'u','u@x',$2)`, user, org)
	mustExec(t, s, `INSERT INTO groups (id, name, org_id) VALUES ($1,'Engineers',$2)`, grp, org)
	mustExec(t, s, `INSERT INTO applications (id, name, enabled, org_id) VALUES ($1,'App',true,$2)`, app, org)

	octx := orgctx.With(ctx, orgctx.Org{ID: org})

	// user grant
	if err := s.CreateAppAssignment(octx, app, "user", user, admin); err != nil {
		t.Fatalf("assign user: %v", err)
	}
	// group grant
	if err := s.CreateAppAssignment(octx, app, "group", grp, admin); err != nil {
		t.Fatalf("assign group: %v", err)
	}
	// idempotent
	if err := s.CreateAppAssignment(octx, app, "group", grp, admin); err != nil {
		t.Fatalf("re-assign group (idempotent): %v", err)
	}
	// invalid principal type
	if err := s.CreateAppAssignment(octx, app, "role", grp, admin); err != errInvalidPrincipalType {
		t.Errorf("invalid type: want errInvalidPrincipalType, got %v", err)
	}
	// unknown principal
	if err := s.CreateAppAssignment(octx, app, "user", ghost, admin); err != errPrincipalNotFound {
		t.Errorf("ghost user: want errPrincipalNotFound, got %v", err)
	}
	// unknown application
	if err := s.CreateAppAssignment(octx, ghostAp, "user", user, admin); err != errApplicationNotFound {
		t.Errorf("ghost app: want errApplicationNotFound, got %v", err)
	}

	list, err := s.ListAppAssignments(octx, app)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 assignments (1 user + 1 group), got %d: %+v", len(list), list)
	}

	// revoke the group grant
	if err := s.DeleteAppAssignment(octx, app, "group", grp); err != nil {
		t.Fatalf("revoke group: %v", err)
	}
	list, _ = s.ListAppAssignments(octx, app)
	if len(list) != 1 || list[0].PrincipalType != "user" {
		t.Fatalf("after revoke want 1 user assignment, got %+v", list)
	}
}

func mustExec(t *testing.T, s *Service, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
