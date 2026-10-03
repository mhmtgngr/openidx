package appaccess

import (
	"context"
	"testing"
)

const (
	orgID    = "00000000-0000-0000-0000-0000000000a0"
	userID   = "11111111-0000-0000-0000-0000000000a1"
	otherOrg = "00000000-0000-0000-0000-0000000000b0"
	groupID  = "22222222-0000-0000-0000-0000000000a1"
	directID = "33333333-0000-0000-0000-0000000000a1"
	groupApp = "33333333-0000-0000-0000-0000000000a2"
	bothApp  = "33333333-0000-0000-0000-0000000000a3"
	otherApp = "33333333-0000-0000-0000-0000000000a4"
	offApp   = "33333333-0000-0000-0000-0000000000a5"
	// windowApp and lapsedApp are assigned for a window (migration v222):
	// one still open, one over.
	windowApp = "33333333-0000-0000-0000-0000000000a6"
	lapsedApp = "33333333-0000-0000-0000-0000000000a7"
	routeID   = "44444444-0000-0000-0000-0000000000a1"
)

func TestAllowed(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	stmts := []string{
		`INSERT INTO applications (id, name, enabled, route_id, org_id) VALUES
		   ('` + directID + `','Direct',true,'` + routeID + `','` + orgID + `'),
		   ('` + groupApp + `','ViaGroup',true,NULL,'` + orgID + `'),
		   ('` + bothApp + `','Both',true,NULL,'` + orgID + `'),
		   ('` + otherApp + `','Unassigned',true,NULL,'` + orgID + `'),
		   ('` + offApp + `','Disabled',false,NULL,'` + orgID + `'),
		   ('` + windowApp + `','Window',true,NULL,'` + orgID + `'),
		   ('` + lapsedApp + `','Lapsed',true,NULL,'` + orgID + `')`,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES
		   ('` + userID + `','` + groupID + `','` + orgID + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES
		   ('` + userID + `','` + directID + `','` + orgID + `'),
		   ('` + userID + `','` + bothApp + `','` + orgID + `'),
		   ('` + userID + `','` + offApp + `','` + orgID + `')`,
		`INSERT INTO user_application_assignments (user_id, application_id, org_id, expires_at) VALUES
		   ('` + userID + `','` + windowApp + `','` + orgID + `', NOW() + interval '1 hour'),
		   ('` + userID + `','` + lapsedApp + `','` + orgID + `', NOW() - interval '1 minute')`,
		`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES
		   ('` + groupID + `','` + groupApp + `','` + orgID + `'),
		   ('` + groupID + `','` + bothApp + `','` + orgID + `')`,
	}
	for _, s := range stmts {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cases := []struct {
		name  string
		appID string
		org   string
		want  bool
	}{
		{"direct assignment", directID, orgID, true},
		{"group-derived assignment", groupApp, orgID, true},
		{"assigned both ways", bothApp, orgID, true},
		{"unassigned denied", otherApp, orgID, false},
		{"disabled application denied even when assigned", offApp, orgID, false},
		{"other org denied", directID, otherOrg, false},
		{"assigned for a window still open", windowApp, orgID, true},
		{"assigned for a window that is over denied", lapsedApp, orgID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Allowed(ctx, db, userID, tc.org, tc.appID)
			if err != nil {
				t.Fatalf("Allowed: %v", err)
			}
			if got != tc.want {
				t.Errorf("Allowed(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}

	apps, err := AppsForUser(ctx, db, userID, orgID)
	if err != nil {
		t.Fatalf("AppsForUser: %v", err)
	}
	if len(apps) != 4 {
		t.Fatalf("AppsForUser returned %d apps, want 4 (direct + group + both + the open window, deduped, excluding disabled, unassigned and the window that is over)", len(apps))
	}
	for _, a := range apps {
		if a.ID == lapsedApp {
			t.Error("AppsForUser lists an application whose window is over")
		}
	}
	var withRoute int
	for _, a := range apps {
		if a.RouteID != "" {
			withRoute++
		}
	}
	if withRoute != 1 {
		t.Errorf("expected exactly one route-linked app, got %d", withRoute)
	}

	p, err := PrincipalsForApp(ctx, db, bothApp, orgID)
	if err != nil {
		t.Fatalf("PrincipalsForApp: %v", err)
	}
	if len(p.UserIDs) != 1 || len(p.GroupIDs) != 1 {
		t.Errorf("PrincipalsForApp = %+v, want 1 user and 1 group", p)
	}
	for app, want := range map[string]int{windowApp: 1, lapsedApp: 0} {
		p, err := PrincipalsForApp(ctx, db, app, orgID)
		if err != nil {
			t.Fatalf("PrincipalsForApp: %v", err)
		}
		if len(p.UserIDs) != want {
			t.Errorf("PrincipalsForApp(%s) names %d users, want %d", app, len(p.UserIDs), want)
		}
	}
}
