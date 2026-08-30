package access

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// TestAssembleAttributesCarriesAppMarkers: a per-app attribute is how an
// assignment reaches the overlay. The dial policy for an app-backed service
// grants #app-<uuid>, so an identity without the marker cannot dial it.
func TestAssembleAttributesCarriesAppMarkers(t *testing.T) {
	got := assembleAttributes([]string{"Engineering"}, true, false,
		[]string{appMarkerAttr("11111111-2222-3333-4444-555555555555")})

	want := map[string]bool{
		"Engineering":    true,
		"enrolled-users": true,
		"device-trusted": true,
		"app-11111111-2222-3333-4444-555555555555": true,
	}
	if len(got) != len(want) {
		t.Fatalf("attributes = %v, want exactly %d entries", got, len(want))
	}
	for _, a := range got {
		if !want[a] {
			t.Errorf("unexpected attribute %q", a)
		}
	}
}

// TestAppMarkerUsesTheUUID: the attribute set is wholesale-replaced on every
// sync, so keying on a renameable name would silently drop reach on rename.
func TestAppMarkerUsesTheUUID(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	got := appMarkerAttr(id)
	if got != "app-"+id {
		t.Errorf("appMarkerAttr = %q, want %q", got, "app-"+id)
	}
	if strings.ContainsAny(got, " #") {
		t.Errorf("attribute %q must not contain a space or a leading hash (the hash is added by the policy)", got)
	}
}

// TestAssembleAttributesWithoutApps keeps the pre-existing shape intact for a
// user with no assignments.
func TestAssembleAttributesWithoutApps(t *testing.T) {
	got := assembleAttributes([]string{"Sales"}, false, true, nil)
	if len(got) != 3 {
		t.Fatalf("attributes = %v, want [Sales enrolled-users browzer-users]", got)
	}
}

// TestBuildUserAttributesIncludesAppMarkers is the DB-backed test for the two
// lines that actually decide access: the appaccess.AppsForUser wiring and the
// r.RouteID != "" filter inside buildUserAttributes. The pure-function tests
// above cover assembleAttributes and appMarkerAttr in isolation; this proves
// the real query + filter combination against real rows, so a wrong filter
// field, a swapped userID/orgID argument order, or a filter on the wrong
// condition would fail this test even though every pure test still passes.
func TestBuildUserAttributesIncludesAppMarkers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	schema := `
	CREATE TABLE users (
		id UUID PRIMARY KEY,
		org_id UUID,
		username TEXT,
		enabled BOOLEAN DEFAULT true
	);
	CREATE TABLE groups (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name TEXT NOT NULL,
		org_id UUID
	);
	CREATE TABLE group_memberships (
		group_id UUID NOT NULL,
		user_id UUID NOT NULL
	);
	CREATE TABLE known_devices (
		user_id UUID NOT NULL,
		trusted BOOLEAN NOT NULL DEFAULT false
	);
	CREATE TABLE applications (
		id UUID PRIMARY KEY,
		name TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT true,
		route_id UUID,
		org_id UUID NOT NULL
	);
	CREATE TABLE user_application_assignments (
		user_id UUID NOT NULL,
		application_id UUID NOT NULL,
		org_id UUID NOT NULL
	);
	CREATE TABLE group_application_assignments (
		group_id UUID NOT NULL,
		application_id UUID NOT NULL,
		org_id UUID NOT NULL
	);`
	if _, err := db.Pool.Exec(ctx, schema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		org             = "aaaaaaaa-0000-0000-0000-000000000000"
		user            = "11111111-0000-0000-0000-000000000000"
		group           = "22222222-0000-0000-0000-000000000000"
		routedDirectApp = "33333333-0000-0000-0000-00000000a001" // direct assignment, has a route
		noRouteApp      = "33333333-0000-0000-0000-00000000a002" // direct assignment, NO route
		routedGroupApp  = "33333333-0000-0000-0000-00000000a003" // group-derived assignment, has a route
		unassignedApp   = "33333333-0000-0000-0000-00000000a004" // not assigned at all, has a route
		route1          = "44444444-0000-0000-0000-000000000001"
		route2          = "44444444-0000-0000-0000-000000000002"
		route3          = "44444444-0000-0000-0000-000000000003"
	)

	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'alice')`, []any{user, org}},
		{`INSERT INTO groups (id, name, org_id) VALUES ($1,'Engineering',$2)`, []any{group, org}},
		{`INSERT INTO group_memberships (group_id, user_id) VALUES ($1,$2)`, []any{group, user}},
		{`INSERT INTO known_devices (user_id, trusted) VALUES ($1, true)`, []any{user}},
		{`INSERT INTO applications (id, name, enabled, route_id, org_id) VALUES
			($1,'Routed Direct',true,$2,$3),
			($4,'No Route',true,NULL,$3),
			($5,'Routed Via Group',true,$6,$3),
			($7,'Unassigned',true,$8,$3)`,
			[]any{routedDirectApp, route1, org, noRouteApp, routedGroupApp, route2, unassignedApp, route3}},
		{`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES
			($1,$2,$3), ($1,$4,$3)`,
			[]any{user, routedDirectApp, org, noRouteApp}},
		{`INSERT INTO group_application_assignments (group_id, application_id, org_id) VALUES ($1,$2,$3)`,
			[]any{group, routedGroupApp, org}},
	}
	for _, s := range stmts {
		if _, err := db.Pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed %q: %v", s.sql, err)
		}
	}

	zm := &ZitiManager{db: db, logger: zap.NewNop(), cfg: &config.Config{}}
	attrs, err := zm.buildUserAttributes(ctx, user)
	if err != nil {
		t.Fatalf("buildUserAttributes: %v", err)
	}

	// Pre-existing attributes must still be present: the new app-marker block
	// must not displace them.
	for _, want := range []string{"Engineering", "enrolled-users", "device-trusted"} {
		if !containsAttr(attrs, want) {
			t.Errorf("attrs %v missing pre-existing attribute %q", attrs, want)
		}
	}

	// A route-linked directly-assigned app produces its marker.
	if !containsAttr(attrs, appMarkerAttr(routedDirectApp)) {
		t.Errorf("attrs %v missing marker for route-linked directly-assigned app %s", attrs, routedDirectApp)
	}
	// A route-linked group-derived assignment ALSO produces its marker.
	if !containsAttr(attrs, appMarkerAttr(routedGroupApp)) {
		t.Errorf("attrs %v missing marker for route-linked group-derived app %s", attrs, routedGroupApp)
	}
	// An assigned application with NO route produces no marker at all.
	if containsAttr(attrs, appMarkerAttr(noRouteApp)) {
		t.Errorf("attrs %v must not contain a marker for the route-less app %s", attrs, noRouteApp)
	}
	// An application the user is not assigned produces no marker, even though
	// it has a route.
	if containsAttr(attrs, appMarkerAttr(unassignedApp)) {
		t.Errorf("attrs %v must not contain a marker for the unassigned app %s", attrs, unassignedApp)
	}
}
