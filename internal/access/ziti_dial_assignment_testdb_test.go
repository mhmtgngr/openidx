package access

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// The App assignment row of docs/evidence/display-equals-enforcement.md at the
// Ziti dial, for a BrowZer (router-hosted) route: the routes, the application,
// the assignment and the BrowZer config come from a migrated Postgres, the
// reconciler writes the Dial policy to a fake controller, and the identities'
// attributes are built the way the user sync builds them. Who may dial is then
// decided by reachabilityForIdentity, the matcher the access map and the
// assignment report share.
//
// Until this test the Ziti half of the row had only TestDialIdentityRolesForRoute,
// a table over the pure function; nothing showed the policy the reconciler
// actually writes, or that an unassigned user's identity is left out of it.
//
// Identity-mode routes are deliberately not covered here. Under enforcement
// their Dial policy loses #access-proxy-clients, which the access proxy's own
// identity carries too, so the proxy stops being able to dial them; that is
// tracked as a defect rather than pinned by a test.
func TestZitiDialFollowsApplicationAssignment(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	appService, openService := "payroll-"+suffix, "wiki-"+suffix

	seedRoute := func(service string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, ziti_enabled, ziti_service_name,
			                          browzer_enabled, hosting_mode)
			VALUES ($1::uuid, $2, $3, 'https://upstream.example.test', true, $2, true, 'direct')
			RETURNING id::text`, org, service, "https://"+service+".example.test").Scan(&id); err != nil {
			t.Fatalf("seed route %s: %v", service, err)
		}
		return id
	}
	appRoute := seedRoute(appService)
	seedRoute(openService) // a route with no application behind it
	var appID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO applications (org_id, client_id, name, type, route_id)
		VALUES ($1::uuid, $2, 'Payroll', 'web', $3::uuid) RETURNING id::text`,
		org, appService, appRoute).Scan(&appID); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	alice, bob := seedUser("dial-assigned"), seedUser("dial-unassigned")
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO user_application_assignments (user_id, application_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, alice, appID, org); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	// BrowZer on, so every synced user carries #browzer-users, the blanket
	// grant a router-hosted route's Dial policy starts from.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO ziti_browzer_config (auth_policy_id, enabled) VALUES ('ap-test', true)`); err != nil {
		t.Fatalf("seed browzer config: %v", err)
	}

	f := &fakeController{}
	zm, stop := newFakeZiti(t, f, db)
	t.Cleanup(stop)

	// converge runs the reconciler's policy step for this test's two routes.
	converge := func(enforce bool) {
		t.Helper()
		rec := NewZitiReconciler(db, zap.NewNop(), newZitiProviderWith(zm), "").SetAssignmentEnforce(enforce)
		desired, err := rec.loadDesiredRoutes(ctx)
		if err != nil {
			t.Fatalf("load desired routes: %v", err)
		}
		found := 0
		for _, d := range desired {
			switch d.ServiceName {
			case appService:
				if d.ApplicationID != appID {
					t.Fatalf("the app route resolved application %q, want %s", d.ApplicationID, appID)
				}
			case openService:
				if d.ApplicationID != "" {
					t.Fatalf("the open route resolved application %q, want none", d.ApplicationID)
				}
			default:
				continue
			}
			found++
			if err := rec.ensurePolicies(ctx, zm, d); err != nil {
				t.Fatalf("ensure policies for %s: %v", d.ServiceName, err)
			}
		}
		if found != 2 {
			t.Fatalf("loaded %d of this test's 2 routes", found)
		}
	}
	dialRoles := func(service string) []string {
		t.Helper()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, p := range f.policies {
			if p.Name == "openidx-dial-"+service {
				roles := append([]string(nil), p.IdentityRoles...)
				sort.Strings(roles)
				return roles
			}
		}
		t.Fatalf("no Dial policy was written for %s", service)
		return nil
	}
	canDial := func(userID, service string) bool {
		t.Helper()
		attrs, err := zm.buildUserAttributes(ctx, userID)
		if err != nil {
			t.Fatalf("attributes for %s: %v", userID, err)
		}
		f.mu.Lock()
		var dial []zitiDialPolicy
		for _, p := range f.policies {
			if p.Type == "Dial" {
				dial = append(dial, zitiDialPolicy{Name: p.Name, IdentityRoles: p.IdentityRoles, ServiceRoles: p.ServiceRoles})
			}
		}
		f.mu.Unlock()
		_, reach := reachabilityForIdentity(dial, "ziti-"+userID, attrs,
			zitiServiceIndex{all: []string{appService, openService}})
		for _, svc := range reach {
			if svc == service {
				return true
			}
		}
		return false
	}
	marker := "#" + appMarkerAttr(appID)

	t.Run("only the assigned user's identity carries the application's marker", func(t *testing.T) {
		for user, want := range map[string]bool{alice: true, bob: false} {
			attrs, err := zm.buildUserAttributes(ctx, user)
			if err != nil {
				t.Fatal(err)
			}
			if got := containsAttr(attrs, appMarkerAttr(appID)); got != want {
				t.Fatalf("user %s carries the marker: %v, want %v (attributes %v)", user, got, want, attrs)
			}
		}
	})

	// Report mode: the marker sits beside the blanket grant, so nobody's reach
	// changes until enforcement is turned on.
	t.Run("with enforcement off, every BrowZer user may still dial", func(t *testing.T) {
		converge(false)
		want := []string{"#browzer-users", marker}
		sort.Strings(want)
		if got, want := strings.Join(dialRoles(appService), ","), strings.Join(want, ","); got != want {
			t.Fatalf("the app route's Dial roles are %s, want %s", got, want)
		}
		if !canDial(alice, appService) || !canDial(bob, appService) {
			t.Fatalf("assigned=%v unassigned=%v, want both able to dial", canDial(alice, appService), canDial(bob, appService))
		}
	})

	// THE NEGATIVE HALF, and its positive twin.
	t.Run("with enforcement on, only the assigned user may dial", func(t *testing.T) {
		converge(true)
		if got := strings.Join(dialRoles(appService), ","); got != marker {
			t.Fatalf("the app route's Dial roles are %s, want only %s", got, marker)
		}
		if !canDial(alice, appService) {
			t.Fatal("the assigned user lost the dial")
		}
		if canDial(bob, appService) {
			t.Fatal("the unassigned user can still dial an application they were never assigned")
		}
	})
	t.Run("a route with no application keeps its blanket grant under enforcement", func(t *testing.T) {
		if got := strings.Join(dialRoles(openService), ","); got != "#browzer-users" {
			t.Fatalf("the open route's Dial roles are %s, want #browzer-users", got)
		}
		if !canDial(bob, openService) {
			t.Fatal("enforcement took away a route no application is behind")
		}
	})
}
