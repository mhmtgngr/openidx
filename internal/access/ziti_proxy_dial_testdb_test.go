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

// #984. In identity mode, the tunnelers end users enroll and the access
// proxy's own identity carry the same attribute, #access-proxy-clients. Under
// assignment enforcement an app route's Dial policy used to drop that
// attribute for the application's marker alone. That cut the unassigned
// tunnelers, which is the point, and it also cut the proxy, which dials every
// Ziti-enabled route it serves. So every proxied request to such an
// application failed, assigned users' included.
//
// The reconciler now names the proxy by id. This proves both halves against
// a migrated Postgres and the fake controller: under enforcement the proxy
// and an assigned user's tunneler may dial, and an unassigned tunneler that
// carries #access-proxy-clients may not.
func TestZitiDialKeepsTheAccessProxyOnIdentityModeRoutes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	service := "ledger-" + suffix

	var routeID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, ziti_enabled, ziti_service_name,
		                          browzer_enabled, hosting_mode)
		VALUES ($1::uuid, $2, $3, 'http://ledger.internal:8080', true, $2, false, 'identity')
		RETURNING id::text`, org, service, "https://"+service+".example.test").Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	var appID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO applications (org_id, client_id, name, type, route_id)
		VALUES ($1::uuid, $2, 'Ledger', 'web', $3::uuid) RETURNING id::text`,
		org, service, routeID).Scan(&appID); err != nil {
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
	alice, bob := seedUser("tunneler-assigned"), seedUser("tunneler-unassigned")
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO user_application_assignments (user_id, application_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, alice, appID, org); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}

	const proxyZitiID = "proxy-zid"
	f := &fakeController{identities: []fakeIdentity{{ID: proxyZitiID, Name: accessProxyIdentityName}}}
	zm, stop := newFakeZiti(t, f, db)
	t.Cleanup(stop)

	converge := func(enforce bool) {
		t.Helper()
		rec := NewZitiReconciler(db, zap.NewNop(), newZitiProviderWith(zm), "").SetAssignmentEnforce(enforce)
		desired, err := rec.loadDesiredRoutes(ctx)
		if err != nil {
			t.Fatalf("load desired routes: %v", err)
		}
		for _, d := range desired {
			if d.ServiceName != service {
				continue
			}
			if d.EffectiveMode() != HostingModeIdentity || d.ApplicationID != appID {
				t.Fatalf("the route loaded as mode %q, application %q", d.EffectiveMode(), d.ApplicationID)
			}
			if err := rec.ensurePolicies(ctx, zm, d); err != nil {
				t.Fatalf("ensure policies: %v", err)
			}
			return
		}
		t.Fatal("the test's route was not loaded")
	}
	dialRoles := func() string {
		t.Helper()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, p := range f.policies {
			if p.Name == "openidx-dial-"+service {
				roles := append([]string(nil), p.IdentityRoles...)
				sort.Strings(roles)
				return strings.Join(roles, ",")
			}
		}
		t.Fatal("no Dial policy was written")
		return ""
	}
	// tunneler returns a user's tunneler identity: the attributes the user
	// sync builds, plus the #access-proxy-clients an identity-mode client is
	// enrolled with.
	tunneler := func(userID string) []string {
		t.Helper()
		attrs, err := zm.buildUserAttributes(ctx, userID)
		if err != nil {
			t.Fatalf("attributes for %s: %v", userID, err)
		}
		return append(attrs, "access-proxy-clients")
	}
	canDial := func(zitiID string, attrs []string) bool {
		t.Helper()
		f.mu.Lock()
		var dial []zitiDialPolicy
		for _, p := range f.policies {
			if p.Type == "Dial" {
				dial = append(dial, zitiDialPolicy{Name: p.Name, IdentityRoles: p.IdentityRoles, ServiceRoles: p.ServiceRoles})
			}
		}
		f.mu.Unlock()
		_, reach := reachabilityForIdentity(dial, zitiID, attrs, zitiServiceIndex{all: []string{service}})
		return len(reach) == 1 && reach[0] == service
	}
	proxyAttrs := []string{"access-proxy-clients"}
	marker := "#" + appMarkerAttr(appID)
	sorted := func(roles ...string) string {
		sort.Strings(roles)
		return strings.Join(roles, ",")
	}

	t.Run("in report mode the proxy and every tunneler may dial", func(t *testing.T) {
		converge(false)
		if got, want := dialRoles(), sorted("#access-proxy-clients", marker); got != want {
			t.Fatalf("Dial roles %s, want %s", got, want)
		}
		if !canDial(proxyZitiID, proxyAttrs) || !canDial("ziti-alice", tunneler(alice)) || !canDial("ziti-bob", tunneler(bob)) {
			t.Fatal("report mode changed who may dial")
		}
	})

	// THE POSITIVE HALF: the proxy keeps its dial, and so does the assignee.
	t.Run("under enforcement the proxy and the assigned user's tunneler may dial", func(t *testing.T) {
		converge(true)
		if got, want := dialRoles(), sorted(marker, "@"+proxyZitiID); got != want {
			t.Fatalf("Dial roles %s, want %s", got, want)
		}
		if !canDial(proxyZitiID, proxyAttrs) {
			t.Fatal("the access proxy cannot dial the service it proxies: every request to this application fails")
		}
		if !canDial("ziti-alice", tunneler(alice)) {
			t.Fatal("the assigned user's tunneler cannot dial")
		}
	})

	// THE NEGATIVE HALF: carrying #access-proxy-clients no longer admits.
	t.Run("under enforcement an unassigned tunneler may not dial", func(t *testing.T) {
		if canDial("ziti-bob", tunneler(bob)) {
			t.Fatal("an unassigned user's tunneler can dial an application they were never assigned")
		}
	})

	t.Run("without the proxy identity nothing else is granted in its place", func(t *testing.T) {
		f.mu.Lock()
		f.identities = nil
		f.mu.Unlock()
		converge(true)
		if got := dialRoles(); got != marker {
			t.Fatalf("Dial roles %s, want only %s", got, marker)
		}
		if canDial("ziti-bob", tunneler(bob)) {
			t.Fatal("a failed lookup opened the service to an unassigned tunneler")
		}
	})
}
