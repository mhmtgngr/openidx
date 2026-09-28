package access

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// zitiRoleFixture is the scope fixture with role attributes on the controller:
// A's service carries its name and browzer-enabled, B's its name and
// openidx-managed, which OpenIDX puts on the services it creates for anyone; A's identity
// carries enrolled-users and engineering, B's enrolled-users and team-b, and
// the access proxy's identity, which no organization owns,
// access-proxy-clients. A's Dial policy grants #engineering, B's #team-b.
func zitiRoleFixture(t *testing.T) *zitiScopeFixture {
	f := newZitiScopeFixture(t)
	list := func(items ...string) string { return `{"data":[` + strings.Join(items, ",") + `]}` }
	f.stub.ok("GET /edge/management/v1/services", list(
		`{"id":"`+f.zsA+`","name":"`+f.svcA+`","roleAttributes":["`+f.svcA+`","browzer-enabled"],"configs":["cfg-a-host-`+f.sfx+`","cfg-a-int-`+f.sfx+`"]}`,
		`{"id":"`+f.zsB+`","name":"`+f.svcB+`","roleAttributes":["`+f.svcB+`","openidx-managed"],"configs":["cfg-b-host-`+f.sfx+`"]}`,
		`{"id":"`+f.zsInstall+`","name":"`+f.svcInstall+`","roleAttributes":["`+f.svcInstall+`"],"configs":["cfg-install-`+f.sfx+`"]}`))
	f.stub.ok("GET /edge/management/v1/identities", list(
		`{"id":"`+f.ziA+`","name":"`+f.users["userA"]+`","roleAttributes":["enrolled-users","engineering"]}`,
		`{"id":"`+f.ziB+`","name":"`+f.users["userB"]+`","roleAttributes":["enrolled-users","team-b"]}`,
		`{"id":"zi-proxy-`+f.sfx+`","name":"access-proxy","roleAttributes":["access-proxy-clients"]}`))
	f.stub.ok("GET /edge/management/v1/identities/"+f.ziB, `{"data":{"id":"`+f.ziB+`","roleAttributes":["enrolled-users","team-b"]}}`)
	f.stub.ok("GET /edge/management/v1/service-policies", list(
		`{"id":"`+f.zpA+`","name":"pol-a-`+f.sfx+`","type":"Dial","serviceRoles":["#`+f.svcA+`"],"identityRoles":["#engineering"]}`,
		`{"id":"`+f.zpB+`","name":"pol-b-`+f.sfx+`","type":"Dial","serviceRoles":["#`+f.svcB+`"],"identityRoles":["#team-b"]}`,
		`{"id":"`+f.zpInstall+`","name":"pol-install-`+f.sfx+`","type":"Bind","serviceRoles":["#`+f.svcInstall+`"],"identityRoles":["#ziti-routers"]}`))
	for _, pattern := range []string{
		"POST /edge/management/v1/", "PUT /edge/management/v1/", "PATCH /edge/management/v1/", "DELETE /edge/management/v1/",
	} {
		f.stub.ok(pattern, `{"data":{"id":"created-`+f.sfx+`"}}`)
	}
	return f
}

// writesTo is what the controller was asked to change since resetCalls.
func (f *zitiScopeFixture) writesTo() []string {
	var out []string
	for _, c := range f.managementCalls() {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

// A SERVICE POLICY NAMES ONLY ITS ORGANIZATION'S SERVICES AND IDENTITIES.
//
// Through the real route table, the second organization's admin is refused,
// and the controller hears nothing, when a policy's service roles name #all,
// the first organization's service by attribute, id or name, the install's
// service, the attribute on the first organization's BrowZer-published
// service, an attribute OpenIDX puts on every organization's services even
// where only theirs carries it, or nothing of theirs; and when its identity roles name #all, the
// first organization's identity, an attribute OpenIDX gives users of every
// organization, the attribute the first organization's identity carries, or
// an app marker. A bare role is malformed. Their own services and identities,
// and the access proxy the install runs, go through, on create and on update;
// the install administrator writes #all.
func TestAServicePolicyNamesOnlyItsOrganizationsObjects(t *testing.T) {
	f := zitiRoleFixture(t)
	adminB := f.caller("adminB", "admin")
	body := func(sr, ir string) string {
		return `{"name":"p-` + f.sfx + `","type":"Dial","service_roles":[` + sr + `],"identity_roles":[` + ir + `]}`
	}
	q := func(s string) string { return `"` + s + `"` }
	own := q("#" + f.svcB)
	for _, tc := range []struct {
		name, sr, ir string
		want         int
	}{
		{"#all services", q("#all"), q("#team-b"), http.StatusForbidden},
		{"A's service by attribute", q("#" + f.svcA), q("#team-b"), http.StatusForbidden},
		{"A's service by id", q("@" + f.zsA), q("#team-b"), http.StatusForbidden},
		{"the install's service by name", q("@" + f.svcInstall), q("#team-b"), http.StatusForbidden},
		{"A's BrowZer-published service", q("#browzer-enabled"), q("#team-b"), http.StatusForbidden},
		{"an attribute OpenIDX puts on every organization's services", q("#openidx-managed"), q("#team-b"), http.StatusForbidden},
		{"no service at all", q("#nothing-" + f.sfx), q("#team-b"), http.StatusForbidden},
		{"a bare role", q(f.svcB), q("#team-b"), http.StatusBadRequest},
		{"#all identities", own, q("#all"), http.StatusForbidden},
		{"A's identity by id", own, q("@" + f.ziA), http.StatusForbidden},
		{"every organization's BrowZer users", own, q("#browzer-users"), http.StatusForbidden},
		{"every organization's enrolled users", own, q("#enrolled-users"), http.StatusForbidden},
		{"the attribute A's identity carries", own, q("#engineering"), http.StatusForbidden},
		{"an app marker", own, q("#app-" + f.sfx), http.StatusForbidden},
		{"A's organization marker", own, q("#org-" + middleware.DefaultOrgID), http.StatusForbidden},
	} {
		f.resetCalls()
		code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/service-policies", body(tc.sr, tc.ir))
		if code != tc.want {
			t.Errorf("policy naming %s as B's admin: %d %s, want %d", tc.name, code, resp, tc.want)
		}
		if w := f.writesTo(); len(w) != 0 {
			t.Errorf("policy naming %s as B's admin reached the controller: %v", tc.name, w)
		}
	}

	for _, tc := range []struct{ name, sr, ir string }{
		{"B's service and B's attribute", own, q("#team-b")},
		{"B's service and identity by id", q("@" + f.zsB), q("@" + f.ziB)},
		{"B's service hosted by the access proxy", own, q("#access-proxy-clients")},
		{"B's own organization marker", own, q("#org-" + f.orgB.ID)},
	} {
		f.resetCalls()
		if code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/service-policies", body(tc.sr, tc.ir)); code != http.StatusCreated {
			t.Errorf("policy naming %s as B's admin: %d %s, want 201", tc.name, code, resp)
		}
		if !f.stub.saw("POST /edge/management/v1/service-policies") {
			t.Errorf("policy naming %s as B's admin did not reach the controller", tc.name)
		}
	}

	policyB := f.scalar(`SELECT id::text FROM ziti_service_policies WHERE ziti_id = $1`, f.zpB)
	f.resetCalls()
	if code, resp := f.do(adminB, http.MethodPut, "/api/v1/access/ziti/service-policies/"+policyB, body(q("#"+f.svcA), q("#team-b"))); code != http.StatusForbidden {
		t.Errorf("updating B's policy to A's service: %d %s, want 403", code, resp)
	}
	if w := f.writesTo(); len(w) != 0 {
		t.Errorf("updating B's policy to A's service reached the controller: %v", w)
	}
	if code, resp := f.do(adminB, http.MethodPut, "/api/v1/access/ziti/service-policies/"+policyB, body(own, q("#team-b"))); code != http.StatusOK {
		t.Errorf("updating B's policy within B: %d %s, want 200", code, resp)
	}

	if code, resp := f.do(f.caller("adminA", "admin"), http.MethodPost, "/api/v1/access/ziti/service-policies", body(q("#all"), q("#all"))); code != http.StatusCreated {
		t.Errorf("a #all policy as the install administrator: %d %s, want 201", code, resp)
	}
}

// AN IDENTITY GETS NO ATTRIBUTE ANOTHER ORGANIZATION'S POLICY OR OPENIDX GRANTS.
//
// B's admin editing B's identity, which carries enrolled-users and team-b, is
// refused, and the controller hears nothing, for adding access-proxy-clients,
// browzer-users, quarantined, an org or app marker, or engineering, which A's
// policy grants, and for dropping enrolled-users; a new identity is refused
// the same attributes. Their own attributes go through, and the install
// administrator may set a managed one.
func TestAnIdentityGetsNoAttributeItIsNotTheOrganizationsToGive(t *testing.T) {
	f := zitiRoleFixture(t)
	adminB := f.caller("adminB", "admin")
	localB := f.scalar(`SELECT id::text FROM ziti_identities WHERE ziti_id = $1`, f.ziB)
	patch := func(attrs ...string) string {
		return `{"attributes":["` + strings.Join(attrs, `","`) + `"]}`
	}
	for _, tc := range []struct {
		name  string
		attrs []string
	}{
		{"access-proxy-clients", []string{"enrolled-users", "team-b", "access-proxy-clients"}},
		{"browzer-users", []string{"enrolled-users", "team-b", "browzer-users"}},
		{"quarantined", []string{"enrolled-users", "team-b", "quarantined"}},
		{"A's organization marker", []string{"enrolled-users", "team-b", "org-" + middleware.DefaultOrgID}},
		{"an app marker", []string{"enrolled-users", "team-b", "app-" + f.sfx}},
		{"the attribute A's policy grants", []string{"enrolled-users", "team-b", "engineering"}},
		{"dropping enrolled-users", []string{"team-b"}},
	} {
		f.resetCalls()
		code, resp := f.do(adminB, http.MethodPatch, "/api/v1/access/ziti/identities/"+localB+"/attributes", patch(tc.attrs...))
		if code != http.StatusForbidden {
			t.Errorf("B's identity with %s: %d %s, want 403", tc.name, code, resp)
		}
		if w := f.writesTo(); len(w) != 0 {
			t.Errorf("B's identity with %s reached the controller: %v", tc.name, w)
		}
	}
	f.resetCalls()
	if code, resp := f.do(adminB, http.MethodPatch, "/api/v1/access/ziti/identities/"+localB+"/attributes",
		patch("enrolled-users", "team-b", "team-b-2")); code != http.StatusOK || !f.stub.saw("PATCH /edge/management/v1/identities/"+f.ziB) {
		t.Errorf("B's identity with its own attributes: %d %s, want 200 reaching the controller", code, resp)
	}

	for _, attr := range []string{"browzer-users", "engineering", "org-" + f.orgB.ID} {
		f.resetCalls()
		if code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/identities",
			`{"name":"dev-b-`+f.sfx+`","attributes":["`+attr+`"]}`); code != http.StatusForbidden || len(f.writesTo()) != 0 {
			t.Errorf("a new identity with %s as B's admin: %d %s, want 403 and no controller write", attr, code, resp)
		}
	}
	if code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/identities",
		`{"name":"dev-b-`+f.sfx+`","attributes":["team-b"]}`); code != http.StatusCreated {
		t.Errorf("a new identity with B's attribute: %d %s, want 201", code, resp)
	}

	localA := f.scalar(`SELECT id::text FROM ziti_identities WHERE ziti_id = $1`, f.ziA)
	if code, resp := f.do(f.caller("adminA", "admin"), http.MethodPatch, "/api/v1/access/ziti/identities/"+localA+"/attributes",
		patch("enrolled-users", "access-proxy-clients")); code != http.StatusOK {
		t.Errorf("a managed attribute set by the install administrator: %d %s, want 200", code, resp)
	}
}

// ADD SERVICE'S ROLES AND INTERCEPT ADDRESS ARE THE ORGANIZATION'S OWN.
//
// B's admin is refused, and the controller hears no write, for a service that
// intercepts a.ziti, which A's service intercepts; whose dial roles name every
// organization's BrowZer users or A's identity; or whose attributes are A's
// service name or browzer-enabled. A service of their own -- its own intercept
// address, dial roles and attributes -- goes through, and the install
// administrator may reuse A's intercept address.
func TestAddServiceTakesOnlyTheOrganizationsOwnRolesAndAddresses(t *testing.T) {
	f := zitiRoleFixture(t)
	adminB := f.caller("adminB", "admin")
	svc := func(name, extra string) string {
		return `{"name":"` + name + `-` + f.sfx + `","host":"192.0.2.44","port":80` + extra + `}`
	}
	for _, tc := range []struct {
		name, extra string
		want        int
	}{
		{"A's intercept address", `,"intercept_address":"A.ziti"`, http.StatusConflict},
		{"every organization's BrowZer users", `,"dial_roles":["browzer-users"]`, http.StatusForbidden},
		{"A's identity", `,"dial_roles":["@` + f.ziA + `"]`, http.StatusForbidden},
		{"A's service name as an attribute", `,"attributes":["` + f.svcA + `"]`, http.StatusForbidden},
		{"browzer-enabled", `,"attributes":["browzer-enabled"]`, http.StatusForbidden},
	} {
		f.resetCalls()
		code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/services", svc("svc-new-b", tc.extra))
		if code != tc.want {
			t.Errorf("Add Service with %s as B's admin: %d %s, want %d", tc.name, code, resp, tc.want)
		}
		if w := f.writesTo(); len(w) != 0 {
			t.Errorf("Add Service with %s as B's admin reached the controller: %v", tc.name, w)
		}
	}

	f.resetCalls()
	if code, resp := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/services",
		svc("svc-own-b", `,"intercept_address":"b-own.ziti","dial_roles":["team-b"],"attributes":["team-b-extra"]`)); code == http.StatusForbidden || code == http.StatusConflict {
		t.Errorf("Add Service with B's own roles as B's admin: %d %s", code, resp)
	}
	if !f.stub.saw("POST /edge/management/v1/configs") {
		t.Errorf("Add Service with B's own roles did not reach the controller: %v", f.stub.received())
	}
	if code, resp := f.do(f.caller("adminA", "admin"), http.MethodPost, "/api/v1/access/ziti/services",
		svc("svc-install", `,"intercept_address":"a.ziti"`)); code == http.StatusForbidden || code == http.StatusConflict {
		t.Errorf("Add Service reusing a.ziti as the install administrator: %d %s", code, resp)
	}
}
