package access

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// CHANGING THE CONTROLLER'S OWN OBJECTS.
//
// A router, an edge-router, authentication or JWT-signer policy, a raw config,
// the AI ledger and its quarantine, a governance-policy sync and the import of
// a service no organization owns are the install's. Each write is refused to
// a plain user and an operator by the admin gate, and to the second
// organization's admin and super_admin with "platform administrator required";
// the controller hears nothing from any refused request, and the rows the
// refused writes aimed at read back unchanged. The administrator of the
// default organization gets through.
func TestChangingTheControllersOwnObjectsNeedsAnInstallAdministrator(t *testing.T) {
	f := newZitiScopeFixture(t)
	for _, pattern := range []string{
		"POST /edge/management/v1/", "PUT /edge/management/v1/", "PATCH /edge/management/v1/", "DELETE /edge/management/v1/",
	} {
		f.stub.ok(pattern, `{"data":{"id":"created"}}`)
	}
	anomaly := f.scalar(`SELECT id::text FROM ziti_ai_anomalies WHERE identity_name = 'anomaly-' || $1`, f.sfx)
	sync := f.scalar(`SELECT id::text FROM policy_sync_state WHERE ziti_policy_id = 'synced-' || $1`, f.sfx)

	writes := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/access/ziti/fabric/routers/enroll-token", `{"name":"edge-new"}`},
		{http.MethodPost, "/api/v1/access/ziti/fabric/reconnect", ""},
		{http.MethodPost, "/api/v1/access/ziti/edge-router-policies", `{"name":"erp-new","edgeRouterRoles":["#all"],"identityRoles":["#all"]}`},
		{http.MethodPut, "/api/v1/access/ziti/edge-router-policies/erp-1", `{"name":"erp-1","edgeRouterRoles":["#all"],"identityRoles":["#all"]}`},
		{http.MethodDelete, "/api/v1/access/ziti/edge-router-policies/erp-1", ""},
		{http.MethodPost, "/api/v1/access/ziti/configs", `{"name":"cfg-new","configTypeId":"host.v1","data":{"address":"192.0.2.99","port":1}}`},
		{http.MethodPut, "/api/v1/access/ziti/configs/cfg-b-host-" + f.sfx, `{"name":"moved","data":{"address":"192.0.2.99","port":1}}`},
		{http.MethodDelete, "/api/v1/access/ziti/configs/cfg-b-host-" + f.sfx, ""},
		{http.MethodPost, "/api/v1/access/ziti/auth-policies", `{"name":"auth-new"}`},
		{http.MethodPut, "/api/v1/access/ziti/auth-policies/ap-1", `{"name":"auth-new"}`},
		{http.MethodDelete, "/api/v1/access/ziti/auth-policies/ap-1", ""},
		{http.MethodPost, "/api/v1/access/ziti/jwt-signers", `{"name":"signer-new","issuer":"https://issuer.example.test"}`},
		{http.MethodPut, "/api/v1/access/ziti/jwt-signers/js-1", `{"name":"signer-new","issuer":"https://issuer.example.test"}`},
		{http.MethodDelete, "/api/v1/access/ziti/jwt-signers/js-1", ""},
		{http.MethodPost, "/api/v1/access/ziti/ai/analyze", ""},
		{http.MethodPost, "/api/v1/access/ziti/ai/anomalies/" + anomaly + "/status", `{"status":"resolved"}`},
		{http.MethodPost, "/api/v1/access/ziti/ai/identities/" + f.ziB + "/quarantine", `{"reason":"test"}`},
		{http.MethodPost, "/api/v1/access/ziti/ai/identities/" + f.ziB + "/unquarantine", ""},
		{http.MethodPost, "/api/v1/access/ziti/policy-sync", `{"governance_policy_id":"` + sync + `","config":{"type":"Dial"}}`},
		{http.MethodPost, "/api/v1/access/ziti/policy-sync/" + sync + "/trigger", ""},
		{http.MethodDelete, "/api/v1/access/ziti/policy-sync/" + sync, ""},
		{http.MethodPost, "/api/v1/access/ziti/import", `{"ziti_id":"` + f.zsInstall + `"}`},
		{http.MethodPost, "/api/v1/access/ziti/import/bulk", `{"ziti_ids":["` + f.zsInstall + `"]}`},
	}

	state := func() string {
		return f.scalar(`SELECT concat_ws('|',
			(SELECT status FROM ziti_ai_anomalies WHERE id::text = $1),
			(SELECT COUNT(*) FROM ziti_ai_quarantine)::text,
			(SELECT COUNT(*) FROM policy_sync_state WHERE id::text = $2)::text,
			(SELECT COUNT(*) FROM proxy_routes WHERE ziti_service_name = $3)::text)`, anomaly, sync, f.svcInstall)
	}
	before := state()

	for _, rq := range writes {
		f.resetCalls()
		for _, refused := range []struct {
			cl   zitiCaller
			want string
		}{
			{f.caller("userA", "user"), "admin access required"},
			{f.caller("operatorA", "operator"), "admin access required"},
			{f.caller("adminB", "admin"), middleware.PlatformAdminRequired},
			{f.caller("superB", "admin", "super_admin"), middleware.PlatformAdminRequired},
		} {
			code, body := f.do(refused.cl, rq.method, rq.path, rq.body)
			if code != http.StatusForbidden || !strings.Contains(body, refused.want) {
				t.Errorf("%s %s as %s: %d %s, want 403 %s", rq.method, rq.path, refused.cl.name, code, body, refused.want)
			}
		}
		if calls := f.managementCalls(); len(calls) != 0 {
			t.Errorf("%s %s: refused requests reached the controller: %v", rq.method, rq.path, calls)
		}
	}
	if after := state(); after != before {
		t.Errorf("refused writes changed what they aimed at: %s, was %s", after, before)
	}

	admin := f.caller("adminA", "admin")
	for _, rq := range writes {
		if code, body := f.do(admin, rq.method, rq.path, rq.body); code == http.StatusForbidden {
			t.Errorf("%s %s as the install administrator: %d %s", rq.method, rq.path, code, body)
		}
	}
	if f.stub.saw("PUT /edge/management/v1/configs/cfg-b-host-"+f.sfx) == false {
		t.Errorf("the install administrator's config change did not reach the controller: %v", f.stub.received())
	}
}

// CHANGING THE ORGANIZATION'S OWN OBJECTS.
//
// Ending a session, ending an identity's sessions, removing a terminator,
// turning BrowZer on or off for a service and rotating a certificate each take
// the object by id. The second organization's admin reaches its own objects,
// and gets the 404 an unknown id gets for the first organization's, for a
// session whose two ends belong to different organizations, either way round,
// and for the install's; the controller hears no write about any of those, and
// the certificate stays as it was. The administrator of the default
// organization reaches any object on the controller.
func TestOpenZitiWritesStayInsideTheOrganization(t *testing.T) {
	f := newZitiScopeFixture(t)
	for _, id := range []string{"sess-aa-", "sess-bb-", "sess-ab-", "sess-ba-", "sess-bind-"} {
		f.stub.ok("DELETE /edge/management/v1/sessions/"+id+f.sfx, `{}`)
	}
	f.stub.ok("GET /edge/management/v1/sessions/sess-aa-"+f.sfx,
		`{"data":{"id":"sess-aa-`+f.sfx+`","identity":{"id":"`+f.ziA+`"},"service":{"id":"`+f.zsA+`"}}}`)
	f.stub.ok("GET /edge/management/v1/sessions/sess-bb-"+f.sfx,
		`{"data":{"id":"sess-bb-`+f.sfx+`","identityId":"`+f.ziB+`","serviceId":"`+f.zsB+`"}}`)
	f.stub.ok("GET /edge/management/v1/sessions/sess-ab-"+f.sfx,
		`{"data":{"id":"sess-ab-`+f.sfx+`","apiSession":{"identity":{"id":"`+f.ziA+`"}},"service":{"id":"`+f.zsB+`"}}}`)
	f.stub.ok("GET /edge/management/v1/sessions/sess-ba-"+f.sfx,
		`{"data":{"id":"sess-ba-`+f.sfx+`","identity":{"id":"`+f.ziB+`"},"service":{"id":"`+f.zsA+`"}}}`)
	for _, id := range []string{"term-a-", "term-b-", "term-install-"} {
		f.stub.ok("DELETE /edge/management/v1/terminators/"+id+f.sfx, `{}`)
	}
	for _, id := range []string{f.zsA, f.zsB, f.zsInstall} {
		f.stub.ok("GET /edge/management/v1/services/"+id, `{"data":{"id":"`+id+`","roleAttributes":["`+id+`"]}}`)
		f.stub.ok("PATCH /edge/management/v1/services/"+id, `{}`)
	}
	certA := f.scalar(`SELECT id::text FROM ziti_certificates WHERE name = 'cert-a-' || $1`, f.sfx)
	certB := f.scalar(`SELECT id::text FROM ziti_certificates WHERE name = 'cert-b-' || $1`, f.sfx)

	adminB := f.caller("adminB", "admin")
	for _, rq := range []struct {
		method, path, body string
		// forbidden is a controller call the refused request must not make.
		forbidden string
	}{
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-aa-" + f.sfx, "", "DELETE /edge/management/v1/sessions/"},
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-ab-" + f.sfx, "", "DELETE /edge/management/v1/sessions/"},
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-ba-" + f.sfx, "", "DELETE /edge/management/v1/sessions/"},
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-none-" + f.sfx, "", "DELETE /edge/management/v1/sessions/"},
		{http.MethodPost, "/api/v1/access/ziti/sessions/batch-terminate", `{"identity_id":"` + f.ziA + `"}`, "DELETE /edge/management/v1/sessions/"},
		{http.MethodDelete, "/api/v1/access/ziti/terminators/term-a-" + f.sfx, "", "DELETE /edge/management/v1/terminators/"},
		{http.MethodDelete, "/api/v1/access/ziti/terminators/term-install-" + f.sfx, "", "DELETE /edge/management/v1/terminators/"},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsA + "/enable", "", "PATCH /edge/management/v1/services/"},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsInstall + "/enable", "", "PATCH /edge/management/v1/services/"},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsA + "/disable", "", "PATCH /edge/management/v1/services/"},
		{http.MethodPost, "/api/v1/access/ziti/certificates/" + certA + "/rotate", "", ""},
	} {
		f.resetCalls()
		code, body := f.do(adminB, rq.method, rq.path, rq.body)
		if code != http.StatusNotFound {
			t.Errorf("%s %s as B's admin: %d %s, want 404", rq.method, rq.path, code, body)
		}
		if rq.forbidden != "" && f.stub.saw(rq.forbidden) {
			t.Errorf("%s %s as B's admin reached the controller: %v", rq.method, rq.path, f.stub.received())
		}
	}
	if got := f.scalar(`SELECT status FROM ziti_certificates WHERE id::text = $1`, certA); got != "active" {
		t.Errorf("A's certificate after B's admin asked to rotate it: status %q, want active", got)
	}

	for _, rq := range []struct {
		method, path, body string
		reaches            string
	}{
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-bb-" + f.sfx, "", "DELETE /edge/management/v1/sessions/sess-bb-" + f.sfx},
		{http.MethodPost, "/api/v1/access/ziti/sessions/batch-terminate", `{"identity_id":"` + f.ziB + `"}`, "DELETE /edge/management/v1/sessions/sess-bb-" + f.sfx},
		{http.MethodDelete, "/api/v1/access/ziti/terminators/term-b-" + f.sfx, "", "DELETE /edge/management/v1/terminators/term-b-" + f.sfx},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsB + "/enable", "", "PATCH /edge/management/v1/services/" + f.zsB},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsB + "/disable", "", "PATCH /edge/management/v1/services/" + f.zsB},
	} {
		f.resetCalls()
		if code, body := f.do(adminB, rq.method, rq.path, rq.body); code != http.StatusOK {
			t.Errorf("%s %s as B's admin: %d %s, want 200", rq.method, rq.path, code, body)
		}
		if !f.stub.saw(rq.reaches) {
			t.Errorf("%s %s as B's admin did not reach %s: %v", rq.method, rq.path, rq.reaches, f.stub.received())
		}
	}
	// B's certificate is B's to rotate: the request gets past the organization
	// check to the rotation itself, which refuses a certificate with no
	// identity behind it.
	if code, body := f.do(adminB, http.MethodPost, "/api/v1/access/ziti/certificates/"+certB+"/rotate", ""); code == http.StatusNotFound || code == http.StatusForbidden {
		t.Errorf("rotate B's certificate as B's admin: %d %s", code, body)
	}

	admin := f.caller("adminA", "admin")
	for _, rq := range []struct {
		method, path string
		reaches      string
	}{
		{http.MethodDelete, "/api/v1/access/ziti/sessions/sess-ab-" + f.sfx, "DELETE /edge/management/v1/sessions/sess-ab-" + f.sfx},
		{http.MethodDelete, "/api/v1/access/ziti/terminators/term-install-" + f.sfx, "DELETE /edge/management/v1/terminators/term-install-" + f.sfx},
		{http.MethodPost, "/api/v1/access/ziti/browzer/services/" + f.zsInstall + "/enable", "PATCH /edge/management/v1/services/" + f.zsInstall},
	} {
		f.resetCalls()
		if code, body := f.do(admin, rq.method, rq.path, ""); code != http.StatusOK {
			t.Errorf("%s %s as the install administrator: %d %s, want 200", rq.method, rq.path, code, body)
		}
		if !f.stub.saw(rq.reaches) {
			t.Errorf("%s %s as the install administrator did not reach %s: %v", rq.method, rq.path, rq.reaches, f.stub.received())
		}
	}
}

// resetCalls forgets what the controller has been asked so far.
func (f *zitiScopeFixture) resetCalls() {
	f.stub.mu.Lock()
	f.stub.calls = nil
	f.stub.mu.Unlock()
}

// managementCalls is what the controller was asked since resetCalls, apart
// from logging in.
func (f *zitiScopeFixture) managementCalls() []string {
	var out []string
	for _, c := range f.stub.received() {
		if !strings.Contains(c, "/authenticate") {
			out = append(out, c)
		}
	}
	return out
}
