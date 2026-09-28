package access

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// THE INTEGRITY DOCTOR IS THE INSTALL'S.
//
// The Relations & Integrity Doctor reads every organization's routes,
// applications and Ziti services under the RLS belt's opt-out, and repairs
// what it finds in all of them: ?heal=safe applies every safe repair, and
// /health/fix applies one, including tearing a service that no route names off
// the controller. Through the real route table, a plain user is refused by the
// admin gate and the second organization's admin and super_admin by the
// install-administrator gate: they get no report, and a repair they ask for
// removes nothing from the controller. The administrator of the default
// organization gets the report, which names the orphaned service, and their
// repair tears it down.
func TestTheIntegrityDoctorNeedsAnInstallAdministrator(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.svc.SetHealthEngine(NewHealthEngine(f.svc))
	// Besides both organizations' services and the install's, the controller
	// holds one named like OpenIDX's own that no route names.
	orphan, orphanID := "openidx-orphan-"+f.sfx, "zs-orphan-"+f.sfx
	f.stub.ok("GET /edge/management/v1/services", `{"data":[`+
		`{"id":"`+f.zsA+`","name":"`+f.svcA+`"},`+
		`{"id":"`+f.zsB+`","name":"`+f.svcB+`"},`+
		`{"id":"`+f.zsInstall+`","name":"`+f.svcInstall+`"},`+
		`{"id":"`+orphanID+`","name":"`+orphan+`"}]}`)
	f.stub.ok("DELETE /edge/management/v1/", `{}`)
	const relations, fix = "/api/v1/access/health/relations", "/api/v1/access/health/fix/ziti-orphan"
	repair := `{"subject":"` + orphan + `"}`

	for _, refused := range []struct {
		cl   zitiCaller
		want string
	}{
		{f.caller("userB", "user"), "admin access required"},
		{f.caller("operatorB", "operator"), "admin access required"},
		{f.caller("adminB", "admin"), middleware.PlatformAdminRequired},
		{f.caller("superB", "admin", "super_admin"), middleware.PlatformAdminRequired},
	} {
		f.resetCalls()
		for _, rq := range []struct{ method, path, body string }{
			{http.MethodGet, relations, ""},
			{http.MethodGet, relations + "?heal=safe", ""},
			{http.MethodPost, fix, repair},
		} {
			code, body := f.do(refused.cl, rq.method, rq.path, rq.body)
			if code != http.StatusForbidden || !strings.Contains(body, refused.want) || strings.Contains(body, orphan) {
				t.Errorf("%s %s as %s: %d %s, want 403 %s", rq.method, rq.path, refused.cl.name, code, body, refused.want)
			}
		}
		if calls := f.managementCalls(); len(calls) != 0 {
			t.Errorf("the doctor refused to %s still asked the controller: %v", refused.cl.name, calls)
		}
	}

	admin := f.caller("adminA", "admin")
	if code, body := f.do(admin, http.MethodGet, relations, ""); code != http.StatusOK || !strings.Contains(body, orphan) {
		t.Errorf("the doctor's report as the install administrator: %d %s, want 200 naming %s", code, body, orphan)
	}
	f.resetCalls()
	if code, body := f.do(admin, http.MethodPost, fix, repair); code != http.StatusOK {
		t.Errorf("the orphan repair as the install administrator: %d %s, want 200", code, body)
	}
	if !f.stub.saw("DELETE /edge/management/v1/services/" + orphanID) {
		t.Errorf("the install administrator's repair did not tear %s down: %v", orphan, f.stub.received())
	}
}
