package access

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// A DEVICE REPORTS ITS OWN POSTURE, AND NOBODY ELSE'S.
//
// POST /ziti/posture/device is the mobile app's self-report, and the results it
// records are what the proxy's posture checks read for an identity. Through the
// real route table, a user of the second organization reports for their own
// identity, by its controller id and by its id, and results are recorded for
// it in their organization. Every other identity is refused with 404 and gets
// no result: the first organization's, another user's in the same
// organization, one an admin names for a user, one a caller of the first
// organization names in the second, the caller's own user's identity where it
// is recorded in another organization, and one that does not exist.
func TestADeviceReportsPostureOnlyForItsOwnIdentity(t *testing.T) {
	f := newZitiScopeFixture(t)
	f.exec(`INSERT INTO ziti_identities (ziti_id, name, user_id, org_id) VALUES ($1, $2::text, $2::uuid, $3::uuid)`,
		"zi-b2-"+f.sfx, f.users["operatorB"], f.orgB.ID)
	// B's user's identity as the first organization records it: a row left
	// behind in another organization is that organization's.
	f.exec(`INSERT INTO ziti_identities (ziti_id, name, user_id, org_id) VALUES ($1, $2, $3::uuid, $4::uuid)`,
		"zi-b-in-a-"+f.sfx, "b-in-a-"+f.sfx, f.users["userB"], middleware.DefaultOrgID)
	local := func(zitiID string) string {
		return f.scalar(`SELECT id::text FROM ziti_identities WHERE ziti_id = $1`, zitiID)
	}
	localA, localB, localB2 := local(f.ziA), local(f.ziB), local("zi-b2-"+f.sfx)
	localBinA := local("zi-b-in-a-" + f.sfx)
	recorded := func(identity string) string {
		return f.scalar(`SELECT COUNT(*)::text FROM device_posture_results WHERE identity_id::text = $1`, identity)
	}
	body := func(ref string) string {
		return `{"identity_id":"` + ref + `","posture":{"os":"linux","os_version":"6.1","screen_lock_enabled":true}}`
	}

	userB := f.caller("userB", "user")
	for _, rq := range []struct {
		name  string
		cl    zitiCaller
		ref   string
		whose string
	}{
		{"another organization's identity, by controller id", userB, f.ziA, localA},
		{"another organization's identity, by id", userB, localA, localA},
		{"another user's identity in the same organization, by controller id", userB, "zi-b2-" + f.sfx, localB2},
		{"another user's identity in the same organization, by id", userB, localB2, localB2},
		{"a user's identity, named by an admin of the organization", f.caller("adminB", "admin"), f.ziB, localB},
		{"the second organization's identity, named in the first", f.caller("operatorA", "operator"), f.ziB, localB},
		{"the caller's identity as another organization records it", userB, "zi-b-in-a-" + f.sfx, localBinA},
		{"an identity that does not exist", userB, "zi-none-" + f.sfx, ""},
	} {
		code, resp := f.do(rq.cl, http.MethodPost, "/api/v1/access/ziti/posture/device", body(rq.ref))
		if code != http.StatusNotFound || !strings.Contains(resp, "ziti identity not found") {
			t.Errorf("%s: %d %s, want 404 ziti identity not found", rq.name, code, resp)
		}
		if rq.whose != "" {
			if n := recorded(rq.whose); n != "0" {
				t.Errorf("%s: %s posture results were recorded for it", rq.name, n)
			}
		}
	}

	for _, ref := range []string{f.ziB, localB} {
		code, resp := f.do(userB, http.MethodPost, "/api/v1/access/ziti/posture/device", body(ref))
		if code != http.StatusOK || !strings.Contains(resp, `"identity_id":"`+localB+`"`) {
			t.Errorf("B's user reporting for their own identity as %s: %d %s, want 200 for %s", ref, code, resp, localB)
		}
	}
	if n := recorded(localB); n == "0" {
		t.Errorf("B's user's own report recorded nothing")
	}
	if org := f.scalar(`SELECT string_agg(DISTINCT org_id::text, ',') FROM device_posture_results WHERE identity_id::text = $1`, localB); org != f.orgB.ID {
		t.Errorf("B's user's results were recorded in %s, want %s", org, f.orgB.ID)
	}
}
