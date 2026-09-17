package access

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// THE LEGAL-HOLD WRITES ARE ADMIN AUTHORITY, measured two ways: that the role
// gate refuses a non-admin, and that the legal-hold registration actually puts
// a gate in front of the two writes and not the read. The census reads the
// registration text; this reads the behaviour.

func TestRequireAdminRoleRefusesANonAdminAndAdmitsAnAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{config: &config.Config{}, logger: zap.NewNop()}

	for _, tc := range []struct {
		roles []string
		want  int
	}{
		{[]string{"user"}, http.StatusForbidden},
		{nil, http.StatusForbidden},
		{[]string{"admin"}, http.StatusOK},
		{[]string{"super_admin"}, http.StatusOK},
	} {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if tc.roles != nil {
				c.Set("roles", tc.roles)
			}
		})
		r.POST("/probe", s.requireAdminRole(), func(c *gin.Context) { c.String(http.StatusOK, "held") })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/probe", nil))
		if w.Code != tc.want {
			t.Errorf("roles %v: got %d, want %d (%s)", tc.roles, w.Code, tc.want, w.Body.String())
		}
	}
}

// The registration puts the gate on POST and DELETE and leaves GET alone. A
// gate that aborts with a distinctive status makes the wiring observable
// without a database or a real role check.
func TestLegalHoldWritesCarryTheGateAndTheReadDoesNot(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const sentinel = http.StatusTeapot
	gate := func(c *gin.Context) { c.AbortWithStatus(sentinel) }

	h := &RemoteSupportHandler{logger: zap.NewNop()}
	r := gin.New()
	h.RegisterLegalHoldAdminRoutes(r.Group("/"), gate)

	for _, tc := range []struct {
		method, path string
		gated        bool
	}{
		{http.MethodPost, "/remote-support/sessions/abc/legal-hold", true},
		{http.MethodDelete, "/remote-support/sessions/abc/legal-hold", true},
		{http.MethodGet, "/remote-support/sessions/abc/legal-holds", false},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if tc.gated && w.Code != sentinel {
			t.Errorf("%s %s reached the handler without passing the admin gate (status %d)", tc.method, tc.path, w.Code)
		}
		if !tc.gated && w.Code == sentinel {
			t.Errorf("%s %s is gated; listing holds grants nothing and must stay open to the tenant", tc.method, tc.path)
		}
	}
}

// WHICH gate, not just whether. The census accepts either requireAdminRole or
// requireFreshMFA as a classification, so swapping the two at the mount site --
// the freshness gate onto the legal-hold writes, the admin gate onto session
// start -- leaves it green while letting any user with a fresh second factor
// release a litigation hold. This pins the mount line: session start takes the
// freshness gate under its own action name, and the legal-hold parameter takes
// the admin gate. The same shape as TestTheLaunchRoutesActuallyCarryTheGate,
// for the same reason: "gated" is not the property; "gated by the right gate"
// is.
func TestTheLegalHoldGateIsTheAdminGateNotTheFreshnessGate(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	const want = `RegisterRemoteSupportAdminRoutes(api, svc.requireFreshMFA("remote_support.start_session"), svc.requireAdminRole())`
	if !strings.Contains(string(b), want) {
		t.Fatalf("service.go does not mount the remote-support surface as\n  %s\n"+
			"The first gate is what a caller needs to START a session (a fresh factor); the second is what a "+
			"caller needs to place or RELEASE a legal hold (admin authority). Swapped or dropped, a "+
			"non-admin with a fresh factor can release a hold and the retention sweep purges the evidence.",
			want)
	}
}
