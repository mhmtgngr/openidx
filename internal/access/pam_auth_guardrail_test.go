package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
)

// TestPamCallerIsAdmin_devDoesNotImplyAdmin locks the A1 endpoint-control fix:
// APP_ENV=development must NOT make every PAM caller an admin. The dev-admin
// convenience is now an explicit opt-in (config.DevAdminBypass) so a box left in
// dev mode still keeps the inventory behind identity instead of exposing it to
// anonymous callers.
func TestPamCallerIsAdmin_devDoesNotImplyAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newCtx := func(roles interface{}) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if roles != nil {
			c.Set("roles", roles)
		}
		return c
	}

	cases := []struct {
		name  string
		cfg   *config.Config
		roles interface{}
		want  bool
	}{
		{"dev + no roles is NOT admin (regression guard)", &config.Config{Environment: "development"}, nil, false},
		{"dev + non-admin role is NOT admin", &config.Config{Environment: "development"}, []string{"user"}, false},
		{"DevAdminBypass opt-in makes caller admin", &config.Config{Environment: "development", DevAdminBypass: true}, nil, true},
		{"admin role is admin (any env)", &config.Config{Environment: "production"}, []string{"admin"}, true},
		{"super_admin role is admin", &config.Config{Environment: "production"}, []string{"super_admin"}, true},
		{"non-admin role is not admin", &config.Config{Environment: "production"}, []string{"user"}, false},
		{"nil config is not admin", nil, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{config: tc.cfg}
			if got := s.pamCallerIsAdmin(newCtx(tc.roles)); got != tc.want {
				t.Fatalf("pamCallerIsAdmin = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHandlePamListMyRequests_failsClosedWithoutIdentity locks the A2 contract:
// the handler returns 401 when no user_id is present (its correct fail-closed
// branch — do NOT delete it), and gets PAST that gate once identity flows,
// proving the earlier 401 was a missing-identity problem (no auth middleware in
// dev), not a broken endpoint. With identity present it reaches the org check
// and returns 403 (no org in this unit context) — i.e. no longer 401.
func TestHandlePamListMyRequests_failsClosedWithoutIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	// No user_id → 401.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/access/pam/my-entry-requests", nil)
	s.handlePamListMyRequests(c)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("without user_id: got %d, want 401", w.Code)
	}

	// With user_id set (as the auth middleware now does) → past the 401 gate.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/api/v1/access/pam/my-entry-requests", nil)
	c2.Set("user_id", "00000000-0000-0000-0000-000000000001")
	s.handlePamListMyRequests(c2)
	if w2.Code == http.StatusUnauthorized {
		t.Fatalf("with user_id: still 401 — identity did not clear the auth gate")
	}
}
