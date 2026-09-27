package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
)

// The tier a caller reaches is computed the way the console computes it. These
// are the cases web/admin-console/src/lib/roles.test.ts pins for roleLevel,
// asked of callerTierRank; if the two ever disagree, a page and the routes
// behind it are held to different tiers.
func TestCallerTierRankMatchesTheConsole(t *testing.T) {
	for _, tc := range []struct {
		roles       []string
		auditDomain bool
		want        int
	}{
		{[]string{"super_admin"}, false, 4},
		{[]string{"admin"}, false, 3},
		{[]string{"operator"}, false, 2},
		{[]string{"auditor"}, false, 1},
		{[]string{"user"}, false, 0},
		{[]string{"user", "auditor", "admin"}, false, 3},
		{[]string{}, false, 0},
		{nil, false, 0},
		{[]string{"something-custom"}, false, 0},
		{[]string{"compliance_reader"}, false, 0},
		{[]string{"compliance_reader"}, true, 1},
		{[]string{"compliance_reader", "operator"}, true, 2},
	} {
		if got := callerTierRank(tc.roles, tc.auditDomain); got != tc.want {
			t.Errorf("callerTierRank(%v, auditDomain=%v) = %d, want %d", tc.roles, tc.auditDomain, got, tc.want)
		}
	}
}

// The gates on their own, without a database: who each admits, what a refusal
// says, and that DevAdminBypass admits everyone as it does for the admin gate.
func TestTheTierGatesAdmitTheirTierAndAbove(t *testing.T) {
	gin.SetMode(gin.TestMode)
	call := func(s *Service, gate func(*Service) gin.HandlerFunc, roles []string) (int, string) {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if roles != nil {
				c.Set("roles", roles)
			}
			c.Next()
		})
		r.GET("/probe", gate(s), func(c *gin.Context) { c.String(http.StatusOK, "through") })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/probe", nil))
		return w.Code, w.Body.String()
	}
	operator := (*Service).requireOperatorTier
	audit := (*Service).requireAuditTier
	s := &Service{config: &config.Config{Environment: "production"}}

	for _, tc := range []struct {
		name  string
		gate  func(*Service) gin.HandlerFunc
		roles []string
		admit bool
		want  string
	}{
		{"operator tier: no roles", operator, nil, false, "operator access required"},
		{"operator tier: user", operator, []string{"user"}, false, "operator access required"},
		{"operator tier: auditor", operator, []string{"auditor"}, false, "operator access required"},
		{"operator tier: compliance_reader", operator, []string{"compliance_reader"}, false, "operator access required"},
		{"operator tier: operator", operator, []string{"operator"}, true, ""},
		{"operator tier: admin", operator, []string{"admin"}, true, ""},
		{"operator tier: super_admin", operator, []string{"super_admin"}, true, ""},
		{"audit tier: user", audit, []string{"user"}, false, "auditor access required"},
		{"audit tier: a role the console does not rank", audit, []string{"manager"}, false, "auditor access required"},
		{"audit tier: compliance_reader", audit, []string{"compliance_reader"}, true, ""},
		{"audit tier: auditor", audit, []string{"auditor"}, true, ""},
		{"audit tier: operator", audit, []string{"operator"}, true, ""},
		{"audit tier: admin", audit, []string{"admin"}, true, ""},
	} {
		code, body := call(s, tc.gate, tc.roles)
		if tc.admit && code != http.StatusOK {
			t.Errorf("%s: %d %s, want admitted", tc.name, code, body)
		}
		if !tc.admit && (code != http.StatusForbidden || !strings.Contains(body, tc.want)) {
			t.Errorf("%s: %d %s, want 403 %q", tc.name, code, body, tc.want)
		}
	}

	bypass := &Service{config: &config.Config{Environment: "development", DevAdminBypass: true}}
	if code, body := call(bypass, operator, []string{"user"}); code != http.StatusOK {
		t.Errorf("DevAdminBypass: operator tier refused a user: %d %s", code, body)
	}
	if code, body := call(bypass, audit, nil); code != http.StatusOK {
		t.Errorf("DevAdminBypass: audit tier refused a caller with no roles: %d %s", code, body)
	}
}
