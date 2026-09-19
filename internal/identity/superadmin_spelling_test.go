package identity

import (
	"context"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/risk"
)

// The elevated role has one spelling. auth.RoleSuperAdmin is the source of
// truth; the helper in this package must agree with it, and must not accept
// a role that merely resembles it.
func TestIdentityCallerIsAdminSpelling(t *testing.T) {
	if string(auth.RoleSuperAdmin) != "super_admin" {
		t.Fatalf("auth.RoleSuperAdmin is %q; this test and the helper assume super_admin", auth.RoleSuperAdmin)
	}
	cases := []struct {
		roles []string
		want  bool
	}{
		{[]string{"admin"}, true},
		{[]string{string(auth.RoleSuperAdmin)}, true},
		{[]string{"user", "super_admin"}, true},
		{[]string{"superadmin"}, false}, // the legacy spelling is not the role
		{[]string{"user"}, false},
		{nil, false},
	}
	for _, tc := range cases {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("roles", tc.roles)
		if got := identityCallerIsAdmin(c); got != tc.want {
			t.Errorf("roles %v: identityCallerIsAdmin = %v, want %v", tc.roles, got, tc.want)
		}
	}
}

// loginHistoryRisk records the user the handler asked about. Every other
// RiskService method is the embedded nil interface and would panic if the
// handler reached it, which is the point: this test drives one path.
type loginHistoryRisk struct {
	RiskService
	askedFor string
}

func (f *loginHistoryRisk) GetLoginHistory(_ context.Context, userID string, _ int) ([]risk.LoginRecord, error) {
	f.askedFor = userID
	return []risk.LoginRecord{}, nil
}

// Measured on 2026-09-19: handleGetLoginHistory compared roles against
// "superadmin", so a caller holding the real super_admin role passed the route
// gate and was then refused another user's history with 403. This is that
// request. It stays green only while the handler asks the same helper the
// gate agrees with; with the old inline check it is red.
func TestSuperAdminSeesAnotherUsersLoginHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := authzSurfaceService()
	fake := &loginHistoryRisk{}
	svc.SetRiskService(fake)

	call := func(roles []string, query string) (int, string) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/risk/login-history"+query, nil)
		c.Set("user_id", "11111111-1111-1111-1111-111111111111")
		c.Set("roles", roles)
		fake.askedFor = ""
		svc.handleGetLoginHistory(c)
		return w.Code, fake.askedFor
	}

	other := "22222222-2222-2222-2222-222222222222"
	if code, asked := call([]string{"super_admin"}, "?user_id="+other); code != http.StatusOK || asked != other {
		t.Fatalf("super_admin asking for another user's history: code=%d askedFor=%q; want 200 and %q", code, asked, other)
	}
	if code, asked := call([]string{"super_admin"}, ""); code != http.StatusOK || asked != "" {
		t.Fatalf("super_admin asking for all history: code=%d askedFor=%q; want 200 and an unscoped query", code, asked)
	}
	// Controls: a plain user is still refused, and still narrowed to themself.
	if code, _ := call([]string{"user"}, "?user_id="+other); code != http.StatusForbidden {
		t.Fatalf("user asking for another user's history: code=%d, want 403", code)
	}
	if code, asked := call([]string{"user"}, ""); code != http.StatusOK || asked != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("user asking for all history: code=%d askedFor=%q; want 200 narrowed to themself", code, asked)
	}
	// The legacy spelling is a role name that does not exist; it gets nothing.
	if code, _ := call([]string{"superadmin"}, "?user_id="+other); code != http.StatusForbidden {
		t.Fatalf("a role spelled superadmin asking for another user's history: code=%d, want 403", code)
	}
}

// No Go source under internal/ or cmd/ may hold the string literal
// "superadmin" as code. Comments may mention it (this file's history does);
// a comparison against it is the defect this test exists to keep out.
//
// internal/governance/privileged_discovery.go is the one exception: it lists
// names that OTHER systems give privileged accounts, and "superadmin" is one
// of those names. That list is about their spelling, not ours.
func TestNoLegacySuperadminLiteralInCode(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "governance", "privileged_discovery.go"): true,
	}
	var offenders []string
	files := 0
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if allowed[rel] {
				return nil
			}
			files++
			fset := gotoken.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if ok && lit.Kind == gotoken.STRING && (lit.Value == `"superadmin"` || lit.Value == "`superadmin`") {
					offenders = append(offenders, fset.Position(lit.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 500 {
		t.Fatalf("walked only %d Go files under internal/ and cmd/; this guard is checking almost nothing", files)
	}
	if len(offenders) > 0 {
		t.Fatalf("the elevated role is spelled super_admin (auth.RoleSuperAdmin); these compare against the legacy spelling and would refuse a real super admin:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
