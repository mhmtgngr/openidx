package oauth

// A SCOPE IS A WHOLE SCOPE, NOT A SUBSTRING.
//
// Five decisions asked whether a grant carried a scope with
// `strings.Contains(scope, "openid")` and `strings.Contains(scope, "offline_access")`.
// Measured at the real token endpoint, before the fix:
//
//   - a code granted `openidx` — the name of this product, so not a contrived
//     value — was answered with an ID TOKEN, although `openid` was never
//     requested;
//   - a code granted `openid offline_access_reports` was answered with a
//     REFRESH TOKEN, although `offline_access` was never requested. That is a
//     long-lived credential handed to a client that did not ask for one.
//
// RFC 6749 §3.3 makes the scope string a space-delimited list of whole scopes.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// scopeMembershipFixture drives real code exchanges through the real handler.
type scopeMembershipFixture struct{ f *refreshGrantFixture }

func setupScopeMembership(t *testing.T) *scopeMembershipFixture {
	t.Helper()
	f := newRefreshGrantFixture(t)
	if _, err := f.db.Pool.Exec(f.ctx, `
		CREATE TABLE oauth_authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_id UUID NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			nonce TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL DEFAULT '',
			code_challenge_method VARCHAR(10) NOT NULL DEFAULT '',
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			org_id UUID NOT NULL
		)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return &scopeMembershipFixture{f: f}
}

// exchange seeds an authorization code with the given granted scope and runs
// the real token endpoint over it.
func (m *scopeMembershipFixture) exchange(t *testing.T, code, scope string) map[string]interface{} {
	t.Helper()
	if _, err := m.f.db.Pool.Exec(m.f.ctx, `
		INSERT INTO oauth_authorization_codes (code, client_id, user_id, redirect_uri, scope, expires_at, org_id)
		VALUES ($1, 'app', $2, 'https://rp.test/cb', $3, NOW() + INTERVAL '5 minutes', $4)`,
		code, grantUser, scope, grantOrg); err != nil {
		t.Fatalf("seed code: %v", err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"app"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://rp.test/cb"},
	}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.Request = req.WithContext(m.f.ctx)
	m.f.svc.handleAuthorizationCodeGrant(c)
	if w.Code != http.StatusOK {
		t.Fatalf("token endpoint for scope %q: %d %s", scope, w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// A scope that merely CONTAINS "openid" is not "openid".
func TestAScopeNamedLikeOpenidDoesNotBuyAnIDToken(t *testing.T) {
	m := setupScopeMembership(t)

	for _, scope := range []string{"openidx", "openid-connect", "api:openid"} {
		got := m.exchange(t, "code-"+scope, scope)
		if _, issued := got["id_token"]; issued {
			t.Fatalf("scope %q was answered with an id_token; only the whole scope `openid` buys one", scope)
		}
	}

	// And the honest request still gets one, so this is a gate rather than a
	// claim that was dropped everywhere.
	if _, issued := m.exchange(t, "code-real-openid", "openid")["id_token"]; !issued {
		t.Fatal("a grant that really did carry `openid` was refused its id_token")
	}
}

// A scope that merely CONTAINS "offline_access" is not "offline_access", and
// this one decides whether a long-lived refresh token is handed out.
func TestAScopeNamedLikeOfflineAccessDoesNotBuyARefreshToken(t *testing.T) {
	m := setupScopeMembership(t)

	for _, scope := range []string{"openid offline_access_reports", "openid no_offline_access"} {
		got := m.exchange(t, "code-"+strings.ReplaceAll(scope, " ", "_"), scope)
		if _, issued := got["refresh_token"]; issued {
			t.Fatalf("scope %q was answered with a refresh_token; only the whole scope `offline_access` buys one", scope)
		}
	}

	if _, issued := m.exchange(t, "code-real-offline", "openid offline_access")["refresh_token"]; !issued {
		t.Fatal("a grant that really did carry `offline_access` was refused its refresh_token")
	}
}

// A CENSUS. Whether a grant carries a scope is one question with one answer,
// and a substring test is not it. This refuses the shape in non-test files:
// strings.Contains(<anything named …Scope/scope>, "<literal>").
func TestNoScopeDecisionIsMadeBySubstring(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string

	looksLikeAScope := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.Ident:
			return strings.Contains(strings.ToLower(v.Name), "scope")
		case *ast.SelectorExpr:
			return strings.Contains(strings.ToLower(v.Sel.Name), "scope")
		}
		return false
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Contains" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "strings" {
				return true
			}
			if !looksLikeAScope(call.Args[0]) {
				return true
			}
			if _, isLit := call.Args[1].(*ast.BasicLit); !isLit {
				return true
			}
			offenders = append(offenders, fmt.Sprintf("%s", fset.Position(call.Pos())))
			return true
		})
	}

	if len(offenders) > 0 {
		t.Fatalf("a scope is a whole scope, not a substring: use scopeGrants(scope, …) at\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
