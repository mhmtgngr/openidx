package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The server-rendered login must stay deleted.
//
// Convergence Task 15 ("delete the server-rendered login") was recorded as an
// operator step behind OAUTH_LOGIN_UI=spa. It was not: the routes below were
// registered unconditionally, so flipping the flag left the second credential
// pipeline serving. An in-tree comment said so outright — "GET /oauth/login
// and /oauth/authorize/v2 both render it unconditionally today, regardless of
// this flag". That is why this is a test and not a checklist item: a checklist
// cannot notice a route coming back.
//
// What was deleted, and why it mattered beyond duplication: the page was Go
// string concatenation with hardcoded English ("Username", "Sign In",
// "Two-step verification") and <label>/<input> pairs carrying no htmlFor — so
// it sat outside every i18n and accessibility gate this project built, on the
// page a public OIDC client got by default.
func TestServerRenderedLoginRoutesAreGone(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	// RegisterRoutes dereferences no service field at registration time, so a
	// zero Service is enough to enumerate the route table.
	RegisterRoutes(r, &Service{}, func(c *gin.Context) { c.Next() })

	registered := map[string]bool{}
	for _, route := range r.Routes() {
		registered[route.Method+" "+route.Path] = true
	}

	for _, gone := range []string{
		"GET /oauth/login",
		"POST /oauth/authorize/callback",
		"POST /oauth/authorize/mfa",
		"POST /oauth/authorize/mfa/method",
		"POST /oauth/authorize/mfa/send",
		"POST /oauth/authorize/mfa/push",
		"GET /oauth/authorize/mfa/wait",
	} {
		if registered[gone] {
			t.Errorf("%s is registered again; it is the server-rendered login, which has one job this product already does in the SPA", gone)
		}
	}

	// Positive control: without it an empty router — or a RegisterRoutes that
	// silently registered nothing — would pass the assertions above.
	for _, present := range []string{
		"GET /oauth/authorize",
		"POST /oauth/login",      // the SPA's JSON login API; NOT the deleted page
		"POST /oauth/mfa-verify", // its second factor
		"POST /oauth/token",
	} {
		if !registered[present] {
			t.Errorf("%s is missing; the route table is not what this test thinks it is", present)
		}
	}
}

// A route table only says what is reachable today. These functions rendered
// the page, and a future change could bring one back under a different route
// name — so the source is checked too.
func TestServerRenderedLoginFunctionsAreGone(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	gone := map[string]string{
		"handleLoginPage":              "served the server-rendered login form",
		"renderLoginPage":              "built the form's HTML",
		"renderBrandedPage":            "the shell every server-rendered auth step shared",
		"handleAuthorizeCallback":      "the form's POST target, the second credential pipeline",
		"loadLoginBranding":            "tenant branding for that page only",
		"defaultLoginBranding":         "its fallback",
		"beginHostedMFA":               "the page's second-factor entry point",
		"renderMFAPage":                "the page's second-factor form",
		"completeHostedMFA":            "the page's second-factor completion",
		"issueHostedAuthorizationCode": "the page's mint site",
		"renderPushWaitPage":           "the page's push-approval waiting screen",
	}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Name == nil {
					return true
				}
				if why, banned := gone[fn.Name.Name]; banned {
					t.Errorf("%s reappeared in %s (%s). There is one login UI; add a route to the SPA instead.",
						fn.Name.Name, path, why)
				}
				return true
			})
		}
	}
}
