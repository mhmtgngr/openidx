package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parse builds an in-memory tree for the analysis, so each rule below is stated
// as the smallest program that exhibits it.
func parse(t *testing.T, files map[string]string) (*token.FileSet, []source) {
	t.Helper()
	fset := token.NewFileSet()
	var srcs []source
	for name, body := range files {
		f, err := parser.ParseFile(fset, name, body, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		srcs = append(srcs, source{Path: name, Pkg: f.Name.Name, File: f})
	}
	return fset, srcs
}

// The register is a list of verdicts, not a list of names. An entry without a
// reason is a finding somebody moved off a report.
func TestEveryRegisterEntryCarriesAVerdict(t *testing.T) {
	for key, verdict := range knownUnmounted {
		if len(verdict) < 60 {
			t.Errorf("%s: verdict is %d characters; say what the absence costs", key, len(verdict))
		}
		if !strings.HasSuffix(strings.TrimSpace(verdict), ".") {
			t.Errorf("%s: verdict does not end in a sentence", key)
		}
		if !strings.Contains(key, ".") {
			t.Errorf("%s: register keys are pkg.FuncName", key)
		}
	}
}

// The defect this tool was built for, reduced: the route says :id and the
// handler asks for user_id.
func TestAParameterTheRouteDoesNotDeclareIsAFinding(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

type S struct{}

func (s *S) handleRevoke(c *gin.Context) { _ = c.Param("user_id") }

func (s *S) routes(r *gin.Engine) { r.DELETE("/users/:id/bypass-codes", s.handleRevoke) }
`})
	res := analyze(fset, srcs)
	if len(res.Params) != 1 {
		t.Fatalf("param findings = %d, want 1: %+v", len(res.Params), res.Params)
	}
	if res.Params[0].Name != "user_id" {
		t.Errorf("finding names %q, want user_id", res.Params[0].Name)
	}
	if got := strings.Join(res.Params[0].Declared, ","); got != "id" {
		t.Errorf("declared = %q, want id", got)
	}
	if len(res.Params[0].Routes) != 1 || res.Params[0].Routes[0] != "DELETE /users/:id/bypass-codes" {
		t.Errorf("routes = %v, want the one route it is mounted on", res.Params[0].Routes)
	}
}

// The other direction, which matters more: a guard that reports correct code is
// one somebody turns off.
func TestAParameterTheRouteDeclaresIsNotAFinding(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

type S struct{}

func (s *S) handleRevoke(c *gin.Context) { _ = c.Param("id") }

func (s *S) routes(r *gin.Engine) { r.DELETE("/users/:id/bypass-codes", s.handleRevoke) }
`})
	if res := analyze(fset, srcs); len(res.Params) != 0 {
		t.Fatalf("param findings = %d, want 0: %+v", len(res.Params), res.Params)
	}
}

// One handler on two routes may legitimately read either name, so the check
// takes the union rather than one route at a time.
func TestParametersAreUnionedAcrossRoutes(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

type S struct{}

func (s *S) handleBoth(c *gin.Context) {
	_ = c.Param("id")
	_ = c.Param("userId")
}

func (s *S) routes(r *gin.Engine) {
	r.GET("/groups/:id", s.handleBoth)
	r.DELETE("/groups/:id/members/:userId", s.handleBoth)
}
`})
	if res := analyze(fset, srcs); len(res.Params) != 0 {
		t.Fatalf("param findings = %d, want 0 (the union covers both): %+v", len(res.Params), res.Params)
	}
}

// A handler that hands its context to a helper is still the thing on the route,
// so the helper is checked against that route's parameters.
func TestReachabilityReachesThroughAHelper(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

type S struct{}

func (s *S) subject(c *gin.Context) string { return c.Param("user_id") }

func (s *S) handleRevoke(c *gin.Context) { _ = s.subject(c) }

func (s *S) routes(r *gin.Engine) { r.DELETE("/users/:id/codes", s.handleRevoke) }
`})
	res := analyze(fset, srcs)
	if len(res.Params) != 1 {
		t.Fatalf("param findings = %d, want 1 (the helper reads a name the route lacks): %+v", len(res.Params), res.Params)
	}
	if res.Params[0].Func != "svc.subject" {
		t.Errorf("finding is on %s, want svc.subject", res.Params[0].Func)
	}
}

// Closures registered inline are handlers too; the first draft only resolved
// named functions and would have skipped them.
func TestAClosureHandlerIsChecked(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

func routes(r *gin.Engine) {
	r.GET("/apps/:id", func(c *gin.Context) { _ = c.Param("appId") })
}
`})
	res := analyze(fset, srcs)
	if len(res.Params) != 1 {
		t.Fatalf("param findings = %d, want 1: %+v", len(res.Params), res.Params)
	}
	if res.Params[0].Name != "appId" {
		t.Errorf("finding names %q, want appId", res.Params[0].Name)
	}
}

// A parameterised route whose handler cannot be resolved is not a pass, it is
// an unchecked route -- and the run says so rather than staying quiet.
func TestAParameterisedRouteWithNoResolvableHandlerIsBlind(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

func routes(r *gin.Engine, elsewhere gin.HandlerFunc) {
	r.GET("/things/:id", elsewhere)
	r.GET("/health", elsewhere)
}
`})
	res := analyze(fset, srcs)
	if len(res.Blind) != 1 {
		t.Fatalf("blind routes = %d, want 1: %+v", len(res.Blind), res.Blind)
	}
	if res.Blind[0].Path != "/things/:id" {
		t.Errorf("blind route = %s, want /things/:id (a route with no parameters has nothing to get wrong)", res.Blind[0].Path)
	}
}

// A handler nothing mounts is the second finding. The middleware beside it is
// referenced, so it is not.
func TestAHandlerNothingReferencesIsUnmounted(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

type S struct{}

func (s *S) handleMounted(c *gin.Context)   {}
func (s *S) handleOrphan(c *gin.Context)    {}
func (s *S) requireAdmin(c *gin.Context)    {}

func (s *S) routes(r *gin.Engine) {
	r.Use(s.requireAdmin)
	r.GET("/mounted", s.handleMounted)
}
`})
	res := analyze(fset, srcs)
	if len(res.Unmounted) != 1 {
		t.Fatalf("unmounted = %d, want 1: %+v", len(res.Unmounted), res.Unmounted)
	}
	if res.Unmounted[0].Key != "svc.handleOrphan" {
		t.Errorf("unmounted = %s, want svc.handleOrphan", res.Unmounted[0].Key)
	}
}

// Only gin.HandlerFunc's shape counts. A function that takes a context and
// returns something is a helper, and its absence from the route table means
// nothing.
func TestOnlyHandlerShapedFunctionsAreCandidates(t *testing.T) {
	fset, srcs := parse(t, map[string]string{"svc.go": `package svc

func helper(c *gin.Context) string        { return "" }
func twoArgs(c *gin.Context, id string)   {}
func notAContext(w http.ResponseWriter)   {}
func orphan(c *gin.Context)               {}
`})
	res := analyze(fset, srcs)
	if res.HandlerShaped != 1 {
		t.Fatalf("handler-shaped = %d, want 1", res.HandlerShaped)
	}
	if len(res.Unmounted) != 1 || res.Unmounted[0].Key != "svc.orphan" {
		t.Fatalf("unmounted = %+v, want only svc.orphan", res.Unmounted)
	}
}

// A test is not a mount. This is the rule that turned up internal/oauth's
// second discovery document: 415 lines of passing test for a handler no service
// serves. parseTree must not read _test.go, or that finding disappears into the
// thing that hid it.
func TestTestFilesAreNotScanned(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("svc.go", "package svc\n\nfunc orphan(c *gin.Context) {}\n")
	write("svc_test.go", "package svc\n\nfunc TestX(t *testing.T) { r.GET(\"/x\", orphan) }\n")

	srcs, fset, err := parseTree([]string{dir})
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	if len(srcs) != 1 {
		t.Fatalf("parsed %d file(s), want 1: the _test.go must not be read", len(srcs))
	}
	if res := analyze(fset, srcs); len(res.Unmounted) != 1 {
		t.Fatalf("unmounted = %+v, want the orphan: a test that mounts it is not a mount", res.Unmounted)
	}
}

// A file that will not parse is fatal. The sibling sweeps learned this the hard
// way: skipping it makes the run report FEWER findings, which reads like a fix.
func TestAParseFailureIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package svc\n\nfunc ("), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseTree([]string{dir}); err == nil {
		t.Fatal("parseTree accepted a file it could not parse")
	}
}

func TestPathParams(t *testing.T) {
	for path, want := range map[string]string{
		"/users/:id/bypass-codes":     "id",
		"/groups/:id/members/:userId": "id,userId",
		"/files/*filepath":            "filepath",
		"/health":                     "",
		"/a/:":                        "",
	} {
		if got := strings.Join(pathParams(path), ","); got != want {
			t.Errorf("pathParams(%q) = %q, want %q", path, got, want)
		}
	}
}

// The claim the param check rests on: no route group in this repository
// contributes a parameter, so a route's own path is the whole source of its
// names. If a group ever declares one, this check goes unsound silently -- so
// it is asserted rather than assumed.
func TestNoRouteGroupDeclaresAParameter(t *testing.T) {
	srcs, fset, err := parseTree([]string{"../../internal", "../../cmd"})
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	_ = fset
	for _, s := range srcs {
		for _, lit := range groupPaths(s) {
			if strings.ContainsAny(lit, ":*") {
				t.Errorf("%s: .Group(%q) declares a parameter; routereach's param check "+
					"assumes the route path is the whole source of parameter names", s.Path, lit)
			}
		}
	}
}

// The live tree: every parameterised route resolves to a handler, so the census
// covers what it claims to cover.
func TestTheRealTreeHasNoBlindRoutes(t *testing.T) {
	srcs, fset, err := parseTree([]string{"../../internal", "../../cmd", "../../pkg"})
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	res := analyze(fset, srcs)
	if len(res.Blind) != 0 {
		t.Errorf("blind routes = %+v, want none", res.Blind)
	}
	if len(res.Routes) < 500 {
		t.Errorf("found %d routes; the scan is not reaching the tree", len(res.Routes))
	}
}
