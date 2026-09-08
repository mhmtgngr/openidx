package middleware

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Seven of the eight HTTP service mains mounted SecurityHeadersForEnv. The
// eighth was cmd/gateway-service — the one that faces the internet, and the one
// host a browser actually talks to — and nothing in internal/gateway set a
// security header either. So the front door sent no HSTS, no nosniff, no
// frame-options on everything it served itself: /metrics, the combined OpenAPI
// spec, and every 404, 429 and 502 the proxy generated.
//
// Nothing was wrong with the middleware. It was mounted seven times out of
// eight, which is the shape of an omission nobody can see: the seven that do it
// look like the rule, and the reviewer reading any one of them sees a service
// that does it correctly.
//
// So the list is DERIVED rather than written down. Any cmd/ main that builds a
// gin engine is an HTTP service, and an HTTP service must mount the headers or
// be listed below with a reason. A ninth service cannot be added without one or
// the other.
//
// It has to live here rather than in a per-service test, because the property is
// about the set: a test inside cmd/gateway-service could only have been written
// by somebody who already knew the gateway was missing it.
var securityHeaderExempt = map[string]string{
	// Nothing today. An entry here is a service that serves no browser-reachable
	// response, and it needs the sentence saying why.
}

func TestEveryHTTPServiceMountsSecurityHeaders(t *testing.T) {
	root := securityRepoRoot(t)
	cmdDir := filepath.Join(root, "cmd")

	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}

	var httpServices, missing []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cmdDir, e.Name())
		buildsEngine, mountsHeaders, err := inspectServiceMain(dir)
		if err != nil {
			t.Fatalf("inspect %s: %v", e.Name(), err)
		}
		if !buildsEngine {
			continue // a CLI tool (migrate, backup, rekey, ...), not an HTTP service
		}
		httpServices = append(httpServices, e.Name())
		if mountsHeaders {
			continue
		}
		if _, exempt := securityHeaderExempt[e.Name()]; exempt {
			continue
		}
		missing = append(missing, e.Name())
	}
	sort.Strings(httpServices)
	sort.Strings(missing)

	// A derived list that derives nothing passes silently, which is how the
	// gateway went eight releases without these headers.
	if len(httpServices) < 5 {
		t.Fatalf("found only %d gin-based service mains (%v) — the detector is not seeing cmd/",
			len(httpServices), httpServices)
	}

	if len(missing) != 0 {
		t.Errorf("HTTP service(s) that build a gin engine but never mount SecurityHeadersForEnv: %s\n\n"+
			"Every response they generate goes out with no HSTS, no X-Content-Type-Options and no "+
			"X-Frame-Options. Add router.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction())), or "+
			"add the service to securityHeaderExempt in this file with the reason it serves nothing a "+
			"browser reaches.\nHTTP services found: %s",
			strings.Join(missing, ", "), strings.Join(httpServices, ", "))
	}
}

// An exemption without a reason is a list entry somebody added to get to green.
func TestEverySecurityHeaderExemptionHasAReason(t *testing.T) {
	for svc, reason := range securityHeaderExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("securityHeaderExempt[%q] has no reason — say what it serves that no browser reaches", svc)
		}
	}
}

// inspectServiceMain reports whether dir's Go files construct a gin engine, and
// whether they mount the security-header middleware.
//
// Matching is on the CALL, not on the file text: a service that only mentions
// SecurityHeadersForEnv in a comment does not mount it. serviceMainCalls
// (trustedproxies_test.go) does the walking, so the two set-level guards in this
// package agree by construction about what a service main is.
func inspectServiceMain(dir string) (buildsEngine, mountsHeaders bool, err error) {
	calls, err := serviceMainCalls(dir)
	if err != nil {
		return false, false, err
	}
	buildsEngine = calls["gin.New"] || calls["gin.Default"]
	// The import is aliased differently across the mains (commonmiddleware,
	// middleware), so the package name is not fixed; the function name is.
	mountsHeaders = calls["SecurityHeadersForEnv"] || calls["SecurityHeadersProduction"] ||
		calls["SecurityHeaders"]
	return buildsEngine, mountsHeaders, nil
}

func securityRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root above the test directory")
	return ""
}
