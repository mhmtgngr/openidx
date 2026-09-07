package middleware

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The same omission as the security headers, on the same service.
//
// Five of the eight HTTP service mains mounted DistributedRateLimit. The
// gateway did not — and the gateway is the one facing the internet. It was not
// an oversight in configuration: gateway.Config has carried EnableRateLimit
// (default true) and a RateLimitConfig of 100/min with 20/min on auth paths
// since it was written, read from ENABLE_RATE_LIMIT and rate_limit.*, and
// consumed by nothing. Its only reader would have been
// internal/gateway/middleware.RateLimitMiddleware, a second limiter no binary
// ever constructed. So the operator set a limit, the config carried it, and the
// front door answered an unlimited number of requests.
//
// That is why this is a derived set rather than a list: the five that mounted it
// looked like the rule, and any reviewer reading one of them saw a service doing
// it right. A ninth service cannot be added without mounting the limiter or
// saying, here, why it needs none.
var rateLimitExempt = map[string]string{
	// Nothing today. An entry here is a service that cannot be reached by an
	// untrusted caller, and it needs the sentence saying why.
}

func TestEveryHTTPServiceMountsARateLimiter(t *testing.T) {
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
		name := e.Name()
		calls, err := serviceMainCalls(filepath.Join(cmdDir, name))
		if err != nil {
			t.Fatalf("inspect %s: %v", name, err)
		}
		if !calls["gin.New"] && !calls["gin.Default"] {
			continue // a CLI tool (migrate, backup, rekey, ...), not an HTTP service
		}
		httpServices = append(httpServices, name)
		if calls["DistributedRateLimit"] {
			continue
		}
		if _, exempt := rateLimitExempt[name]; exempt {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(httpServices)
	sort.Strings(missing)

	// A derived list that derives nothing passes silently, which is how the
	// gateway ran unlimited while its config said 100 a minute.
	if len(httpServices) < 5 {
		t.Fatalf("found only %d gin-based service mains (%v) — the detector is not seeing cmd/",
			len(httpServices), httpServices)
	}

	if len(missing) != 0 {
		t.Errorf("HTTP service(s) that build a gin engine but never mount DistributedRateLimit: %s\n\n"+
			"They accept an unbounded request rate, including on the auth paths the limiter protects "+
			"fail-closed. Add router.Use(middleware.DistributedRateLimit(...)) behind cfg.EnableRateLimit, "+
			"or add the service to rateLimitExempt in this file with the reason no untrusted caller "+
			"reaches it.\nHTTP services found: %s",
			strings.Join(missing, ", "), strings.Join(httpServices, ", "))
	}
}

// An exemption without a reason is a list entry somebody added to get to green.
func TestEveryRateLimitExemptionHasAReason(t *testing.T) {
	for svc, reason := range rateLimitExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("rateLimitExempt[%q] has no reason — say why no untrusted caller reaches it", svc)
		}
	}
}
