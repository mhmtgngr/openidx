package middleware

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Derived, for the reason the rate-limit guard next door is derived: the
// gateway carried a rate-limit configuration that nothing read, for a full
// release, and every reviewer who looked at one of the five services that did
// mount it saw a codebase doing the right thing.
//
// A bound on concurrency is worth less than that one, in exactly one way: it
// is off by default, so a service that forgets to mount it looks identical to
// one where the operator has not sized it. The mount is what makes sizing
// POSSIBLE, and a service that cannot be sized is the one that falls over.

var admissionExempt = map[string]string{
	// Nothing today.
}

// The per-tenant cost budget needs a resolved tenant, so its exemptions are
// about tenancy rather than about traffic.
var costBudgetExempt = map[string]string{
	"gateway-service": "Never resolves a tenant: it derives X-Org-Slug from the Host for the " +
		"backends to resolve and does no lookup of its own, so there is no org id to key a " +
		"budget by. Keying by slug would open a second key space for the same tenant and both " +
		"budgets would be wrong.",
}

func TestEveryHTTPServiceMountsAdmissionControl(t *testing.T) {
	forEachHTTPService(t, "Admission", admissionExempt,
		"They can be driven past what their connection pool and memory can serve, with no way "+
			"for an operator to bound it. Add router.Use(middleware.Admission(...)) -- it is a "+
			"pass-through until ADMISSION_MAX_INFLIGHT is set, so mounting it changes nothing "+
			"by itself -- or add the service to admissionExempt with the reason.")
}

func TestEveryHTTPServiceMountsTheTenantCostBudget(t *testing.T) {
	forEachHTTPService(t, "TenantCostLimit", costBudgetExempt,
		"One tenant's expensive traffic can exhaust the process with no per-tenant shedding. "+
			"Add router.Use(middleware.TenantCostLimit(...)) AFTER the tenant resolver -- it is "+
			"a pass-through until RATELIMIT_COST_MODE is set -- or add the service to "+
			"costBudgetExempt with the reason.")
}

func forEachHTTPService(t *testing.T, call string, exempt map[string]string, why string) {
	t.Helper()
	cmdDir := filepath.Join(securityRepoRoot(t), "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}

	var httpServices, missing []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		calls, cerr := serviceMainCalls(filepath.Join(cmdDir, e.Name()))
		if cerr != nil {
			t.Fatalf("inspect %s: %v", e.Name(), cerr)
		}
		if !calls["gin.New"] && !calls["gin.Default"] {
			continue // a CLI tool, not an HTTP service
		}
		httpServices = append(httpServices, e.Name())
		if calls[call] {
			continue
		}
		if _, ok := exempt[e.Name()]; ok {
			continue
		}
		missing = append(missing, e.Name())
	}
	sort.Strings(httpServices)
	sort.Strings(missing)

	// A derived list that derives nothing passes silently.
	if len(httpServices) < 5 {
		t.Fatalf("found only %d gin-based service mains (%v) -- the detector is not seeing cmd/",
			len(httpServices), httpServices)
	}
	if len(missing) != 0 {
		t.Errorf("HTTP service(s) that build a gin engine but never call %s: %s\n\n%s\nHTTP services found: %s",
			call, strings.Join(missing, ", "), why, strings.Join(httpServices, ", "))
	}
}

func TestEveryAdmissionAndCostExemptionHasAReason(t *testing.T) {
	for name, list := range map[string]map[string]string{
		"admissionExempt": admissionExempt, "costBudgetExempt": costBudgetExempt,
	} {
		for svc, reason := range list {
			if len(strings.TrimSpace(reason)) < 40 {
				t.Errorf("%s[%q] has no real reason -- say what makes this service different", name, svc)
			}
		}
	}
}
