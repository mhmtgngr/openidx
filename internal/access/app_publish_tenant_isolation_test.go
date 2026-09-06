package access

import (
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestDiscoveryContextCarriesOrg is v169's second half in one assertion.
//
// v73 scoped published_apps and discovered_paths and then declined to belt
// them, recording as half its reason that "runAppDiscovery runs in a background
// goroutine with no org ctx". That was accurate, and it made the belt
// impossible: the goroutine started from context.Background(), the pool sets
// app.org_id from orgctx at checkout, so under a belt every statement in a
// discovery run would have matched no rows — the app sitting at "discovering"
// forever with nothing in the log to say why. The SQL was never the problem;
// all six of those statements already carry `AND org_id = $N`.
//
// So a control was skipped for a reason that was one line of plumbing. This
// pins the line: the context the goroutine runs on carries the tenant, and does
// not expire with the request that started it.
//
// (Cross-tenant handler behaviour for this surface is covered by
// TestPublishedApps_TenantIsolation in app_publish_isolation_test.go.)
func TestDiscoveryContextCarriesOrg(t *testing.T) {
	org := orgctx.Org{ID: "00000000-0000-0000-0000-0000000000e1", Slug: "acme"}

	ctx, cancel := discoveryContext(org)
	defer cancel()

	got, err := orgctx.From(ctx)
	if err != nil {
		t.Fatalf("the background discovery context carries no organization (%v). "+
			"Under the v169 belt the pool sets no app.org_id from it, so every "+
			"statement in the discovery run matches nothing and the app stays "+
			"'discovering' with no error recorded anywhere", err)
	}
	if got.ID != org.ID {
		t.Errorf("discovery context carries org %q, want %q", got.ID, org.ID)
	}

	// Detached from the request, but not unbounded: a hung upstream must not
	// leak the goroutine.
	if _, ok := ctx.Deadline(); !ok {
		t.Error("discovery context has no deadline")
	}
	if ctx.Err() != nil {
		t.Errorf("discovery context is already done: %v", ctx.Err())
	}
}
