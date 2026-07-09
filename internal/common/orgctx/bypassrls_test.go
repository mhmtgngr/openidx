package orgctx

import (
	"context"
	"testing"
)

// TestIsBypassRLS_default_false is the fail-closed guarantee: a context that was
// never explicitly marked must NOT bypass Row-Level Security. A regression here
// would silently disable tenant isolation for ordinary requests.
func TestIsBypassRLS_default_false(t *testing.T) {
	if IsBypassRLS(context.Background()) {
		t.Fatal("default context must not bypass RLS")
	}
}

func TestWithBypassRLS_marksContext(t *testing.T) {
	if !IsBypassRLS(WithBypassRLS(context.Background())) {
		t.Fatal("WithBypassRLS should mark the context as bypassing RLS")
	}
}

// The bypass marker must coexist with an org value (cross-org writers set both).
func TestBypassRLS_composesWithOrg(t *testing.T) {
	ctx := WithBypassRLS(With(context.Background(), Org{ID: "org-1"}))
	if !IsBypassRLS(ctx) {
		t.Error("bypass marker lost when combined with an org value")
	}
	org, err := From(ctx)
	if err != nil || org.ID != "org-1" {
		t.Errorf("org value lost: got %+v err=%v", org, err)
	}
}

// Deriving a bypass context must not retroactively mark the parent (no leak).
func TestBypassRLS_doesNotLeakToParent(t *testing.T) {
	parent := context.Background()
	_ = WithBypassRLS(parent)
	if IsBypassRLS(parent) {
		t.Fatal("WithBypassRLS leaked the marker to its parent context")
	}
}
