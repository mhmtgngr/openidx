package database

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The RLS checkout hook derives (app.org_id, app.bypass_rls) from the request
// context. Precedence and fail-closed behavior are the security-critical part.
func TestRLSValuesFromContext(t *testing.T) {
	const orgID = "11111111-2222-3333-4444-555555555555"

	t.Run("no org, no bypass -> empty (fail-closed)", func(t *testing.T) {
		org, bypass := rlsValuesFromContext(context.Background())
		if org != "" || bypass != "off" {
			t.Fatalf("got (%q,%q), want (\"\",\"off\")", org, bypass)
		}
	})

	t.Run("resolved org -> org_id set, no bypass", func(t *testing.T) {
		ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID, Slug: "acme"})
		org, bypass := rlsValuesFromContext(ctx)
		if org != orgID || bypass != "off" {
			t.Fatalf("got (%q,%q), want (%q,\"off\")", org, bypass, orgID)
		}
	})

	t.Run("explicit bypass -> bypass on, org empty", func(t *testing.T) {
		ctx := orgctx.WithBypassRLS(context.Background())
		org, bypass := rlsValuesFromContext(ctx)
		if org != "" || bypass != "on" {
			t.Fatalf("got (%q,%q), want (\"\",\"on\")", org, bypass)
		}
	})

	t.Run("bypass wins over org", func(t *testing.T) {
		ctx := orgctx.WithBypassRLS(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
		org, bypass := rlsValuesFromContext(ctx)
		if org != "" || bypass != "on" {
			t.Fatalf("got (%q,%q), want (\"\",\"on\")", org, bypass)
		}
	})
}
