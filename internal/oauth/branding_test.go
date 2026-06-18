package oauth

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// loadLoginBranding must fall back to safe defaults when there is no org on the
// context or no DB — the login page must always render.
func TestLoadLoginBrandingDefaults(t *testing.T) {
	s := &Service{} // nil db

	t.Run("no org context", func(t *testing.T) {
		b := s.loadLoginBranding(context.Background())
		assertDefaults(t, b)
	})

	t.Run("org but no db", func(t *testing.T) {
		ctx := orgctx.With(context.Background(), orgctx.Org{ID: "11111111-2222-3333-4444-555555555555", Slug: "acme"})
		b := s.loadLoginBranding(ctx)
		assertDefaults(t, b)
	})
}

func assertDefaults(t *testing.T, b loginBranding) {
	t.Helper()
	d := defaultLoginBranding()
	if b != d {
		t.Fatalf("branding = %+v, want defaults %+v", b, d)
	}
	if b.LoginPageTitle == "" || b.PrimaryColor == "" || !b.PoweredByVisible {
		t.Fatalf("defaults look wrong: %+v", b)
	}
}
