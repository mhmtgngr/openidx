package oauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestBuildAuditInsertArgs_defaultOrgFallback(t *testing.T) {
	args := buildAuditInsertArgs(context.Background(),
		"sso.login", "authentication", "sso_login", "success",
		"user-1", "1.2.3.4", "user-1", "user", map[string]interface{}{"idp_id": "idp-1"})

	if len(args) != 10 {
		t.Fatalf("expected 10 args, got %d", len(args))
	}
	// Field mapping.
	checks := map[int]string{0: "sso.login", 1: "authentication", 2: "sso_login", 3: "success", 4: "user-1", 5: "1.2.3.4", 6: "user-1", 7: "user"}
	for i, want := range checks {
		if got, _ := args[i].(string); got != want {
			t.Errorf("args[%d] = %q, want %q", i, got, want)
		}
	}
	// No org on context → default org UUID.
	if got, _ := args[9].(string); got != "00000000-0000-0000-0000-000000000010" {
		t.Errorf("org fallback = %q, want default org UUID", got)
	}
	// Details is valid JSON carrying the metadata.
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(args[8].(string)), &details); err != nil {
		t.Fatalf("details not valid JSON: %v", err)
	}
	if details["idp_id"] != "idp-1" {
		t.Errorf("details idp_id = %v, want idp-1", details["idp_id"])
	}
}

func TestBuildAuditInsertArgs_usesContextOrg(t *testing.T) {
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: "org-abc"})
	args := buildAuditInsertArgs(ctx, "sso.login", "authentication", "sso_login", "success",
		"u", "", "u", "user", nil)
	if got, _ := args[9].(string); got != "org-abc" {
		t.Errorf("org = %q, want org-abc (from context)", got)
	}
	// nil metadata still marshals (to "null"), never panics.
	if _, ok := args[8].(string); !ok {
		t.Error("details arg should be a string even for nil metadata")
	}
}
