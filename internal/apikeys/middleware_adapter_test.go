package apikeys

import "testing"

// TestToMiddlewareInfo verifies the apikeys.APIKeyInfo -> middleware.APIKeyInfo
// mapping used to wire minted API keys into the auth middleware. A regression
// here (e.g. dropping OrgID) would silently break tenant scoping for API-key
// callers or reject valid keys.
func TestToMiddlewareInfo(t *testing.T) {
	in := &APIKeyInfo{
		KeyID:            "key-123",
		UserID:           "user-456",
		ServiceAccountID: "sa-789",
		Scopes:           []string{"read", "write"},
		Status:           "active",
		OrgID:            "org-abc",
	}

	out := toMiddlewareInfo(in)

	if out.KeyID != in.KeyID {
		t.Errorf("KeyID = %q, want %q", out.KeyID, in.KeyID)
	}
	if out.UserID != in.UserID {
		t.Errorf("UserID = %q, want %q", out.UserID, in.UserID)
	}
	if out.ServiceAccountID != in.ServiceAccountID {
		t.Errorf("ServiceAccountID = %q, want %q", out.ServiceAccountID, in.ServiceAccountID)
	}
	if out.OrgID != in.OrgID {
		t.Errorf("OrgID = %q, want %q — dropping OrgID breaks API-key tenant scoping", out.OrgID, in.OrgID)
	}
	if len(out.Scopes) != len(in.Scopes) {
		t.Fatalf("Scopes len = %d, want %d", len(out.Scopes), len(in.Scopes))
	}
	for i := range in.Scopes {
		if out.Scopes[i] != in.Scopes[i] {
			t.Errorf("Scopes[%d] = %q, want %q", i, out.Scopes[i], in.Scopes[i])
		}
	}
}

// TestMiddlewareValidator_NotNil ensures a Service exposes a usable validator
// for middleware.AuthWithAPIKey (the wiring middleware.Auth's nil validator
// previously omitted).
func TestMiddlewareValidator_NotNil(t *testing.T) {
	s := &Service{}
	if s.MiddlewareValidator() == nil {
		t.Fatal("MiddlewareValidator() returned nil")
	}
}
