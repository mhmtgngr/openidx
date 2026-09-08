package middleware

import "testing"

// TestInferResourceType locks in the template→OPA-resource mapping (and its
// plural stripping), since a wrong resource type feeds a wrong authorization
// decision.
//
// Every case here used to be a COLLECTION path, which is why this test passed
// while the mapping was broken: the function took the last segment of the
// REQUEST PATH, so it was right for /users and wrong for /users/<uuid> -- and
// nothing asked it about the second kind. The object cases below are the ones
// that matter, because authz.rego keys role_permissions and its user/session/
// report rules on input.resource.type, and a UUID matches none of them.
func TestInferResourceType(t *testing.T) {
	cases := map[string]string{
		// collections
		"/api/v1/identity/users":      "user",    // trailing s
		"/api/v1/identity/sessions":   "session", // trailing s
		"/api/v1/governance/policies": "policy",  // ies → y
		"/api/v1/x/statuses":          "status",  // ses → s
		"/api/v1/x/addresses":         "address", // ses → s
		"/api/v1/audit/audit":         "audit",   // no plural

		// objects: the template's last STATIC segment, not its last segment
		"/api/v1/identity/users/:id":               "user",
		"/api/v1/identity/sessions/:id":            "session",
		"/api/v1/governance/policies/:id":          "policy",
		"/api/v1/governance/policies/:id/evaluate": "evaluate",
		"/api/v1/governance/reviews/:id/items":     "item",
		"/api/v1/identity/users/:id/roles":         "role",
		"/api/v1/x/files/*filepath":                "file",

		"/health": "", // too short (<3 segments)
		"/api/v1": "", // too short
		"":        "", // empty — an unmatched route yields no resource type
	}
	for template, want := range cases {
		if got := inferResourceType(template); got != want {
			t.Errorf("inferResourceType(%q) = %q, want %q", template, got, want)
		}
	}
}
