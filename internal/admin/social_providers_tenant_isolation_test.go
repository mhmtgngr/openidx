package admin

import (
	"net/http"
	"testing"
)

// Tenant isolation for social_providers, the table behind the sign-in buttons.
//
// Before v143 every one of these handlers crossed tenants, and the list query
// is the one worth remembering, because it read as if it did not:
//
//	FROM social_providers sp
//	LEFT JOIN identity_providers ip ON sp.provider_id = ip.id AND ip.org_id = $1
//
// The caller's org is right there in the SQL. It filters nothing: inside a LEFT
// JOIN's ON clause the predicate decides only whether the joined row
// contributes, so every tenant's providers came back and the org check blanked
// out nothing but the idp_name column of the ones belonging to somebody else.
// Get, update and delete then took a bare id with no org at all.
//
// This matters beyond disclosure. internal/oauth/social_policy.go reads this
// table on the sign-in path for allowed_domains and auto_create_users, so a
// cross-tenant update changes which e-mail domains may sign in to somebody
// else's deployment and whether unknown visitors are provisioned accounts
// there — and a cross-tenant delete removes their sign-in button entirely.
//
// The harness connects as the superuser, which bypasses RLS, so what is proved
// here is the explicit org predicate in each query. The belt is proved
// separately under a NOSUPERUSER role by test/integration/cross_org_test.go.
func TestTenantIsolation_SocialProviders(t *testing.T) {
	f, cleanup := newTenantFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	seed := func(org, key string) string {
		f.t.Helper()
		var id string
		if err := f.db.Pool.QueryRow(f.bypass(),
			`INSERT INTO social_providers (org_id, provider_key, display_name, enabled)
			 VALUES ($1, $2, $2, true) RETURNING id`, org, key).Scan(&id); err != nil {
			f.t.Fatalf("seed social provider %s: %v", key, err)
		}
		return id
	}

	aID := seed(f.orgA, "ti-google-a-"+f.orgA[:8])
	bID := seed(f.orgB, "ti-google-b-"+f.orgB[:8])

	t.Run("the list shows only the caller's providers", func(t *testing.T) {
		w := f.call(f.orgA, f.s.handleListSocialProviders, http.MethodGet, "/social-providers", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
		// The handler wraps the list in {"data": [...]}.
		var body struct {
			Data []struct {
				ID          string `json:"id"`
				ProviderKey string `json:"provider_key"`
			} `json:"data"`
		}
		decode(t, w, &body)
		got := body.Data
		if len(got) == 0 {
			t.Fatal("org A's provider list came back empty")
		}
		for _, p := range got {
			if p.ID == bID {
				t.Errorf("org A's provider list contains org B's %q", p.ProviderKey)
			}
		}
		var sawA bool
		for _, p := range got {
			if p.ID == aID {
				sawA = true
			}
		}
		if !sawA {
			t.Error("org A cannot see its own provider; the predicate is too strict")
		}
	})

	t.Run("get by id cannot reach another tenant's provider", func(t *testing.T) {
		w := f.call(f.orgA, f.s.handleGetSocialProvider, http.MethodGet,
			"/social-providers/"+bID, map[string]string{"id": bID}, nil)
		if w.Code == http.StatusOK {
			t.Errorf("org A read org B's provider by id: %s", w.Body.String())
		}
	})

	t.Run("update by id cannot edit another tenant's sign-in button", func(t *testing.T) {
		disabled := false
		w := f.call(f.orgA, f.s.handleUpdateSocialProvider, http.MethodPut,
			"/social-providers/"+bID, map[string]string{"id": bID},
			map[string]interface{}{"enabled": disabled, "display_name": "hijacked"})
		if w.Code == http.StatusOK {
			t.Errorf("org A updated org B's provider: %s", w.Body.String())
		}
		var name string
		if err := f.db.Pool.QueryRow(f.bypass(),
			"SELECT display_name FROM social_providers WHERE id = $1", bID).Scan(&name); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if name == "hijacked" {
			t.Error("org B's provider was renamed by org A")
		}
	})

	t.Run("delete by id cannot remove another tenant's sign-in button", func(t *testing.T) {
		w := f.call(f.orgA, f.s.handleDeleteSocialProvider, http.MethodDelete,
			"/social-providers/"+bID, map[string]string{"id": bID}, nil)
		if w.Code == http.StatusOK {
			t.Errorf("org A deleted org B's provider: %s", w.Body.String())
		}
		if n := f.count("SELECT count(*) FROM social_providers WHERE id = $1", bID); n != 1 {
			t.Errorf("org B's provider is gone (count=%d)", n)
		}
	})

	// provider_key was UNIQUE across the install, so the first tenant to
	// register 'google' took the name from everybody else and their create
	// failed with a duplicate-key error they could do nothing about.
	t.Run("two tenants may register the same provider key", func(t *testing.T) {
		key := "ti-shared-" + f.orgA[:8]
		w := f.call(f.orgA, f.s.handleCreateSocialProvider, http.MethodPost, "/social-providers", nil,
			map[string]interface{}{"provider_key": key, "display_name": "A's Google", "enabled": true})
		if w.Code != http.StatusCreated {
			t.Fatalf("org A create: %d %s", w.Code, w.Body.String())
		}
		w = f.call(f.orgB, f.s.handleCreateSocialProvider, http.MethodPost, "/social-providers", nil,
			map[string]interface{}{"provider_key": key, "display_name": "B's Google", "enabled": true})
		if w.Code != http.StatusCreated {
			t.Fatalf("org B could not register the same provider_key as org A: %d %s", w.Code, w.Body.String())
		}
		if n := f.count(
			"SELECT count(*) FROM social_providers WHERE provider_key = $1", key); n != 2 {
			t.Errorf("expected one row per org for provider_key %q, got %d", key, n)
		}
	})

	// No explicit cleanup: social_providers.org_id is ON DELETE CASCADE, so the
	// fixture's org teardown takes these rows with it. A t.Cleanup here would
	// run after the fixture's deferred cleanup had closed the pool.
}
