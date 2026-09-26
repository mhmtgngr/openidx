package oauth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
)

// DYNAMIC REGISTRATION REGISTERS CLIENTS IN ONE ORGANIZATION.
//
// POST /oauth/register creates its client in the organization the request
// resolves to, and the tenant resolver takes that from the request: the
// X-Org-Slug header, the tenant's host, or the default organization when it
// names neither. DCR_INITIAL_ACCESS_TOKEN is one token for the whole install,
// so its holder -- and, with DCR_ALLOW_OPEN_REGISTRATION, anyone -- could
// create a client in any organization by naming it. Driven through
// RegisterRoutes behind the tenant resolver, as cmd/oauth-service serves it:
//
//   - bound to A, a registration with the initial access token naming B, or
//     naming nothing (the default organization), is refused with 401 and
//     creates no client anywhere; one naming A is registered, in A, and is
//     managed there with its registration access token and not from B;
//   - bound to nothing (DCR_ORG_ID and DEFAULT_ORG_ID unset in the service),
//     registration lands only in the default organization;
//   - open registration is held to the same organization.
func TestDynamicRegistrationRegistersInOneOrganization(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("dcr-a"), h.seedOrg("dcr-b")
	api := h.oauthRouteTable(nil)
	const iat = "iat-bound"

	n := 0
	// register answers the status, the organization the client landed in and
	// the client's id and registration access token.
	register := func(bearer, slug string) (code int, landed, clientID, rat string) {
		n++
		name := "dcr-bound-" + h.suffix + "-" + string(rune('a'+n))
		header := []string{}
		if bearer != "" {
			header = append(header, "Authorization", "Bearer "+bearer)
		}
		if slug != "" {
			header = append(header, "X-Org-Slug", slug)
		}
		w := serve(api, http.MethodPost, "/oauth/register", "application/json",
			`{"client_name":"`+name+`","grant_types":["client_credentials"]}`, header...)
		var reg struct {
			ClientID string `json:"client_id"`
			RAT      string `json:"registration_access_token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &reg)
		if w.Code != http.StatusCreated && h.scalar(`SELECT COUNT(*)::text FROM oauth_clients WHERE name = $1`, name) != "0" {
			t.Errorf("a refused registration (%d) created a client", w.Code)
		}
		if w.Code == http.StatusCreated {
			landed = h.scalar(`SELECT org_id::text FROM oauth_clients WHERE client_id = $1`, reg.ClientID)
		}
		return w.Code, landed, reg.ClientID, reg.RAT
	}

	h.issuer.dcrInitialAccessToken, h.issuer.dcrOrgID = iat, orgA.ID
	if code, _, _, _ := register(iat, orgB.Slug); code != http.StatusUnauthorized {
		t.Errorf("bound to A, naming B: %d, want 401", code)
	}
	if code, _, _, _ := register(iat, ""); code != http.StatusUnauthorized {
		t.Errorf("bound to A, naming no organization: %d, want 401", code)
	}
	if code, _, _, _ := register("wrong-token", orgA.Slug); code != http.StatusUnauthorized {
		t.Errorf("bound to A, naming A with a wrong token: %d, want 401", code)
	}
	code, landed, clientID, rat := register(iat, orgA.Slug)
	if code != http.StatusCreated || landed != orgA.ID {
		t.Fatalf("bound to A, naming A: %d, landed in %q; want 201 in A", code, landed)
	}
	manage := func(slug string) int {
		return serve(api, http.MethodGet, "/oauth/register/"+clientID, "", "",
			"Authorization", "Bearer "+rat, "X-Org-Slug", slug).Code
	}
	if code := manage(orgA.Slug); code != http.StatusOK {
		t.Errorf("managing the client in A: %d, want 200", code)
	}
	if code := manage(orgB.Slug); code != http.StatusUnauthorized {
		t.Errorf("managing A's client from B: %d, want 401", code)
	}

	// Unset: the default organization, where a request naming none lands.
	h.issuer.dcrOrgID = ""
	if code, _, _, _ := register(iat, orgA.Slug); code != http.StatusUnauthorized {
		t.Errorf("unbound, naming A: %d, want 401", code)
	}
	if code, landed, _, _ := register(iat, ""); code != http.StatusCreated || landed != middleware.DefaultOrgID {
		t.Errorf("unbound, naming no organization: %d, landed in %q; want 201 in the default organization", code, landed)
	}

	// Open registration is held to the same organization.
	h.issuer.dcrInitialAccessToken, h.issuer.dcrAllowOpenRegistration, h.issuer.dcrOrgID = "", true, orgA.ID
	if code, _, _, _ := register("", orgB.Slug); code != http.StatusUnauthorized {
		t.Errorf("open registration naming B: %d, want 401", code)
	}
	if code, landed, _, _ := register("", orgA.Slug); code != http.StatusCreated || landed != orgA.ID {
		t.Errorf("open registration naming A: %d, landed in %q; want 201 in A", code, landed)
	}
}

// DCR_ORG_ID binds registration; unset, DEFAULT_ORG_ID does.
func TestTheRegistrationOrganizationComesFromTheConfiguration(t *testing.T) {
	for _, tc := range []struct {
		dcr, fallback, want string
	}{
		{"11111111-1111-1111-1111-111111111111", middleware.DefaultOrgID, "11111111-1111-1111-1111-111111111111"},
		{"", "22222222-2222-2222-2222-222222222222", "22222222-2222-2222-2222-222222222222"},
		{" 33333333-3333-3333-3333-333333333333 ", "", "33333333-3333-3333-3333-333333333333"},
	} {
		if got := dcrOrgFromConfig(&config.Config{DCROrgID: tc.dcr, DefaultOrgID: tc.fallback}); got != tc.want {
			t.Errorf("DCR_ORG_ID %q, DEFAULT_ORG_ID %q: %q, want %q", tc.dcr, tc.fallback, got, tc.want)
		}
	}
}
