package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/openidx/openidx/internal/common/middleware"
)

// ONLY A CONFIDENTIAL CLIENT MAY USE THE CLIENT CREDENTIALS GRANT.
//
// The grant compared the stored secret with the presented one and nothing
// else. A public client stores none, so naming it and presenting none matched:
// anyone could mint an access token for any public client of an organization,
// among them the seeded admin console, whose tokens OpenIDX's own APIs accept.
// Driven through RegisterRoutes behind the tenant resolver, as
// cmd/oauth-service serves /oauth/token:
//
//   - the admin console, another public client allowed to call the API, and a
//     console "native" client presenting its secret are refused with 401
//     invalid_client, with or without a made-up secret, and are issued nothing;
//   - a confidential client presenting its secret, by form or by HTTP Basic, is
//     issued a token with its API access; a wrong secret is 401, and both
//     methods at once 400;
//   - dynamic registration refuses a public client for the grant.
func TestOnlyAConfidentialClientMayUseClientCredentials(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("cc")
	api := h.oauthRouteTable(nil)

	public := h.exchangeClient(org, "cc-public", "public", "", []string{"client_credentials"}, nil, true)
	native := h.exchangeClient(org, "cc-native", "native", "native-secret", []string{"client_credentials"}, nil, true)
	service := h.exchangeClient(org, "cc-service", "service", "service-secret", []string{"client_credentials"}, nil, true)

	grant := func(slug, client, secret string, basic bool) (int, map[string]interface{}) {
		form := url.Values{"grant_type": {"client_credentials"}}
		header := []string{}
		if slug != "" {
			header = append(header, "X-Org-Slug", slug)
		}
		if basic {
			header = append(header, "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(client+":"+secret)))
		} else {
			form.Set("client_id", client)
			if secret != "" {
				form.Set("client_secret", secret)
			}
		}
		w := serve(api, http.MethodPost, "/oauth/token", formType, form.Encode(), header...)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}

	for _, tc := range []struct {
		name           string
		slug, client   string
		secret         string
		basic          bool
		code           int
		error          string
		mayCallTheAPIs bool
	}{
		// The admin console lives in the default organization, which a
		// request without a tenant signal resolves to.
		{"the admin console", "", "admin-console", "", false, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"the admin console with a made-up secret", "", "admin-console", "guess", false, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"the admin console over Basic", "", "admin-console", "guess", true, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"a public client", org.Slug, public, "", false, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"a native client with its secret", org.Slug, native, "native-secret", false, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"a service client with a wrong secret", org.Slug, service, "wrong", false, http.StatusUnauthorized, ErrorInvalidClient, false},
		{"a service client with its secret", org.Slug, service, "service-secret", false, http.StatusOK, "", true},
		{"a service client with its secret over Basic", org.Slug, service, "service-secret", true, http.StatusOK, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := grant(tc.slug, tc.client, tc.secret, tc.basic)
			if code != tc.code {
				t.Fatalf("status %d (%v), want %d", code, body, tc.code)
			}
			if tc.error != "" {
				if body["error"] != tc.error || body["access_token"] != nil {
					t.Errorf("refused with %v, want %s and no token", body, tc.error)
				}
				return
			}
			tok, _ := body["access_token"].(string)
			claims := claimsOf(t, tok)
			if claims["client_id"] != tc.client || claims["sub"] != "" {
				t.Errorf("issued client_id %v sub %v, want %s and no subject", claims["client_id"], claims["sub"], tc.client)
			}
			if got := middleware.HasAPIAccess(claims); got != tc.mayCallTheAPIs {
				t.Errorf("issued token may call the API = %v, want %v", got, tc.mayCallTheAPIs)
			}
		})
	}

	form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {"service-secret"}}
	w := serve(api, http.MethodPost, "/oauth/token", formType, form.Encode(), "X-Org-Slug", org.Slug,
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(service+":service-secret")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("two authentication methods: %d %s, want 400", w.Code, w.Body.String())
	}

	h.issuer.dcrInitialAccessToken = "iat-" + h.suffix
	register := func(authMethod string) int {
		body := `{"client_name":"machine","grant_types":["client_credentials"],"token_endpoint_auth_method":"` + authMethod + `"}`
		return serve(api, http.MethodPost, "/oauth/register", "application/json", body,
			"Authorization", "Bearer "+h.issuer.dcrInitialAccessToken).Code
	}
	if code := register("none"); code != http.StatusBadRequest {
		t.Errorf("registering a public client for client credentials: %d, want 400", code)
	}
	if code := register("client_secret_basic"); code != http.StatusCreated {
		t.Errorf("registering a confidential client for client credentials: %d, want 201", code)
	}
}
