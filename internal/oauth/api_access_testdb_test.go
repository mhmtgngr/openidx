package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// claimsOf reads a minted token's claims without verifying it; the tests below
// verify through the consumers instead.
func claimsOf(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse %q: %v", token, err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

// An administrator signs in to two applications and each is issued an access
// token carrying the administrator's roles: the console, which v205 left
// allowed to call OpenIDX's own APIs, and a third-party application registered
// afterwards, which is not. Only the console's token opens an admin route; the
// third-party token is still an answer at UserInfo, the endpoint every relying
// party calls.
func TestOnlyAnApplicationAllowedToCallTheAPIGetsIn(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.seedUser(middleware.DefaultOrgID, "api-admin", "admin")
	thirdPartyClient := h.registerClient(defaultOrg, "third-party", false)
	console, thirdParty := h.accessToken(defaultOrg, admin), h.tokenFor(defaultOrg, admin, thirdPartyClient)

	if got := claimsOf(t, console)[middleware.APIAccessClaim]; got != true {
		t.Fatalf("the console's token: %s = %v, want true", middleware.APIAccessClaim, got)
	}
	if got, ok := claimsOf(t, thirdParty)[middleware.APIAccessClaim]; ok {
		t.Fatalf("the third-party token carries %s = %v", middleware.APIAccessClaim, got)
	}

	for _, route := range []struct {
		name string
		api  *gin.Engine
		path string
	}{
		{"identity admin route", h.identityAPI, "/api/v1/identity/users/" + admin},
		{"shared-middleware admin route", h.adminAPI, "/api/v1/admin/probe"},
	} {
		if w := h.call(route.api, route.path, console, ""); w.Code != http.StatusOK {
			t.Errorf("%s: the console's token answered %d, want 200: %s", route.name, w.Code, w.Body.String())
		}
		w := h.call(route.api, route.path, thirdParty, "")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "may not call the OpenIDX API") {
			t.Errorf("%s: the third-party token answered %d %s, want 401 naming the reason", route.name, w.Code, w.Body.String())
		}
	}

	for name, bearer := range map[string]string{"the console's token": console, "the third-party token": thirdParty} {
		if w := h.call(h.oauthAPI, "/oauth/userinfo", bearer, ""); w.Code != http.StatusOK {
			t.Errorf("userinfo: %s answered %d, want 200: %s", name, w.Code, w.Body.String())
		}
	}

	// The social-login flow mints its own access token, for the console; it
	// takes the claim from the client the same way.
	user := &SAMLUser{ID: admin, Email: "api-admin@example.test"}
	ctx := orgctx.With(context.Background(), defaultOrg)
	for clientID, want := range map[string]bool{"admin-console": true, thirdPartyClient: false} {
		resp, err := h.issuer.generateTokensForUser(ctx, user, clientID, []string{"openid"})
		if err != nil {
			t.Fatalf("social-login tokens for %s: %v", clientID, err)
		}
		if got := middleware.HasAPIAccess(claimsOf(t, resp.AccessToken)); got != want {
			t.Errorf("social-login access token for %s may call the API = %v, want %v", clientID, got, want)
		}
	}
}

// The permission is read when a token is minted, so an administrator's change
// reaches an application with its next token: turned on, the next token opens
// the API; turned off, the next one no longer does. A client update that does
// not name the permission leaves it as it is.
func TestAnApplicationsNextTokenFollowsItsAPIAccess(t *testing.T) {
	h := newTokenHarness(t)
	admin := h.seedUser(middleware.DefaultOrgID, "switch-admin", "admin")
	clientID := h.registerClient(defaultOrg, "switch", false)
	store := NewPostgresOAuthClientStore(h.db)
	ctx := orgctx.With(context.Background(), defaultOrg)

	probe := func() int {
		t.Helper()
		return h.call(h.adminAPI, "/api/v1/admin/probe", h.tokenFor(defaultOrg, admin, clientID), "").Code
	}
	set := func(apiAccess *bool) {
		t.Helper()
		client, err := store.GetByClientID(ctx, clientID)
		if err != nil {
			t.Fatalf("read client: %v", err)
		}
		client.APIAccess = apiAccess
		if err := store.Update(ctx, clientID, client); err != nil {
			t.Fatalf("update client: %v", err)
		}
	}
	on, off := true, false

	if code := probe(); code != http.StatusUnauthorized {
		t.Fatalf("before the change: %d, want 401", code)
	}
	set(&on)
	if code := probe(); code != http.StatusOK {
		t.Fatalf("after turning API access on: %d, want 200", code)
	}
	set(nil)
	if code := probe(); code != http.StatusOK {
		t.Fatalf("an update that did not name the permission changed it: %d, want 200", code)
	}
	set(&off)
	if code := probe(); code != http.StatusUnauthorized {
		t.Fatalf("after turning API access off: %d, want 401", code)
	}
}

// The token endpoint's grants mint through GenerateJWT, which reads the
// permission from the client the grant authenticated: a refresh and a
// client_credentials grant for a client allowed to call the API carry the
// claim, and the same grants for one that is not do not.
func TestTheGrantsMintTheAPIAccessOfTheirClient(t *testing.T) {
	f := newRefreshGrantFixture(t)
	if _, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, allow_refresh_token, api_access, org_id)
		VALUES (gen_random_uuid(), 'api-app', 'api-secret', 'api-app', true, true, $1)`, grantOrg); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	r := routedService(t, f.svc, grantOrg, nil)

	for _, tc := range []struct {
		client, secret string
		want           bool
	}{
		{"api-app", "api-secret", true},
		{"app", "s3cret", false},
	} {
		refreshToken := "rt-api-access-" + tc.client + "-" + uuid.NewString()
		f.mintRefresh(t, refreshToken, tc.client, grantUser, "openid offline_access", "", "", time.Now().Add(time.Hour))
		for grant, form := range map[string]url.Values{
			"refresh_token":      creds(tc.client, tc.secret, "grant_type", "refresh_token", "refresh_token", refreshToken),
			"client_credentials": creds(tc.client, tc.secret, "grant_type", "client_credentials"),
		} {
			w := serve(r, "POST", "/oauth/token", formType, form.Encode())
			if w.Code != http.StatusOK {
				t.Fatalf("%s grant for %s: %d %s", grant, tc.client, w.Code, w.Body.String())
			}
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			token, _ := body["access_token"].(string)
			if got := middleware.HasAPIAccess(claimsOf(t, token)); got != tc.want {
				t.Errorf("%s grant for %s: token may call the API = %v, want %v", grant, tc.client, got, tc.want)
			}
		}
	}
}

// The client store carries the permission both ways: a client registered
// without naming it may not call the API, one registered with it may, and an
// update that leaves it out changes nothing.
func TestClientStoreRoundTripsAPIAccess(t *testing.T) {
	_, db, _ := bclSetup(t)
	store := NewPostgresOAuthClientStore(db)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: ssoTestOrg})

	read := func(clientID string) *bool {
		t.Helper()
		got, err := store.GetByClientID(ctx, clientID)
		if err != nil {
			t.Fatal(err)
		}
		return got.APIAccess
	}

	plain := &OAuthClient{ID: uuid.New().String(), ClientID: "api-store-plain", Name: "A", Type: "confidential"}
	if err := store.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if got := read("api-store-plain"); got == nil || *got {
		t.Fatalf("a client registered without naming it: %v, want false", got)
	}

	on := true
	allowed := &OAuthClient{ID: uuid.New().String(), ClientID: "api-store-on", Name: "B", Type: "confidential", APIAccess: &on}
	if err := store.Create(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	if got := read("api-store-on"); got == nil || !*got {
		t.Fatalf("a client registered with it: %v, want true", got)
	}

	allowed.APIAccess = nil
	allowed.Description = "renamed"
	if err := store.Update(ctx, "api-store-on", allowed); err != nil {
		t.Fatal(err)
	}
	if got := read("api-store-on"); got == nil || !*got {
		t.Fatalf("an update that left it out changed it: %v", got)
	}

	clients, _, err := store.List(ctx, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, c := range clients {
		if c.APIAccess != nil {
			listed[c.ClientID] = *c.APIAccess
		}
	}
	if allowedListed, ok := listed["api-store-on"]; !ok || !allowedListed || listed["api-store-plain"] {
		t.Fatalf("the list reports %v", listed)
	}
}
