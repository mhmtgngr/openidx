package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/apikeys"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/auth"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// oauthRouteTable is this service's route table wired the way cmd/oauth-service
// wires it: the tenant resolver on the engine, ahead of authentication, and
// AuthWithAPIKey -- over the issuer's JWKS and the given API-key validator --
// as the management middleware and the interactive-flow middleware alike.
func (h *tokenHarness) oauthRouteTable(keys middleware.APIKeyValidator) *gin.Engine {
	r := gin.New()
	r.Use(middleware.TenantResolver(h.orgs, middleware.TenantResolverConfig{
		DefaultOrgFallback:     true,
		DefaultOrgID:           middleware.DefaultOrgID,
		PlatformAdminPredicate: auth.SuperAdminPredicate,
		OnPlatformCrossOrg:     audit.CrossOrgAuditor(h.db.Pool, zap.NewNop()),
	}))
	authMW := middleware.AuthWithAPIKey(h.jwksURL, keys)
	RegisterRoutes(r, h.issuer, authMW, authMW)
	return r
}

// scalar reads one value as text; the test connects as a superuser, so it
// sees every organization's rows.
func (h *tokenHarness) scalar(query string, args ...interface{}) string {
	h.t.Helper()
	var v string
	if err := h.db.Pool.QueryRow(context.Background(), query, args...).Scan(&v); err != nil {
		h.t.Fatalf("read %q: %v", query, err)
	}
	return v
}

func (h *tokenHarness) exec(query string, args ...interface{}) {
	h.t.Helper()
	if _, err := h.db.Pool.Exec(context.Background(), query, args...); err != nil {
		h.t.Fatalf("exec %q: %v", query, err)
	}
}

// mgmtCallerKind is what a caller should get from a management route that acts
// on organization A.
type mgmtCallerKind int

const (
	// refused: 403 from the role gate, and nothing of A's changes or shows.
	mgmtRefused mgmtCallerKind = iota
	// elsewhere: another organization's administrator, in their own
	// organization. Their request is served there, so it neither shows nor
	// changes anything of A's.
	mgmtElsewhere
	// admitted: A's administrators, whose reads return A's data and whose
	// writes land.
	mgmtAdmitted
)

type mgmtCaller struct {
	name   string
	bearer string
	slug   string
	kind   mgmtCallerKind
}

// mgmtRoute is one management route. call seeds, in organization A, whatever
// that one request acts on, and returns the request, the marker a response
// carrying A's data would contain, and a reader of the state the route changes
// (nil for a read).
type mgmtRoute struct {
	method, route string
	call          func(n int) (path, body, marker string, state func() string)
}

// THE MANAGEMENT APIS NEED THE ADMIN ROLE.
//
// OAuth clients, SAML service providers and SSF streams are managed behind
// clientMgmtAuth, which authenticates and nothing more. Driven here through
// RegisterRoutes -- the route table cmd/oauth-service serves -- with the tenant
// resolver in front and AuthWithAPIKey, over the issuer's real JWKS and the
// API-key service, as the management middleware, exactly as that binary wires
// them. Every token is minted by GenerateJWT from database rows, and every
// write aims at a client, service provider or stream seeded for that one
// request, which is read back around it:
//
//   - a signed-in user holding no role, one holding operator, a
//     client-credentials token (no subject, no role) and a service account's
//     API key are refused with 403 on every route, their reads carry none of
//     A's data and their writes change nothing;
//   - A's admin and A's super_admin read A's data and their writes land;
//   - B's admin, working in B, is served there and neither sees nor changes
//     anything of A's.
func TestOAuthClientSAMLAndSSFManagementNeedTheAdminRole(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("mgmt-a"), h.seedOrg("mgmt-b")
	ctxA := orgctx.With(context.Background(), orgA)

	keys := apikeys.NewService(h.db, h.issuer.redis, zap.NewNop())
	account, err := keys.CreateServiceAccount(ctxA, "mgmt-robot-"+h.suffix, "management gate test", "")
	if err != nil {
		t.Fatalf("seed service account: %v", err)
	}
	accountKey, _, err := keys.CreateAPIKey(ctxA, "mgmt-robot-key", nil, &account.ID, nil, nil)
	if err != nil {
		t.Fatalf("seed service account key: %v", err)
	}
	api := h.oauthRouteTable(keys.MiddlewareValidator())

	machineClient := h.registerClient(orgA, "mgmt-machine", true)
	callers := []mgmtCaller{
		{"A's user with no role", h.accessToken(orgA, h.seedUser(orgA.ID, "mgmt-plain")), orgA.Slug, mgmtRefused},
		{"A's operator", h.accessToken(orgA, h.seedUser(orgA.ID, "mgmt-operator", "operator")), orgA.Slug, mgmtRefused},
		{"a client-credentials token of A", h.tokenFor(orgA, "", machineClient), orgA.Slug, mgmtRefused},
		{"a service account key of A", accountKey, orgA.Slug, mgmtRefused},
		{"B's admin, in B", h.accessToken(orgB, h.seedUser(orgB.ID, "mgmt-admin-b", "admin")), orgB.Slug, mgmtElsewhere},
		{"A's admin", h.accessToken(orgA, h.seedUser(orgA.ID, "mgmt-admin", "admin")), orgA.Slug, mgmtAdmitted},
		{"A's super_admin", h.accessToken(orgA, h.seedUser(orgA.ID, "mgmt-super", "super_admin")), orgA.Slug, mgmtAdmitted},
	}

	// What each request acts on, seeded in A and unique to the request.
	tag := func(kind string, n int) string { return fmt.Sprintf("mgmt-%s-%d-%s", kind, n, h.suffix) }
	seedClient := func(n int) string {
		clientID := tag("client", n)
		h.exec(`INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, api_access, org_id)
			VALUES ($1, 'seeded-secret', $1, 'confidential', '["https://app.example.test/cb"]'::jsonb, false, $2::uuid)`,
			clientID, orgA.ID)
		return clientID
	}
	seedSP := func(n int) (id, entityID string) {
		entityID = "https://" + tag("sp", n) + ".example.test"
		id = h.scalar(`INSERT INTO saml_service_providers (org_id, name, entity_id, acs_url, certificate)
			VALUES ($1::uuid, $2::text, $2::text, $2::text || '/acs', 'SEEDED-CERT') RETURNING id::text`, orgA.ID, entityID)
		return id, entityID
	}
	seedStream := func(n int) string {
		return h.scalar(`INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
			VALUES ($1::uuid, $2::text, $2::text || '/ssf/events') RETURNING id::text`, orgA.ID, "https://"+tag("rp", n)+".example.test")
	}
	client := func(clientID, columns string) func() string {
		return func() string {
			return h.scalar(`SELECT COALESCE((SELECT `+columns+` FROM oauth_clients WHERE client_id = $1 AND org_id = $2::uuid), '<gone>')`,
				clientID, orgA.ID)
		}
	}
	sp := func(id, column string) func() string {
		return func() string {
			return h.scalar(`SELECT COALESCE((SELECT `+column+` FROM saml_service_providers WHERE id = $1::uuid AND org_id = $2::uuid), '<gone>')`,
				id, orgA.ID)
		}
	}
	countInA := func(query, arg string) func() string {
		return func() string { return h.scalar(query, arg, orgA.ID) }
	}
	spMetadata := func(entityID string) string {
		xml := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
			`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + entityID + `/acs" index="0"/>` +
			`</md:SPSSODescriptor></md:EntityDescriptor>`
		b, _ := json.Marshal(map[string]string{"metadata_xml": xml})
		return string(b)
	}

	routes := []mgmtRoute{
		// OAuth clients.
		{http.MethodGet, "/api/v1/oauth/clients", func(n int) (string, string, string, func() string) {
			id := seedClient(n)
			return "/api/v1/oauth/clients?limit=100", "", id, nil
		}},
		{http.MethodGet, "/api/v1/oauth/clients/:id", func(n int) (string, string, string, func() string) {
			id := seedClient(n)
			return "/api/v1/oauth/clients/" + id, "", id, nil
		}},
		{http.MethodPost, "/api/v1/oauth/clients", func(n int) (string, string, string, func() string) {
			name := tag("new-client", n)
			return "/api/v1/oauth/clients",
				`{"name":"` + name + `","type":"confidential","redirect_uris":["https://` + name + `.example.test/cb"],"api_access":true}`,
				"", countInA(`SELECT COUNT(*)::text FROM oauth_clients WHERE name = $1 AND org_id = $2::uuid`, name)
		}},
		{http.MethodPut, "/api/v1/oauth/clients/:id", func(n int) (string, string, string, func() string) {
			id := seedClient(n)
			return "/api/v1/oauth/clients/" + id,
				`{"name":"` + id + `","type":"confidential","redirect_uris":["https://app.example.test/cb","https://` + tag("elsewhere", n) + `.example.test/cb"],"api_access":true}`,
				"", client(id, "redirect_uris::text || ' ' || api_access::text")
		}},
		{http.MethodPost, "/api/v1/oauth/clients/:id/regenerate-secret", func(n int) (string, string, string, func() string) {
			id := seedClient(n)
			return "/api/v1/oauth/clients/" + id + "/regenerate-secret", "", "", client(id, "client_secret")
		}},
		{http.MethodDelete, "/api/v1/oauth/clients/:id", func(n int) (string, string, string, func() string) {
			id := seedClient(n)
			return "/api/v1/oauth/clients/" + id, "", "", client(id, "client_id")
		}},

		// SAML service providers.
		{http.MethodGet, "/api/v1/saml/service-providers", func(n int) (string, string, string, func() string) {
			_, entityID := seedSP(n)
			return "/api/v1/saml/service-providers?page_size=100", "", entityID, nil
		}},
		{http.MethodGet, "/api/v1/saml/service-providers/:id", func(n int) (string, string, string, func() string) {
			id, entityID := seedSP(n)
			return "/api/v1/saml/service-providers/" + id, "", entityID, nil
		}},
		{http.MethodPost, "/api/v1/saml/service-providers", func(n int) (string, string, string, func() string) {
			entityID := "https://" + tag("new-sp", n) + ".example.test"
			return "/api/v1/saml/service-providers",
				`{"name":"` + entityID + `","entity_id":"` + entityID + `","acs_url":"` + entityID + `/acs"}`,
				"", countInA(`SELECT COUNT(*)::text FROM saml_service_providers WHERE entity_id = $1 AND org_id = $2::uuid`, entityID)
		}},
		{http.MethodPost, "/api/v1/saml/service-providers/import-metadata", func(n int) (string, string, string, func() string) {
			entityID := "https://" + tag("imported-sp", n) + ".example.test"
			return "/api/v1/saml/service-providers/import-metadata", spMetadata(entityID),
				"", countInA(`SELECT COUNT(*)::text FROM saml_service_providers WHERE entity_id = $1 AND org_id = $2::uuid`, entityID)
		}},
		{http.MethodPut, "/api/v1/saml/service-providers/:id", func(n int) (string, string, string, func() string) {
			id, _ := seedSP(n)
			return "/api/v1/saml/service-providers/" + id,
				`{"acs_url":"https://` + tag("moved-acs", n) + `.example.test/acs"}`, "", sp(id, "acs_url")
		}},
		{http.MethodPost, "/api/v1/saml/service-providers/:id/rotate-certificate", func(n int) (string, string, string, func() string) {
			id, _ := seedSP(n)
			return "/api/v1/saml/service-providers/" + id + "/rotate-certificate",
				`{"certificate":"` + tag("cert", n) + `"}`, "", sp(id, "certificate")
		}},
		{http.MethodDelete, "/api/v1/saml/service-providers/:id", func(n int) (string, string, string, func() string) {
			id, _ := seedSP(n)
			return "/api/v1/saml/service-providers/" + id, "", "", sp(id, "entity_id")
		}},

		// SSF streams.
		{http.MethodGet, "/ssf/streams", func(n int) (string, string, string, func() string) {
			id := seedStream(n)
			return "/ssf/streams", "", id, nil
		}},
		{http.MethodGet, "/ssf/streams/:id", func(n int) (string, string, string, func() string) {
			id := seedStream(n)
			return "/ssf/streams/" + id, "", id, nil
		}},
		{http.MethodPost, "/ssf/streams", func(n int) (string, string, string, func() string) {
			aud := "https://" + tag("new-rp", n) + ".example.test"
			return "/ssf/streams", `{"aud":"` + aud + `","delivery_endpoint":"` + aud + `/ssf/events"}`,
				"", countInA(`SELECT COUNT(*)::text FROM ssf_streams WHERE audience = $1 AND org_id = $2::uuid`, aud)
		}},
		{http.MethodPost, "/ssf/streams/:id/verify", func(n int) (string, string, string, func() string) {
			id := seedStream(n)
			return "/ssf/streams/" + id + "/verify?state=" + tag("state", n), "",
				"", countInA(`SELECT COUNT(*)::text FROM ssf_stream_delivery WHERE stream_id = $1::uuid AND org_id = $2::uuid`, id)
		}},
		{http.MethodDelete, "/ssf/streams/:id", func(n int) (string, string, string, func() string) {
			id := seedStream(n)
			return "/ssf/streams/" + id, "",
				"", countInA(`SELECT COUNT(*)::text FROM ssf_streams WHERE id = $1::uuid AND org_id = $2::uuid`, id)
		}},
	}

	n := 0
	for _, route := range routes {
		route := route
		t.Run(route.method+" "+route.route, func(t *testing.T) {
			for _, cl := range callers {
				n++
				path, body, marker, state := route.call(n)
				var before string
				if state != nil {
					before = state()
				}
				contentType := ""
				if body != "" {
					contentType = "application/json"
				}
				w := serve(api, route.method, path, contentType, body,
					"Authorization", "Bearer "+cl.bearer, "X-Org-Slug", cl.slug)
				var after string
				if state != nil {
					after = state()
				}
				showsA := marker != "" && strings.Contains(w.Body.String(), marker)

				switch cl.kind {
				case mgmtAdmitted:
					if w.Code < 200 || w.Code > 299 {
						t.Errorf("%s: status %d (%s), want 2xx", cl.name, w.Code, w.Body.String())
					}
					if marker != "" && !showsA {
						t.Errorf("%s: the answer does not carry A's %s: %s", cl.name, marker, w.Body.String())
					}
					if state != nil && before == after {
						t.Errorf("%s was admitted (%d) but nothing changed: %s", cl.name, w.Code, after)
					}
				case mgmtRefused:
					if w.Code != http.StatusForbidden {
						t.Errorf("%s: status %d (%s), want 403", cl.name, w.Code, w.Body.String())
					}
					fallthrough
				case mgmtElsewhere:
					if showsA {
						t.Errorf("%s: the answer carries A's %s: %s", cl.name, marker, w.Body.String())
					}
					if before != after {
						t.Errorf("%s changed A's state (%d):\n  before %s\n  after  %s", cl.name, w.Code, before, after)
					}
				}
			}
		})
	}
}

// Dynamic client registration (RFC 7591) is the other way to create a client,
// and it is not gated by a role: it is opened by the initial access token the
// operator configures (DCR_INITIAL_ACCESS_TOKEN; with none configured it is
// closed unless DCR_ALLOW_OPEN_REGISTRATION is set), and each client it
// registers by that client's own registration access token (RFC 7592). What
// neither can do is let an application call OpenIDX's own APIs: api_access in
// a registration or an update is ignored, and the client is stored without it.
func TestDynamicClientRegistrationCannotSetAPIAccess(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("dcr")
	h.issuer.dcrInitialAccessToken = "iat-" + h.suffix
	api := h.oauthRouteTable(nil)
	adminToken := h.accessToken(org, h.seedUser(org.ID, "dcr-admin", "admin"))

	const body = `{"client_name":"dcr","redirect_uris":["https://dcr.example.test/cb"],"api_access":true}`
	type registration struct {
		ClientID string `json:"client_id"`
		RAT      string `json:"registration_access_token"`
	}
	register := func(bearer string) (int, registration) {
		t.Helper()
		w := serve(api, http.MethodPost, "/oauth/register", "application/json", body,
			"Authorization", "Bearer "+bearer, "X-Org-Slug", org.Slug)
		var reg registration
		_ = json.Unmarshal(w.Body.Bytes(), &reg)
		return w.Code, reg
	}

	// An administrator's access token is not the initial access token.
	if code, _ := register(adminToken); code != http.StatusUnauthorized {
		t.Fatalf("registration with an admin's access token: %d, want 401", code)
	}
	code, reg := register(h.issuer.dcrInitialAccessToken)
	if code != http.StatusCreated || reg.ClientID == "" || reg.RAT == "" {
		t.Fatalf("registration with the initial access token: %d, client %q", code, reg.ClientID)
	}
	apiAccess := func() string {
		return h.scalar(`SELECT api_access::text FROM oauth_clients WHERE client_id = $1 AND org_id = $2::uuid`, reg.ClientID, org.ID)
	}
	if got := apiAccess(); got != "false" {
		t.Fatalf("a client registered with api_access in the request: api_access = %s, want false", got)
	}

	w := serve(api, http.MethodPut, "/oauth/register/"+reg.ClientID, "application/json", body,
		"Authorization", "Bearer "+reg.RAT, "X-Org-Slug", org.Slug)
	if w.Code != http.StatusOK {
		t.Fatalf("update with the registration access token: %d %s", w.Code, w.Body.String())
	}
	if got := apiAccess(); got != "false" {
		t.Fatalf("an update with api_access in the request: api_access = %s, want false", got)
	}
}
