package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// sessionAdminToken mints an access token for userID bound to a new session
// whose last second factor was verified mfaAgo ago, or never when mfaAgo is
// negative; with noSession the token carries no sid at all.
func (h *tokenHarness) sessionAdminToken(org orgctx.Org, userID string, mfaAgo time.Duration, noSession bool) string {
	h.t.Helper()
	client := h.consoleClient(org)
	if noSession {
		return h.tokenFor(org, userID, client)
	}
	sid := uuid.NewString()
	var verified interface{}
	if mfaAgo >= 0 {
		verified = time.Now().Add(-mfaAgo)
	}
	h.exec(`INSERT INTO sessions (id, user_id, client_id, expires_at, org_id, mfa_verified_at)
		VALUES ($1::uuid, $2::uuid, $3, NOW() + interval '1 hour', $4::uuid, $5)`, sid, userID, client, org.ID, verified)
	tok, err := h.issuer.GenerateJWT(orgctx.With(context.Background(), org), userID, client, "openid profile email", 300, sid)
	if err != nil {
		h.t.Fatalf("mint token: %v", err)
	}
	return tok
}

// stepUpRoute is one management write: seed what it acts on in org, and return
// the request and a reader of the state it changes.
type stepUpRoute struct {
	method, route string
	call          func(n int) (path, body string, state func() string)
}

func (h *tokenHarness) managementWrites(org orgctx.Org) []stepUpRoute {
	tag := func(kind string, n int) string { return fmt.Sprintf("su-%s-%d-%s", kind, n, h.suffix) }
	client := func(n int) string {
		id := tag("client", n)
		h.exec(`INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, api_access, org_id)
			VALUES ($1, 'seeded-secret', $1, 'confidential', '["https://app.example.test/cb"]'::jsonb, false, $2::uuid)`, id, org.ID)
		return id
	}
	sp := func(n int) string {
		entityID := "https://" + tag("sp", n) + ".example.test"
		return h.scalar(`INSERT INTO saml_service_providers (org_id, name, entity_id, acs_url, certificate)
			VALUES ($1::uuid, $2::text, $2::text, $2::text || '/acs', 'SEEDED-CERT') RETURNING id::text`, org.ID, entityID)
	}
	stream := func(n int) string {
		return h.scalar(`INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
			VALUES ($1::uuid, $2::text, $2::text || '/ssf/events') RETURNING id::text`, org.ID, "https://"+tag("rp", n)+".example.test")
	}
	read := func(query string, args ...interface{}) func() string {
		return func() string { return h.scalar(query, args...) }
	}
	metadata := func(entityID string) string {
		xml := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
			`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + entityID + `/acs" index="0"/>` +
			`</md:SPSSODescriptor></md:EntityDescriptor>`
		b, _ := json.Marshal(map[string]string{"metadata_xml": xml})
		return string(b)
	}
	return []stepUpRoute{
		{http.MethodPost, "/api/v1/oauth/clients", func(n int) (string, string, func() string) {
			name := tag("new-client", n)
			return "/api/v1/oauth/clients", `{"name":"` + name + `","type":"confidential","redirect_uris":["https://` + name + `.example.test/cb"]}`,
				read(`SELECT COUNT(*)::text FROM oauth_clients WHERE name = $1 AND org_id = $2::uuid`, name, org.ID)
		}},
		{http.MethodPut, "/api/v1/oauth/clients/:id", func(n int) (string, string, func() string) {
			id := client(n)
			return "/api/v1/oauth/clients/" + id, `{"name":"` + id + `","type":"confidential","redirect_uris":["https://` + tag("moved", n) + `.example.test/cb"]}`,
				read(`SELECT COALESCE((SELECT redirect_uris::text FROM oauth_clients WHERE client_id = $1), '<gone>')`, id)
		}},
		{http.MethodPost, "/api/v1/oauth/clients/:id/regenerate-secret", func(n int) (string, string, func() string) {
			id := client(n)
			return "/api/v1/oauth/clients/" + id + "/regenerate-secret", "",
				read(`SELECT COALESCE((SELECT client_secret FROM oauth_clients WHERE client_id = $1), '<gone>')`, id)
		}},
		{http.MethodDelete, "/api/v1/oauth/clients/:id", func(n int) (string, string, func() string) {
			id := client(n)
			return "/api/v1/oauth/clients/" + id, "", read(`SELECT COUNT(*)::text FROM oauth_clients WHERE client_id = $1`, id)
		}},
		{http.MethodPost, "/api/v1/saml/service-providers", func(n int) (string, string, func() string) {
			entityID := "https://" + tag("new-sp", n) + ".example.test"
			return "/api/v1/saml/service-providers", `{"name":"` + entityID + `","entity_id":"` + entityID + `","acs_url":"` + entityID + `/acs"}`,
				read(`SELECT COUNT(*)::text FROM saml_service_providers WHERE entity_id = $1`, entityID)
		}},
		{http.MethodPost, "/api/v1/saml/service-providers/import-metadata", func(n int) (string, string, func() string) {
			entityID := "https://" + tag("imported-sp", n) + ".example.test"
			return "/api/v1/saml/service-providers/import-metadata", metadata(entityID),
				read(`SELECT COUNT(*)::text FROM saml_service_providers WHERE entity_id = $1`, entityID)
		}},
		{http.MethodPut, "/api/v1/saml/service-providers/:id", func(n int) (string, string, func() string) {
			id := sp(n)
			return "/api/v1/saml/service-providers/" + id, `{"acs_url":"https://` + tag("moved-acs", n) + `.example.test/acs"}`,
				read(`SELECT COALESCE((SELECT acs_url FROM saml_service_providers WHERE id = $1::uuid), '<gone>')`, id)
		}},
		{http.MethodPost, "/api/v1/saml/service-providers/:id/rotate-certificate", func(n int) (string, string, func() string) {
			id := sp(n)
			return "/api/v1/saml/service-providers/" + id + "/rotate-certificate", `{"certificate":"` + tag("cert", n) + `"}`,
				read(`SELECT COALESCE((SELECT certificate FROM saml_service_providers WHERE id = $1::uuid), '<gone>')`, id)
		}},
		{http.MethodDelete, "/api/v1/saml/service-providers/:id", func(n int) (string, string, func() string) {
			id := sp(n)
			return "/api/v1/saml/service-providers/" + id, "", read(`SELECT COUNT(*)::text FROM saml_service_providers WHERE id = $1::uuid`, id)
		}},
		{http.MethodPost, "/ssf/streams", func(n int) (string, string, func() string) {
			aud := "https://" + tag("new-rp", n) + ".example.test"
			return "/ssf/streams", `{"aud":"` + aud + `","delivery_endpoint":"` + aud + `/ssf/events"}`,
				read(`SELECT COUNT(*)::text FROM ssf_streams WHERE audience = $1`, aud)
		}},
		{http.MethodPost, "/ssf/streams/:id/verify", func(n int) (string, string, func() string) {
			id := stream(n)
			return "/ssf/streams/" + id + "/verify?state=" + tag("state", n), "",
				read(`SELECT COUNT(*)::text FROM ssf_stream_delivery WHERE stream_id = $1::uuid`, id)
		}},
		{http.MethodDelete, "/ssf/streams/:id", func(n int) (string, string, func() string) {
			id := stream(n)
			return "/ssf/streams/" + id, "", read(`SELECT COUNT(*)::text FROM ssf_streams WHERE id = $1::uuid`, id)
		}},
	}
}

// stepUpEvents counts the step-up decisions recorded in org, by event type.
func (h *tokenHarness) stepUpEvents(org orgctx.Org, eventType string) int {
	h.t.Helper()
	var n int
	if err := h.db.Pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM unified_audit_events
		 WHERE org_id = $1::uuid AND source = $2 AND event_type = $3
		   AND details->>'enforcement_point' = $4`,
		org.ID, appaccess.SourceOIDC, eventType, appaccess.EnforcementPointAdminWrite).Scan(&n); err != nil {
		h.t.Fatalf("count step-up events: %v", err)
	}
	return n
}

// OAUTH CLIENT, SAML SERVICE PROVIDER AND SSF STREAM WRITES ASK FOR STEP-UP.
//
// admin-api asks an administrator for a recently verified second factor on
// every write when STEPUP_GATE is on; the oauth-service's management APIs did
// not, although they decide where the organization's sign-ins and security
// events go. Driven through RegisterRoutes behind the tenant resolver and
// AuthWithAPIKey, as cmd/oauth-service wires them, with administrators'
// tokens bound to session rows whose mfa_verified_at says how fresh their
// factor is, on every write route of the three APIs:
//
//   - enforce: an administrator whose factor is two hours old, one whose
//     session never verified one, and one whose token names no session are
//     refused with 403 step_up_required and the challenge URL, and nothing
//     changes; each refusal is recorded (access.stepup.required). An
//     administrator who verified a factor a minute ago writes, and the write
//     lands. Reads are not gated;
//   - observe: the stale administrator's writes land, and each is recorded as
//     one that would have been refused (access.stepup.would_require);
//   - off: the stale administrator's writes land and nothing is recorded.
func TestManagementWritesAskForStepUpUnderTheGate(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("stepup")
	admin := h.seedUser(org.ID, "stepup-admin", "admin")
	fresh := h.sessionAdminToken(org, admin, time.Minute, false)
	stale := h.sessionAdminToken(org, admin, 2*time.Hour, false)
	never := h.sessionAdminToken(org, admin, -1, false)
	noSession := h.sessionAdminToken(org, admin, 0, true)
	routes := h.managementWrites(org)

	n := 0
	write := func(api *gin.Engine, rt stepUpRoute, bearer string) (int, string, bool) {
		n++
		path, body, state := rt.call(n)
		before := state()
		ct := ""
		if body != "" {
			ct = "application/json"
		}
		w := serve(api, rt.method, path, ct, body, "Authorization", "Bearer "+bearer, "X-Org-Slug", org.Slug)
		return w.Code, w.Body.String(), state() != before
	}

	t.Run("enforce", func(t *testing.T) {
		h.issuer.config.StepUpGate = "enforce"
		api := h.oauthRouteTable(nil)
		refusedBefore := h.stepUpEvents(org, appaccess.EventTypeStepUpRequired)
		refusals := 0
		for _, rt := range routes {
			for name, bearer := range map[string]string{"a stale factor": stale, "no factor": never, "no session": noSession} {
				code, body, changed := write(api, rt, bearer)
				refusals++
				if code != http.StatusForbidden || !strings.Contains(body, "step_up_required") || !strings.Contains(body, "/oauth/stepup-challenge") {
					t.Errorf("%s %s, %s: %d %s, want 403 step_up_required", rt.method, rt.route, name, code, body)
				}
				if changed {
					t.Errorf("%s %s, %s: the write landed", rt.method, rt.route, name)
				}
			}
			code, body, changed := write(api, rt, fresh)
			if code < 200 || code > 299 || !changed {
				t.Errorf("%s %s, a fresh factor: %d %s, changed %v; want the write to land", rt.method, rt.route, code, body, changed)
			}
		}
		if got := h.stepUpEvents(org, appaccess.EventTypeStepUpRequired) - refusedBefore; got != refusals {
			t.Errorf("recorded %d refusals, want %d", got, refusals)
		}
		for _, path := range []string{"/api/v1/oauth/clients", "/api/v1/saml/service-providers", "/ssf/streams"} {
			if w := serve(api, http.MethodGet, path, "", "", "Authorization", "Bearer "+stale, "X-Org-Slug", org.Slug); w.Code != http.StatusOK {
				t.Errorf("GET %s with a stale factor: %d %s, want 200", path, w.Code, w.Body.String())
			}
		}
	})

	for _, mode := range []string{"observe", "off"} {
		t.Run(mode, func(t *testing.T) {
			h.issuer.config.StepUpGate = mode
			api := h.oauthRouteTable(nil)
			recordedBefore := h.stepUpEvents(org, appaccess.EventTypeStepUpWouldRequire)
			for _, rt := range routes {
				code, body, changed := write(api, rt, stale)
				if code < 200 || code > 299 || !changed {
					t.Errorf("%s %s, a stale factor: %d %s, changed %v; want the write to land", rt.method, rt.route, code, body, changed)
				}
			}
			want := 0
			if mode == "observe" {
				want = len(routes)
			}
			if got := h.stepUpEvents(org, appaccess.EventTypeStepUpWouldRequire) - recordedBefore; got != want {
				t.Errorf("recorded %d would-require decisions, want %d", got, want)
			}
		})
	}
}
