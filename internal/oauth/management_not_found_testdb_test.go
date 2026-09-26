package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ANOTHER ORGANIZATION'S CLIENT IS NOT FOUND, ON EVERY ROUTE.
//
// The client-management routes went straight to their write, scoped to the
// caller's organization, and reported what it returned. For a client of
// another organization that was 500 on an update, 200 with a freshly minted
// secret -- stored nowhere -- on a secret regeneration, and 204 on a delete:
// nothing changed, and each answer said otherwise. Driven through
// RegisterRoutes behind the tenant resolver and AuthWithAPIKey, as
// cmd/oauth-service wires them, with administrators' tokens minted from
// database rows:
//
//   - B's administrator, working in B, names a client of A on each of the four
//     routes that take one and gets 404 "client not found", before the body
//     is read (a malformed update is 404 as well), with no secret in any
//     answer; A's client reads back unchanged. An id nobody has is the same
//     404;
//   - A's administrator reads, updates, regenerates the secret of and deletes
//     A's clients, and each write lands.
func TestClientManagementAnswersNotFoundForAnotherOrganizationsClient(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("mnf-a"), h.seedOrg("mnf-b")
	api := h.oauthRouteTable(nil)
	adminA := h.accessToken(orgA, h.seedUser(orgA.ID, "mnf-admin-a", "admin"))
	adminB := h.accessToken(orgB, h.seedUser(orgB.ID, "mnf-admin-b", "admin"))

	n := 0
	seedA := func() string {
		n++
		id := fmt.Sprintf("mnf-client-%d-%s", n, h.suffix)
		h.exec(`INSERT INTO oauth_clients (client_id, client_secret, name, type, redirect_uris, api_access, org_id)
			VALUES ($1, 'seeded-secret', $1, 'confidential', '["https://a.example.test/cb"]'::jsonb, false, $2::uuid)`, id, orgA.ID)
		return id
	}
	state := func(id string) string {
		return h.scalar(`SELECT COALESCE((SELECT client_secret || ' ' || name || ' ' || redirect_uris::text
			FROM oauth_clients WHERE client_id = $1 AND org_id = $2::uuid), '<gone>')`, id, orgA.ID)
	}
	const update = `{"name":"renamed","type":"confidential","redirect_uris":["https://renamed.example.test/cb"]}`

	for _, rt := range []struct {
		method, path, body string
		admitted           int
		changes            bool
	}{
		{http.MethodGet, "/api/v1/oauth/clients/%s", "", http.StatusOK, false},
		{http.MethodPut, "/api/v1/oauth/clients/%s", update, http.StatusOK, true},
		{http.MethodPut, "/api/v1/oauth/clients/%s", `{"name":`, http.StatusBadRequest, false},
		{http.MethodPost, "/api/v1/oauth/clients/%s/regenerate-secret", "", http.StatusOK, true},
		{http.MethodDelete, "/api/v1/oauth/clients/%s", "", http.StatusNoContent, true},
	} {
		t.Run(rt.method+" "+rt.path+" "+rt.body, func(t *testing.T) {
			send := func(bearer, slug, id string) (int, string) {
				ct := ""
				if rt.body != "" {
					ct = "application/json"
				}
				w := serve(api, rt.method, fmt.Sprintf(rt.path, id), ct, rt.body,
					"Authorization", "Bearer "+bearer, "X-Org-Slug", slug)
				return w.Code, w.Body.String()
			}

			id := seedA()
			before := state(id)
			code, body := send(adminB, orgB.Slug, id)
			if code != http.StatusNotFound || !strings.Contains(body, "client not found") {
				t.Errorf("B's admin naming A's client: %d %s, want 404 client not found", code, body)
			}
			if strings.Contains(body, "client_secret") || strings.Contains(body, "seeded-secret") {
				t.Errorf("B's admin was answered with a secret: %s", body)
			}
			if after := state(id); after != before {
				t.Errorf("B's admin changed A's client:\n  before %s\n  after  %s", before, after)
			}

			if code, body := send(adminA, orgA.Slug, "mnf-nobody-"+h.suffix); code != http.StatusNotFound {
				t.Errorf("an id nobody has: %d %s, want 404", code, body)
			}

			code, body = send(adminA, orgA.Slug, id)
			if code != rt.admitted {
				t.Fatalf("A's admin: %d %s, want %d", code, body, rt.admitted)
			}
			if changed := state(id) != before; changed != rt.changes {
				t.Errorf("A's admin: changed = %v, want %v (%s)", changed, rt.changes, state(id))
			}
			if rt.method == http.MethodPost && !strings.Contains(state(id), strings.Trim(extract(body, "client_secret"), `"`)) {
				t.Errorf("the regenerated secret answered to A's admin is not the one stored")
			}
		})
	}
}

// The secret regeneration stores the new secret before it answers with it, and
// answers ErrOAuthClientNotFound when there was no row to store it in -- which
// is what keeps a secret that was never stored from being handed out, should a
// caller reach it without the lookup the route makes first.
func TestARegeneratedSecretIsOneThatWasStored(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("regen-a"), h.seedOrg("regen-b")
	id := "regen-client-" + h.suffix
	h.exec(`INSERT INTO oauth_clients (client_id, client_secret, name, type, org_id)
		VALUES ($1, 'seeded-secret', $1, 'confidential', $2::uuid)`, id, orgA.ID)

	if secret, err := h.issuer.RegenerateClientSecret(orgctx.With(context.Background(), orgB), id); !errors.Is(err, ErrOAuthClientNotFound) || secret != "" {
		t.Errorf("regenerating A's client in B: %q, %v; want no secret and ErrOAuthClientNotFound", secret, err)
	}
	if got := h.scalar(`SELECT client_secret FROM oauth_clients WHERE client_id = $1`, id); got != "seeded-secret" {
		t.Errorf("A's secret changed: %s", got)
	}
	secret, err := h.issuer.RegenerateClientSecret(orgctx.With(context.Background(), orgA), id)
	if err != nil || secret == "" {
		t.Fatalf("regenerating A's client in A: %q, %v", secret, err)
	}
	if got := h.scalar(`SELECT client_secret FROM oauth_clients WHERE client_id = $1`, id); got != secret {
		t.Errorf("the secret handed out is not the one stored")
	}
}

// extract pulls one string field out of a small JSON answer without a decoder,
// enough for the regenerated secret.
func extract(body, field string) string {
	i := strings.Index(body, `"`+field+`":`)
	if i < 0 {
		return "<none>"
	}
	rest := body[i+len(field)+3:]
	if j := strings.IndexAny(rest, ",}"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// A value the client store will not keep is the administrator's mistake, and
// the answer says so: 400 with the reason, where every one of these used to be
// a 500 "create client" or "update client".
func TestClientManagementRefusesAnInvalidClientWith400(t *testing.T) {
	h := newTokenHarness(t)
	org := h.seedOrg("mnf-invalid")
	api := h.oauthRouteTable(nil)
	admin := h.accessToken(org, h.seedUser(org.ID, "mnf-invalid-admin", "admin"))
	send := func(method, path, body string) (int, string) {
		w := serve(api, method, path, "application/json", body, "Authorization", "Bearer "+admin, "X-Org-Slug", org.Slug)
		return w.Code, w.Body.String()
	}
	for name, body := range map[string]string{
		"an access-token lifetime past the revocation marker": `{"name":"x","type":"confidential","access_token_lifetime":999999999}`,
		"a post-logout redirect URI with no host":             `{"name":"x","type":"confidential","post_logout_redirect_uris":["not-a-uri"]}`,
		"a back-channel logout URI over plain http":           `{"name":"x","type":"confidential","back_channel_logout_uri":"http://rp.example.test/bcl"}`,
		"an empty token-exchange audience":                    `{"name":"x","type":"confidential","token_exchange_audiences":[""]}`,
	} {
		if code, out := send(http.MethodPost, "/api/v1/oauth/clients", body); code != http.StatusBadRequest {
			t.Errorf("create with %s: %d %s, want 400", name, code, out)
		}
	}
	code, out := send(http.MethodPost, "/api/v1/oauth/clients", `{"name":"valid","type":"confidential"}`)
	if code != http.StatusCreated {
		t.Fatalf("create a valid client: %d %s", code, out)
	}
	id := strings.Trim(extract(out, "client_id"), `"`)
	if code, out := send(http.MethodPut, "/api/v1/oauth/clients/"+id, `{"name":"valid","type":"confidential","token_exchange_audiences":["  "]}`); code != http.StatusBadRequest {
		t.Errorf("update with a blank audience: %d %s, want 400", code, out)
	}
	if code, out := send(http.MethodPut, "/api/v1/oauth/clients/"+id, `{"name":"renamed","type":"confidential"}`); code != http.StatusOK {
		t.Errorf("a valid update: %d %s, want 200", code, out)
	}
}

// The SAML service-provider and SSF stream routes already answered 404 for
// another organization's record. An id that is not a UUID is 404 too now: it
// was a 500 on a delete or a certificate rotation, and on a stream delete a 404
// whose body was the database's complaint about the cast.
func TestServiceProviderAndStreamRoutesAnswerNotFound(t *testing.T) {
	h := newTokenHarness(t)
	orgA, orgB := h.seedOrg("mnf-sp-a"), h.seedOrg("mnf-sp-b")
	api := h.oauthRouteTable(nil)
	adminA := h.accessToken(orgA, h.seedUser(orgA.ID, "mnf-sp-admin-a", "admin"))
	adminB := h.accessToken(orgB, h.seedUser(orgB.ID, "mnf-sp-admin-b", "admin"))
	entityID := "https://mnf-sp-" + h.suffix + ".example.test"
	sp := h.scalar(`INSERT INTO saml_service_providers (org_id, name, entity_id, acs_url, certificate)
		VALUES ($1::uuid, $2::text, $2::text, $2::text || '/acs', 'SEEDED-CERT') RETURNING id::text`, orgA.ID, entityID)
	stream := h.scalar(`INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
		VALUES ($1::uuid, $2::text, $2::text || '/ssf/events') RETURNING id::text`, orgA.ID, "https://mnf-rp-"+h.suffix+".example.test")

	for _, tc := range []struct {
		method, path, body, bearer, slug string
	}{
		{http.MethodDelete, "/api/v1/saml/service-providers/not-a-uuid", "", adminA, orgA.Slug},
		{http.MethodPost, "/api/v1/saml/service-providers/not-a-uuid/rotate-certificate", `{"certificate":"X"}`, adminA, orgA.Slug},
		{http.MethodDelete, "/ssf/streams/not-a-uuid", "", adminA, orgA.Slug},
		{http.MethodDelete, "/api/v1/saml/service-providers/" + sp, "", adminB, orgB.Slug},
		{http.MethodPost, "/api/v1/saml/service-providers/" + sp + "/rotate-certificate", `{"certificate":"X"}`, adminB, orgB.Slug},
		{http.MethodPut, "/api/v1/saml/service-providers/" + sp, `{"acs_url":"https://moved.example.test/acs"}`, adminB, orgB.Slug},
		{http.MethodDelete, "/ssf/streams/" + stream, "", adminB, orgB.Slug},
	} {
		ct := ""
		if tc.body != "" {
			ct = "application/json"
		}
		w := serve(api, tc.method, tc.path, ct, tc.body, "Authorization", "Bearer "+tc.bearer, "X-Org-Slug", tc.slug)
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "syntax") {
			t.Errorf("%s %s: %d %s, want a plain 404", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if got := h.scalar(`SELECT certificate || ' ' || acs_url FROM saml_service_providers WHERE id = $1::uuid`, sp); got != "SEEDED-CERT "+entityID+"/acs" {
		t.Errorf("A's service provider changed: %s", got)
	}
	if got := h.scalar(`SELECT COUNT(*)::text FROM ssf_streams WHERE id = $1::uuid`, stream); got != "1" {
		t.Errorf("A's stream is gone")
	}
	// A's administrator still deletes both.
	for _, path := range []string{"/api/v1/saml/service-providers/" + sp, "/ssf/streams/" + stream} {
		if w := serve(api, http.MethodDelete, path, "", "", "Authorization", "Bearer "+adminA, "X-Org-Slug", orgA.Slug); w.Code != http.StatusOK {
			t.Errorf("A's admin deleting %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
