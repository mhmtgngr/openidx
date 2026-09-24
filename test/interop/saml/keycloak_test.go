//go:build samlinterop

package saml_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// Keycloak as the service provider: a realm whose SAML identity provider is
// OpenIDX (identity brokering). Keycloak is configured through its admin REST
// API, starting from what it imports out of the OpenIDX metadata.
//
// Two identity-provider aliases, because Keycloak receives an unsolicited
// (IdP-initiated) Response only at an alias's /endpoint/clients/<name> URL,
// where it signs the user in and starts IdP-initiated SSO to that SAML client
// of its own. Each alias is a separate SAML service provider with its own
// entity ID, so each is registered in OpenIDX with its own ACS URL.
//
// In every profile Keycloak signs its AuthnRequests (HTTP-Redirect) and
// logout messages (HTTP-POST), and requires signed assertions whose
// signatures it validates against the certificate from the metadata.

const (
	kcRealm          = "interop"
	kcAlias          = "openidx"
	kcUnsolAlias     = "openidx-unsolicited"
	kcSAMLClientName = "interop-saml-app"
	kcCallback       = "http://localhost:9/cb"
	kcSAMLAppACS     = "http://localhost:9/saml-acs"
	kcLoggedOut      = "http://localhost:9/loggedout"
	kcStop           = "http://localhost:9/"
)

type keycloak struct {
	t     *testing.T
	env   interopEnv
	token string
}

func newKeycloak(t *testing.T, env interopEnv) *keycloak {
	t.Helper()
	resp, err := http.PostForm(env.keycloakURL+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {env.keycloakAdminPassword},
	})
	must(t, err, "Keycloak admin token")
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("Keycloak admin token: %d %v", resp.StatusCode, err)
	}
	return &keycloak{t: t, env: env, token: tok.AccessToken}
}

func (k *keycloak) admin(method, path string, body interface{}, ok ...int) []byte {
	k.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, k.env.keycloakURL+"/admin/realms"+path, rd)
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(k.t, err, "%s %s", method, path)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if len(ok) == 0 {
		ok = []int{200, 201, 204}
	}
	for _, code := range ok {
		if resp.StatusCode == code {
			return out
		}
	}
	k.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, out)
	return nil
}

func (k *keycloak) exists(path string) bool {
	k.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, k.env.keycloakURL+"/admin/realms"+path, nil)
	req.Header.Set("Authorization", "Bearer "+k.token)
	resp, err := http.DefaultClient.Do(req)
	must(k.t, err, "GET %s", path)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// setupRealm creates the realm, an OIDC client the SP-initiated flow starts
// from, and the SAML client IdP-initiated SSO is delivered to.
func (k *keycloak) setupRealm() {
	k.admin(http.MethodDelete, "/"+kcRealm, nil, 204, 404)
	k.admin(http.MethodPost, "", map[string]interface{}{"realm": kcRealm, "enabled": true, "sslRequired": "none"})
	k.admin(http.MethodPost, "/"+kcRealm+"/clients", map[string]interface{}{
		"clientId": "interop-app", "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{kcCallback},
		"attributes":   map[string]string{"post.logout.redirect.uris": kcLoggedOut},
	})
	k.admin(http.MethodPost, "/"+kcRealm+"/clients", map[string]interface{}{
		"clientId": "urn:interop:saml-app", "protocol": "saml", "enabled": true,
		"redirectUris": []string{kcStop + "*"},
		"attributes": map[string]string{
			"saml_idp_initiated_sso_url_name":  kcSAMLClientName,
			"saml_assertion_consumer_url_post": kcSAMLAppACS,
			"saml.client.signature":            "false",
		},
	})
}

// configureIdP creates or replaces an identity-provider alias for OpenIDX.
func (k *keycloak) configureIdP(alias, entityID string, encrypt bool) spMetadata {
	var imported map[string]interface{}
	must(k.t, json.Unmarshal(k.admin(http.MethodPost, "/"+kcRealm+"/identity-provider/import-config",
		map[string]string{"providerId": "saml", "fromUrl": k.env.idpURL + "/saml/idp/metadata"}), &imported),
		"import the OpenIDX metadata")
	config := map[string]interface{}{}
	for key, v := range imported {
		config[key] = v
	}
	for key, v := range map[string]string{
		"entityId":                entityID,
		"nameIDPolicyFormat":      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"principalType":           "SUBJECT",
		"postBindingResponse":     "true",
		"postBindingAuthnRequest": "false",
		"postBindingLogout":       "true",
		"wantAuthnRequestsSigned": "true",
		"signatureAlgorithm":      "RSA_SHA256",
		"wantAssertionsSigned":    "true",
		"wantAssertionsEncrypted": fmt.Sprint(encrypt),
		"validateSignature":       "true",
		"backchannelSupported":    "true",
		"syncMode":                "FORCE",
		"allowedClockSkew":        "30",
	} {
		config[key] = v
	}
	rep := map[string]interface{}{"alias": alias, "providerId": "saml", "enabled": true, "trustEmail": true, "config": config}
	path := "/" + kcRealm + "/identity-provider/instances"
	// Updated in place after the first profile: deleting an alias drops the
	// users' links to it, and Keycloak then fails the next brokered sign-on
	// of a user it already knows with an internal error.
	if k.exists(path + "/" + alias) {
		k.admin(http.MethodPut, path+"/"+alias, rep)
	} else {
		k.admin(http.MethodPost, path, rep)
		for _, attr := range []string{"email", "firstName", "lastName"} {
			k.admin(http.MethodPost, path+"/"+alias+"/mappers", map[string]interface{}{
				"name": attr, "identityProviderAlias": alias, "identityProviderMapper": "saml-user-attribute-idp-mapper",
				"config": map[string]string{"syncMode": "INHERIT", "attribute.name": attr, "user.attribute": attr},
			})
		}
	}
	resp, err := http.Get(fmt.Sprintf("%s/realms/%s/broker/%s/endpoint/descriptor", k.env.keycloakURL, kcRealm, alias))
	must(k.t, err, "Keycloak SP descriptor")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return parseSPMetadata(k.t, string(raw))
}

type idToken struct {
	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

// exchange trades the code in the callback URL for tokens.
func (k *keycloak) exchange(callback string) (idTokenRaw, refresh string, claims idToken) {
	k.t.Helper()
	u, err := url.Parse(callback)
	must(k.t, err, "callback")
	code := u.Query().Get("code")
	if code == "" {
		k.t.Fatalf("Keycloak sent the browser back without a code: %s", callback)
	}
	resp, err := http.PostForm(fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.env.keycloakURL, kcRealm), url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"interop-app"}, "code": {code}, "redirect_uri": {kcCallback}})
	must(k.t, err, "token exchange")
	defer resp.Body.Close()
	var tok struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	must(k.t, json.NewDecoder(resp.Body).Decode(&tok), "token response")
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		k.t.Fatalf("no ID token: %+v", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(k.t, err, "ID token payload")
	must(k.t, json.Unmarshal(payload, &claims), "ID token claims")
	return tok.IDToken, tok.RefreshToken, claims
}

// sessionActive reports whether Keycloak still honours the refresh token,
// which is how its user session is observed from outside.
func (k *keycloak) sessionActive(refresh string) bool {
	resp, err := http.PostForm(fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.env.keycloakURL, kcRealm), url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"interop-app"}, "refresh_token": {refresh}})
	must(k.t, err, "refresh")
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

var nameIDRE = regexp.MustCompile(`<(?:saml2?:)?NameID[^>]*>([^<]+)<`)

func TestKeycloakServiceProvider(t *testing.T) {
	env := loadEnv(t)
	h := newIdP(t, env)
	k := newKeycloak(t, env)
	k.setupRealm()
	alice := h.seedUser("kc-alice", "Alice", "Keycloak")
	carol := h.seedUser("kc-carol", "Carol", "Keycloak")
	realmURL := env.keycloakURL + "/realms/" + kcRealm
	authURL := realmURL + "/protocol/openid-connect/auth?" + url.Values{
		"client_id": {"interop-app"}, "redirect_uri": {kcCallback}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {"st"}, "kc_idp_hint": {kcAlias}}.Encode()

	var unsolicited spMetadata
	for _, profile := range []struct {
		name    string
		encrypt bool
	}{
		{"signed assertion in a signed response", false},
		{"encrypted assertion in a signed response", true},
	} {
		md := k.configureIdP(kcAlias, realmURL, profile.encrypt)
		if profile.encrypt && md.encryptCert == "" {
			t.Fatal("Keycloak publishes no encryption key; the encrypted profile would test nothing")
		}
		h.registerSP("Keycloak interop", md, profile.encrypt)
		unsolicited = k.configureIdP(kcUnsolAlias, realmURL+"/unsolicited", profile.encrypt)
		unsolicited.acs = fmt.Sprintf("%s/broker/%s/endpoint/clients/%s", realmURL, kcUnsolAlias, kcSAMLClientName)
		h.registerSP("Keycloak interop (unsolicited)", unsolicited, profile.encrypt)

		signOn := func(t *testing.T) (*browser, string, string, string) {
			t.Helper()
			b, token := h.signedInBrowser(alice, kcStop)
			p := b.get(authURL)
			if !strings.HasPrefix(p.stoppedAt, kcCallback) {
				t.Fatalf("Keycloak did not complete the brokered sign-on: %d at %s: %.800s", p.status, p.url, p.body)
			}
			resp, ok := p.lastResponse()
			if !ok {
				t.Fatal("no SAMLResponse reached Keycloak")
			}
			if got := strings.Contains(decodeMessage(t, resp.value), "EncryptedAssertion"); got != profile.encrypt {
				t.Fatalf("EncryptedAssertion present = %v, want %v", got, profile.encrypt)
			}
			idt, refresh, claims := k.exchange(p.stoppedAt)
			if claims.Email != alice.email || claims.GivenName != alice.first || claims.FamilyName != alice.last {
				t.Fatalf("Keycloak's user is not the one OpenIDX asserted: %+v", claims)
			}
			return b, token, idt, refresh
		}

		t.Run(profile.name+"/SP-initiated SSO then SP-initiated SLO", func(t *testing.T) {
			b, token, idt, refresh := signOn(t)
			p := b.get(realmURL + "/protocol/openid-connect/logout?" + url.Values{
				"id_token_hint": {idt}, "post_logout_redirect_uri": {kcLoggedOut}, "client_id": {"interop-app"}}.Encode())
			if !strings.HasPrefix(p.stoppedAt, kcLoggedOut) {
				t.Fatalf("Keycloak's logout did not complete through the IdP: %d at %s: %.800s", p.status, p.url, p.body)
			}
			if h.sessionAlive(token) {
				t.Fatal("the IdP session outlived Keycloak's LogoutRequest")
			}
			if k.sessionActive(refresh) {
				t.Fatal("the Keycloak session outlived its own logout")
			}
		})

		t.Run(profile.name+"/IdP-initiated SLO", func(t *testing.T) {
			b, token, _, refresh := signOn(t)
			if p := b.get(env.idpURL + "/saml/idp/slo"); p.status != 200 || h.sessionAlive(token) {
				t.Fatalf("IdP-initiated logout answered %d; IdP session alive = %v", p.status, h.sessionAlive(token))
			}
			eventually(t, "Keycloak to end the brokered session", func() bool { return !k.sessionActive(refresh) })
		})

		t.Run(profile.name+"/IdP-initiated SSO", func(t *testing.T) {
			b, _ := h.signedInBrowser(carol, kcStop)
			p := b.get(env.idpURL + "/saml/idp/sso/unsolicited?" + url.Values{"sp_entity_id": {unsolicited.entityID}}.Encode())
			if p.stoppedAt != kcSAMLAppACS {
				t.Fatalf("Keycloak did not accept the unsolicited Response: %d at %s: %.800s", p.status, p.url, p.body)
			}
			// What Keycloak then asserts to its own SAML client names the user
			// OpenIDX asserted to Keycloak.
			resp, _ := p.lastResponse()
			if m := nameIDRE.FindStringSubmatch(decodeMessage(t, resp.value)); m == nil || m[1] != carol.email {
				t.Fatalf("Keycloak asserted %v, want %s", m, carol.email)
			}
		})
	}

	t.Run("Keycloak refuses forged responses", func(t *testing.T) {
		unsolicited = k.configureIdP(kcUnsolAlias, realmURL+"/unsolicited", false)
		unsolicited.acs = fmt.Sprintf("%s/broker/%s/endpoint/clients/%s", realmURL, kcUnsolAlias, kcSAMLClientName)
		h.registerSP("Keycloak interop (unsolicited)", unsolicited, false)
		genuine := func() string {
			b, _ := h.signedInBrowser(carol, unsolicited.acs)
			p := b.get(env.idpURL + "/saml/idp/sso/unsolicited?" + url.Values{"sp_entity_id": {unsolicited.entityID}}.Encode())
			resp, ok := p.lastResponse()
			if !ok || p.stoppedAt != unsolicited.acs {
				t.Fatalf("the IdP did not answer with a Response for Keycloak: %d %.400s", p.status, p.body)
			}
			return resp.value
		}
		deliver := func(samlResponse string) bool {
			b := newBrowser(t, kcStop)
			return b.post(unsolicited.acs, url.Values{"SAMLResponse": {samlResponse}}).stoppedAt == kcSAMLAppACS
		}
		if !deliver(genuine()) {
			t.Fatal("control: Keycloak refused a genuine Response, so a refusal below would prove nothing")
		}
		// No replay case here: replay is the SP's property, not the IdP's,
		// and SimpleSAMLphp's run covers it.
		for _, f := range h.forgeries(t) {
			f := f
			t.Run(f.name, func(t *testing.T) {
				if deliver(f.make(t, genuine())) {
					t.Fatalf("Keycloak accepted a Response %s", f.name)
				}
			})
		}
	})
}
