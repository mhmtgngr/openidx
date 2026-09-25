//go:build samlinterop

package saml_test

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

// SimpleSAMLphp as the service provider. Its configuration is under
// simplesamlphp/; the harness switches its per-profile settings by writing
// the profile file config/authsources.php and config/saml2int.conf.php read on
// every request.
//
// In every profile SimpleSAMLphp signs its AuthnRequests (HTTP-Redirect) and
// its logout messages, validates the IdP's logout messages, and requires the
// Response to be signed (SAML2Int, [SDP-IDP30]); it verifies the assertion's
// signature as well whenever there is one, which OpenIDX always sends.

type sspProfile struct {
	name    string
	encrypt bool
}

type sspSession struct {
	Authenticated bool                `json:"authenticated"`
	Attributes    map[string][]string `json:"attributes"`
	NameID        string              `json:"nameId"`
	SessionIndex  string              `json:"sessionIndex"`
}

func sspWhoami(t *testing.T, p *page) sspSession {
	t.Helper()
	var s sspSession
	if err := json.Unmarshal([]byte(p.body), &s); err != nil {
		t.Fatalf("SimpleSAMLphp answered %d at %s with something that is not the test application's JSON: %.600s", p.status, p.url, p.body)
	}
	return s
}

func writeSSPProfile(t *testing.T, env interopEnv, encrypt bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]bool{
		"sign_authnrequest":       true,
		"require_signed_response": true,
		"require_encryption":      encrypt,
	})
	must(t, os.WriteFile(env.sspProfileFile, raw, 0o644), "write the SimpleSAMLphp profile")
}

func TestSimpleSAMLphpServiceProvider(t *testing.T) {
	env := loadEnv(t)
	h := newIdP(t, env)
	writeSSPProfile(t, env, false)
	md := parseSPMetadata(t, h.fetch(env.sspURL+"/module.php/saml/sp/metadata/openidx"))
	if !md.authnRequestsSigned {
		t.Fatal("the SimpleSAMLphp metadata does not say it signs AuthnRequests; the profile file did not take")
	}
	alice := h.seedUser("ssp-alice", "Alice", "Interop")
	whoami := env.sspURL + "/app/whoami"

	checkSession := func(t *testing.T, p *page, encrypted, unsolicited bool) {
		t.Helper()
		s := sspWhoami(t, p)
		if !s.Authenticated {
			t.Fatalf("SimpleSAMLphp did not accept the sign-on; it answered %d at %s: %.800s", p.status, p.url, p.body)
		}
		if s.NameID != alice.email || first(s.Attributes["email"]) != alice.email ||
			first(s.Attributes["firstName"]) != alice.first || first(s.Attributes["lastName"]) != alice.last {
			t.Fatalf("SimpleSAMLphp holds the wrong subject: %+v", s)
		}
		resp, ok := p.lastResponse()
		if !ok {
			t.Fatal("no SAMLResponse was carried")
		}
		xml := decodeMessage(t, resp.value)
		if got := strings.Contains(xml, "EncryptedAssertion"); got != encrypted {
			t.Fatalf("EncryptedAssertion present = %v, want %v", got, encrypted)
		}
		if got := strings.Contains(xml, "InResponseTo="); got == unsolicited {
			t.Fatalf("InResponseTo present = %v in a response that is unsolicited = %v", got, unsolicited)
		}
	}

	for _, profile := range []sspProfile{
		{name: "signed assertion in a signed response", encrypt: false},
		{name: "encrypted assertion in a signed response", encrypt: true},
	} {
		writeSSPProfile(t, env, profile.encrypt)
		h.registerSP("SimpleSAMLphp interop", md, profile.encrypt)

		t.Run(profile.name+"/SP-initiated SSO then SP-initiated SLO", func(t *testing.T) {
			b, token := h.signedInBrowser(alice)
			checkSession(t, b.get(env.sspURL+"/app/login"), profile.encrypt, false)

			p := b.get(env.sspURL + "/app/logout")
			if s := sspWhoami(t, p); s.Authenticated {
				t.Fatalf("still signed in at SimpleSAMLphp after its logout: %+v", s)
			}
			if h.sessionAlive(token) {
				t.Fatal("the IdP session outlived an SP-initiated Single Logout")
			}
		})

		t.Run(profile.name+"/IdP-initiated SSO then IdP-initiated SLO", func(t *testing.T) {
			b, token := h.signedInBrowser(alice)
			q := url.Values{"sp_entity_id": {md.entityID}, "RelayState": {whoami}}
			checkSession(t, b.get(env.idpURL+"/saml/idp/sso/unsolicited?"+q.Encode()), profile.encrypt, true)

			p := b.get(env.idpURL + "/saml/idp/slo")
			if p.status != 200 || h.sessionAlive(token) {
				t.Fatalf("IdP-initiated logout answered %d; IdP session alive = %v", p.status, h.sessionAlive(token))
			}
			// The IdP tells SimpleSAMLphp over the back channel; the SP ends the
			// session it holds for this NameID and SessionIndex.
			eventually(t, "SimpleSAMLphp to end its session", func() bool {
				return !sspWhoami(t, b.get(whoami)).Authenticated
			})
		})
	}

	t.Run("SimpleSAMLphp refuses forged and replayed responses", func(t *testing.T) {
		writeSSPProfile(t, env, false)
		h.registerSP("SimpleSAMLphp interop", md, false)
		genuine := func() string {
			b, _ := h.signedInBrowser(alice, md.acs)
			q := url.Values{"sp_entity_id": {md.entityID}, "RelayState": {whoami}}
			p := b.get(env.idpURL + "/saml/idp/sso/unsolicited?" + q.Encode())
			resp, ok := p.lastResponse()
			if !ok || p.stoppedAt != md.acs {
				t.Fatalf("the IdP did not answer with a Response for the ACS: %d %.400s", p.status, p.body)
			}
			return resp.value
		}
		deliver := func(samlResponse string) bool {
			b := newBrowser(t)
			b.post(md.acs, url.Values{"SAMLResponse": {samlResponse}, "RelayState": {whoami}})
			return sspWhoami(t, b.get(whoami)).Authenticated
		}

		original := genuine()
		if !deliver(original) {
			t.Fatal("control: SimpleSAMLphp refused a genuine Response, so a refusal below would prove nothing")
		}
		t.Run("replayed", func(t *testing.T) {
			if deliver(original) {
				t.Fatal("SimpleSAMLphp accepted the same Response a second time")
			}
		})
		for _, f := range h.forgeries(t) {
			f := f
			t.Run(f.name, func(t *testing.T) {
				if deliver(f.make(t, genuine())) {
					t.Fatalf("SimpleSAMLphp accepted a Response %s", f.name)
				}
			})
		}
	})
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
