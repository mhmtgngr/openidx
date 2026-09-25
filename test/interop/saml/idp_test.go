//go:build samlinterop

// Package saml_test runs the OpenIDX SAML identity provider against two
// service providers built on SAML stacks that share no code with it:
// SimpleSAMLphp (PHP: simplesamlphp/saml2 and xmlseclibs) and Keycloak acting
// as a service provider that brokers to OpenIDX (Java: Keycloak's SAML core on
// Apache Santuario). OpenIDX signs and encrypts with goxmldsig and the Go
// standard library; a service provider built on those would agree with every
// mistake OpenIDX makes, so neither is used here.
//
// It needs the three running (.github/workflows/saml-interop.yml starts them)
// and is behind the samlinterop build tag so that no other job compiles it.
package saml_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/signingkeys"
)

const defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations

type interopEnv struct {
	idpURL, sspURL, keycloakURL string
	keycloakAdminPassword       string
	databaseURL, encryptionKey  string
	sspProfileFile              string
}

func loadEnv(t *testing.T) interopEnv {
	t.Helper()
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is not set: this suite runs in the SAML interop workflow, which sets it", name)
		}
		return strings.TrimRight(v, "/")
	}
	return interopEnv{
		idpURL:                get("OPENIDX_URL"),
		sspURL:                get("SSP_URL"),
		keycloakURL:           get("KEYCLOAK_URL"),
		keycloakAdminPassword: get("KEYCLOAK_ADMIN_PASSWORD"),
		databaseURL:           get("INTEROP_DATABASE_URL"),
		encryptionKey:         get("INTEROP_ENCRYPTION_KEY"),
		sspProfileFile:        get("SSP_PROFILE_FILE"),
	}
}

// idp is the OpenIDX identity provider under test, and its database.
type idp struct {
	t    *testing.T
	env  interopEnv
	pool *pgxpool.Pool
	// key and cert are the IdP's signing key and the certificate its metadata
	// publishes; the forged-response controls sign with them.
	key     *rsa.PrivateKey
	certDER []byte
}

func newIdP(t *testing.T, env interopEnv) *idp {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, env.databaseURL)
	if err != nil {
		t.Fatalf("connect to the IdP database: %v", err)
	}
	t.Cleanup(pool.Close)
	h := &idp{t: t, env: env, pool: pool}

	// The key the IdP signs with, read the way the IdP reads it.
	active, err := signingkeys.NewStore(pool, env.encryptionKey, "", zap.NewNop()).Active(ctx)
	if err != nil {
		t.Fatalf("read the IdP's active signing key: %v", err)
	}
	h.key = active.Private

	md := h.fetch(env.idpURL + "/saml/idp/metadata")
	var doc struct {
		Keys []struct {
			Use  string `xml:"use,attr"`
			Cert string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"IDPSSODescriptor>KeyDescriptor"`
	}
	if err := xml.Unmarshal([]byte(md), &doc); err != nil {
		t.Fatalf("parse the IdP metadata: %v", err)
	}
	for _, k := range doc.Keys {
		if k.Use == "signing" {
			h.certDER, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(k.Cert), ""))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	cert, err := x509.ParseCertificate(h.certDER)
	if err != nil {
		t.Fatalf("the IdP metadata carries no usable signing certificate: %v", err)
	}
	if !cert.PublicKey.(*rsa.PublicKey).Equal(&h.key.PublicKey) {
		t.Fatal("the IdP metadata's certificate is not for the active signing key")
	}
	return h
}

func (h *idp) fetch(target string) string {
	h.t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		h.t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET %s: %d %s", target, resp.StatusCode, body)
	}
	return string(body)
}

func (h *idp) exec(sql string, args ...interface{}) {
	h.t.Helper()
	if _, err := h.pool.Exec(context.Background(), sql, args...); err != nil {
		h.t.Fatalf("%v\n%s", err, sql)
	}
}

// user is a directory user with an IdP session.
type user struct {
	id, email, first, last string
}

func (h *idp) seedUser(local, first, last string) user {
	h.t.Helper()
	u := user{email: local + "@interop.example.test", first: first, last: last}
	if err := h.pool.QueryRow(context.Background(), `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled, email_verified)
		VALUES ($1, $2, $3, $4, $5, true, true)
		ON CONFLICT (username) DO UPDATE SET email = EXCLUDED.email
		RETURNING id::text`, defaultOrg, "interop."+local, u.email, first, last).Scan(&u.id); err != nil {
		h.t.Fatalf("seed user: %v", err)
	}
	return u
}

// session signs the user in at the IdP: the openidx_session cookie a login
// would leave behind. The login page is not what this suite tests.
func (h *idp) session(u user) string {
	h.t.Helper()
	token := "interop-" + uuid.NewString()
	h.exec(`INSERT INTO user_sessions (user_id, session_token, expires_at, org_id)
	        VALUES ($1, $2, NOW() + interval '1 hour', $3)`, u.id, token, defaultOrg)
	return token
}

func (h *idp) sessionAlive(token string) bool {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_sessions WHERE session_token = $1`, token).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n > 0
}

// signedInBrowser is a browser that holds the user's IdP session cookie.
func (h *idp) signedInBrowser(u user, stopAt ...string) (*browser, string) {
	h.t.Helper()
	token := h.session(u)
	b := newBrowser(h.t, stopAt...)
	idpHost := strings.TrimPrefix(strings.TrimPrefix(h.env.idpURL, "http://"), "https://")
	b.extraCookies[idpHost] = "openidx_session=" + token
	return b, token
}

// spMetadata is what the IdP needs from a service provider's metadata.
type spMetadata struct {
	entityID, acs, slo       string
	signingCert, encryptCert string
	authnRequestsSigned      bool
}

func parseSPMetadata(t *testing.T, doc string) spMetadata {
	t.Helper()
	var md struct {
		EntityID string `xml:"entityID,attr"`
		SP       struct {
			AuthnRequestsSigned bool `xml:"AuthnRequestsSigned,attr"`
			Keys                []struct {
				Use  string `xml:"use,attr"`
				Cert string `xml:"KeyInfo>X509Data>X509Certificate"`
			} `xml:"KeyDescriptor"`
			ACS []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			} `xml:"AssertionConsumerService"`
			SLO []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			} `xml:"SingleLogoutService"`
		} `xml:"SPSSODescriptor"`
	}
	if err := xml.Unmarshal([]byte(doc), &md); err != nil {
		t.Fatalf("parse SP metadata: %v", err)
	}
	out := spMetadata{entityID: md.EntityID, authnRequestsSigned: md.SP.AuthnRequestsSigned}
	for _, k := range md.SP.Keys {
		cert := strings.Join(strings.Fields(k.Cert), "")
		switch k.Use {
		case "signing", "":
			if out.signingCert == "" {
				out.signingCert = cert
			}
		case "encryption":
			out.encryptCert = cert
		}
	}
	for _, a := range md.SP.ACS {
		if strings.HasSuffix(a.Binding, "HTTP-POST") {
			out.acs = a.Location
		}
	}
	for _, s := range md.SP.SLO {
		if strings.HasSuffix(s.Binding, "HTTP-Redirect") {
			out.slo = s.Location
		}
	}
	if out.entityID == "" || out.acs == "" || out.signingCert == "" {
		t.Fatalf("SP metadata lacks an entity id, an HTTP-POST ACS or a signing certificate: %+v", out)
	}
	return out
}

// registerSP (re)registers a service provider, as an administrator would
// from its metadata.
func (h *idp) registerSP(name string, md spMetadata, encrypt bool) {
	h.t.Helper()
	var enc interface{}
	if md.encryptCert != "" && md.encryptCert != md.signingCert {
		enc = md.encryptCert
	}
	h.exec(`DELETE FROM saml_service_providers WHERE entity_id = $1`, md.entityID)
	h.exec(`INSERT INTO saml_service_providers
	          (org_id, name, entity_id, acs_url, slo_url, certificate, encryption_certificate,
	           name_id_format, enabled, want_assertions_signed, encryption_enabled, require_signed_authn_requests)
	        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, true, $9, $10)`,
		defaultOrg, name, md.entityID, md.acs, md.slo, md.signingCert, enc,
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", encrypt, md.authnRequestsSigned)
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func decodeMessage(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	return string(raw)
}

func must(t *testing.T, err error, format string, args ...interface{}) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", fmt.Sprintf(format, args...), err)
	}
}
