package oauth

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/beevik/etree"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	dsig "github.com/russellhaering/goxmldsig"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The SAML IdP's protocol endpoints, driven through the real routes against a
// migrated PostgreSQL, with crafted messages.
//
// OpenIDX is a SAML IDENTITY PROVIDER only: nothing in this tree consumes an
// assertion (there is no ACS; identity_providers rows of type "saml" have no
// login path). So the list "an unsigned, wrongly signed, wrong-audience,
// expired or replayed assertion must be refused" has no assertion consumer
// here to apply to. It applies instead to the signed protocol messages this
// IdP does receive: AuthnRequests at /saml/idp/sso and LogoutRequests at
// /saml/idp/slo. For a LogoutRequest the five checks map one to one --
// signature absent, signature by another key, Destination (the audience of a
// protocol message) naming another endpoint, IssueInstant or NotOnOrAfter
// past, and an ID already processed. The assertions the IdP ISSUES are
// checked by the independent service providers in the SAML interop workflow,
// which also refuse forged ones there.

const (
	samlTestOrg    = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	samlTestIssuer = "https://idp.example.test"
)

type samlTestKey struct {
	priv    *rsa.PrivateKey
	certDER []byte
	cert    *x509.Certificate
}

func (k samlTestKey) certB64() string { return base64.StdEncoding.EncodeToString(k.certDER) }

func newSAMLTestKey(t *testing.T, cn string) samlTestKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return samlTestKey{priv: priv, certDER: der, cert: cert}
}

// samlIdPHarness is the IdP's public SAML routes on a migrated database.
type samlIdPHarness struct {
	t      *testing.T
	svc    *Service
	db     *database.PostgresDB
	router *gin.Engine
	idp    samlTestKey
	userID string
	token  string // the user's openidx_session cookie
	email  string
}

func newSAMLIdPHarness(t *testing.T) *samlIdPHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	mini := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	h := &samlIdPHarness{t: t, db: db, idp: newSAMLTestKey(t, "idp"), token: "session-" + uuid.NewString()}
	h.svc = &Service{
		db:         db,
		redis:      &database.RedisClient{Client: rdb},
		logger:     zap.NewNop(),
		issuer:     samlTestIssuer,
		privateKey: h.idp.priv,
		publicKey:  &h.idp.priv.PublicKey,
		config:     &config.Config{},
	}

	h.email = "saml-" + uuid.NewString()[:8] + "@example.test"
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled)
		VALUES ($1, $2, $2, 'Ada', 'Lovelace', true) RETURNING id::text`,
		samlTestOrg, h.email).Scan(&h.userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO user_sessions (user_id, session_token, expires_at, org_id)
		VALUES ($1, $2, NOW() + interval '1 hour', $3)`, h.userID, h.token, samlTestOrg); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	h.router = gin.New()
	h.router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: samlTestOrg}))
		c.Next()
	})
	h.svc.RegisterSAMLIdPRoutes(h.router, func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) })
	return h
}

type samlTestSP struct {
	entityID, acs, slo string
	key                samlTestKey
}

// registerSP registers a service provider the way the management API stores
// one, and returns it.
func (h *samlIdPHarness) registerSP(name string, opts func(*CreateSAMLServiceProviderRequest)) samlTestSP {
	h.t.Helper()
	sp := samlTestSP{
		entityID: "https://" + name + ".sp.example.test",
		acs:      "https://" + name + ".sp.example.test/acs",
		slo:      "https://" + name + ".sp.example.test/slo",
		key:      newSAMLTestKey(h.t, name),
	}
	req := &CreateSAMLServiceProviderRequest{
		Name: name, EntityID: sp.entityID, ACSURL: sp.acs, SLOURL: sp.slo,
		Certificate: sp.key.certB64(), NameIDFormat: NameIDFormatEmail,
	}
	if opts != nil {
		opts(req)
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: samlTestOrg})
	if _, err := h.svc.createSAMLServiceProvider(ctx, req); err != nil {
		h.t.Fatalf("register %s: %v", name, err)
	}
	return sp
}

func (h *samlIdPHarness) do(method, target string, form url.Values, withSession bool) *httptest.ResponseRecorder {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if withSession {
		req.AddCookie(&http.Cookie{Name: "openidx_session", Value: h.token})
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func (h *samlIdPHarness) sessionAlive() bool {
	h.t.Helper()
	var n int
	if err := h.db.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_sessions WHERE session_token = $1`, h.token).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n > 0
}

// --- message construction -------------------------------------------------

func authnRequestXML(id, issuer, acs string) string {
	acsAttr := ""
	if acs != "" {
		acsAttr = ` AssertionConsumerServiceURL="` + acs + `"`
	}
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="` + id + `" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"` + acsAttr + `>` +
		`<saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
}

func logoutRequestXML(id, issuer, destination string, issued time.Time, notOnOrAfter, nameID, sessionIndex string) string {
	extra := ""
	if destination != "" {
		extra += ` Destination="` + destination + `"`
	}
	if notOnOrAfter != "" {
		extra += ` NotOnOrAfter="` + notOnOrAfter + `"`
	}
	x := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="` + id + `" Version="2.0" IssueInstant="` + issued.UTC().Format(time.RFC3339) + `"` + extra + `>` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` +
		`<saml:NameID Format="` + NameIDFormatEmail + `">` + nameID + `</saml:NameID>`
	if sessionIndex != "" {
		x += `<samlp:SessionIndex>` + sessionIndex + `</samlp:SessionIndex>`
	}
	return x + `</samlp:LogoutRequest>`
}

// redirectQuery encodes msg for the HTTP-Redirect binding and, when key is
// non-nil, signs it the way SAML Bindings 3.4.4.1 says.
func redirectQuery(t *testing.T, param, msg, relay string, key *rsa.PrivateKey) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(msg))
	_ = w.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if key == nil {
		return q
	}
	q += "&SigAlg=" + url.QueryEscape(samlRedirectSigAlg)
	digest := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// signEmbedded returns msg with an enveloped signature on its root, as a
// service provider signs a POST-binding message.
func signEmbedded(t *testing.T, msg string, key samlTestKey) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(msg); err != nil {
		t.Fatal(err)
	}
	ctx, err := dsig.NewSigningContext(key.priv, [][]byte{key.certDER})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, err := out.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func samlPostForm(param, msg, relay string) url.Values {
	v := url.Values{param: {base64.StdEncoding.EncodeToString([]byte(msg))}}
	if relay != "" {
		v.Set("RelayState", relay)
	}
	return v
}

var autoPostRE = regexp.MustCompile(`action="([^"]*)"[\s\S]*name="SAMLResponse" value="([^"]*)"[\s\S]*name="RelayState" value="([^"]*)"`)

// autoPost reads the auto-submitting form the IdP answers a sign-on with.
func autoPost(t *testing.T, w *httptest.ResponseRecorder) (action string, response *etree.Document, relay string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("sign-on answered %d, want the auto-post form: %s", w.Code, w.Body.String())
	}
	m := autoPostRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no SAMLResponse form in: %s", w.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[2]))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("the Response is not XML: %v", err)
	}
	return html.UnescapeString(m[1]), doc, html.UnescapeString(m[3])
}

// decryptAssertion opens an EncryptedAssertion with the SP's key: RSA-OAEP
// for the content key, AES-GCM (nonce || ciphertext || tag) for the data.
func decryptAssertion(t *testing.T, enc *etree.Element, key *rsa.PrivateKey) *etree.Element {
	t.Helper()
	data := enc.FindElement("./EncryptedData")
	if data == nil {
		t.Fatal("EncryptedAssertion carries no EncryptedData")
	}
	if alg := data.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""); alg != xmlEncAES256GCM {
		t.Fatalf("data encryption algorithm %q, want %q", alg, xmlEncAES256GCM)
	}
	ek := data.FindElement("./KeyInfo/EncryptedKey")
	if ek == nil {
		t.Fatal("no EncryptedKey in the EncryptedData's KeyInfo")
	}
	if alg := ek.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""); alg != xmlEncRSAOAEPMGF1P {
		t.Fatalf("key transport algorithm %q, want %q", alg, xmlEncRSAOAEPMGF1P)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(ek.FindElement("./CipherData/CipherValue").Text())
	cek, err := rsa.DecryptOAEP(sha1.New(), nil, key, wrapped, nil)
	if err != nil {
		t.Fatalf("the content key does not decrypt with the SP's key: %v", err)
	}
	ct, _ := base64.StdEncoding.DecodeString(data.FindElement("./CipherData/CipherValue").Text())
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, ct[:gcmNonceSize], ct[gcmNonceSize:], nil)
	if err != nil {
		t.Fatalf("the assertion does not decrypt: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plain); err != nil {
		t.Fatalf("the decrypted assertion is not XML on its own: %v", err)
	}
	return doc.Root()
}

// requireSignatureAfterIssuer checks where the SAML schema puts ds:Signature.
func requireSignatureAfterIssuer(t *testing.T, el *etree.Element) {
	t.Helper()
	kids := el.ChildElements()
	if len(kids) < 2 || kids[0].Tag != "Issuer" || kids[1].Tag != "Signature" || kids[1].NamespaceURI() != XMLDSigNamespace {
		t.Fatalf("<%s>: the signature must directly follow the Issuer", el.Tag)
	}
}

// requireSelfContainedNamespaces fails when an element under el uses a
// prefix -- in its name, an attribute name, or an xsi:type value -- that is
// not declared on el or inside it. An assertion is canonicalized and, when
// encrypted, parsed on its own; an undeclared prefix breaks both.
func requireSelfContainedNamespaces(t *testing.T, el *etree.Element) {
	t.Helper()
	var walk func(e *etree.Element, declared map[string]bool)
	walk = func(e *etree.Element, declared map[string]bool) {
		scope := map[string]bool{}
		for k := range declared {
			scope[k] = true
		}
		for _, a := range e.Attr {
			if a.Space == "xmlns" {
				scope[a.Key] = true
			}
		}
		check := func(prefix, where string) {
			if prefix != "" && prefix != "xml" && !scope[prefix] {
				t.Errorf("prefix %q used by %s is not declared within the assertion", prefix, where)
			}
		}
		check(e.Space, "<"+e.FullTag()+">")
		for _, a := range e.Attr {
			if a.Space != "xmlns" {
				check(a.Space, "attribute "+a.FullKey())
			}
			if a.Space == "xsi" && a.Key == "type" {
				if p, _, ok := strings.Cut(a.Value, ":"); ok {
					check(p, "xsi:type value "+a.Value)
				}
			}
		}
		for _, c := range e.ChildElements() {
			walk(c, scope)
		}
	}
	walk(el, map[string]bool{})
}

// --- AuthnRequest ---------------------------------------------------------

func TestSAMLIdPRefusesAuthnRequestsItMustNotAnswer(t *testing.T) {
	h := newSAMLIdPHarness(t)
	open := h.registerSP("open", nil)
	strict := h.registerSP("strict", func(r *CreateSAMLServiceProviderRequest) { r.RequireSignedAuthnRequests = true })
	off := h.registerSP("off", func(r *CreateSAMLServiceProviderRequest) { r.Enabled = boolPtr(false) })
	stranger := newSAMLTestKey(t, "stranger")

	id := func() string { return "_" + uuid.NewString() }
	sso := func(query string) *httptest.ResponseRecorder {
		return h.do(http.MethodGet, "/saml/idp/sso?"+query, nil, true)
	}
	ssoPost := func(msg string) *httptest.ResponseRecorder {
		return h.do(http.MethodPost, "/saml/idp/sso", samlPostForm("SAMLRequest", msg, "rs"), true)
	}

	refused := []struct {
		name string
		resp func() *httptest.ResponseRecorder
		code int
	}{
		{"unknown service provider", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), "https://nobody.example.test", ""), "", nil))
		}, http.StatusBadRequest},
		{"disabled service provider", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), off.entityID, off.acs), "", nil))
		}, http.StatusForbidden},
		{"an ACS URL the service provider did not register", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), open.entityID, "https://attacker.example.test/acs"), "", open.key.priv))
		}, http.StatusBadRequest},
		{"unsigned, redirect binding, signing required", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), strict.entityID, strict.acs), "rs", nil))
		}, http.StatusBadRequest},
		{"unsigned, POST binding, signing required", func() *httptest.ResponseRecorder {
			return ssoPost(authnRequestXML(id(), strict.entityID, strict.acs))
		}, http.StatusBadRequest},
		{"redirect binding signed by another key", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), strict.entityID, strict.acs), "rs", stranger.priv))
		}, http.StatusBadRequest},
		{"POST binding signed by another key", func() *httptest.ResponseRecorder {
			return ssoPost(signEmbedded(t, authnRequestXML(id(), strict.entityID, strict.acs), stranger))
		}, http.StatusBadRequest},
		{"redirect binding altered after signing", func() *httptest.ResponseRecorder {
			q := redirectQuery(t, "SAMLRequest", authnRequestXML(id(), strict.entityID, strict.acs), "rs", strict.key.priv)
			return sso(strings.Replace(q, "RelayState=rs", "RelayState=rt", 1))
		}, http.StatusBadRequest},
		{"POST binding altered after signing", func() *httptest.ResponseRecorder {
			signed := signEmbedded(t, authnRequestXML(id(), strict.entityID, ""), strict.key)
			return ssoPost(strings.Replace(signed, `Version="2.0"`, `Version="2.0" ForceAuthn="true"`, 1))
		}, http.StatusBadRequest},
		{"a bad signature is refused where signing is optional", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), open.entityID, open.acs), "", stranger.priv))
		}, http.StatusBadRequest},
		{"an unsupported SigAlg", func() *httptest.ResponseRecorder {
			q := redirectQuery(t, "SAMLRequest", authnRequestXML(id(), strict.entityID, strict.acs), "", strict.key.priv)
			return sso(strings.Replace(q, url.QueryEscape(samlRedirectSigAlg), url.QueryEscape("http://www.w3.org/2000/09/xmldsig#dsa-sha1"), 1))
		}, http.StatusBadRequest},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			w := tc.resp()
			if w.Code != tc.code {
				t.Fatalf("answered %d, want %d: %s", w.Code, tc.code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "SAMLResponse") {
				t.Fatal("a refused request produced a SAML Response")
			}
		})
	}

	accepted := []struct {
		name string
		resp func() *httptest.ResponseRecorder
		sp   samlTestSP
	}{
		{"signed, redirect binding", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), strict.entityID, strict.acs), "rs", strict.key.priv))
		}, strict},
		{"signed, POST binding", func() *httptest.ResponseRecorder {
			return ssoPost(signEmbedded(t, authnRequestXML(id(), strict.entityID, strict.acs), strict.key))
		}, strict},
		{"unsigned where signing is optional", func() *httptest.ResponseRecorder {
			return sso(redirectQuery(t, "SAMLRequest", authnRequestXML(id(), open.entityID, ""), "rs", nil))
		}, open},
	}
	for _, tc := range accepted {
		t.Run("answered: "+tc.name, func(t *testing.T) {
			action, _, _ := autoPost(t, tc.resp())
			if action != tc.sp.acs {
				t.Fatalf("the Response goes to %q, want the registered ACS %q", action, tc.sp.acs)
			}
		})
	}
}

// --- the Response the IdP issues -------------------------------------------

func TestSAMLIdPResponsesAreSignedAndEncryptedAsRegistered(t *testing.T) {
	h := newSAMLIdPHarness(t)
	plain := h.registerSP("plain", nil)
	sealed := h.registerSP("sealed", func(r *CreateSAMLServiceProviderRequest) { r.EncryptionEnabled = true })
	encKey := newSAMLTestKey(t, "sealed-enc")
	split := h.registerSP("split", func(r *CreateSAMLServiceProviderRequest) {
		r.EncryptionEnabled = true
		r.EncryptionCertificate = encKey.certB64()
	})
	broken := h.registerSP("broken", func(r *CreateSAMLServiceProviderRequest) {
		r.EncryptionEnabled = true
		r.EncryptionCertificate = "not a certificate"
	})

	signOn := func(sp samlTestSP, reqID string) *httptest.ResponseRecorder {
		return h.do(http.MethodGet, "/saml/idp/sso?"+redirectQuery(t, "SAMLRequest",
			authnRequestXML(reqID, sp.entityID, sp.acs), "relay-1", nil), nil, true)
	}
	verifyWithIdP := func(el *etree.Element) error {
		return verifyEnvelopedRootSignature(el, h.idp.cert)
	}

	t.Run("signed Response around a signed Assertion", func(t *testing.T) {
		action, doc, relay := autoPost(t, signOn(plain, "_req-plain"))
		if action != plain.acs || relay != "relay-1" {
			t.Fatalf("form posts to %q with RelayState %q", action, relay)
		}
		root := doc.Root()
		if err := verifyWithIdP(root); err != nil {
			t.Fatalf("the Response signature does not verify with the IdP certificate: %v", err)
		}
		requireSignatureAfterIssuer(t, root)
		assertion := findAssertionElement(root)
		if assertion == nil {
			t.Fatal("no Assertion")
		}
		if err := verifyWithIdP(assertion); err != nil {
			t.Fatalf("the Assertion signature does not verify with the IdP certificate: %v", err)
		}
		requireSignatureAfterIssuer(t, assertion)
		requireSelfContainedNamespaces(t, assertion)
		if got := root.SelectAttrValue("InResponseTo", ""); got != "_req-plain" {
			t.Fatalf("InResponseTo = %q", got)
		}
		if got := assertion.FindElement(".//Audience").Text(); got != plain.entityID {
			t.Fatalf("Audience = %q, want %q", got, plain.entityID)
		}
		if got := assertion.FindElement(".//NameID").Text(); got != h.email {
			t.Fatalf("NameID = %q, want %q", got, h.email)
		}

		// Tampering with either signed part is detected.
		assertion.FindElement(".//NameID").SetText("mallory@example.test")
		if verifyWithIdP(assertion) == nil || verifyWithIdP(root) == nil {
			t.Fatal("an altered NameID still verified")
		}
	})

	for _, tc := range []struct {
		name string
		sp   samlTestSP
		key  *rsa.PrivateKey
	}{
		{"encrypted to the one certificate the SP registered", sealed, sealed.key.priv},
		{"encrypted to the SP's separate encryption certificate", split, encKey.priv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, doc, _ := autoPost(t, signOn(tc.sp, "_req-enc"))
			root := doc.Root()
			if findAssertionElement(root) != nil {
				t.Fatal("a plaintext Assertion was sent to an SP that asked for encryption")
			}
			if err := verifyWithIdP(root); err != nil {
				t.Fatalf("the Response signature over the EncryptedAssertion does not verify: %v", err)
			}
			enc := root.FindElement("./EncryptedAssertion")
			if enc == nil {
				t.Fatal("no EncryptedAssertion")
			}
			assertion := decryptAssertion(t, enc, tc.key)
			if err := verifyWithIdP(assertion); err != nil {
				t.Fatalf("the decrypted Assertion's signature does not verify: %v", err)
			}
			requireSelfContainedNamespaces(t, assertion)
			if got := assertion.FindElement(".//Audience").Text(); got != tc.sp.entityID {
				t.Fatalf("Audience = %q", got)
			}
		})
	}

	t.Run("encryption that cannot be done is refused, never downgraded", func(t *testing.T) {
		w := signOn(broken, "_req-broken")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "SAMLResponse") {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a Response is never built without a signature", func(t *testing.T) {
		b := h.svc.NewSAMLResponseBuilder()
		b.signAssertion, b.signResponse = false, false
		b.SetRequest("_r", plain.acs)
		b.SetAudience(plain.entityID)
		b.SetSubject("x@example.test", NameIDFormatEmail)
		if _, err := b.Build(); err == nil {
			t.Fatal("Build produced a response with no signature")
		}
	})
}

func TestSAMLIdPInitiatedSSO(t *testing.T) {
	h := newSAMLIdPHarness(t)
	sp := h.registerSP("unsolicited", nil)
	off := h.registerSP("unsolicited-off", func(r *CreateSAMLServiceProviderRequest) { r.Enabled = boolPtr(false) })

	target := "/saml/idp/sso/unsolicited?" + url.Values{
		"sp_entity_id": {sp.entityID}, "RelayState": {"https://unsolicited.sp.example.test/app"}}.Encode()
	action, doc, relay := autoPost(t, h.do(http.MethodGet, target, nil, true))
	if action != sp.acs || relay != "https://unsolicited.sp.example.test/app" {
		t.Fatalf("posted to %q with RelayState %q", action, relay)
	}
	root := doc.Root()
	if err := verifyEnvelopedRootSignature(root, h.idp.cert); err != nil {
		t.Fatal(err)
	}
	// Unsolicited: no InResponseTo anywhere, which is how an SP tells.
	if root.SelectAttr("InResponseTo") != nil {
		t.Fatal("an unsolicited Response carries InResponseTo")
	}
	scd := root.FindElement(".//SubjectConfirmationData")
	if scd.SelectAttr("InResponseTo") != nil || scd.SelectAttrValue("Recipient", "") != sp.acs {
		t.Fatalf("SubjectConfirmationData is not an unsolicited one for %s", sp.acs)
	}

	for name, tc := range map[string]struct {
		target  string
		session bool
		code    int
	}{
		"unknown SP":      {"/saml/idp/sso/unsolicited?sp_entity_id=https%3A%2F%2Fnobody", true, http.StatusNotFound},
		"disabled SP":     {"/saml/idp/sso/unsolicited?sp_entity_id=" + url.QueryEscape(off.entityID), true, http.StatusForbidden},
		"no SP named":     {"/saml/idp/sso/unsolicited", true, http.StatusBadRequest},
		"no user session": {target, false, http.StatusFound},
	} {
		t.Run(name, func(t *testing.T) {
			w := h.do(http.MethodGet, tc.target, nil, tc.session)
			if w.Code != tc.code || strings.Contains(w.Body.String(), "SAMLResponse") {
				t.Fatalf("answered %d, want %d: %s", w.Code, tc.code, w.Body.String())
			}
		})
	}
}

// --- LogoutRequest --------------------------------------------------------

func TestSAMLIdPRefusesLogoutRequestsItCannotTrust(t *testing.T) {
	h := newSAMLIdPHarness(t)
	sp := h.registerSP("slo", nil)
	stranger := newSAMLTestKey(t, "stranger")
	dest := samlTestIssuer + "/saml/idp/slo"

	// Sign on first, so there is a SAML session for the SP to end.
	_, doc, _ := autoPost(t, h.do(http.MethodGet, "/saml/idp/sso?"+redirectQuery(t, "SAMLRequest",
		authnRequestXML("_req-slo", sp.entityID, sp.acs), "", nil), nil, true))
	sessionIndex := doc.Root().FindElement(".//AuthnStatement").SelectAttrValue("SessionIndex", "")
	if sessionIndex == "" {
		t.Fatal("the assertion carries no SessionIndex")
	}

	now := time.Now()
	msg := func(id, destination string, issued time.Time, notOnOrAfter string) string {
		return logoutRequestXML(id, sp.entityID, destination, issued, notOnOrAfter, h.email, sessionIndex)
	}
	slo := func(q string) *httptest.ResponseRecorder { return h.do(http.MethodGet, "/saml/idp/slo?"+q, nil, false) }

	for _, tc := range []struct {
		name string
		resp func() *httptest.ResponseRecorder
	}{
		{"unsigned, redirect binding", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_u1", dest, now, ""), "", nil))
		}},
		{"unsigned, POST binding", func() *httptest.ResponseRecorder {
			return h.do(http.MethodPost, "/saml/idp/slo", samlPostForm("SAMLRequest", msg("_u2", dest, now, ""), ""), false)
		}},
		{"signed by another key, redirect binding", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_w1", dest, now, ""), "", stranger.priv))
		}},
		{"signed by another key, POST binding", func() *httptest.ResponseRecorder {
			return h.do(http.MethodPost, "/saml/idp/slo", samlPostForm("SAMLRequest", signEmbedded(t, msg("_w2", dest, now, ""), stranger), ""), false)
		}},
		{"addressed to another endpoint", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_d1", "https://other.example.test/saml/idp/slo", now, ""), "", sp.key.priv))
		}},
		{"issued too long ago", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_e1", dest, now.Add(-30*time.Minute), ""), "", sp.key.priv))
		}},
		{"past its NotOnOrAfter", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_e2", dest, now, now.Add(-10*time.Minute).UTC().Format(time.RFC3339)), "", sp.key.priv))
		}},
		{"issued in the future", func() *httptest.ResponseRecorder {
			return slo(redirectQuery(t, "SAMLRequest", msg("_e3", dest, now.Add(30*time.Minute), ""), "", sp.key.priv))
		}},
		{"from an unknown SP", func() *httptest.ResponseRecorder {
			x := logoutRequestXML("_n1", "https://nobody.example.test", dest, now, "", h.email, sessionIndex)
			return slo(redirectQuery(t, "SAMLRequest", x, "", sp.key.priv))
		}},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			w := tc.resp()
			if w.Code < 400 {
				t.Fatalf("answered %d: %s", w.Code, w.Body.String())
			}
			if !h.sessionAlive() {
				t.Fatal("a refused LogoutRequest ended the session")
			}
		})
	}

	valid := redirectQuery(t, "SAMLRequest", msg("_ok", dest, now, now.Add(5*time.Minute).UTC().Format(time.RFC3339)), "relay-9", sp.key.priv)
	t.Run("a valid signed request ends the session and is answered, signed", func(t *testing.T) {
		w := slo(valid)
		if w.Code != http.StatusFound {
			t.Fatalf("answered %d: %s", w.Code, w.Body.String())
		}
		if h.sessionAlive() {
			t.Fatal("the session survived a valid LogoutRequest")
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil || !strings.HasPrefix(loc.String(), sp.slo+"?") {
			t.Fatalf("the LogoutResponse goes to %q, want the SP's SLO URL", w.Header().Get("Location"))
		}
		if loc.Query().Get("RelayState") != "relay-9" {
			t.Fatalf("RelayState %q not returned", loc.Query().Get("RelayState"))
		}
		if err := verifyRedirectBindingSignature(loc.RawQuery, "SAMLResponse", h.idp.cert); err != nil {
			t.Fatalf("the LogoutResponse signature does not verify with the IdP certificate: %v", err)
		}
		raw, _ := inflateAndDecode(loc.Query().Get("SAMLResponse"))
		resp := etree.NewDocument()
		if err := resp.ReadFromBytes(raw); err != nil {
			t.Fatal(err)
		}
		code := resp.Root().FindElement("./Status/StatusCode")
		if code == nil || code.NamespaceURI() != SAMLProtocolNamespace || code.SelectAttrValue("Value", "") != SAMLLogoutStatusSuccess {
			t.Fatalf("LogoutResponse status is not a samlp:StatusCode Success: %s", raw)
		}
		if resp.Root().SelectAttrValue("InResponseTo", "") != "_ok" {
			t.Fatal("InResponseTo does not name the request")
		}
	})

	t.Run("refused: the same request replayed", func(t *testing.T) {
		if _, err := h.db.Pool.Exec(context.Background(), `
			INSERT INTO user_sessions (user_id, session_token, expires_at, org_id)
			VALUES ($1, $2, NOW() + interval '1 hour', $3)`, h.userID, h.token, samlTestOrg); err != nil {
			t.Fatal(err)
		}
		w := slo(valid)
		if w.Code < 400 {
			t.Fatalf("a replayed LogoutRequest answered %d", w.Code)
		}
		if !h.sessionAlive() {
			t.Fatal("a replayed LogoutRequest ended the new session")
		}
	})
}

func TestCheckLogoutRequestFreshness(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	f := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, tc := range []struct {
		issued, notOnOrAfter string
		ok                   bool
	}{
		{f(0), "", true},
		{f(-7 * time.Minute), "", true}, // within max age plus skew
		{f(-9 * time.Minute), "", false},
		{f(2 * time.Minute), "", true}, // clock skew
		{f(4 * time.Minute), "", false},
		{f(0), f(time.Minute), true},
		{f(0), f(-4 * time.Minute), false},
		{"yesterday", "", false},
	} {
		err := checkLogoutRequestFreshness(tc.issued, tc.notOnOrAfter, now)
		if (err == nil) != tc.ok {
			t.Errorf("issued %s notOnOrAfter %q: err=%v, want ok=%v", tc.issued, tc.notOnOrAfter, err, tc.ok)
		}
	}
}

// Service provider metadata as SimpleSAMLphp 2.5 and Keycloak 26 publish it.
// The parser used to name the md: prefix in its struct tags, which
// encoding/xml never matches, so importing any real metadata failed.
func TestParseServiceProviderMetadataFromIndependentSPs(t *testing.T) {
	signCert := newSAMLTestKey(t, "sign").certB64()
	encCert := newSAMLTestKey(t, "enc").certB64()
	keyDesc := func(use, cert string) string {
		u := ""
		if use != "" {
			u = ` use="` + use + `"`
		}
		return `<md:KeyDescriptor` + u + `><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>
` + cert + `
</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	}
	ssp := `<?xml version="1.0" encoding="utf-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:ssp">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">` +
		keyDesc("signing", signCert) + keyDesc("encryption", signCert) + `
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://ssp/slo"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://ssp/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`
	keycloak := `<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://kc/realms/r">
<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="true">` +
		keyDesc("signing", signCert) + keyDesc("encryption", encCert) + `
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://kc/post-slo"></md:SingleLogoutService>
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://kc/slo"></md:SingleLogoutService>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://kc/redirect-acs" isDefault="true" index="1"></md:AssertionConsumerService>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://kc/acs" index="2"></md:AssertionConsumerService>
</md:SPSSODescriptor></md:EntityDescriptor>`

	for _, tc := range []struct {
		name, doc, entity, acs, slo, enc string
		signed                           bool
	}{
		{"SimpleSAMLphp", ssp, "urn:ssp", "https://ssp/acs", "https://ssp/slo", "", true},
		{"Keycloak", keycloak, "https://kc/realms/r", "https://kc/acs", "https://kc/slo", encCert, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &CreateSAMLServiceProviderRequest{MetadataXML: tc.doc}
			if err := (&Service{}).parseMetadataIntoRequest(req); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if req.EntityID != tc.entity || req.ACSURL != tc.acs || req.SLOURL != tc.slo {
				t.Fatalf("entity %q acs %q slo %q", req.EntityID, req.ACSURL, req.SLOURL)
			}
			if req.Certificate != signCert || req.EncryptionCertificate != tc.enc {
				t.Fatalf("certificates not taken by use: signing ok=%v, encryption %q", req.Certificate == signCert, req.EncryptionCertificate)
			}
			if req.RequireSignedAuthnRequests != tc.signed || !req.WantAssertionsSigned {
				t.Fatalf("require signed %v, want assertions signed %v", req.RequireSignedAuthnRequests, req.WantAssertionsSigned)
			}
		})
	}
	_ = fmt.Sprint
}
