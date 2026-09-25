//go:build samlinterop

package saml_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The negative controls. OpenIDX consumes no assertions -- it is only an
// identity provider -- so "an unsigned, wrongly signed, wrong-audience,
// expired or replayed assertion must be refused" is a property of the
// service providers here, and these controls establish it: each takes a
// genuine Response the IdP issued, turns it into one of the five, and posts
// it to the service provider, which must refuse it. That is what makes the
// positive runs mean something. A service provider that accepted any of
// these would accept a broken OpenIDX Response too.

const (
	dsigNS = "http://www.w3.org/2000/09/xmldsig#"
)

type forgery struct {
	name string
	make func(t *testing.T, genuine string) string
}

// strangerKey is a key no service provider trusts.
func strangerKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err, "generate key")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stranger"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err, "create certificate")
	return key, der
}

func parseResponseDoc(t *testing.T, b64 string) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	must(t, doc.ReadFromString(decodeMessage(t, b64)), "parse Response")
	return doc
}

func encodeDoc(t *testing.T, doc *etree.Document) string {
	t.Helper()
	s, err := doc.WriteToString()
	must(t, err, "serialize Response")
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func assertionOf(t *testing.T, doc *etree.Document) *etree.Element {
	t.Helper()
	a := doc.Root().FindElement("./Assertion")
	if a == nil {
		t.Fatal("the genuine Response carries no plaintext Assertion; forge from an unencrypted profile")
	}
	return a
}

func stripSignatures(el *etree.Element) {
	for _, c := range el.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == dsigNS {
			el.RemoveChild(c)
		}
	}
}

// resign signs the assertion and then the Response with key, placing each
// signature after the Issuer, as a real signer would.
func resign(t *testing.T, doc *etree.Document, key *rsa.PrivateKey, certDER []byte) {
	t.Helper()
	root := doc.Root()
	assertion := assertionOf(t, doc)
	stripSignatures(assertion)
	stripSignatures(root)
	ctx, err := dsig.NewSigningContext(key, [][]byte{certDER})
	must(t, err, "signing context")
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	for _, el := range []*etree.Element{assertion, root} {
		sig, err := ctx.ConstructSignature(el.Copy(), true)
		must(t, err, "sign %s", el.Tag)
		idx := 0
		if iss := el.FindElement("./Issuer"); iss != nil {
			idx = iss.Index() + 1
		}
		el.InsertChildAt(idx, sig)
	}
}

// forgeries are four of the five the issue lists; each changes one thing.
// The fifth, a replay, is the genuine Response posted a second time.
func (h *idp) forgeries(t *testing.T) []forgery {
	strangerPriv, strangerCert := strangerKey(t)
	return []forgery{
		{"unsigned assertion and response", func(t *testing.T, genuine string) string {
			doc := parseResponseDoc(t, genuine)
			stripSignatures(assertionOf(t, doc))
			stripSignatures(doc.Root())
			return encodeDoc(t, doc)
		}},
		{"signed by a key the SP does not trust", func(t *testing.T, genuine string) string {
			doc := parseResponseDoc(t, genuine)
			resign(t, doc, strangerPriv, strangerCert)
			return encodeDoc(t, doc)
		}},
		{"validly signed, for another audience", func(t *testing.T, genuine string) string {
			doc := parseResponseDoc(t, genuine)
			assertionOf(t, doc).FindElement(".//Conditions/AudienceRestriction/Audience").SetText("https://another-sp.example.test")
			resign(t, doc, h.key, h.certDER)
			return encodeDoc(t, doc)
		}},
		{"validly signed, expired", func(t *testing.T, genuine string) string {
			doc := parseResponseDoc(t, genuine)
			past := func(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }
			a := assertionOf(t, doc)
			doc.Root().CreateAttr("IssueInstant", past(30*time.Minute))
			a.CreateAttr("IssueInstant", past(30*time.Minute))
			cond := a.FindElement(".//Conditions")
			cond.CreateAttr("NotBefore", past(40*time.Minute))
			cond.CreateAttr("NotOnOrAfter", past(20*time.Minute))
			a.FindElement(".//SubjectConfirmationData").CreateAttr("NotOnOrAfter", past(20*time.Minute))
			a.FindElement(".//AuthnStatement").CreateAttr("AuthnInstant", past(30*time.Minute))
			resign(t, doc, h.key, h.certDER)
			return encodeDoc(t, doc)
		}},
	}
}
