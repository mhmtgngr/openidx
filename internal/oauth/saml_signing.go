// Package oauth - Standards-compliant SAML 2.0 XML-DSig signing and verification.
//
// The earlier implementation hand-built the <ds:Signature> with string
// concatenation: it signed a SHA-256 digest of the raw assertion instead of the
// canonicalized SignedInfo, applied no XML canonicalization, and inserted the
// signature after digesting — so no compliant SP could validate it. It also
// published a bare PKIX public key in place of an X.509 certificate and never
// verified inbound signatures.
//
// This file replaces all of that with github.com/russellhaering/goxmldsig
// (exclusive canonicalization, enveloped-signature transform, RSA-SHA256) over a
// real self-signed X.509 certificate derived from the OAuth signing key.
package oauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlCertValidity is how long the generated self-signed IdP certificate is valid.
const samlCertValidity = 10 * 365 * 24 * time.Hour

// samlCertCache memoizes the self-signed certificate per signing key so we mint
// one cert per key (and regenerate automatically after a key rotation), instead
// of on every request.
type samlCertCache struct {
	mu      sync.Mutex
	forKey  *rsa.PublicKey
	certDER []byte
}

var samlCerts = &samlCertCache{}

// samlCertificate returns a DER-encoded self-signed X.509 certificate for the
// given RSA signing key, generating and caching it on first use (and whenever the
// key changes).
func samlCertificate(issuer string, priv *rsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("no SAML signing key configured")
	}

	samlCerts.mu.Lock()
	defer samlCerts.mu.Unlock()

	if samlCerts.certDER != nil && samlCerts.forKey != nil && samlCerts.forKey.Equal(&priv.PublicKey) {
		return samlCerts.certDER, nil
	}

	// Deterministic-enough serial; uniqueness matters more than randomness here.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   issuer,
			Organization: []string{"OpenIDX"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(samlCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create SAML certificate: %w", err)
	}

	samlCerts.forKey = &priv.PublicKey
	samlCerts.certDER = der
	return der, nil
}

// samlKeyStore adapts the OAuth signing key + generated cert to goxmldsig's
// X509KeyStore interface.
type samlKeyStore struct {
	priv    *rsa.PrivateKey
	certDER []byte
}

func (k *samlKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.priv, k.certDER, nil
}

// signAssertionEnveloped parses the response XML, signs the <saml:Assertion>
// element in place with a compliant enveloped RSA-SHA256 signature, and returns
// the re-serialized document.
func (s *Service) signAssertionEnveloped(responseXML []byte) (string, error) {
	if s.privateKey == nil {
		return "", fmt.Errorf("no SAML signing key configured")
	}

	certDER, err := samlCertificate(s.issuer, s.privateKey)
	if err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(responseXML); err != nil {
		return "", fmt.Errorf("parse SAML response: %w", err)
	}

	assertion := findAssertionElement(doc.Root())
	if assertion == nil {
		return "", fmt.Errorf("no Assertion element found to sign")
	}

	ctx := &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      &samlKeyStore{priv: s.privateKey, certDER: certDER},
		IdAttribute:   "ID",
		Prefix:        "ds",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	signed, err := ctx.SignEnveloped(assertion)
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

	// Replace the unsigned assertion with the signed one in the document tree,
	// preserving its position (an Assertion must follow Issuer/Status in a
	// Response). goxmldsig returns a signed copy, so swap it in at the same index.
	parent := assertion.Parent()
	if parent == nil {
		// Assertion is the root; emit it directly.
		out := etree.NewDocument()
		out.SetRoot(signed)
		str, serr := out.WriteToString()
		if serr != nil {
			return "", serr
		}
		return str, nil
	}
	idx := assertion.Index()
	parent.RemoveChildAt(idx)
	parent.InsertChildAt(idx, signed)

	str, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("serialize signed response: %w", err)
	}
	return str, nil
}

// findAssertionElement locates the first saml:Assertion element in the tree.
func findAssertionElement(el *etree.Element) *etree.Element {
	if el == nil {
		return nil
	}
	if el.Tag == "Assertion" {
		return el
	}
	for _, child := range el.ChildElements() {
		if found := findAssertionElement(child); found != nil {
			return found
		}
	}
	return nil
}

// samlSigningCertBase64 returns the base64 DER of the IdP's real X.509 signing
// certificate, for publication in IdP metadata (<ds:X509Certificate>).
func (s *Service) samlSigningCertBase64() (string, error) {
	certDER, err := samlCertificate(s.issuer, s.privateKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(certDER), nil
}

// verifySAMLSignature validates an enveloped XML-DSig signature on inbound SAML
// (e.g. an SP's signed AuthnRequest or LogoutRequest) against the SP's registered
// X.509 certificate (base64 DER, as stored from SP metadata).
func verifySAMLSignature(signedXML []byte, spCertBase64 string) error {
	if spCertBase64 == "" {
		return fmt.Errorf("no SP certificate on file to verify signature")
	}
	certDER, err := base64.StdEncoding.DecodeString(normalizeBase64Cert(spCertBase64))
	if err != nil {
		return fmt.Errorf("decode SP certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse SP certificate: %w", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signedXML); err != nil {
		return fmt.Errorf("parse inbound SAML: %w", err)
	}

	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	ctx.IdAttribute = "ID"

	// The signature may sit on the root (signed AuthnRequest) or on a nested
	// element (a signed Assertion inside a Response). Validate the element that
	// directly carries the <Signature> child.
	target := findSignedElement(doc.Root())
	if target == nil {
		return fmt.Errorf("no signature element found in inbound SAML")
	}

	if _, err := ctx.Validate(target); err != nil {
		return fmt.Errorf("SAML signature validation failed: %w", err)
	}
	return nil
}

// findSignedElement returns the first element that has a direct <Signature>
// child (the element an enveloped signature covers).
func findSignedElement(el *etree.Element) *etree.Element {
	if el == nil {
		return nil
	}
	for _, child := range el.ChildElements() {
		if child.Tag == "Signature" {
			return el
		}
	}
	for _, child := range el.ChildElements() {
		if found := findSignedElement(child); found != nil {
			return found
		}
	}
	return nil
}

// normalizeBase64Cert strips PEM armor and whitespace so a stored certificate
// (however it was captured from SP metadata) decodes as raw base64 DER.
func normalizeBase64Cert(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-----BEGIN CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "-----END CERTIFICATE-----", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}
