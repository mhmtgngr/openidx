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
	"net/url"
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

// samlSigningContext returns a goxmldsig signing context over the active
// signing key and the certificate published for it. Read once per message:
// the certificate and the key must be the same key even if a rotation lands
// between two signatures of one response.
func (s *Service) samlSigningContext() (*dsig.SigningContext, error) {
	priv := s.activePrivateKey()
	if priv == nil {
		return nil, fmt.Errorf("no SAML signing key configured")
	}
	certDER, err := samlCertificate(s.issuer, priv)
	if err != nil {
		return nil, err
	}
	return &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      &samlKeyStore{priv: priv, certDER: certDER},
		IdAttribute:   "ID",
		Prefix:        "ds",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}, nil
}

// signEnvelopedInPlace signs el with an enveloped signature and inserts the
// <ds:Signature> where the SAML schema puts it: directly after the element's
// <Issuer>, or first when there is none. goxmldsig's SignEnveloped appends the
// signature as the LAST child, which schema-validating service providers
// refuse. The digest does not depend on the position, because the
// enveloped-signature transform removes the signature before digesting.
//
// The signature is computed over a COPY. goxmldsig's exclusive
// canonicalization rewrites the element it digests in place, and exclusive
// canonicalization drops every namespace declaration that no element or
// attribute name uses -- including xmlns:xs, which only the xsi:type VALUE
// "xs:string" refers to. Signing el itself therefore sent assertions whose
// attribute types named an undeclared prefix. The digest of the copy is the
// digest of el, because canonicalization depends on the infoset and el
// declares every prefix it uses itself.
func signEnvelopedInPlace(ctx *dsig.SigningContext, el *etree.Element) error {
	sig, err := ctx.ConstructSignature(el.Copy(), true)
	if err != nil {
		return err
	}
	idx := 0
	for _, child := range el.ChildElements() {
		if child.Tag == "Issuer" {
			idx = child.Index() + 1
			break
		}
	}
	el.InsertChildAt(idx, sig)
	return nil
}

// signAssertionEnveloped parses the response XML, signs the <saml:Assertion>
// element in place with a compliant enveloped RSA-SHA256 signature, and returns
// the re-serialized document.
func (s *Service) signAssertionEnveloped(responseXML []byte) (string, error) {
	ctx, err := s.samlSigningContext()
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
	if err := signEnvelopedInPlace(ctx, assertion); err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

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
	certDER, err := samlCertificate(s.issuer, s.activePrivateKey())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(certDER), nil
}

// parseSAMLCertificate decodes a certificate as it is stored from service
// provider metadata: base64 DER, with or without PEM armor and whitespace.
func parseSAMLCertificate(stored string) (*x509.Certificate, error) {
	if strings.TrimSpace(stored) == "" {
		return nil, fmt.Errorf("no certificate on file")
	}
	der, err := base64.StdEncoding.DecodeString(normalizeBase64Cert(stored))
	if err != nil {
		return nil, fmt.Errorf("decode certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// verifyEnvelopedRootSignature verifies the enveloped XML-DSig signature that
// covers root itself (a signed AuthnRequest or LogoutRequest) against cert.
//
// Two things about it are deliberate. The ROOT is what is verified, because the
// root is what the handler reads: a signature over some nested element proves
// nothing about the values the IdP acts on. And any KeyInfo the message carries
// is removed first, so the only key that can make it verify is the one
// registered for the service provider; a message that names its own
// certificate does not get to choose who it is trusted as.
func verifyEnvelopedRootSignature(root *etree.Element, cert *x509.Certificate) error {
	if root == nil {
		return fmt.Errorf("empty message")
	}
	el := root.Copy()
	for _, sig := range el.ChildElements() {
		if sig.Tag != "Signature" || sig.NamespaceURI() != XMLDSigNamespace {
			continue
		}
		for _, child := range sig.ChildElements() {
			if child.Tag == "KeyInfo" {
				sig.RemoveChild(child)
			}
		}
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	ctx.IdAttribute = "ID"
	if _, err := ctx.Validate(el); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}
	return nil
}

// hasEnvelopedSignature reports whether root carries an XML-DSig <Signature>
// as a direct child, by element and namespace rather than by searching the
// text for "<ds:Signature" (which a signature under any other prefix defeats).
func hasEnvelopedSignature(root *etree.Element) bool {
	if root == nil {
		return false
	}
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == XMLDSigNamespace {
			return true
		}
	}
	return false
}

// redirectSignatureAlgorithms maps the SigAlg URIs of the HTTP-Redirect binding
// to the x509 algorithm that checks them. It is the set the POST binding
// accepts: goxmldsig verifies embedded signatures through the same
// Certificate.CheckSignature, which still accepts RSA-SHA1. Anything else is
// refused by name.
var redirectSignatureAlgorithms = map[string]x509.SignatureAlgorithm{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        x509.SHA1WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": x509.SHA256WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": x509.SHA384WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": x509.SHA512WithRSA,
}

// verifyRedirectBindingSignature verifies the detached signature of an
// HTTP-Redirect binding message (SAML Bindings 3.4.4.1). The signed octets are
// the message, RelayState and SigAlg parameters exactly as they appear in the
// received query string, in that order: re-encoding them would change the
// bytes and reject every correctly signed message from a sender that encodes
// differently.
func verifyRedirectBindingSignature(rawQuery, messageParam string, cert *x509.Certificate) error {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		key, value, _ := strings.Cut(part, "=")
		switch key {
		case messageParam, "RelayState", "SigAlg", "Signature":
			if _, dup := raw[key]; dup {
				return fmt.Errorf("parameter %s appears more than once", key)
			}
			raw[key] = value
		}
	}
	msg, ok := raw[messageParam]
	if !ok {
		return fmt.Errorf("no %s parameter", messageParam)
	}
	sigAlgRaw, ok := raw["SigAlg"]
	if !ok {
		return fmt.Errorf("signature without SigAlg")
	}
	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return fmt.Errorf("decode SigAlg: %w", err)
	}
	algo, known := redirectSignatureAlgorithms[sigAlg]
	if !known {
		return fmt.Errorf("unsupported signature algorithm %q", sigAlg)
	}
	sigRaw, err := url.QueryUnescape(raw["Signature"])
	if err != nil {
		return fmt.Errorf("decode Signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil {
		return fmt.Errorf("decode Signature: %w", err)
	}

	signed := messageParam + "=" + msg
	if relay, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + relay
	}
	signed += "&SigAlg=" + sigAlgRaw

	if err := cert.CheckSignature(algo, []byte(signed), signature); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is not valid at this time")
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
