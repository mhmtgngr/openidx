// Package oauth - XML Encryption of SAML assertions (EncryptedAssertion).
//
// A service provider registered with encryption_enabled receives its assertion
// as <saml:EncryptedAssertion>: the signed <saml:Assertion> is serialized,
// encrypted with a fresh AES-256-GCM key, and that key is encrypted to the
// service provider's encryption certificate with RSA-OAEP (MGF1, SHA-1, the
// rsa-oaep-mgf1p algorithm every SAML stack implements). The assertion is
// signed BEFORE it is encrypted, so the service provider verifies the
// signature on the plaintext it decrypts; a signed Response additionally
// covers the ciphertext.
//
// AES-GCM rather than AES-CBC: CBC in XML Encryption is open to the padding
// oracle Jager and Somorovsky published in 2011, and GCM authenticates the
// ciphertext. SimpleSAMLphp (xmlseclibs), Keycloak and Shibboleth all decrypt
// xmlenc11#aes256-gcm.
package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // the OAEP digest rsa-oaep-mgf1p names; no signature or password is hashed with it
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/google/uuid"
)

// XML Encryption algorithm identifiers.
const (
	XMLEncNamespace       = "http://www.w3.org/2001/04/xmlenc#"
	xmlEncTypeElement     = "http://www.w3.org/2001/04/xmlenc#Element"
	xmlEncAES256GCM       = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	xmlEncRSAOAEPMGF1P    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	xmlDSigDigestSHA1     = "http://www.w3.org/2000/09/xmldsig#sha1"
	samlEncryptionKeySize = 32 // AES-256
	gcmNonceSize          = 12
)

// assertionEncryptionCert returns the certificate assertions to this service
// provider are encrypted to: its encryption certificate, or its signing
// certificate when it registered only one.
func (sp *SAMLServiceProvider) assertionEncryptionCert() (*x509.Certificate, error) {
	stored := sp.EncryptionCertificate
	if stored == "" {
		stored = sp.Certificate
	}
	if stored == "" {
		return nil, fmt.Errorf("service provider %q has encryption enabled but no certificate on file", sp.EntityID)
	}
	cert, err := parseSAMLCertificate(stored)
	if err != nil {
		return nil, fmt.Errorf("service provider %q encryption certificate: %w", sp.EntityID, err)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("service provider %q encryption certificate: only RSA keys are supported", sp.EntityID)
	}
	return cert, nil
}

// encryptAssertionElement returns the <saml:EncryptedAssertion> that carries
// assertion encrypted to cert. The assertion must declare every namespace it
// uses (the builder puts saml, xs and xsi on it, and goxmldsig puts ds on the
// signature), because it is decrypted and parsed outside the Response.
func encryptAssertionElement(assertion *etree.Element, cert *x509.Certificate) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("encryption certificate does not carry an RSA key")
	}

	plain := etree.NewDocument()
	plain.SetRoot(assertion.Copy())
	plaintext, err := plain.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize assertion: %w", err)
	}

	key := make([]byte, samlEncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate content key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// XML Encryption 1.1 §5.2.4: the nonce precedes the ciphertext and the
	// 128-bit tag follows it, which is exactly nonce || Seal(...).
	cipherValue := append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, plaintext, nil)...)

	wrappedKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt content key: %w", err)
	}

	encAssertion := etree.NewElement("saml:EncryptedAssertion")
	encAssertion.CreateAttr("xmlns:saml", SAMLAssertionNamespace)

	encData := encAssertion.CreateElement("xenc:EncryptedData")
	encData.CreateAttr("xmlns:xenc", XMLEncNamespace)
	encData.CreateAttr("Id", "_"+uuid.New().String())
	encData.CreateAttr("Type", xmlEncTypeElement)
	encData.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", xmlEncAES256GCM)

	keyInfo := encData.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr("xmlns:ds", XMLDSigNamespace)
	encKey := keyInfo.CreateElement("xenc:EncryptedKey")
	keyMethod := encKey.CreateElement("xenc:EncryptionMethod")
	keyMethod.CreateAttr("Algorithm", xmlEncRSAOAEPMGF1P)
	keyMethod.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", xmlDSigDigestSHA1)
	encKey.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrappedKey))

	encData.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").
		SetText(base64.StdEncoding.EncodeToString(cipherValue))

	return encAssertion, nil
}
