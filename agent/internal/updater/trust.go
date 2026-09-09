package updater

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// WHO WROTE THE MANIFEST.
//
// The digest in the manifest proves the artifact arrived intact. It cannot
// prove anything about who chose it, because the same document supplies both
// halves: whoever writes the manifest writes the url AND the sha256 that
// matches it. What that buys an attacker is not a corrupted download, it is
// `msiexec /i` under SYSTEM on Windows and `sudo -n dpkg -i` on Linux, on every
// endpoint that polls.
//
// So the manifest is signed, and this file holds the only key that counts.
//
// THE PUBLISHER IS PINNED, NOT DISCOVERED. release-publisher.cer is a byte copy
// of agent/packaging/openidx-codesign.cer — the certificate the release already
// uses for Authenticode on openidx-agent.exe and the MSI, self-signed, with its
// private half held only as the WINDOWS_CERT_PFX_BASE64 secret. There is no
// chain to build and no store to consult: a manifest is trusted when this exact
// key signed it. (The two copies exist because //go:embed cannot read outside
// its own package directory; trust_test.go compares them byte for byte, so they
// cannot drift.)
//
// The Authenticode signature on the MSI is not a substitute. msiexec run by a
// SYSTEM service installs an unsigned package without a word — nothing on the
// apply path ever reads it — and on Linux and macOS there is no Authenticode at
// all. This signature covers the document on every platform, before a byte is
// downloaded.
//
// A ZERO Trust TRUSTS NOBODY. Trust is a required parameter of Fetch and
// CheckAndApply rather than a package-level default, and its zero value
// verifies nothing and therefore refuses everything. A caller that forgets it
// installs nothing; a caller that forgets a default would have installed
// anything.

//go:embed release-publisher.cer
var releasePublisherDER []byte

// Trust is the set of publishers whose manifests this agent will act on.
//
// Empty means empty: no key, no update. Construct it with ReleaseTrust (the
// pinned publisher above) or TrustFromPEM (an operator running their own
// release channel).
type Trust struct {
	certs []*x509.Certificate
	// source names where the anchor came from, for error messages that say
	// which key refused rather than only that some key did.
	source string
}

// ReleaseTrust returns the pinned OpenIDX release publisher.
func ReleaseTrust() Trust {
	c, err := x509.ParseCertificate(releasePublisherDER)
	if err != nil {
		// Unreachable short of a corrupted build: the file is embedded from the
		// repository and parsed by trust_test.go. Returning an empty Trust is
		// the fail-closed answer if it ever happens — no key, no update.
		return Trust{source: "pinned release publisher (unparseable: " + err.Error() + ")"}
	}
	return Trust{certs: []*x509.Certificate{c}, source: "pinned release publisher"}
}

// TrustFromPEM builds a Trust from one or more PEM CERTIFICATE blocks, for an
// operator publishing their own builds to their own manifest URL.
//
// This REPLACES the pinned publisher rather than adding to it: an on-premise
// install that ships its own agent should not also accept upstream's, and a
// reader of agent.json should be able to see the whole answer to "what can
// install software here" in one field.
//
// Setting it is a trust decision, and the file it is read from is the control:
// agent.json lives in the agent's config directory, 0600 inside a 0700 dir on
// Unix and under an owner-only ACL on Windows. Anyone who can write it already
// chooses the manifest URL, so this widens nothing they did not already have.
func TrustFromPEM(pemData string) (Trust, error) {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return Trust{}, fmt.Errorf("update_trusted_cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return Trust{}, fmt.Errorf("update_trusted_cert contains no PEM CERTIFICATE block; " +
			"an agent with no trusted publisher installs nothing, so this is refused at " +
			"configuration time rather than at the next poll")
	}
	return Trust{certs: certs, source: "update_trusted_cert"}, nil
}

// TrustForConfig resolves the anchor an agent should use: the operator's
// certificate when agent.json carries one, otherwise the pinned publisher.
//
// One entry point, so neither the service loop nor the CLI decides for itself
// what an empty setting means. Nothing here can produce an empty Trust: a blank
// setting yields the pinned publisher and a malformed one yields an error, so
// "trusts nobody" is reachable only by never asking.
func TrustForConfig(certPEM string) (Trust, error) {
	if strings.TrimSpace(certPEM) == "" {
		return ReleaseTrust(), nil
	}
	return TrustFromPEM(certPEM)
}

// Empty reports whether this Trust names no publisher, which is the state in
// which nothing can be installed.
func (t Trust) Empty() bool { return len(t.certs) == 0 }

// Describe names the anchor for logs and errors.
func (t Trust) Describe() string {
	if t.Empty() {
		return "no trusted publisher"
	}
	subjects := make([]string, 0, len(t.certs))
	for _, c := range t.certs {
		subjects = append(subjects, c.Subject.String())
	}
	src := t.source
	if src == "" {
		src = "unnamed"
	}
	return fmt.Sprintf("%s (%s)", src, strings.Join(subjects, "; "))
}

// signingInput is the exact byte string a publisher signs.
//
// A canonical form built from the manifest's fields, NOT the JSON bytes: JSON
// has no single serialization, and the producer (PowerShell, via
// ConvertTo-Json) and the consumer (encoding/json) would have to agree on key
// order, indentation and escaping for a byte-level signature to survive a
// round trip. Naming the fields removes the whole class.
//
// The first line is a domain separator, so a signature made by this key for
// anything else — now or later — cannot be replayed as a manifest.
//
// Every field of Manifest except Signature itself appears here.
// TestTheSignatureCoversEveryManifestField enumerates the struct by reflection
// and fails if a field is ever added without being covered, because a field
// outside the signature is a field an attacker can choose.
func signingInput(m *Manifest) ([]byte, error) {
	fields := [][2]string{
		{"version", m.Version},
		{"url", m.URL},
		{"sha256", m.SHA256},
	}
	var b strings.Builder
	b.WriteString(signingDomain)
	b.WriteByte('\n')
	for _, f := range fields {
		// A newline inside a value would let one field's content pose as
		// another line, which is how a signed message gets to mean two things.
		if strings.ContainsAny(f[1], "\n\r") {
			return nil, fmt.Errorf("manifest field %q contains a line break; refusing to sign or verify an ambiguous message", f[0])
		}
		b.WriteString(f[0])
		b.WriteByte('=')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// signingDomain separates this signature's meaning from every other use of the
// same key. Changing it invalidates every existing manifest, so it is versioned.
const signingDomain = "openidx-agent-update-manifest/v1"

// Verify checks the manifest's signature against the trusted publisher.
//
// Refuses, naming the reason, when: the Trust is empty; the manifest carries no
// signature; the signature is not base64; the publisher's validity window does
// not contain now; or no trusted key verifies it.
//
// The validity window is enforced deliberately. A pinned self-signed key has no
// revocation path, so its expiry is the only thing that bounds the damage of a
// compromise discovered late, and it forces the rotation that would otherwise
// never be scheduled. The cost of enforcing it is that updates stop, which is
// the safe direction, and the error says so in as many words.
func Verify(m *Manifest, trust Trust) error {
	if trust.Empty() {
		return fmt.Errorf("no trusted update publisher is configured, so this agent will not " +
			"install anything: the manifest names the artifact AND the digest that matches it, " +
			"so without a signature there is nothing to check the manifest itself against")
	}
	sig := strings.TrimSpace(m.Signature)
	if sig == "" {
		return fmt.Errorf("the manifest carries no signature. Expected one from %s. An unsigned "+
			"manifest is an instruction to run an installer as SYSTEM from whoever served it",
			trust.Describe())
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("the manifest's signature is not base64: %w", err)
	}
	input, err := signingInput(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(input)

	now := time.Now()
	var reasons []string
	for _, c := range trust.certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			reasons = append(reasons, fmt.Sprintf("%s is outside its validity window (%s to %s): "+
				"a pinned publisher has no revocation path, so its expiry is what bounds a late-discovered "+
				"key compromise. Publish with a rotated key, or correct this machine's clock",
				c.Subject.CommonName, c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)))
			continue
		}
		if err := verifyWith(c, sum[:], raw); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", c.Subject.CommonName, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("the manifest is not signed by %s: %s", trust.Describe(), strings.Join(reasons, "; "))
}

// verifyWith checks one RSASSA-PKCS1-v1_5 / SHA-256 signature.
//
// One algorithm, chosen by this code and not by the message: the manifest has
// no algorithm field, so there is no "alg: none" to negotiate. The publisher's
// certificate is RSA (sha256WithRSAEncryption); a key of any other type is
// refused rather than silently skipped, so replacing the pinned certificate
// with, say, an ECDSA one fails loudly here instead of accepting nothing.
func verifyWith(c *x509.Certificate, digest, sig []byte) error {
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is %T, and this verifier only implements RSA PKCS#1 v1.5 over SHA-256", c.PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
		return fmt.Errorf("signature does not verify: %w", err)
	}
	return nil
}
