package updater

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// A test publisher: a throwaway RSA key and a self-signed certificate for it,
// which is the same shape as the pinned one. Generated once — 2048-bit keygen
// is the slowest thing in this package by an order of magnitude, and every case
// below wants the same key.

type testPublisher struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newTestPublisher(t *testing.T, cn string, notBefore, notAfter time.Time) *testPublisher {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &testPublisher{key: key, cert: c}
}

var (
	validPublisherOnce sync.Once
	validPublisher     *testPublisher
	otherPublisherOnce sync.Once
	otherPublisher     *testPublisher
)

// publisher is the test's stand-in for the pinned release publisher.
func publisher(t *testing.T) *testPublisher {
	t.Helper()
	validPublisherOnce.Do(func() {
		validPublisher = newTestPublisher(t, "Test Publisher", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	})
	if validPublisher == nil {
		t.Fatal("publisher setup failed")
	}
	return validPublisher
}

// impostor is a different key with a perfectly valid certificate — the case
// that matters, because an attacker who can serve the manifest can also sign it
// with SOMETHING.
func impostor(t *testing.T) *testPublisher {
	t.Helper()
	otherPublisherOnce.Do(func() {
		otherPublisher = newTestPublisher(t, "Somebody Else", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	})
	if otherPublisher == nil {
		t.Fatal("impostor setup failed")
	}
	return otherPublisher
}

func (p *testPublisher) trust() Trust {
	return Trust{certs: []*x509.Certificate{p.cert}, source: "test publisher"}
}

// sign produces what the release workflow produces: base64 RSA PKCS#1 v1.5 over
// SHA-256 of the canonical form.
func (p *testPublisher) sign(t *testing.T, m *Manifest) string {
	t.Helper()
	input, err := signingInput(m)
	if err != nil {
		t.Fatalf("signingInput: %v", err)
	}
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (p *testPublisher) pemCert() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw}))
}

// signV2 produces signature_v2: the same algorithm over signingInputV2.
func (p *testPublisher) signV2(t *testing.T, m *Manifest) string {
	t.Helper()
	input, err := signingInputV2(m)
	if err != nil {
		t.Fatalf("signingInputV2: %v", err)
	}
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// expiresIn is an expires value d from now, in the form the release writes:
// RFC 3339, UTC, whole seconds.
func expiresIn(d time.Duration) string {
	return time.Now().Add(d).UTC().Truncate(time.Second).Format(time.RFC3339)
}

// signedManifest returns a manifest this publisher has signed both ways, as
// the release does, expiring in 30 days.
func (p *testPublisher) signedManifest(t *testing.T, version, url, sha string) *Manifest {
	t.Helper()
	m := &Manifest{Version: version, URL: url, SHA256: sha, Expires: expiresIn(30 * 24 * time.Hour)}
	m.Signature = p.sign(t, m)
	m.SignatureV2 = p.signV2(t, m)
	return m
}

// ---------------------------------------------------------------------------
// The pin itself.
// ---------------------------------------------------------------------------

// TestThePinnedPublisherIsTheCommittedSigningCertificate.
//
// release-publisher.cer is a byte copy of agent/packaging/openidx-codesign.cer,
// which exists because //go:embed cannot read outside its own package
// directory. Two copies of a trust anchor is exactly the arrangement that
// drifts silently — the release keeps signing with one key while the agent
// keeps trusting the other, and the symptom is that updates stop, on endpoints,
// months later. This is the thing that makes them one file.
func TestThePinnedPublisherIsTheCommittedSigningCertificate(t *testing.T) {
	const packaged = "../../packaging/openidx-codesign.cer"
	want, err := os.ReadFile(packaged)
	if err != nil {
		t.Fatalf("%s: %v (this is the certificate the release workflow imports and signs with; "+
			"if it moved, move release-publisher.cer with it and point this test at the new path)", packaged, err)
	}
	if string(releasePublisherDER) != string(want) {
		t.Fatalf("release-publisher.cer (%d bytes) differs from %s (%d bytes). The agent trusts the "+
			"first and the release signs with the second, so every published manifest would be refused "+
			"by every agent. Copy the packaging certificate over the embedded one.",
			len(releasePublisherDER), packaged, len(want))
	}
}

// TestTheReleaseTrustIsUsable. ReleaseTrust swallows a parse failure and returns
// an empty Trust, because refusing to update is the safe answer to a corrupt
// pin — but an empty Trust also means self-update is silently off for everyone,
// so the parse has to be checked somewhere that fails loudly. Here.
func TestTheReleaseTrustIsUsable(t *testing.T) {
	tr := ReleaseTrust()
	if tr.Empty() {
		t.Fatalf("the pinned release publisher did not parse, so no agent built from this tree will "+
			"ever apply an update: %s", tr.Describe())
	}
	c := tr.certs[0]
	if _, ok := c.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("the pinned publisher's key is %T; verifyWith implements RSA PKCS#1 v1.5 only, so "+
			"nothing it signs would verify", c.PublicKey)
	}
	if now := time.Now(); now.Before(c.NotBefore) || now.After(c.NotAfter) {
		t.Errorf("the pinned publisher is outside its validity window (%s to %s) as of %s: Verify "+
			"refuses it, so self-update is off until the certificate is rotated. This test is the "+
			"warning that it is time.",
			c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	}
}

// ---------------------------------------------------------------------------
// What the signature covers.
// ---------------------------------------------------------------------------

// TestTheSignatureCoversEveryManifestField enumerates Manifest by reflection and
// proves each field (other than Signature) changes the signed bytes.
//
// Not a name check against a list — that would pass for a field that is written
// into the canonical form and then ignored. This mutates the actual struct and
// requires the signing input to move, so the only way to pass is to be an input.
//
// A field that is NOT an input is a field an attacker can set freely on a
// manifest that still verifies. If this fails after you added one, add it to
// signingInputV2 and bump signingDomainV2. (signingInput, the v1 form, stays
// as it is: agents built before manifests expired verify it, and a field
// added to it would break every one of them.)
func TestTheSignatureCoversEveryManifestField(t *testing.T) {
	base := &Manifest{Version: "1.0.0", URL: "https://example.com/a.msi", SHA256: strings.Repeat("a", 64),
		Expires: "2027-01-13T10:00:00Z"}
	baseline, err := signingInputV2(base)
	if err != nil {
		t.Fatalf("signingInputV2: %v", err)
	}

	typ := reflect.TypeOf(*base)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name == "Signature" || f.Name == "SignatureV2" {
			continue // a signature cannot sign itself
		}
		if f.Type.Kind() != reflect.String {
			t.Fatalf("Manifest.%s is %s; this test only knows how to mutate strings. Teach it, "+
				"or the new field's coverage goes unchecked.", f.Name, f.Type)
		}
		mutated := *base
		reflect.ValueOf(&mutated).Elem().Field(i).SetString("attacker-chosen")
		got, err := signingInputV2(&mutated)
		if err != nil {
			t.Fatalf("signingInputV2(%s mutated): %v", f.Name, err)
		}
		if string(got) == string(baseline) {
			t.Errorf("Manifest.%s (json %q) is outside the signature: a manifest can carry any value "+
				"for it and still verify. Add it to signingInputV2 and bump signingDomainV2.",
				f.Name, f.Tag.Get("json"))
		}
	}
}

// TestSigningInputRefusesALineBreak. The canonical form is line-oriented, so a
// newline inside a value would let one field's content pose as another line —
// the way a signed message comes to mean two things.
func TestSigningInputRefusesALineBreak(t *testing.T) {
	for _, injected := range []string{
		"1.0.0\nurl=https://evil.example.com/a.msi",
		"1.0.0\r\nsha256=" + strings.Repeat("b", 64),
	} {
		if _, err := signingInput(&Manifest{Version: injected, URL: "https://x/a", SHA256: strings.Repeat("a", 64)}); err == nil {
			t.Errorf("signingInput accepted a version containing a line break: %q", injected)
		}
		if _, err := signingInputV2(&Manifest{Version: "1.0.0", URL: "https://x/a", SHA256: strings.Repeat("a", 64), Expires: injected}); err == nil {
			t.Errorf("signingInputV2 accepted an expires containing a line break: %q", injected)
		}
	}
}

// TestTheSigningDomainSeparatesThisFromEverythingElseTheKeySigns. The same key
// Authenticode-signs openidx-agent.exe and the MSI. A domain separator is what
// stops a signature made for one purpose being replayed as another.
func TestTheSigningDomainSeparatesThisFromEverythingElseTheKeySigns(t *testing.T) {
	in, err := signingInput(&Manifest{Version: "1.0.0", URL: "https://x/a", SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("signingInput: %v", err)
	}
	if !strings.HasPrefix(string(in), signingDomain+"\n") {
		t.Errorf("the signed bytes do not begin with the domain separator %q:\n%s", signingDomain, in)
	}
	in2, err := signingInputV2(&Manifest{Version: "1.0.0", URL: "https://x/a", SHA256: strings.Repeat("a", 64), Expires: "2027-01-13T10:00:00Z"})
	if err != nil {
		t.Fatalf("signingInputV2: %v", err)
	}
	if !strings.HasPrefix(string(in2), signingDomainV2+"\n") {
		t.Errorf("the v2 signed bytes do not begin with the domain separator %q:\n%s", signingDomainV2, in2)
	}
	for _, d := range []string{signingDomain, signingDomainV2} {
		if !strings.Contains(d, "/v") {
			t.Errorf("the signing domain %q carries no version; changing the canonical form later would "+
				"silently accept old signatures over new meanings", d)
		}
	}
	// The two forms must not be interchangeable: a v1 signature covers no
	// expiry, so presenting one as a v2 signature would be the way to make a
	// manifest that never expires.
	if signingDomain == signingDomainV2 {
		t.Error("the v1 and v2 signing domains are the same string, so a signature over the form " +
			"without an expiry could be presented as one over the form with it")
	}
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

func TestVerifyAcceptsOnlyThePublishersSignature(t *testing.T) {
	pub := publisher(t)
	good := pub.signedManifest(t, "1.2.0", "https://example.com/OpenIDX-1.2.0.msi", strings.Repeat("a", 64))

	t.Run("the publisher's own signature", func(t *testing.T) {
		if err := Verify(good, pub.trust()); err != nil {
			t.Fatalf("Verify rejected a manifest the trusted publisher signed: %v", err)
		}
	})

	// signature (v1) is produced for agents built before manifests expired;
	// this agent verifies signature_v2 and asks nothing of v1. An operator
	// channel that serves only v2 is therefore accepted.
	t.Run("the v1 signature is not needed", func(t *testing.T) {
		m := *good
		m.Signature = ""
		if err := Verify(&m, pub.trust()); err != nil {
			t.Fatalf("Verify rejected a manifest carrying signature_v2 but no signature: %v", err)
		}
	})

	// Each of these is a manifest an attacker would want to serve.
	for _, tc := range []struct {
		name   string
		mutate func(m *Manifest)
		reason string
	}{
		{
			name:   "no signature at all",
			mutate: func(m *Manifest) { m.Signature, m.SignatureV2 = "", "" },
			reason: "the shape every manifest had before it was signed",
		},
		{
			name:   "only the signature agents verified before manifests expired",
			mutate: func(m *Manifest) { m.SignatureV2 = "" },
			reason: "a manifest from before the expiry, or one with its signature_v2 stripped off; either could be served forever",
		},
		{
			name:   "signature_v2 is not base64",
			mutate: func(m *Manifest) { m.SignatureV2 = "not base64 !!" },
			reason: "malformed rather than wrong",
		},
		{
			name:   "signature_v2 is empty base64",
			mutate: func(m *Manifest) { m.SignatureV2 = base64.StdEncoding.EncodeToString(nil) },
			reason: "decodes fine, verifies nothing",
		},
		{
			name:   "the expiry is pushed out after signing",
			mutate: func(m *Manifest) { m.Expires = expiresIn(300 * 24 * time.Hour) },
			reason: "keep a captured manifest alive past its lifetime",
		},
		{
			name:   "the expiry is removed after signing",
			mutate: func(m *Manifest) { m.Expires = "" },
			reason: "the same, by taking the field away",
		},
		{
			name:   "the url is swapped after signing",
			mutate: func(m *Manifest) { m.URL = "https://evil.example.com/OpenIDX-1.2.0.msi" },
			reason: "point the same version and digest at another host",
		},
		{
			name:   "the digest is swapped after signing",
			mutate: func(m *Manifest) { m.SHA256 = strings.Repeat("b", 64) },
			reason: "the whole point: choose the artifact by choosing the digest",
		},
		{
			name:   "the version is raised after signing",
			mutate: func(m *Manifest) { m.Version = "99.0.0" },
			reason: "force a downgrade-shaped install of an older signed payload",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := *good
			tc.mutate(&m)
			if err := Verify(&m, pub.trust()); err == nil {
				t.Fatalf("Verify accepted a manifest with %s (%s); this agent would hand the named "+
					"artifact to msiexec as SYSTEM", tc.name, tc.reason)
			}
		})
	}
}

// TestVerifyRefusesAnotherPublishersValidSignature is the case a naive
// implementation gets wrong: the manifest IS signed, the signature IS valid, and
// the key is not ours.
func TestVerifyRefusesAnotherPublishersValidSignature(t *testing.T) {
	pub, other := publisher(t), impostor(t)
	m := other.signedManifest(t, "1.2.0", "https://evil.example.com/a.msi", strings.Repeat("c", 64))

	if err := Verify(m, pub.trust()); err == nil {
		t.Fatal("Verify accepted a well-formed signature made by a key this agent does not trust")
	}
	// And it verifies under its own publisher, so the case above failed for the
	// right reason rather than because the fixture was broken.
	if err := Verify(m, other.trust()); err != nil {
		t.Fatalf("the impostor's own trust rejected its own signature, so the case above proves nothing: %v", err)
	}
}

// TestAZeroTrustInstallsNothing. Trust is a required parameter; this pins what
// its zero value means, because a caller that forgets it must fail closed.
func TestAZeroTrustInstallsNothing(t *testing.T) {
	pub := publisher(t)
	m := pub.signedManifest(t, "1.2.0", "https://example.com/a.msi", strings.Repeat("a", 64))

	err := Verify(m, Trust{})
	if err == nil {
		t.Fatal("Verify accepted a manifest against an empty Trust: a caller that passes no anchor " +
			"would install anything")
	}
	if !strings.Contains(err.Error(), "no trusted update publisher") {
		t.Errorf("the refusal does not name the missing publisher: %v", err)
	}
}

// TestVerifyRefusesAManifestPastItsExpiry: the publisher really signed each
// of these, and only the ones still inside their lifetime are accepted.
// Without this, a copy of any manifest the publisher ever signed would be as
// good as the newest one for as long as anyone kept it.
func TestVerifyRefusesAManifestPastItsExpiry(t *testing.T) {
	pub := publisher(t)
	signed := func(expires string) *Manifest {
		m := &Manifest{Version: "1.2.0", URL: "https://example.com/a.msi", SHA256: strings.Repeat("a", 64), Expires: expires}
		m.Signature = pub.sign(t, m)
		m.SignatureV2 = pub.signV2(t, m)
		return m
	}
	if err := Verify(signed(expiresIn(time.Hour)), pub.trust()); err != nil {
		t.Fatalf("a signed manifest an hour from its expiry was refused: %v", err)
	}
	if err := Verify(signed(expiresIn(90*24*time.Hour)), pub.trust()); err != nil {
		t.Fatalf("a signed manifest with the release's 90-day lifetime was refused: %v", err)
	}
	for _, tc := range []struct {
		name, expires, want string
	}{
		{"expired a minute ago", expiresIn(-time.Minute), "expired"},
		{"no expiry, signed that way", "", "no expires"},
		{"an expiry that is not a time", "next Tuesday", "not an RFC 3339 time"},
		{"an expiry two years out", expiresIn(2 * 365 * 24 * time.Hour), "more than a year ahead"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(signed(tc.expires), pub.trust())
			if err == nil {
				t.Fatalf("Verify accepted a manifest with %s; a manifest that is good for longer than its "+
					"lifetime is one that hides every later release", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q, so an operator cannot tell a stale channel from a bad "+
					"signature: %v", tc.want, err)
			}
		})
	}
}

func TestVerifyRefusesAPublisherOutsideItsValidityWindow(t *testing.T) {
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired", time.Now().Add(-48 * time.Hour), time.Now().Add(-time.Hour)},
		{"not yet valid", time.Now().Add(time.Hour), time.Now().Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPublisher(t, "Lapsed Publisher", tc.notBefore, tc.notAfter)
			m := p.signedManifest(t, "1.2.0", "https://example.com/a.msi", strings.Repeat("a", 64))
			err := Verify(m, p.trust())
			if err == nil {
				t.Fatal("Verify accepted a signature from a certificate outside its validity window; " +
					"a pinned key has no revocation path, so expiry is the only bound on a " +
					"late-discovered compromise")
			}
			if !strings.Contains(err.Error(), "validity window") {
				t.Errorf("the refusal does not name the validity window, so an operator cannot tell it "+
					"from a bad signature: %v", err)
			}
		})
	}
}

// TestVerifySignatureAppliesTheManifestRulesToOtherInputs. VerifySignature is
// what the plugin loader uses, so that a plugin is held to the same publisher
// and the same rules as an update. Each refusal below is one Verify already
// makes for a manifest; this proves the shared path makes it too.
func TestVerifySignatureAppliesTheManifestRulesToOtherInputs(t *testing.T) {
	pub, other := publisher(t), impostor(t)
	input := []byte("openidx-test-input/v1\nfield=value\n")
	signRaw := func(p *testPublisher, msg []byte) string {
		sum := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	good := signRaw(pub, input)

	if err := pub.trust().VerifySignature(input, good); err != nil {
		t.Fatalf("VerifySignature rejected the trusted publisher's own signature: %v", err)
	}
	// A trailing newline is what `base64` without -w0, or an editor, leaves in a
	// signature file. Verify trims it from a manifest, so this does too.
	if err := pub.trust().VerifySignature(input, good+"\n"); err != nil {
		t.Errorf("VerifySignature rejected a signature followed by a newline: %v", err)
	}

	lapsed := newTestPublisher(t, "Lapsed Publisher", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	for _, tc := range []struct {
		name  string
		trust Trust
		input []byte
		sig   string
		want  string
	}{
		{"no signature", pub.trust(), input, "", "no signature"},
		{"not base64", pub.trust(), input, "not base64 !!", "base64"},
		{"the input changed after signing", pub.trust(), []byte("openidx-test-input/v1\nfield=other\n"), good, "not signed by"},
		{"another publisher's valid signature", pub.trust(), input, signRaw(other, input), "not signed by"},
		{"a publisher outside its validity window", lapsed.trust(), input, signRaw(lapsed, input), "validity window"},
		{"an empty Trust", Trust{}, input, good, "no trusted publisher"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.trust.VerifySignature(tc.input, tc.sig)
			if err == nil {
				t.Fatalf("VerifySignature accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q: %v", tc.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Where the anchor comes from.
// ---------------------------------------------------------------------------

func TestTrustForConfigDefaultsToThePinnedPublisher(t *testing.T) {
	for _, blank := range []string{"", "   ", "\n\t"} {
		tr, err := TrustForConfig(blank)
		if err != nil {
			t.Fatalf("TrustForConfig(%q): %v", blank, err)
		}
		if tr.Empty() {
			t.Fatalf("TrustForConfig(%q) produced an empty Trust; a blank setting must mean the "+
				"pinned publisher, not 'trust nobody' — which would disable self-update for every "+
				"install that never set the field", blank)
		}
		if !strings.Contains(tr.Describe(), "OpenIDX") {
			t.Errorf("TrustForConfig(%q) = %s, want the pinned OpenIDX publisher", blank, tr.Describe())
		}
	}
}

func TestTrustForConfigAcceptsAnOperatorsOwnPublisher(t *testing.T) {
	other := impostor(t)
	tr, err := TrustForConfig(other.pemCert())
	if err != nil {
		t.Fatalf("TrustForConfig with a PEM certificate: %v", err)
	}
	m := other.signedManifest(t, "1.2.0", "https://internal.example.com/a.msi", strings.Repeat("d", 64))
	if err := Verify(m, tr); err != nil {
		t.Fatalf("a manifest signed by the operator's configured publisher was refused: %v", err)
	}

	// And it REPLACES the pin rather than adding to it, which is what the field
	// documents: an on-premise install should not also accept upstream's builds.
	pinned := ReleaseTrust()
	if len(tr.certs) != 1 || tr.certs[0].Equal(pinned.certs[0]) {
		t.Errorf("update_trusted_cert did not replace the pinned publisher: trust is %s", tr.Describe())
	}
}

func TestTrustForConfigRefusesSomethingThatIsNotACertificate(t *testing.T) {
	for _, tc := range []struct{ name, pemData string }{
		{"prose", "please trust me"},
		{"a PEM block of the wrong type", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"},
		{"a CERTIFICATE block with garbage in it", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := TrustForConfig(tc.pemData)
			if err == nil {
				t.Fatalf("TrustForConfig accepted %s and returned %s; a malformed anchor must be "+
					"reported, not silently turned into 'trust nobody' or 'trust the default'",
					tc.name, tr.Describe())
			}
			if !tr.Empty() {
				t.Errorf("TrustForConfig returned an error AND a non-empty Trust (%s)", tr.Describe())
			}
		})
	}
}
