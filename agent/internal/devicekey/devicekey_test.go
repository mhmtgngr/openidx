package devicekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"
)

// memKey is a Key held in memory, for the tests of what is built on Key.
type memKey struct{ priv *ecdsa.PrivateKey }

func newMemKey(t *testing.T) *memKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &memKey{priv: priv}
}
func (k *memKey) Public() *ecdsa.PublicKey { return &k.priv.PublicKey }
func (k *memKey) Kind() string             { return "test" }
func (k *memKey) Close()                   {}
func (k *memKey) Sign(d []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, k.priv, d)
}

// The server rebuilds these exact bytes, so their format is pinned.
func TestRequestSigningInputIsPinned(t *testing.T) {
	got, err := RequestSigningInput("POST", "/api/v1/access/agent/report", "agent-1", 1759665600, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"a":1}`))
	want := "openidx-agent-request/v1\nPOST\n/api/v1/access/agent/report\nagent-1\n1759665600\n" +
		hexOf(sum[:]) + "\n"
	if string(got) != want {
		t.Fatalf("signing input\n got %q\nwant %q", got, want)
	}
	for _, bad := range []struct{ method, path, agent string }{
		{"POST\nGET", "/p", "a"}, {"POST", "/p\r\n/q", "a"}, {"POST", "/p", "a\nb"},
	} {
		if _, err := RequestSigningInput(bad.method, bad.path, bad.agent, 1, nil); err == nil {
			t.Fatalf("a line break in %+v must be refused", bad)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// A signature verifies against the signing input the server would build, and
// against nothing else.
func TestSignerSignsWhatTheServerVerifies(t *testing.T) {
	k := newMemKey(t)
	now := time.Unix(1759665600, 0)
	s := Signer{Key: k, AgentID: "agent-1", Now: func() time.Time { return now }}
	body := []byte(`{"results":[]}`)
	ts, sigB64, err := s.SignRequest("POST", "/api/v1/access/agent/report", body)
	if err != nil {
		t.Fatal(err)
	}
	if ts != "1759665600" {
		t.Fatalf("timestamp %q", ts)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(method, path, agent string, b []byte) bool {
		unix, _ := strconv.ParseInt(ts, 10, 64)
		in, _ := RequestSigningInput(method, path, agent, unix, b)
		d := sha256.Sum256(in)
		return ecdsa.VerifyASN1(k.Public(), d[:], sig)
	}
	if !verify("POST", "/api/v1/access/agent/report", "agent-1", body) {
		t.Fatal("the signature does not verify over its own request")
	}
	if verify("POST", "/api/v1/access/agent/report", "agent-1", []byte(`{"results":[1]}`)) ||
		verify("POST", "/api/v1/access/agent/config", "agent-1", body) ||
		verify("POST", "/api/v1/access/agent/report", "agent-2", body) {
		t.Fatal("the signature verifies over a different request")
	}
}

func TestPublicKeyBase64IsPKIX(t *testing.T) {
	k := newMemKey(t)
	b64, err := PublicKeyBase64(k)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("the encoded key is not the key")
	}
}

func eccBlob(pub *ecdsa.PublicKey, magic, size uint32) []byte {
	b := make([]byte, 8, 72)
	binary.LittleEndian.PutUint32(b[0:4], magic)
	binary.LittleEndian.PutUint32(b[4:8], size)
	b = append(b, pub.X.FillBytes(make([]byte, 32))...)
	return append(b, pub.Y.FillBytes(make([]byte, 32))...)
}

func TestParseECCPublicBlob(t *testing.T) {
	k := newMemKey(t)
	got, err := parseECCPublicBlob(eccBlob(k.Public(), eccPublicP256Magic, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k.Public()) {
		t.Fatal("parsed key differs")
	}
	if _, err := parseECCPublicBlob(eccBlob(k.Public(), 0x32534345, 32)); err == nil {
		t.Fatal("a non-P-256 magic must be refused")
	}
	if _, err := parseECCPublicBlob(eccBlob(k.Public(), eccPublicP256Magic, 32)[:40]); err == nil {
		t.Fatal("a short blob must be refused")
	}
	off := eccBlob(k.Public(), eccPublicP256Magic, 32)
	off[71] ^= 1
	if _, err := parseECCPublicBlob(off); err == nil {
		t.Fatal("a point off the curve must be refused")
	}
}

func TestRawSignatureToASN1(t *testing.T) {
	k := newMemKey(t)
	d := sha256.Sum256([]byte("x"))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	der, err := rawSignatureToASN1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k.Public(), d[:], der) {
		t.Fatal("converted signature does not verify")
	}
	if _, err := rawSignatureToASN1(raw[:63]); err == nil {
		t.Fatal("a short signature must be refused")
	}
	if !strings.HasPrefix(string(der), "\x30") {
		t.Fatal("not a DER SEQUENCE")
	}
}
