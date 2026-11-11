package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func winHTTPBlob(flags uint32, proxy, bypass string) []byte {
	var b []byte
	put := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	put(0x28)
	put(7)
	put(flags)
	put(uint32(len(proxy)))
	b = append(b, proxy...)
	put(uint32(len(bypass)))
	b = append(b, bypass...)
	return b
}

func TestParsesWinHttpSettingsBlob(t *testing.T) {
	p, err := parseWinHTTPSettings(winHTTPBlob(3, "proxy.corp:3128", "<local>;*.corp.example;192.0.2.*"))
	if err != nil || p == nil {
		t.Fatalf("parse: %v %v", p, err)
	}
	mustURL := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	if got := p.proxyFor(mustURL("https://idx.example.com/api")); got == nil || got.Host != "proxy.corp:3128" {
		t.Fatalf("expected proxy.corp:3128, got %v", got)
	}
	for _, bypassed := range []string{"https://intranet/", "https://a.corp.example/", "http://192.0.2.3/"} {
		if got := p.proxyFor(mustURL(bypassed)); got != nil {
			t.Errorf("%s should bypass, got %v", bypassed, got)
		}
	}

	per, err := parseWinHTTPSettings(winHTTPBlob(3, "http=h1:80;https=h2:443", ""))
	if err != nil || per.proxyFor(mustURL("https://x.example")).Host != "h2:443" ||
		per.proxyFor(mustURL("http://x.example")).Host != "h1:80" {
		t.Fatalf("per-scheme parse wrong: %+v %v", per, err)
	}

	if d, err := parseWinHTTPSettings(winHTTPBlob(1, "", "")); err != nil || d != nil {
		t.Fatalf("direct blob should be nil,nil: %v %v", d, err)
	}
	if _, err := parseWinHTTPSettings([]byte{0x28, 0, 0}); err == nil {
		t.Fatal("truncated blob accepted")
	}
	bad := winHTTPBlob(3, "p:1", "")
	binary.LittleEndian.PutUint32(bad[12:], 9999)
	if _, err := parseWinHTTPSettings(bad); err == nil {
		t.Fatal("overrunning length accepted")
	}
}

func selfSignedPEM(t *testing.T, cn string) (string, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), c
}

func TestServerCAPEMIsAppendedNotReplacing(t *testing.T) {
	sysPEM, sysCert := selfSignedPEM(t, "pretend public root")
	privPEM, privCert := selfSignedPEM(t, "private server CA")
	orig := systemCertPool
	t.Cleanup(func() { systemCertPool = orig })
	systemCertPool = func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM([]byte(sysPEM))
		return p, nil
	}

	tr, err := NetworkOptions{CAPEM: privPEM}.httpTransport()
	if err != nil {
		t.Fatal(err)
	}
	pool := tr.TLSClientConfig.RootCAs
	for _, c := range []*x509.Certificate{sysCert, privCert} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			t.Errorf("%s not trusted by the combined pool: %v", c.Subject.CommonName, err)
		}
	}
	if _, err := (NetworkOptions{CAPEM: "not a pem"}).httpTransport(); err == nil {
		t.Fatal("garbage CA accepted")
	}
}

func TestSharedTransportIsRebuiltBySetNetworkOptions(t *testing.T) {
	t.Cleanup(func() { _ = SetNetworkOptions(NetworkOptions{}) })
	a := SharedTransport()
	if SharedTransport() != a || HTTPClient(0).Transport != a {
		t.Fatal("transport not shared")
	}
	if err := SetNetworkOptions(NetworkOptions{ProxyURL: "http://p.example:8080"}); err != nil {
		t.Fatal(err)
	}
	b := SharedTransport()
	if b == a {
		t.Fatal("transport not rebuilt")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://idx.example.com", nil)
	got, _ := b.Proxy(req)
	if got == nil || got.Host != "p.example:8080" {
		t.Fatalf("explicit proxy not used: %v", got)
	}
	if err := SetNetworkOptions(NetworkOptions{ProxyURL: "ftp://x"}); err == nil {
		t.Fatal("bad proxy accepted")
	}
}
