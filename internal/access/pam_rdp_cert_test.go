package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeRDPServer answers one X.224 connection request the way an RDP server
// does: selecting TLS and handshaking with cert, or refusing TLS when cert is
// nil (a server offering standard RDP security only). It records whether
// anything arrived after the handshake.
func fakeRDPServer(t *testing.T, cert *tls.Certificate) (addr string, afterHandshake chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	afterHandshake = make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req := make([]byte, 19)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		if cert == nil {
			// RDP_NEG_FAILURE, SSL_NOT_ALLOWED_BY_SERVER
			_, _ = c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0x00,
				0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00})
			return
		}
		// RDP_NEG_RSP selecting PROTOCOL_SSL
		_, _ = c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0x00,
			0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00})
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := io.Copy(io.Discard, tc)
		afterHandshake <- int(n)
	}()
	return ln.Addr().String(), afterHandshake
}

func selfSignedRDPCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "rdp.example.test"},
		DNSNames: []string{"rdp.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	h := hex.EncodeToString(sum[:])
	var pairs []string
	for i := 0; i < len(h); i += 2 {
		pairs = append(pairs, h[i:i+2])
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, "sha256:" + strings.Join(pairs, ":")
}

func TestReadRDPCertificate(t *testing.T) {
	cert, want := selfSignedRDPCert(t)
	addr, after := fakeRDPServer(t, &cert)
	got, err := readRDPCertificate(context.Background(), addr, "rdp.example.test")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Fingerprint != want {
		t.Errorf("fingerprint %s, want %s", got.Fingerprint, want)
	}
	if _, ok := normalizePamCertFingerprint(got.Fingerprint); !ok {
		t.Errorf("the fingerprint read is not one an entry accepts: %s", got.Fingerprint)
	}
	if !got.SelfSigned || got.Trusted || got.TrustError == "" || got.Protocol != "tls" {
		t.Errorf("self-signed %v trusted %v trust error %q protocol %q", got.SelfSigned, got.Trusted, got.TrustError, got.Protocol)
	}
	if n := <-after; n != 0 {
		t.Errorf("%d bytes were sent after the handshake; nothing should be", n)
	}

	addr, _ = fakeRDPServer(t, nil)
	if _, err := readRDPCertificate(context.Background(), addr, "rdp.example.test"); err != errRDPNoTLS {
		t.Errorf("a standard-RDP-only target: %v, want errRDPNoTLS", err)
	}
}

func TestReadRDPNegotiationRejectsGarbage(t *testing.T) {
	for name, in := range map[string][]byte{
		"not tpkt":  {0x16, 0x03, 0x01, 0x00},
		"too long":  {0x03, 0x00, 0xff, 0xff},
		"too short": {0x03, 0x00, 0x00, 0x05},
		"truncated": {0x03, 0x00, 0x00, 0x13, 0x0e},
	} {
		if _, err := readRDPNegotiation(strings.NewReader(string(in))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
