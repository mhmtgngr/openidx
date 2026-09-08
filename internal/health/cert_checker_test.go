package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// The certificate check is the one thing kept from EnhancedHealthService, the
// second health service in this package that nothing constructed. Keeping it
// only counts if it is mounted and if it answers correctly, so these are about
// the three answers an operator acts on differently: fine, renew it soon, and
// it has already expired.

// writeCert writes a self-signed certificate expiring at notAfter and returns
// its path.
func writeCert(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	return path
}

func TestACertificateWithPlentyOfLifeIsUp(t *testing.T) {
	c := NewCertChecker(writeCert(t, "openidx.test", time.Now().Add(180*24*time.Hour)))
	got := c.Check(context.Background())
	if got.Status != "up" {
		t.Errorf("a certificate valid for six months is %q: %s", got.Status, got.Details)
	}
}

// The case the check exists for: still serving, but the renewal has to be
// booked now.
func TestACertificateInsideTheWarningWindowIsDegradedNotDown(t *testing.T) {
	c := NewCertChecker(writeCert(t, "openidx.test", time.Now().Add(10*24*time.Hour)))
	got := c.Check(context.Background())
	if got.Status != "degraded" {
		t.Errorf("a certificate ten days from expiry is %q, want degraded: %s", got.Status, got.Details)
	}
	if !strings.Contains(got.Details, "openidx.test") {
		t.Errorf("the warning does not name the certificate, so an operator with several cannot tell "+
			"which one: %s", got.Details)
	}
	// Not critical: failing readiness on a warning would take the service out
	// of the load balancer over a certificate that still works.
	if c.IsCritical() {
		t.Error("the certificate check is critical, so a renewal warning would fail readiness")
	}
}

func TestAnExpiredCertificateIsDown(t *testing.T) {
	c := NewCertChecker(writeCert(t, "openidx.test", time.Now().Add(-time.Hour)))
	got := c.Check(context.Background())
	if got.Status != "down" {
		t.Errorf("an expired certificate is %q, want down: %s", got.Status, got.Details)
	}
}

// A path that cannot be read is a misconfiguration, not a pass. The check was
// asked for by naming a file.
func TestAnUnreadableCertificatePathIsReported(t *testing.T) {
	c := NewCertChecker(filepath.Join(t.TempDir(), "absent.pem"))
	got := c.Check(context.Background())
	if got.Status == "up" {
		t.Errorf("a certificate path that does not exist reported %q: %s", got.Status, got.Details)
	}
	if !strings.Contains(got.Details, "absent.pem") {
		t.Errorf("the failure does not name the path: %s", got.Details)
	}
}

// RegisterCertCheck is the half that stops this becoming what it replaced: a
// check nothing mounts.
func TestTheCertCheckIsMountedOnlyWhenTheServiceServesTLSFromAFile(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enabled    bool
		certFile   string
		wantMounts int
	}{
		{"TLS on with a cert file", true, "/etc/openidx/tls.crt", 1},
		{"TLS off", false, "/etc/openidx/tls.crt", 0},
		{"TLS on with no file (cert supplied elsewhere)", true, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := NewHealthService(zap.NewNop())
			before := len(hs.checkers)
			RegisterCertCheck(hs, tc.enabled, tc.certFile)
			if got := len(hs.checkers) - before; got != tc.wantMounts {
				t.Errorf("mounted %d certificate check(s), want %d", got, tc.wantMounts)
			}
		})
	}
}
