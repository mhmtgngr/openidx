package health

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertChecker reports how long a TLS certificate has left.
//
// This is the one thing worth keeping from EnhancedHealthService, the second
// health service that sat in this package with its own Check, its own handlers
// and its own RegisterStandardRoutes, constructed by nothing. It could gather
// certificate expiry; nothing ever asked it to. An expiring certificate is a
// scheduled outage that announces itself weeks in advance to anybody looking,
// so the check is worth having and worth mounting -- which is the difference
// between this and what it replaces.
//
// It is deliberately NOT critical. A certificate 20 days from expiry is
// degraded, not down: failing readiness would take the service out of the load
// balancer over a warning, which is the opposite of what the operator wants.
type CertChecker struct {
	path string
	// warnWithin is how close to expiry counts as degraded.
	warnWithin time.Duration
}

// NewCertChecker checks the certificate at path, warning inside 30 days.
func NewCertChecker(path string) *CertChecker {
	return &CertChecker{path: path, warnWithin: 30 * 24 * time.Hour}
}

// Name returns the checker name.
func (c *CertChecker) Name() string { return "tls_certificate" }

// IsCritical is false: expiry is a warning until it happens.
func (c *CertChecker) IsCritical() bool { return false }

// Check reads the certificate and reports its remaining life.
func (c *CertChecker) Check(_ context.Context) ComponentStatus {
	start := time.Now()
	now := time.Now()

	status := ComponentStatus{CheckedAt: now.UTC().Format(time.RFC3339)}
	defer func() { status.LatencyMS = float64(time.Since(start).Microseconds()) / 1000.0 }()

	notAfter, subject, err := certNotAfter(c.path)
	if err != nil {
		// A path that cannot be read is a misconfiguration the operator needs
		// to see, not a silent pass: the check was asked for by naming a file.
		status.Status = "degraded"
		status.Details = fmt.Sprintf("cannot read the certificate at %s: %v", c.path, err)
		return status
	}

	remaining := notAfter.Sub(now)
	switch {
	case remaining <= 0:
		status.Status = "down"
		status.Details = fmt.Sprintf("the certificate for %s expired %s", subject,
			notAfter.UTC().Format(time.RFC3339))
	case remaining <= c.warnWithin:
		status.Status = "degraded"
		status.Details = fmt.Sprintf("the certificate for %s expires in %d day(s), on %s",
			subject, int(remaining.Hours()/24), notAfter.UTC().Format(time.RFC3339))
	default:
		status.Status = "up"
		status.Details = fmt.Sprintf("valid for %d more day(s)", int(remaining.Hours()/24))
	}
	return status
}

// certNotAfter returns the expiry and common name of the first certificate in a
// PEM file. A chain file leads with the leaf, which is the one that expires
// first and the one a client rejects.
func certNotAfter(path string) (time.Time, string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return time.Time{}, "", fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse certificate: %w", err)
	}
	subject := cert.Subject.CommonName
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}
	return cert.NotAfter, subject, nil
}

// RegisterCertCheck mounts a certificate-expiry check when the service is
// actually serving TLS from a file on disk.
//
// No TLS, or a certificate supplied some other way, means no check at all
// rather than a check that always reports a problem — a health endpoint that
// is permanently degraded is a health endpoint nobody reads.
func RegisterCertCheck(hs *HealthService, tlsEnabled bool, certFile string) {
	if hs == nil || !tlsEnabled || certFile == "" {
		return
	}
	hs.RegisterCheck(NewCertChecker(certFile))
}
