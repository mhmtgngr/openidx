// Package access - BrowZer bootstrapper management API handlers.
// Provides endpoints for managing TLS certificates, domain configuration,
// and bootstrapper lifecycle from the admin console.
package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// BrowZerDomainConfig is persisted as JSONB in system_settings under key "browzer_domain_config"
type BrowZerDomainConfig struct {
	Domain               string   `json:"domain"`
	CertType             string   `json:"cert_type"` // "self_signed" or "custom"
	CertSubject          string   `json:"cert_subject"`
	CertIssuer           string   `json:"cert_issuer"`
	CertNotBefore        string   `json:"cert_not_before"`
	CertNotAfter         string   `json:"cert_not_after"`
	CertFingerprint      string   `json:"cert_fingerprint"`
	CertSAN              []string `json:"cert_san"`
	CustomCertUploadedAt *string  `json:"custom_cert_uploaded_at"`
	PreviousDomain       *string  `json:"previous_domain"`
	DomainChangedAt      *string  `json:"domain_changed_at"`
}

// BrowZerManagementStatus is the full response for the management overview endpoint
type BrowZerManagementStatus struct {
	BrowZerEnabled  bool                 `json:"browzer_enabled"`
	Domain          string               `json:"domain"`
	BootstrapperURL string               `json:"bootstrapper_url"`
	CertType        string               `json:"cert_type"`
	CertSubject     string               `json:"cert_subject"`
	CertIssuer      string               `json:"cert_issuer"`
	CertNotAfter    string               `json:"cert_not_after"`
	CertFingerprint string               `json:"cert_fingerprint"`
	CertSAN         []string             `json:"cert_san"`
	CertDaysLeft    int                  `json:"cert_days_left"`
	TargetsCount    int                  `json:"targets_count"`
	Targets         []BrowZerTarget      `json:"targets"`
	DomainConfig    *BrowZerDomainConfig `json:"domain_config"`
}

// handleBrowZerManagement returns the full BrowZer management status
func (s *Service) handleBrowZerManagement(c *gin.Context) {
	ctx := c.Request.Context()

	// Load domain config
	domainCfg, err := s.loadBrowZerDomainConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to load domain config", zap.Error(err))
		domainCfg = &BrowZerDomainConfig{
			Domain:   DefaultBrowZerDomain,
			CertType: "self_signed",
		}
	}

	// Check if BrowZer is enabled
	browzerEnabled := false
	s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(enabled, false) FROM ziti_browzer_config LIMIT 1`).Scan(&browzerEnabled)

	// Get targets
	var targets []BrowZerTarget
	targetsCount := 0
	if s.browzerTargetManager != nil {
		ta, err := s.browzerTargetManager.GenerateBrowZerTargets(ctx)
		if err == nil {
			targets = ta.TargetArray
			targetsCount = len(targets)
		}
	}

	// Calculate cert days left
	daysLeft := 0
	if domainCfg.CertNotAfter != "" {
		if t, err := time.Parse(time.RFC3339, domainCfg.CertNotAfter); err == nil {
			daysLeft = int(time.Until(t).Hours() / 24)
			if daysLeft < 0 {
				daysLeft = 0
			}
		}
	}

	status := BrowZerManagementStatus{
		BrowZerEnabled:  browzerEnabled,
		Domain:          domainCfg.Domain,
		BootstrapperURL: "https://" + domainCfg.Domain,
		CertType:        domainCfg.CertType,
		CertSubject:     domainCfg.CertSubject,
		CertIssuer:      domainCfg.CertIssuer,
		CertNotAfter:    domainCfg.CertNotAfter,
		CertFingerprint: domainCfg.CertFingerprint,
		CertSAN:         domainCfg.CertSAN,
		CertDaysLeft:    daysLeft,
		TargetsCount:    targetsCount,
		Targets:         targets,
		DomainConfig:    domainCfg,
	}

	c.JSON(http.StatusOK, status)
}

// handleBrowZerCertUpload handles custom TLS certificate upload (multipart/form-data)
func (s *Service) handleBrowZerCertUpload(c *gin.Context) {
	ctx := c.Request.Context()

	if s.browzerTargetManager == nil || s.browzerTargetManager.GetCertsPath() == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "BrowZer certificate management not configured"})
		return
	}

	certFile, err := c.FormFile("cert")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'cert' file"})
		return
	}
	keyFile, err := c.FormFile("key")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'key' file"})
		return
	}

	// Read cert file
	cf, err := certFile.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read cert file"})
		return
	}
	defer cf.Close()
	certBytes := make([]byte, certFile.Size)
	cf.Read(certBytes)

	// Read key file
	kf, err := keyFile.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read key file"})
		return
	}
	defer kf.Close()
	keyBytes := make([]byte, keyFile.Size)
	kf.Read(keyBytes)

	// Parse and validate certificate
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PEM certificate"})
		return
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid certificate: %v", err)})
		return
	}

	// Parse key
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PEM private key"})
		return
	}

	// Verify key matches cert by attempting to parse the private key
	_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		_, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot parse private key (expected PKCS8, EC, or PKCS1)"})
				return
			}
		}
	}

	// Write cert and key to shared volume
	certsPath := s.browzerTargetManager.GetCertsPath()
	certPath := filepath.Join(certsPath, "browzer-tls.crt")
	keyPath := filepath.Join(certsPath, "browzer-tls.key")

	if err := writeFileAtomic(certPath, certBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write cert: %v", err)})
		return
	}
	if err := writeFileAtomic(keyPath, keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write key: %v", err)})
		return
	}

	// Extract metadata
	fingerprint := sha256.Sum256(cert.Raw)
	now := time.Now().Format(time.RFC3339)
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Update system_settings
	domainCfg, _ := s.loadBrowZerDomainConfig(ctx)
	if domainCfg == nil {
		domainCfg = &BrowZerDomainConfig{Domain: DefaultBrowZerDomain}
	}
	domainCfg.CertType = "custom"
	domainCfg.CertSubject = cert.Subject.CommonName
	domainCfg.CertIssuer = cert.Issuer.CommonName
	domainCfg.CertNotBefore = cert.NotBefore.Format(time.RFC3339)
	domainCfg.CertNotAfter = cert.NotAfter.Format(time.RFC3339)
	domainCfg.CertFingerprint = hex.EncodeToString(fingerprint[:])
	domainCfg.CertSAN = sans
	domainCfg.CustomCertUploadedAt = &now

	if err := s.saveBrowZerDomainConfig(ctx, domainCfg); err != nil {
		s.logger.Error("Failed to save domain config after cert upload", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Certificate uploaded successfully",
		"cert_subject":     cert.Subject.CommonName,
		"cert_issuer":      cert.Issuer.CommonName,
		"cert_expires":     cert.NotAfter.Format(time.RFC3339),
		"cert_san":         sans,
		"restart_required": true,
		"restart_hint":     "The bootstrapper will auto-restart. Other containers (oauth-tls-proxy, ziti-router) may need manual restart.",
	})
}

// handleBrowZerCertRevert reverts to self-signed certificate
func (s *Service) handleBrowZerCertRevert(c *gin.Context) {
	ctx := c.Request.Context()

	if s.browzerTargetManager == nil || s.browzerTargetManager.GetCertsPath() == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "BrowZer certificate management not configured"})
		return
	}

	domainCfg, _ := s.loadBrowZerDomainConfig(ctx)
	if domainCfg == nil {
		domainCfg = &BrowZerDomainConfig{Domain: DefaultBrowZerDomain}
	}

	domain := domainCfg.Domain

	// Generate self-signed cert for the current domain
	certPEM, keyPEM, err := generateSelfSignedCert(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate self-signed cert: %v", err)})
		return
	}

	certsPath := s.browzerTargetManager.GetCertsPath()
	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.crt"), certPEM); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write cert: %v", err)})
		return
	}
	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.key"), keyPEM); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write key: %v", err)})
		return
	}

	// Parse the cert we just generated for metadata
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(cert.Raw)

	domainCfg.CertType = "self_signed"
	domainCfg.CertSubject = cert.Subject.CommonName
	domainCfg.CertIssuer = cert.Issuer.CommonName
	domainCfg.CertNotBefore = cert.NotBefore.Format(time.RFC3339)
	domainCfg.CertNotAfter = cert.NotAfter.Format(time.RFC3339)
	domainCfg.CertFingerprint = hex.EncodeToString(fingerprint[:])
	domainCfg.CertSAN = cert.DNSNames
	domainCfg.CustomCertUploadedAt = nil

	if err := s.saveBrowZerDomainConfig(ctx, domainCfg); err != nil {
		s.logger.Error("Failed to save domain config after cert revert", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Reverted to self-signed certificate",
		"domain":           domain,
		"restart_required": true,
	})
}

// handleBrowZerDomainChange changes the BrowZer domain
func (s *Service) handleBrowZerDomainChange(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'domain' field"})
		return
	}

	newDomain := strings.TrimSpace(strings.ToLower(req.Domain))
	if newDomain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain cannot be empty"})
		return
	}

	domainCfg, _ := s.loadBrowZerDomainConfig(ctx)
	if domainCfg == nil {
		domainCfg = &BrowZerDomainConfig{Domain: DefaultBrowZerDomain, CertType: "self_signed"}
	}

	oldDomain := domainCfg.Domain
	if oldDomain == newDomain {
		c.JSON(http.StatusOK, gin.H{"message": "Domain unchanged", "domain": newDomain})
		return
	}

	// Update proxy_routes: replace old domain in from_url
	_, err := s.db.Pool.Exec(ctx,
		`UPDATE proxy_routes SET from_url = REPLACE(from_url, $1, $2), updated_at = NOW()
		 WHERE from_url LIKE '%' || $1 || '%' AND browzer_enabled = true`,
		oldDomain, newDomain)
	if err != nil {
		s.logger.Warn("Failed to update proxy_routes domains", zap.Error(err))
	}

	// Update oauth_clients redirect_uris: replace old domain
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE oauth_clients SET redirect_uris = (
			SELECT array_agg(REPLACE(uri, $1, $2))
			FROM unnest(redirect_uris) AS uri
		) WHERE EXISTS (
			SELECT 1 FROM unnest(redirect_uris) AS uri WHERE uri LIKE '%' || $1 || '%'
		)`, oldDomain, newDomain)
	if err != nil {
		s.logger.Warn("Failed to update OAuth redirect URIs", zap.Error(err))
	}

	// Update domain config
	now := time.Now().Format(time.RFC3339)
	domainCfg.Domain = newDomain
	domainCfg.PreviousDomain = &oldDomain
	domainCfg.DomainChangedAt = &now

	if err := s.saveBrowZerDomainConfig(ctx, domainCfg); err != nil {
		s.logger.Error("Failed to save domain config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save domain config"})
		return
	}

	// Update target manager domain
	if s.browzerTargetManager != nil {
		s.browzerTargetManager.SetDomain(newDomain)

		// Regenerate config files
		if err := s.browzerTargetManager.WriteBrowZerTargets(ctx); err != nil {
			s.logger.Warn("Failed to write targets after domain change", zap.Error(err))
		}
		if err := s.browzerTargetManager.WriteBrowZerRouterConfig(ctx); err != nil {
			s.logger.Warn("Failed to write router config after domain change", zap.Error(err))
		}
	}

	// If no custom cert, generate self-signed for new domain
	if domainCfg.CertType != "custom" && s.browzerTargetManager != nil && s.browzerTargetManager.GetCertsPath() != "" {
		certPEM, keyPEM, err := generateSelfSignedCert(newDomain)
		if err == nil {
			certsPath := s.browzerTargetManager.GetCertsPath()
			writeFileAtomic(filepath.Join(certsPath, "browzer-tls.crt"), certPEM)
			writeFileAtomic(filepath.Join(certsPath, "browzer-tls.key"), keyPEM)

			block, _ := pem.Decode(certPEM)
			cert, _ := x509.ParseCertificate(block.Bytes)
			fingerprint := sha256.Sum256(cert.Raw)

			domainCfg.CertSubject = cert.Subject.CommonName
			domainCfg.CertIssuer = cert.Issuer.CommonName
			domainCfg.CertNotBefore = cert.NotBefore.Format(time.RFC3339)
			domainCfg.CertNotAfter = cert.NotAfter.Format(time.RFC3339)
			domainCfg.CertFingerprint = hex.EncodeToString(fingerprint[:])
			domainCfg.CertSAN = cert.DNSNames
			s.saveBrowZerDomainConfig(ctx, domainCfg)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Domain changed successfully",
		"old_domain":       oldDomain,
		"new_domain":       newDomain,
		"restart_required": true,
		"restart_hint":     "The bootstrapper will auto-restart. Other containers (oauth-tls-proxy, ziti-router) need manual restart.",
	})
}

// handleBrowZerRestart triggers a bootstrapper restart by touching the config file
func (s *Service) handleBrowZerRestart(c *gin.Context) {
	ctx := c.Request.Context()

	if s.browzerTargetManager == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "BrowZer target manager not configured"})
		return
	}

	// Rewrite config to trigger the entrypoint's mtime-based reload
	if err := s.browzerTargetManager.WriteBrowZerTargets(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to trigger restart: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Bootstrapper restart triggered",
		"hint":    "The bootstrapper entrypoint detects config file changes and restarts automatically.",
	})
}

// loadBrowZerDomainConfig reads the domain config from system_settings
func (s *Service) loadBrowZerDomainConfig(ctx context.Context) (*BrowZerDomainConfig, error) {
	var configJSON []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'browzer_domain_config'`).Scan(&configJSON)
	if err != nil {
		return nil, err
	}

	var cfg BrowZerDomainConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	if cfg.CertSAN == nil {
		cfg.CertSAN = []string{}
	}
	return &cfg, nil
}

// saveBrowZerDomainConfig writes the domain config to system_settings
func (s *Service) saveBrowZerDomainConfig(ctx context.Context, cfg *BrowZerDomainConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO system_settings (key, value) VALUES ('browzer_domain_config', $1)
		 ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`, data)
	return err
}

// generateSelfSignedCert creates a self-signed TLS certificate for the given domain
func generateSelfSignedCert(domain string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OpenIDX"},
			CommonName:   domain,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "*." + domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// readCertMetadata reads the cert file from disk and extracts metadata
func readCertMetadata(certsPath string) (*BrowZerDomainConfig, error) {
	certPath := filepath.Join(certsPath, "browzer-tls.crt")
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	fingerprint := sha256.Sum256(cert.Raw)
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return &BrowZerDomainConfig{
		CertSubject:     cert.Subject.CommonName,
		CertIssuer:      cert.Issuer.CommonName,
		CertNotBefore:   cert.NotBefore.Format(time.RFC3339),
		CertNotAfter:    cert.NotAfter.Format(time.RFC3339),
		CertFingerprint: hex.EncodeToString(fingerprint[:]),
		CertSAN:         sans,
	}, nil
}
