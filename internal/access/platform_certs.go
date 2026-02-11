// Package access - Platform-wide TLS certificate management.
// Manages the shared platform certificate used by oauth-tls-proxy, ziti-controller-proxy,
// ziti-router, browzer-bootstrapper, and optionally APISIX.
// Also provides APISIX SSL enable/disable by writing ssls entries into apisix.yaml.
package access

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PlatformCertConsumer represents a service consuming the platform TLS cert
type PlatformCertConsumer struct {
	Name        string `json:"name"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Status      string `json:"status"`
	Description string `json:"description"`
	RestartHint string `json:"restart_hint"`
}

// PlatformCertInfo is the response for GET /certificates/platform
type PlatformCertInfo struct {
	CertType     string                 `json:"cert_type"`
	Subject      string                 `json:"subject"`
	Issuer       string                 `json:"issuer"`
	NotBefore    string                 `json:"not_before"`
	NotAfter     string                 `json:"not_after"`
	DaysLeft     int                    `json:"days_left"`
	Fingerprint  string                 `json:"fingerprint"`
	SANs         []string               `json:"sans"`
	SerialNumber string                 `json:"serial_number"`
	UploadedAt   *string                `json:"uploaded_at"`
	Consumers    []PlatformCertConsumer `json:"consumers"`
}

// APISIXSSLConfig is stored in system_settings under key "apisix_ssl_config"
type APISIXSSLConfig struct {
	Enabled         bool   `json:"enabled"`
	LastUpdated     string `json:"last_updated"`
	CertFingerprint string `json:"cert_fingerprint"`
}

// CertExpiryAlert represents a certificate nearing expiry
type CertExpiryAlert struct {
	Source   string `json:"source"`
	Name     string `json:"name"`
	DaysLeft int    `json:"days_left"`
	Severity string `json:"severity"`
	NotAfter string `json:"not_after"`
}

// PlatformCertHealthStatus is the combined health response
type PlatformCertHealthStatus struct {
	Platform     *PlatformCertInfo `json:"platform"`
	APISIX       *APISIXSSLConfig  `json:"apisix"`
	ExpiryAlerts []CertExpiryAlert `json:"expiry_alerts"`
}

// handleGetPlatformCert returns platform cert info + all consumers
func (s *Service) handleGetPlatformCert(c *gin.Context) {
	info, err := s.buildPlatformCertInfo(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, PlatformCertInfo{
			CertType:  "self_signed",
			Consumers: s.buildConsumerList(c.Request.Context()),
			SANs:      []string{},
		})
		return
	}
	c.JSON(http.StatusOK, info)
}

// handleUploadPlatformCert handles platform-wide cert upload
func (s *Service) handleUploadPlatformCert(c *gin.Context) {
	ctx := c.Request.Context()

	certsPath := ""
	if s.browzerTargetManager != nil {
		certsPath = s.browzerTargetManager.GetCertsPath()
	}
	if certsPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate management not configured"})
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

	// Read cert
	cf, err := certFile.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read cert file"})
		return
	}
	defer cf.Close()
	certBytes := make([]byte, certFile.Size)
	cf.Read(certBytes)

	// Read key
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
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
			if _, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot parse private key (expected PKCS8, EC, or PKCS1)"})
				return
			}
		}
	}

	// Write cert and key to shared volume
	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.crt"), certBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write cert: %v", err)})
		return
	}
	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.key"), keyBytes); err != nil {
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

	// Update browzer_domain_config in system_settings
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
	s.saveBrowZerDomainConfig(ctx, domainCfg)

	// If APISIX SSL is enabled, update apisix.yaml with new cert
	apisixCfg, _ := s.loadAPISIXSSLConfig(ctx)
	if apisixCfg != nil && apisixCfg.Enabled && s.apisixConfigPath != "" {
		if err := s.updateAPISIXSSL(certBytes, keyBytes, sans); err != nil {
			s.logger.Warn("Failed to update APISIX SSL config", zap.Error(err))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Platform certificate uploaded successfully",
		"cert_subject":     cert.Subject.CommonName,
		"cert_issuer":      cert.Issuer.CommonName,
		"cert_expires":     cert.NotAfter.Format(time.RFC3339),
		"cert_san":         sans,
		"restart_required": true,
		"restart_hint":     "Restart these containers to pick up the new certificate:\ndocker restart openidx-oauth-tls-proxy openidx-ziti-controller-proxy openidx-ziti-router\nThe BrowZer bootstrapper restarts automatically.",
		"consumers":        s.buildConsumerList(ctx),
	})
}

// handleRevertPlatformCert reverts to self-signed certificate
func (s *Service) handleRevertPlatformCert(c *gin.Context) {
	ctx := c.Request.Context()

	certsPath := ""
	if s.browzerTargetManager != nil {
		certsPath = s.browzerTargetManager.GetCertsPath()
	}
	if certsPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate management not configured"})
		return
	}

	// Get current domain
	domain := DefaultBrowZerDomain
	if s.browzerTargetManager != nil {
		domain = s.browzerTargetManager.GetDomain()
	}

	// Generate self-signed cert
	certPEM, keyPEM, err := generateSelfSignedCert(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate cert: %v", err)})
		return
	}

	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.crt"), certPEM); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write cert: %v", err)})
		return
	}
	if err := writeFileAtomic(filepath.Join(certsPath, "browzer-tls.key"), keyPEM); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write key: %v", err)})
		return
	}

	// Update metadata
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	fingerprint := sha256.Sum256(cert.Raw)

	domainCfg, _ := s.loadBrowZerDomainConfig(ctx)
	if domainCfg == nil {
		domainCfg = &BrowZerDomainConfig{Domain: domain}
	}
	domainCfg.CertType = "self_signed"
	domainCfg.CertSubject = cert.Subject.CommonName
	domainCfg.CertIssuer = cert.Issuer.CommonName
	domainCfg.CertNotBefore = cert.NotBefore.Format(time.RFC3339)
	domainCfg.CertNotAfter = cert.NotAfter.Format(time.RFC3339)
	domainCfg.CertFingerprint = hex.EncodeToString(fingerprint[:])
	domainCfg.CertSAN = cert.DNSNames
	domainCfg.CustomCertUploadedAt = nil
	s.saveBrowZerDomainConfig(ctx, domainCfg)

	// If APISIX SSL is enabled, update with new cert
	apisixCfg, _ := s.loadAPISIXSSLConfig(ctx)
	if apisixCfg != nil && apisixCfg.Enabled && s.apisixConfigPath != "" {
		s.updateAPISIXSSL(certPEM, keyPEM, cert.DNSNames)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "Reverted to self-signed certificate",
		"domain":           domain,
		"restart_required": true,
	})
}

// handleEnableAPISIXSSL enables HTTPS on APISIX by injecting ssls into apisix.yaml
func (s *Service) handleEnableAPISIXSSL(c *gin.Context) {
	ctx := c.Request.Context()

	if s.apisixConfigPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "APISIX config path not configured"})
		return
	}

	certsPath := ""
	if s.browzerTargetManager != nil {
		certsPath = s.browzerTargetManager.GetCertsPath()
	}
	if certsPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Certificate path not configured"})
		return
	}

	// Read current cert
	certPEM, err := os.ReadFile(filepath.Join(certsPath, "browzer-tls.crt"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot read platform certificate"})
		return
	}
	keyPEM, err := os.ReadFile(filepath.Join(certsPath, "browzer-tls.key"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot read platform key"})
		return
	}

	// Extract SANs from cert
	block, _ := pem.Decode(certPEM)
	if block == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid cert PEM on disk"})
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot parse cert on disk"})
		return
	}
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Inject ssls section into apisix.yaml
	if err := s.updateAPISIXSSL(certPEM, keyPEM, sans); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update APISIX config: %v", err)})
		return
	}

	// Save state
	fingerprint := sha256.Sum256(cert.Raw)
	now := time.Now().Format(time.RFC3339)
	s.saveAPISIXSSLConfig(ctx, &APISIXSSLConfig{
		Enabled:         true,
		LastUpdated:     now,
		CertFingerprint: hex.EncodeToString(fingerprint[:]),
	})

	s.logger.Info("APISIX SSL enabled", zap.String("config_path", s.apisixConfigPath))
	c.JSON(http.StatusOK, gin.H{
		"message": "APISIX HTTPS enabled on port 8443",
		"hint":    "APISIX auto-reloads configuration. HTTPS is available at https://localhost:8443",
	})
}

// handleDisableAPISIXSSL removes ssls section from apisix.yaml
func (s *Service) handleDisableAPISIXSSL(c *gin.Context) {
	ctx := c.Request.Context()

	if s.apisixConfigPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "APISIX config path not configured"})
		return
	}

	if err := s.removeAPISIXSSL(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update APISIX config: %v", err)})
		return
	}

	now := time.Now().Format(time.RFC3339)
	s.saveAPISIXSSLConfig(ctx, &APISIXSSLConfig{
		Enabled:     false,
		LastUpdated: now,
	})

	s.logger.Info("APISIX SSL disabled")
	c.JSON(http.StatusOK, gin.H{
		"message": "APISIX HTTPS disabled",
	})
}

// handleGetCertStatus returns combined certificate health status
func (s *Service) handleGetCertStatus(c *gin.Context) {
	ctx := c.Request.Context()

	var platformInfo *PlatformCertInfo
	info, err := s.buildPlatformCertInfo(ctx)
	if err == nil {
		platformInfo = info
	}

	apisixCfg, _ := s.loadAPISIXSSLConfig(ctx)

	// Build expiry alerts
	var alerts []CertExpiryAlert
	if platformInfo != nil && platformInfo.DaysLeft > 0 && platformInfo.DaysLeft <= 30 {
		severity := "warning"
		if platformInfo.DaysLeft <= 7 {
			severity = "critical"
		}
		alerts = append(alerts, CertExpiryAlert{
			Source:   "platform",
			Name:     "Platform TLS Certificate",
			DaysLeft: platformInfo.DaysLeft,
			Severity: severity,
			NotAfter: platformInfo.NotAfter,
		})
	}

	c.JSON(http.StatusOK, PlatformCertHealthStatus{
		Platform:     platformInfo,
		APISIX:       apisixCfg,
		ExpiryAlerts: alerts,
	})
}

// buildPlatformCertInfo reads the cert from disk and builds the full info response
func (s *Service) buildPlatformCertInfo(ctx context.Context) (*PlatformCertInfo, error) {
	certsPath := ""
	if s.browzerTargetManager != nil {
		certsPath = s.browzerTargetManager.GetCertsPath()
	}
	if certsPath == "" {
		return nil, fmt.Errorf("certs path not configured")
	}

	certPath := filepath.Join(certsPath, "browzer-tls.crt")
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if sans == nil {
		sans = []string{}
	}

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	// Get cert type from DB
	certType := "self_signed"
	var uploadedAt *string
	domainCfg, _ := s.loadBrowZerDomainConfig(ctx)
	if domainCfg != nil {
		certType = domainCfg.CertType
		uploadedAt = domainCfg.CustomCertUploadedAt
	}

	return &PlatformCertInfo{
		CertType:     certType,
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		DaysLeft:     daysLeft,
		Fingerprint:  hex.EncodeToString(fingerprint[:]),
		SANs:         sans,
		SerialNumber: cert.SerialNumber.String(),
		UploadedAt:   uploadedAt,
		Consumers:    s.buildConsumerList(ctx),
	}, nil
}

// buildConsumerList returns the list of services consuming the platform cert
func (s *Service) buildConsumerList(ctx context.Context) []PlatformCertConsumer {
	consumers := []PlatformCertConsumer{
		{
			Name:        "BrowZer Bootstrapper",
			Port:        443,
			Protocol:    "HTTPS",
			Status:      "active",
			Description: "Serves the BrowZer SDK to browsers",
			RestartHint: "Auto-restarts on cert change",
		},
		{
			Name:        "OAuth TLS Proxy",
			Port:        8446,
			Protocol:    "HTTPS",
			Status:      "active",
			Description: "TLS termination for OpenIDX OAuth service",
			RestartHint: "docker restart openidx-oauth-tls-proxy",
		},
		{
			Name:        "Ziti Controller Proxy",
			Port:        1280,
			Protocol:    "HTTPS",
			Status:      "active",
			Description: "TLS termination for Ziti management plane",
			RestartHint: "docker restart openidx-ziti-controller-proxy",
		},
		{
			Name:        "Ziti Router (WSS)",
			Port:        3023,
			Protocol:    "WSS",
			Status:      "active",
			Description: "WebSocket Secure listener for BrowZer data plane",
			RestartHint: "docker restart openidx-ziti-router",
		},
	}

	// Check if APISIX SSL is enabled
	apisixCfg, _ := s.loadAPISIXSSLConfig(ctx)
	apisixStatus := "inactive"
	if apisixCfg != nil && apisixCfg.Enabled {
		apisixStatus = "active"
	}
	consumers = append(consumers, PlatformCertConsumer{
		Name:        "APISIX Gateway",
		Port:        8443,
		Protocol:    "HTTPS",
		Status:      apisixStatus,
		Description: "API Gateway HTTPS endpoint",
		RestartHint: "APISIX auto-reloads on config change",
	})

	return consumers
}

// ---- APISIX YAML management ----

// updateAPISIXSSL reads apisix.yaml, injects ssls section, writes back atomically
func (s *Service) updateAPISIXSSL(certPEM, keyPEM []byte, sans []string) error {
	if s.apisixConfigPath == "" {
		return fmt.Errorf("APISIX config path not set")
	}

	existing, err := os.ReadFile(s.apisixConfigPath)
	if err != nil {
		return fmt.Errorf("read apisix.yaml: %w", err)
	}

	content := string(existing)

	// Remove existing ssls section if present
	content = removeAPISIXSSLSection(content)

	// Build new ssls block
	sslBlock := buildAPISIXSSLBlock(certPEM, keyPEM, sans)

	// Insert before #END marker
	if strings.Contains(content, "#END") {
		content = strings.Replace(content, "#END", sslBlock+"#END", 1)
	} else {
		content += "\n" + sslBlock
	}

	return writeFileAtomic(s.apisixConfigPath, []byte(content))
}

// removeAPISIXSSL removes the ssls section from apisix.yaml
func (s *Service) removeAPISIXSSL() error {
	if s.apisixConfigPath == "" {
		return fmt.Errorf("APISIX config path not set")
	}

	existing, err := os.ReadFile(s.apisixConfigPath)
	if err != nil {
		return fmt.Errorf("read apisix.yaml: %w", err)
	}

	content := removeAPISIXSSLSection(string(existing))
	return writeFileAtomic(s.apisixConfigPath, []byte(content))
}

// buildAPISIXSSLBlock creates the YAML ssls section with inline cert content
func buildAPISIXSSLBlock(certPEM, keyPEM []byte, sans []string) string {
	var b strings.Builder
	b.WriteString("ssls:\n")
	b.WriteString("  - id: 1\n")

	// Write cert as YAML multiline string
	b.WriteString("    cert: |\n")
	for _, line := range strings.Split(strings.TrimSpace(string(certPEM)), "\n") {
		b.WriteString("      " + line + "\n")
	}

	// Write key as YAML multiline string
	b.WriteString("    key: |\n")
	for _, line := range strings.Split(strings.TrimSpace(string(keyPEM)), "\n") {
		b.WriteString("      " + line + "\n")
	}

	// Write SNIs from SANs
	b.WriteString("    snis:\n")
	added := make(map[string]bool)
	for _, san := range sans {
		if !added[san] {
			b.WriteString(fmt.Sprintf("      - \"%s\"\n", san))
			added[san] = true
		}
	}
	// Always include localhost as fallback
	if !added["localhost"] {
		b.WriteString("      - \"localhost\"\n")
	}
	b.WriteString("\n")

	return b.String()
}

// removeAPISIXSSLSection removes the ssls: block from APISIX YAML content.
// It finds "ssls:" at column 0 and removes all lines until the next top-level key.
func removeAPISIXSSLSection(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inSSL := false
	for _, line := range lines {
		if strings.HasPrefix(line, "ssls:") {
			inSSL = true
			continue
		}
		if inSSL {
			// Check if this line is a new top-level key (not indented, not empty, not a comment)
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inSSL = false
				result = append(result, line)
			}
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// ---- system_settings helpers ----

func (s *Service) loadAPISIXSSLConfig(ctx context.Context) (*APISIXSSLConfig, error) {
	var configJSON []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = 'apisix_ssl_config'`).Scan(&configJSON)
	if err != nil {
		return nil, err
	}
	var cfg APISIXSSLConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Service) saveAPISIXSSLConfig(ctx context.Context, cfg *APISIXSSLConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO system_settings (key, value) VALUES ('apisix_ssl_config', $1)
		 ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`, data)
	return err
}
