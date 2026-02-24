// ============================================================================
// OpenIDX Production Certbot Tests
// Tests for certbot-entrypoint.sh script validation
// ============================================================================

package docker

import (
	"os"
	"strings"
	"testing"
)

// TestCertbotDomainValidation validates domain configuration in certbot script
func TestCertbotDomainValidation(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate CERTBOT_DOMAIN variable
	if !strings.Contains(contentStr, "CERTBOT_DOMAIN") {
		t.Error("Missing CERTBOT_DOMAIN variable")
	}

	// Validate default domain
	if !strings.Contains(contentStr, "openidx.tdv.org") {
		t.Error("Script should reference production domain")
	}

	// Validate www subdomain is included
	if !strings.Contains(contentStr, "www.$DOMAIN") {
		t.Error("Certificate should include www subdomain")
	}
}

// TestCertbotEmailConfiguration validates email configuration
func TestCertbotEmailConfiguration(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate CERTBOT_EMAIL variable
	if !strings.Contains(contentStr, "CERTBOT_EMAIL") {
		t.Error("Missing CERTBOT_EMAIL variable")
	}

	// Validate --email flag usage
	if !strings.Contains(contentStr, "--email") {
		t.Error("Script should use --email flag for certbot")
	}

	// Validate --agree-tos flag
	if !strings.Contains(contentStr, "--agree-tos") {
		t.Error("Script should auto-agree to Let's Encrypt TOS")
	}

	// Validate non-interactive mode
	if !strings.Contains(contentStr, "--non-interactive") {
		t.Error("Script should run in non-interactive mode")
	}
}

// TestCertbotWebrootConfiguration validates webroot authentication
func TestCertbotWebrootConfiguration(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate webroot path
	if !strings.Contains(contentStr, "--webroot") {
		t.Error("Should use webroot authentication method")
	}

	if !strings.Contains(contentStr, "--webroot-path") {
		t.Error("Should specify webroot path")
	}

	// Validate webroot variable
	if !strings.Contains(contentStr, "WEBROOT=") {
		t.Error("Should define WEBROOT variable")
	}

	// Validate default webroot
	if !strings.Contains(contentStr, "/var/www/certbot") {
		t.Error("Should use /var/www/certbot as webroot")
	}
}

// TestCertbotCertificateValidation validates certificate checks
func TestCertbotCertificateValidation(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate certificate file check
	if !strings.Contains(contentStr, "fullchain.pem") {
		t.Error("Should check for fullchain.pem")
	}

	// Validate certificate expiry check with openssl
	if !strings.Contains(contentStr, "openssl x509 -checkend") {
		t.Error("Should check certificate expiry with openssl")
	}

	// Validate 30-day threshold (2592000 seconds)
	if !strings.Contains(contentStr, "2592000") {
		t.Error("Should use 30-day threshold for renewal")
	}
}

// TestCertbotRenewalLogic validates certificate renewal logic
func TestCertbotRenewalLogic(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate certbot renew command
	if !strings.Contains(contentStr, "certbot renew") {
		t.Error("Should have certbot renew command")
	}

	// Validate renewal with webroot
	if !strings.Contains(contentStr, "certbot renew --webroot") {
		t.Error("Should use webroot for renewal")
	}

	// Validate nginx reload after renewal
	if !strings.Contains(contentStr, "nginx -s reload") {
		t.Error("Should reload nginx after renewal")
	}

	// Validate renewal daemon/loop
	if !strings.Contains(contentStr, "while true") {
		t.Error("Should have renewal loop")
	}
}

// TestCertbotLogging validates logging configuration
func TestCertbotLogging(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate log directory
	if !strings.Contains(contentStr, "LOG_DIR") {
		t.Error("Should define LOG_DIR variable")
	}

	// Validate config directory
	if !strings.Contains(contentStr, "CONFIG_DIR") {
		t.Error("Should define CONFIG_DIR variable")
	}

	// Validate log functions
	if !strings.Contains(contentStr, "log()") {
		t.Error("Should have log function")
	}

	if !strings.Contains(contentStr, "warn()") {
		t.Error("Should have warn function")
	}

	if !strings.Contains(contentStr, "error()") {
		t.Error("Should have error function")
	}
}

// TestCertbotStagingMode validates staging environment support
func TestCertbotStagingMode(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate staging flag variable
	if !strings.Contains(contentStr, "CERTBOT_STAGING") {
		t.Error("Should support CERTBOT_STAGING variable")
	}

	// Validate --staging flag usage
	if !strings.Contains(contentStr, "--staging") {
		t.Error("Should support --staging flag for testing")
	}
}

// TestCertbotErrorHandling validates error handling
func TestCertbotErrorHandling(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate set -e for error handling
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Script should use 'set -e' for error handling")
	}

	// Validate directory creation checks
	if strings.Count(contentStr, "mkdir -p") < 2 {
		t.Error("Should create required directories")
	}
}

// TestCertbotNginxReload validates nginx reload logic
func TestCertbotNginxReload(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate nginx test command
	if !strings.Contains(contentStr, "nginx -t") {
		t.Error("Should test nginx configuration before reload")
	}

	// Validate nginx reload command
	if !strings.Contains(contentStr, "nginx -s reload") {
		t.Error("Should reload nginx after certificate update")
	}

	// Validate post-hook for renewal
	if !strings.Contains(contentStr, "--post-hook") {
		t.Error("Should use post-hook for nginx reload during renewal")
	}
}

// TestCertbotVolumePaths validates volume path configuration
func TestCertbotVolumePaths(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"
	composePath := "docker-compose.prod.yml"

	scriptContent, _ := os.ReadFile(scriptPath)
	composeContent, _ := os.ReadFile(composePath)

	scriptStr := string(scriptContent)
	composeStr := string(composeContent)

	// Validate certbot webroot volume in compose
	if !strings.Contains(composeStr, "certbot_webroot") {
		t.Error("Missing certbot_webroot volume in compose")
	}

	// Validate certbot certs volume in compose
	if !strings.Contains(composeStr, "certbot_certs") {
		t.Error("Missing certbot_certs volume in compose")
	}

	// Validate script uses /etc/letsencrypt for config
	if !strings.Contains(scriptStr, "/etc/letsencrypt") {
		t.Error("Script should use /etc/letsencrypt for config")
	}

	// Validate script uses /var/log/letsencrypt for logs
	if !strings.Contains(scriptStr, "/var/log/letsencrypt") {
		t.Error("Script should use /var/log/letsencrypt for logs")
	}
}

// TestCertbotEntrypointMount validates entrypoint is mounted correctly
func TestCertbotEntrypointMount(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Find certbot service section
	certbotIndex := strings.Index(contentStr, "certbot:")
	if certbotIndex == -1 {
		t.Skip("Certbot service not found in compose")
		return
	}

	// Extract certbot service section (next 1000 chars should be enough)
	certbotSection := contentStr[certbotIndex:certbotIndex+1000]

	// Validate entrypoint script is mounted
	if !strings.Contains(certbotSection, "/scripts/certbot-entrypoint.sh") {
		t.Error("Certbot entrypoint script should be mounted")
	}
}

// TestCertbotDailyRenewalSchedule validates renewal schedule
func TestCertbotDailyRenewalSchedule(t *testing.T) {
	scriptPath := "scripts/certbot-entrypoint.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read certbot-entrypoint.sh: %v", err)
	}

	contentStr := string(content)

	// Validate sleep for daily check (86400 seconds)
	if !strings.Contains(contentStr, "86400") {
		t.Error("Should check certificate daily (86400 seconds)")
	}

	// Validate renewal happens in background/loop
	if !strings.Contains(contentStr, "while true") {
		t.Error("Should run continuous renewal loop")
	}

	// Validate trap for graceful shutdown
	if !strings.Contains(contentStr, "trap exit") {
		t.Error("Should handle graceful shutdown")
	}
}
