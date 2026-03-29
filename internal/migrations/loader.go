//go:build !embed_migrations

package migrations

import (
	"embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed *.sql
var loaderSQLFiles embed.FS

// LoadMigrations loads all migrations from the embedded filesystem
func (m *Migrator) LoadMigrations() ([]*Migration, error) {
	// For embedded migrations, use predefined list
	return allMigrations(), nil
}

// allMigrations returns the complete list of migrations
// This is generated from the migrations directory
func allMigrations() []*Migration {
	return []*Migration{
		{
			Version:     1,
			Name:        "initial_schema",
			Description: "Initial database schema with core tables",
			UpSQL:       initialSchemaUp,
			DownSQL:     initialSchemaDown,
		},
		{
			Version:     2,
			Name:        "oauth_oidc",
			Description: "OAuth 2.0 / OIDC tables",
			UpSQL:       oauthOIDCUp,
			DownSQL:     oauthOIDCDown,
		},
		{
			Version:     3,
			Name:        "scim",
			Description: "SCIM 2.0 provisioning tables",
			UpSQL:       scimUp,
			DownSQL:     scimDown,
		},
		{
			Version:     4,
			Name:        "governance",
			Description: "Governance tables for access reviews and policies",
			UpSQL:       governanceUp,
			DownSQL:     governanceDown,
		},
		{
			Version:     5,
			Name:        "mfa",
			Description: "Multi-factor authentication tables (TOTP, WebAuthn, Push)",
			UpSQL:       mfaUp,
			DownSQL:     mfaDown,
		},
		{
			Version:     6,
			Name:        "sessions",
			Description: "Session management tables",
			UpSQL:       sessionsUp,
			DownSQL:     sessionsDown,
		},
		{
			Version:     7,
			Name:        "applications",
			Description: "Application management tables",
			UpSQL:       applicationsUp,
			DownSQL:     applicationsDown,
		},
		{
			Version:     8,
			Name:        "audit_compliance",
			Description: "Audit and compliance tables",
			UpSQL:       auditComplianceUp,
			DownSQL:     auditComplianceDown,
		},
		{
			Version:     9,
			Name:        "indexes",
			Description: "Performance indexes",
			UpSQL:       indexesUp,
			DownSQL:     indexesDown,
		},
		{
			Version:     10,
			Name:        "seed_data",
			Description: "Initial seed data (admin user, roles, groups)",
			UpSQL:       seedDataUp,
			DownSQL:     seedDataDown,
		},
		{
			Version:     11,
			Name:        "identity_providers",
			Description: "External identity provider integration (OIDC/SAML)",
			UpSQL:       identityProvidersUp,
			DownSQL:     identityProvidersDown,
		},
		{
			Version:     12,
			Name:        "provisioning_rules",
			Description: "Provisioning rules and password reset tokens",
			UpSQL:       provisioningRulesUp,
			DownSQL:     provisioningRulesDown,
		},
		{
			Version:     13,
			Name:        "permissions",
			Description: "Permissions and role permissions tables",
			UpSQL:       permissionsUp,
			DownSQL:     permissionsDown,
		},
		{
			Version:     14,
			Name:        "system_settings",
			Description: "System settings and configuration",
			UpSQL:       systemSettingsUp,
			DownSQL:     systemSettingsDown,
		},
		{
			Version:     15,
			Name:        "directory_integrations",
			Description: "Directory integration tables",
			UpSQL:       directoryIntegrationsUp,
			DownSQL:     directoryIntegrationsDown,
		},
		{
			Version:     16,
			Name:        "proxy_routes",
			Description: "Zero Trust Access Proxy routes and sessions",
			UpSQL:       proxyRoutesUp,
			DownSQL:     proxyRoutesDown,
		},
		{
			Version:     17,
			Name:        "openziti",
			Description: "OpenZiti integration tables",
			UpSQL:       openzitiUp,
			DownSQL:     openzitiDown,
		},
		{
			Version:     18,
			Name:        "directory_sync",
			Description: "Directory sync state and logs",
			UpSQL:       directorySyncUp,
			DownSQL:     directorySyncDown,
		},
		{
			Version:     19,
			Name:        "conditional_access",
			Description: "Conditional access and risk engine tables",
			UpSQL:       conditionalAccessUp,
			DownSQL:     conditionalAccessDown,
		},
		{
			Version:     20,
			Name:        "api_keys_webhooks",
			Description: "API keys, webhooks, email verification, invitations",
			UpSQL:       apiKeysWebhooksUp,
			DownSQL:     apiKeysWebhooksDown,
		},
		{
			Version:     21,
			Name:        "access_requests",
			Description: "Access request and approval workflow tables",
			UpSQL:       accessRequestsUp,
			DownSQL:     accessRequestsDown,
		},
		{
			Version:     22,
			Name:        "security_alerts",
			Description: "Security alerts and anomaly detection",
			UpSQL:       securityAlertsUp,
			DownSQL:     securityAlertsDown,
		},
		{
			Version:     23,
			Name:        "password_management",
			Description: "Password history and credential rotation",
			UpSQL:       passwordManagementUp,
			DownSQL:     passwordManagementDown,
		},
		{
			Version:     24,
			Name:        "session_enhancements",
			Description: "Session management enhancements",
			UpSQL:       sessionEnhancementsUp,
			DownSQL:     sessionEnhancementsDown,
		},
		{
			Version:     25,
			Name:        "multitenancy",
			Description: "Multi-tenancy support with organizations",
			UpSQL:       multitenancyUp,
			DownSQL:     multitenancyDown,
		},
		{
			Version:     26,
			Name:        "reporting",
			Description: "Advanced reporting tables",
			UpSQL:       reportingUp,
			DownSQL:     reportingDown,
		},
		{
			Version:     27,
			Name:        "self_service",
			Description: "Self-service portal tables",
			UpSQL:       selfServiceUp,
			DownSQL:     selfServiceDown,
		},
		{
			Version:     28,
			Name:        "notifications",
			Description: "Notification system tables",
			UpSQL:       notificationsUp,
			DownSQL:     notificationsDown,
		},
		{
			Version:     29,
			Name:        "ziti_enhanced",
			Description: "OpenZiti enhanced features (posture checks, policy sync)",
			UpSQL:       zitiEnhancedUp,
			DownSQL:     zitiEnhancedDown,
		},
	}
}

// parseMigrationVersion extracts the version number from a filename like "001_name.up.sql"
func parseMigrationVersion(filename string) (int, string, string, error) {
	// Expected format: XXX_name.[up|down].sql
	parts := strings.Split(filename, ".")
	if len(parts) < 3 {
		return 0, "", "", fmt.Errorf("invalid migration filename format: %s", filename)
	}

	versionStr := parts[0]
	direction := parts[1]

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid version number: %s", versionStr)
	}

	// Extract name (remove direction and extension)
	name := strings.Join(parts[1:len(parts)-1], "_")
	name = strings.ReplaceAll(name, "_" + direction, "")

	return version, name, direction, nil
}
