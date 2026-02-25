// This file exports all page components for the admin console

// Core Pages
export { DashboardPage as Dashboard } from './dashboard'
export { UsersPage as Users } from './users'
export { AccessReviewsPage as AccessReviews } from './access-reviews'
export { PoliciesPage as Policies } from './policies'
export { AuditLogsPage as AuditLogs } from './audit-logs'
export { SettingsPage as Settings } from './settings'

// Identity & Access
export { GroupsPage as Groups } from './groups'
export { RolesPage as Roles } from './roles'
export { DirectoriesPage as Directories } from './directories'
export { ServiceAccountsPage as ServiceAccounts } from './service-accounts'
export { IdentityProvidersPage as IdentityProviders } from './identity-providers'

// Applications
export { ApplicationsPage as Applications } from './applications'
export { AppLauncherPage as AppLauncher } from './app-launcher'
export { AppPublishPage as AppPublish } from './app-publish'
export { ProvisioningRulesPage as ProvisioningRules } from './provisioning-rules'
export { LifecycleWorkflowsPage as LifecycleWorkflows } from './lifecycle-workflows'
export { FederationConfigPage as FederationConfig } from './federation-config'
export { SocialProvidersPage as SocialProviders } from './social-providers'

// Network & Access
export { ProxyRoutesPage as ProxyRoutes } from './proxy-routes'
export { ZitiNetworkPage as ZitiNetwork } from './ziti-network'
export { ZitiDiscoveryPage as ZitiDiscovery } from './ziti-discovery'
export { BrowZerManagementPage as BrowzerManagement } from './browzer-management'
export { CertificatesPage as Certificates } from './certificates'
export { DevicesPage as Devices } from './devices'

// Governance
export { ApprovalPoliciesPage as ApprovalPolicies } from './approval-policies'
export { CertificationCampaignsPage as CertificationCampaigns } from './certification-campaigns'
export { EntitlementsPage as Entitlements } from './entitlements'
export { ABACPoliciesPage as ABACPolicies } from './abac-policies'
export { SessionsAdminPage as SessionsAdmin } from './sessions-admin'
export { SecurityAlertsPage as SecurityAlerts } from './security-alerts'
export { PrivacyDashboardPage as PrivacyDashboard } from './privacy-dashboard'
export { ConsentManagementPage as ConsentManagement } from './consent-management'

// Security & MFA
export { default as MFAManagement } from './mfa-management'
export { RiskPoliciesPage as RiskPolicies } from './risk-policies'
export { default as LoginAnomalies } from './login-anomalies'
export { HardwareTokensPage as HardwareTokens } from './hardware-tokens'
export { DeviceTrustApprovalPage as DeviceTrustApproval } from './device-trust-approval'
export { MFABypassCodesPage as MFABypassCodes } from './mfa-bypass-codes'
export { PasswordlessSettingsPage as PasswordlessSettings } from './passwordless-settings'
export { SecurityKeysPage as SecurityKeys } from './security-keys'
export { PushDevicesPage as PushDevices } from './push-devices'

// Audit & Reports
export { UnifiedAuditPage as UnifiedAudit } from './unified-audit'
export { AdminAuditLogPage as AdminAuditLog } from './admin-audit-log'
export { LoginAnalyticsPage as LoginAnalytics } from './login-analytics'
export { AuthAnalyticsPage as AuthAnalytics } from './auth-analytics'
export { UsageAnalyticsPage as UsageAnalytics } from './usage-analytics'
export { RiskDashboardPage as RiskDashboard } from './risk-dashboard'
export { ComplianceReportsPage as ComplianceReports } from './compliance-reports'
export { ComplianceDashboardPage as ComplianceDashboard } from './compliance-dashboard'
export { ReportsPage as Reports } from './reports'

// AI & Intelligence
export { AIAgentsPage as AIAgents } from './ai-agents'
export { ISPMDashboardPage as ISPMDashboard } from './ispm-dashboard'
export { AIRecommendationsPage as AIRecommendations } from './ai-recommendations'
export { PredictiveAnalyticsPage as PredictiveAnalytics } from './predictive-analytics'

// Enterprise
export { SAMLServiceProvidersPage as SAMLServiceProviders } from './saml-service-providers'
export { BulkOperationsPage as BulkOperations } from './bulk-operations'
export { EmailTemplatesPage as EmailTemplates } from './email-templates'
export { LifecyclePoliciesPage as LifecyclePolicies } from './lifecycle-policies'
export { AttestationCampaignsPage as AttestationCampaigns } from './attestation-campaigns'
export { AuditArchivalPage as AuditArchival } from './audit-archival'

// Developer
export { ApiExplorerPage as APIExplorer } from './api-explorer'
export { OAuthPlaygroundPage as OAuthPlayground } from './oauth-playground'
export { DeveloperSettingsPage as DeveloperSettings } from './developer-settings'
export { ErrorCatalogPage as ErrorCatalog } from './error-catalog'
export { ApiDocsPage as APIDocs } from './api-docs'

// System
export { SystemHealthPage as SystemHealth } from './system-health'
export { OrganizationsPage as Organizations } from './organizations'
export { DelegationsPage as Delegations } from './delegations'
export { WebhooksPage as Webhooks } from './webhooks'
export { TenantManagementPage as TenantManagement } from './tenant-management'
export { NotificationAdminPage as NotificationAdmin } from './notification-admin'

// User-facing pages
export { LoginPage as Login } from './login'
export { LandingPage as Landing } from './landing'
export { ForgotPasswordPage as ForgotPassword } from './forgot-password'
export { ResetPasswordPage as ResetPassword } from './reset-password'
export { MagicLinkVerifyPage as MagicLinkVerify } from './magic-link-verify'

// My Pages
export { MyAccessPage as MyAccess } from './my-access'
export { MyDevicesPage as MyDevices } from './my-devices'
export { TrustedBrowsersPage as TrustedBrowsers } from './trusted-browsers'
export { AccessRequestsPage as AccessRequests } from './access-requests'
export { NotificationCenterPage as NotificationCenter } from './notification-center'
export { NotificationPreferencesPage as NotificationPreferences } from './notification-preferences'

// Other pages
export { ReviewDetailPage as ReviewDetail } from './review-detail'
