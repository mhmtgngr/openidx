import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from '@/components/layout'
import {
  Dashboard,
  Users,
  Groups,
  Roles,
  Directories,
  ServiceAccounts,
  AccessReviews,
  Policies,
  ApprovalPolicies,
  CertificationCampaigns,
  Entitlements,
  ABACPolicies,
  SessionsAdmin,
  SecurityAlerts,
  PrivacyDashboard,
  ConsentManagement,
  AuditLogs,
  UnifiedAudit,
  AdminAuditLog,
  LoginAnalytics,
  AuthAnalytics,
  UsageAnalytics,
  RiskDashboard,
  ComplianceReports,
  ComplianceDashboard,
  Reports,
  Settings,
  Applications,
  AppLauncher,
  AppPublish,
  IdentityProviders,
  ProvisioningRules,
  LifecycleWorkflows,
  FederationConfig,
  SocialProviders,
  ProxyRoutes,
  ZitiNetwork,
  ZitiDiscovery,
  BrowzerManagement,
  Certificates,
  Devices,
  MFAManagement,
  RiskPolicies,
  LoginAnomalies,
  HardwareTokens,
  DeviceTrustApproval,
  MFABypassCodes,
  PasswordlessSettings,
  SecurityKeys,
  PushDevices,
  AIAgents,
  ISPMDashboard,
  AIRecommendations,
  PredictiveAnalytics,
  SAMLServiceProviders,
  BulkOperations,
  EmailTemplates,
  LifecyclePolicies,
  AttestationCampaigns,
  AuditArchival,
  APIExplorer,
  OAuthPlayground,
  DeveloperSettings,
  ErrorCatalog,
  APIDocs,
  SystemHealth,
  Organizations,
  Delegations,
  Webhooks,
  TenantManagement,
  NotificationAdmin,
  Login,
  Landing,
  ForgotPassword,
  ResetPassword,
  MagicLinkVerify,
  MyAccess,
  MyDevices,
  TrustedBrowsers,
  AccessRequests,
  NotificationCenter,
  NotificationPreferences,
  ReviewDetail,
} from '@/pages'
import { useAppStore } from '@/lib/store'
import { useAuth } from '@/lib/auth'

// ProtectedRoute wrapper component that checks authentication before rendering
// This prevents admin URLs from being accessible without proper authentication
interface ProtectedRouteProps {
  children: React.ReactNode
}

function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth()

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-blue-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Verifying authentication...</p>
        </div>
      </div>
    )
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  const { theme } = useAppStore()
  const { isAuthenticated, isLoading } = useAuth()

  // Apply theme
  useEffect(() => {
    const root = document.documentElement
    const isDark =
      theme === 'dark' ||
      (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)

    root.classList.toggle('dark', isDark)
  }, [theme])

  // Loading state
  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-blue-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/landing" element={<Landing />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/magic-link-verify" element={<MagicLinkVerify />} />

      {/* Protected routes with auth guard */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />

        {/* My Pages (user-facing) */}
        <Route path="profile" element={<div className="p-8"><h1 className="text-2xl font-bold">My Profile</h1><p className="text-muted-foreground">Profile management coming soon</p></div>} />
        <Route path="app-launcher" element={<AppLauncher />} />
        <Route path="my-access" element={<MyAccess />} />
        <Route path="my-devices" element={<MyDevices />} />
        <Route path="trusted-browsers" element={<TrustedBrowsers />} />
        <Route path="access-requests" element={<AccessRequests />} />
        <Route path="notification-center" element={<NotificationCenter />} />

        {/* Identity Management - Admin Protected */}
        <Route path="users" element={<Users />} />
        <Route path="groups" element={<Groups />} />
        <Route path="roles" element={<Roles />} />
        <Route path="directories" element={<Directories />} />
        <Route path="service-accounts" element={<ServiceAccounts />} />

        {/* Applications - Admin Protected */}
        <Route path="applications" element={<Applications />} />
        <Route path="identity-providers" element={<IdentityProviders />} />
        <Route path="provisioning-rules" element={<ProvisioningRules />} />
        <Route path="lifecycle-workflows" element={<LifecycleWorkflows />} />
        <Route path="social-providers" element={<SocialProviders />} />
        <Route path="federation-config" element={<FederationConfig />} />

        {/* Network & Access - Admin Protected */}
        <Route path="proxy-routes" element={<ProxyRoutes />} />
        <Route path="ziti-network" element={<ZitiNetwork />} />
        <Route path="ziti-discovery" element={<ZitiDiscovery />} />
        <Route path="browzer-management" element={<BrowzerManagement />} />
        <Route path="app-publish" element={<AppPublish />} />
        <Route path="certificates" element={<Certificates />} />
        <Route path="devices" element={<Devices />} />

        {/* Governance - Admin Protected */}
        <Route path="policies" element={<Policies />} />
        <Route path="approval-policies" element={<ApprovalPolicies />} />
        <Route path="access-reviews" element={<AccessReviews />} />
        <Route path="certification-campaigns" element={<CertificationCampaigns />} />
        <Route path="entitlements" element={<Entitlements />} />
        <Route path="abac-policies" element={<ABACPolicies />} />
        <Route path="sessions" element={<SessionsAdmin />} />
        <Route path="security-alerts" element={<SecurityAlerts />} />
        <Route path="privacy-dashboard" element={<PrivacyDashboard />} />
        <Route path="consent-management" element={<ConsentManagement />} />

        {/* Security & MFA - Admin Protected */}
        <Route path="mfa-management" element={<MFAManagement />} />
        <Route path="risk-policies" element={<RiskPolicies />} />
        <Route path="login-anomalies" element={<LoginAnomalies />} />
        <Route path="hardware-tokens" element={<HardwareTokens />} />
        <Route path="device-trust-approval" element={<DeviceTrustApproval />} />
        <Route path="mfa-bypass-codes" element={<MFABypassCodes />} />
        <Route path="passwordless-settings" element={<PasswordlessSettings />} />
        <Route path="security-keys" element={<SecurityKeys />} />
        <Route path="push-devices" element={<PushDevices />} />

        {/* Audit & Reports - Admin Protected */}
        <Route path="audit-logs" element={<AuditLogs />} />
        <Route path="unified-audit" element={<UnifiedAudit />} />
        <Route path="admin-audit-log" element={<AdminAuditLog />} />
        <Route path="login-analytics" element={<LoginAnalytics />} />
        <Route path="auth-analytics" element={<AuthAnalytics />} />
        <Route path="usage-analytics" element={<UsageAnalytics />} />
        <Route path="risk-dashboard" element={<RiskDashboard />} />
        <Route path="compliance-reports" element={<ComplianceReports />} />
        <Route path="compliance-dashboard" element={<ComplianceDashboard />} />
        <Route path="reports" element={<Reports />} />

        {/* AI & Intelligence - Admin Protected */}
        <Route path="ai-agents" element={<AIAgents />} />
        <Route path="ispm" element={<ISPMDashboard />} />
        <Route path="ai-recommendations" element={<AIRecommendations />} />
        <Route path="predictive-analytics" element={<PredictiveAnalytics />} />

        {/* Enterprise - Admin Protected */}
        <Route path="saml-service-providers" element={<SAMLServiceProviders />} />
        <Route path="bulk-operations" element={<BulkOperations />} />
        <Route path="email-templates" element={<EmailTemplates />} />
        <Route path="lifecycle-policies" element={<LifecyclePolicies />} />
        <Route path="attestation-campaigns" element={<AttestationCampaigns />} />
        <Route path="audit-archival" element={<AuditArchival />} />

        {/* Developer - Admin Protected */}
        <Route path="api-explorer" element={<APIExplorer />} />
        <Route path="oauth-playground" element={<OAuthPlayground />} />
        <Route path="developer-settings" element={<DeveloperSettings />} />
        <Route path="error-catalog" element={<ErrorCatalog />} />
        <Route path="api-docs" element={<APIDocs />} />

        {/* System - Admin Protected */}
        <Route path="system-health" element={<SystemHealth />} />
        <Route path="organizations" element={<Organizations />} />
        <Route path="delegations" element={<Delegations />} />
        <Route path="webhooks" element={<Webhooks />} />
        <Route path="settings" element={<Settings />} />
        <Route path="tenant-management" element={<TenantManagement />} />
        <Route path="notification-admin" element={<NotificationAdmin />} />

        {/* Additional Routes */}
        <Route path="notification-preferences" element={<NotificationPreferences />} />
        <Route path="reviews/:id" element={<ReviewDetail />} />

        {/* Catch all - redirect to dashboard */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>

      {/* Root redirect */}
      <Route path="*" element={<Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />} />
    </Routes>
  )
}

export default App
