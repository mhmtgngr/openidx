import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './lib/auth'
import { Layout } from './components/layout'
import { LoginPage } from './pages/login'
import { DashboardPage } from './pages/dashboard'
import { UsersPage } from './pages/users'
import { GroupsPage } from './pages/groups'
import { RolesPage } from './pages/roles'
import { UserProfilePage } from './pages/user-profile'
import { ApplicationsPage } from './pages/applications'
import { AccessReviewsPage } from './pages/access-reviews'
import { ReviewDetailPage } from './pages/review-detail'
import { PoliciesPage } from './pages/policies'
import { AuditLogsPage } from './pages/audit-logs'
import { ComplianceReportsPage } from './pages/compliance-reports'
import { DirectoriesPage } from './pages/directories'
import { IdentityProvidersPage } from './pages/identity-providers'
import { ProvisioningRulesPage } from './pages/provisioning-rules'
import { DevicesPage } from './pages/devices'
import { ServiceAccountsPage } from './pages/service-accounts'
import { WebhooksPage } from './pages/webhooks'
import { AccessRequestsPage } from './pages/access-requests'
import { SecurityAlertsPage } from './pages/security-alerts'
import { SessionsAdminPage } from './pages/sessions-admin'
import { ApprovalPoliciesPage } from './pages/approval-policies'
import { ProxyRoutesPage } from './pages/proxy-routes'
import { ZitiNetworkPage } from './pages/ziti-network'
import { BrowZerManagementPage } from './pages/browzer-management'
import { CertificatesPage } from './pages/certificates'
import { UnifiedAuditPage } from './pages/unified-audit'
import { ZitiDiscoveryPage } from './pages/ziti-discovery'
import { AppPublishPage } from './pages/app-publish'
import { SettingsPage } from './pages/settings'
import { ForgotPasswordPage } from './pages/forgot-password'
import { ResetPasswordPage } from './pages/reset-password'
import { MagicLinkVerifyPage } from './pages/magic-link-verify'
import { OrganizationsPage } from './pages/organizations'
import { ReportsPage } from './pages/reports'
import { AppLauncherPage } from './pages/app-launcher'
import { MyAccessPage } from './pages/my-access'
import { MyDevicesPage } from './pages/my-devices'
import { NotificationPreferencesPage } from './pages/notification-preferences'
import { HardwareTokensPage } from './pages/hardware-tokens'
import { DeviceTrustApprovalPage } from './pages/device-trust-approval'
import { MFABypassCodesPage } from './pages/mfa-bypass-codes'
import { PasswordlessSettingsPage } from './pages/passwordless-settings'
import { RiskPoliciesPage } from './pages/risk-policies'
import { TrustedBrowsersPage } from './pages/trusted-browsers'
import { LoginAnalyticsPage } from './pages/login-analytics'
import { SecurityKeysPage } from './pages/security-keys'
import { PushDevicesPage } from './pages/push-devices'
import { ApiDocsPage } from './pages/api-docs'
import { CertificationCampaignsPage } from './pages/certification-campaigns'
import { LifecycleWorkflowsPage } from './pages/lifecycle-workflows'
import { EntitlementsPage } from './pages/entitlements'
import { ComplianceDashboardPage } from './pages/compliance-dashboard'
import { DelegationsPage } from './pages/delegations'
import { ABACPoliciesPage } from './pages/abac-policies'
import { SAMLServiceProvidersPage } from './pages/saml-service-providers'
import { AuthAnalyticsPage } from './pages/auth-analytics'
import { UsageAnalyticsPage } from './pages/usage-analytics'
import { RiskDashboardPage } from './pages/risk-dashboard'
import { AdminAuditLogPage } from './pages/admin-audit-log'
import { ApiExplorerPage } from './pages/api-explorer'
import { DeveloperSettingsPage } from './pages/developer-settings'
import { ErrorCatalogPage } from './pages/error-catalog'
import { OAuthPlaygroundPage } from './pages/oauth-playground'
import { SystemHealthPage } from './pages/system-health'
import { AIAgentsPage } from './pages/ai-agents'
import { ISPMDashboardPage } from './pages/ispm-dashboard'
import { AIRecommendationsPage } from './pages/ai-recommendations'
import { PredictiveAnalyticsPage } from './pages/predictive-analytics'
import { BulkOperationsPage } from './pages/bulk-operations'
import { EmailTemplatesPage } from './pages/email-templates'
import { LifecyclePoliciesPage } from './pages/lifecycle-policies'
import { AttestationCampaignsPage } from './pages/attestation-campaigns'
import { AuditArchivalPage } from './pages/audit-archival'
import { LoadingSpinner } from './components/ui/loading-spinner'
import { Toaster } from './components/ui/toaster'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, hasRole } = useAuth()

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  if (!hasRole('admin')) {
    return <Navigate to="/dashboard" replace />
  }

  return <>{children}</>
}

export default function App() {
  return (
    <>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/magic-link-verify" element={<MagicLinkVerifyPage />} />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="profile" element={<UserProfilePage />} />
          <Route path="users" element={
            <AdminRoute>
              <UsersPage />
            </AdminRoute>
          } />
          <Route path="groups" element={
            <AdminRoute>
              <GroupsPage />
            </AdminRoute>
          } />
          <Route path="roles" element={
            <AdminRoute>
              <RolesPage />
            </AdminRoute>
          } />
          <Route path="applications" element={
            <AdminRoute>
              <ApplicationsPage />
            </AdminRoute>
          } />
          <Route path="access-reviews" element={
            <AdminRoute>
              <AccessReviewsPage />
            </AdminRoute>
          } />
          <Route path="access-reviews/:id" element={
            <AdminRoute>
              <ReviewDetailPage />
            </AdminRoute>
          } />
          <Route path="policies" element={
            <AdminRoute>
              <PoliciesPage />
            </AdminRoute>
          } />
          <Route path="audit-logs" element={
            <AdminRoute>
              <AuditLogsPage />
            </AdminRoute>
          } />
          <Route path="compliance-reports" element={
            <AdminRoute>
              <ComplianceReportsPage />
            </AdminRoute>
          } />
          <Route path="directories" element={
            <AdminRoute>
              <DirectoriesPage />
            </AdminRoute>
          } />
          <Route path="devices" element={
            <AdminRoute>
              <DevicesPage />
            </AdminRoute>
          } />
          <Route path="service-accounts" element={
            <AdminRoute>
              <ServiceAccountsPage />
            </AdminRoute>
          } />
          <Route path="webhooks" element={
            <AdminRoute>
              <WebhooksPage />
            </AdminRoute>
          } />
          <Route path="access-requests" element={
            <AccessRequestsPage />
          } />
          <Route path="approval-policies" element={
            <AdminRoute>
              <ApprovalPoliciesPage />
            </AdminRoute>
          } />
          <Route path="security-alerts" element={
            <AdminRoute>
              <SecurityAlertsPage />
            </AdminRoute>
          } />
          <Route path="sessions" element={
            <AdminRoute>
              <SessionsAdminPage />
            </AdminRoute>
          } />
          <Route path="identity-providers" element={
            <AdminRoute>
              <IdentityProvidersPage />
            </AdminRoute>
          } />
          <Route path="provisioning-rules" element={
            <AdminRoute>
              <ProvisioningRulesPage />
            </AdminRoute>
          } />
          <Route path="proxy-routes" element={
            <AdminRoute>
              <ProxyRoutesPage />
            </AdminRoute>
          } />
          <Route path="ziti-network" element={
            <AdminRoute>
              <ZitiNetworkPage />
            </AdminRoute>
          } />
          <Route path="ziti-discovery" element={
            <AdminRoute>
              <ZitiDiscoveryPage />
            </AdminRoute>
          } />
          <Route path="app-publish" element={
            <AdminRoute>
              <AppPublishPage />
            </AdminRoute>
          } />
          <Route path="browzer-management" element={
            <AdminRoute>
              <BrowZerManagementPage />
            </AdminRoute>
          } />
          <Route path="certificates" element={
            <AdminRoute>
              <CertificatesPage />
            </AdminRoute>
          } />
          <Route path="unified-audit" element={
            <AdminRoute>
              <UnifiedAuditPage />
            </AdminRoute>
          } />
          <Route path="settings" element={
            <AdminRoute>
              <SettingsPage />
            </AdminRoute>
          } />
          <Route path="organizations" element={
            <AdminRoute>
              <OrganizationsPage />
            </AdminRoute>
          } />
          <Route path="reports" element={
            <AdminRoute>
              <ReportsPage />
            </AdminRoute>
          } />
          <Route path="app-launcher" element={
            <AppLauncherPage />
          } />
          <Route path="my-access" element={
            <MyAccessPage />
          } />
          <Route path="my-devices" element={
            <MyDevicesPage />
          } />
          <Route path="notification-preferences" element={
            <NotificationPreferencesPage />
          } />
          <Route path="trusted-browsers" element={
            <TrustedBrowsersPage />
          } />
          <Route path="hardware-tokens" element={
            <AdminRoute>
              <HardwareTokensPage />
            </AdminRoute>
          } />
          <Route path="device-trust-approval" element={
            <AdminRoute>
              <DeviceTrustApprovalPage />
            </AdminRoute>
          } />
          <Route path="mfa-bypass-codes" element={
            <AdminRoute>
              <MFABypassCodesPage />
            </AdminRoute>
          } />
          <Route path="passwordless-settings" element={
            <AdminRoute>
              <PasswordlessSettingsPage />
            </AdminRoute>
          } />
          <Route path="security-keys" element={
            <AdminRoute>
              <SecurityKeysPage />
            </AdminRoute>
          } />
          <Route path="push-devices" element={
            <AdminRoute>
              <PushDevicesPage />
            </AdminRoute>
          } />
          <Route path="risk-policies" element={
            <AdminRoute>
              <RiskPoliciesPage />
            </AdminRoute>
          } />
          <Route path="login-analytics" element={
            <AdminRoute>
              <LoginAnalyticsPage />
            </AdminRoute>
          } />
          <Route path="api-docs" element={
            <AdminRoute>
              <ApiDocsPage />
            </AdminRoute>
          } />
          <Route path="certification-campaigns" element={
            <AdminRoute>
              <CertificationCampaignsPage />
            </AdminRoute>
          } />
          <Route path="lifecycle-workflows" element={
            <AdminRoute>
              <LifecycleWorkflowsPage />
            </AdminRoute>
          } />
          <Route path="entitlements" element={
            <AdminRoute>
              <EntitlementsPage />
            </AdminRoute>
          } />
          <Route path="compliance-dashboard" element={
            <AdminRoute>
              <ComplianceDashboardPage />
            </AdminRoute>
          } />
          <Route path="delegations" element={
            <AdminRoute>
              <DelegationsPage />
            </AdminRoute>
          } />
          <Route path="abac-policies" element={
            <AdminRoute>
              <ABACPoliciesPage />
            </AdminRoute>
          } />
          <Route path="saml-service-providers" element={
            <AdminRoute>
              <SAMLServiceProvidersPage />
            </AdminRoute>
          } />
          <Route path="auth-analytics" element={
            <AdminRoute>
              <AuthAnalyticsPage />
            </AdminRoute>
          } />
          <Route path="usage-analytics" element={
            <AdminRoute>
              <UsageAnalyticsPage />
            </AdminRoute>
          } />
          <Route path="risk-dashboard" element={
            <AdminRoute>
              <RiskDashboardPage />
            </AdminRoute>
          } />
          <Route path="admin-audit-log" element={
            <AdminRoute>
              <AdminAuditLogPage />
            </AdminRoute>
          } />
          <Route path="api-explorer" element={
            <AdminRoute>
              <ApiExplorerPage />
            </AdminRoute>
          } />
          <Route path="developer-settings" element={
            <AdminRoute>
              <DeveloperSettingsPage />
            </AdminRoute>
          } />
          <Route path="error-catalog" element={
            <AdminRoute>
              <ErrorCatalogPage />
            </AdminRoute>
          } />
          <Route path="oauth-playground" element={
            <AdminRoute>
              <OAuthPlaygroundPage />
            </AdminRoute>
          } />
          <Route path="system-health" element={
            <AdminRoute>
              <SystemHealthPage />
            </AdminRoute>
          } />
          <Route path="ai-agents" element={
            <AdminRoute>
              <AIAgentsPage />
            </AdminRoute>
          } />
          <Route path="ispm" element={
            <AdminRoute>
              <ISPMDashboardPage />
            </AdminRoute>
          } />
          <Route path="ai-recommendations" element={
            <AdminRoute>
              <AIRecommendationsPage />
            </AdminRoute>
          } />
          <Route path="predictive-analytics" element={
            <AdminRoute>
              <PredictiveAnalyticsPage />
            </AdminRoute>
          } />
          <Route path="bulk-operations" element={
            <AdminRoute>
              <BulkOperationsPage />
            </AdminRoute>
          } />
          <Route path="email-templates" element={
            <AdminRoute>
              <EmailTemplatesPage />
            </AdminRoute>
          } />
          <Route path="lifecycle-policies" element={
            <AdminRoute>
              <LifecyclePoliciesPage />
            </AdminRoute>
          } />
          <Route path="attestation-campaigns" element={
            <AdminRoute>
              <AttestationCampaignsPage />
            </AdminRoute>
          } />
          <Route path="audit-archival" element={
            <AdminRoute>
              <AuditArchivalPage />
            </AdminRoute>
          } />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster />
    </>
  )
}
