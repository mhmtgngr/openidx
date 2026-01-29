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
import { IdentityProvidersPage } from './pages/identity-providers'
import { ProvisioningRulesPage } from './pages/provisioning-rules'
import { SettingsPage } from './pages/settings'
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
          <Route path="settings" element={
            <AdminRoute>
              <SettingsPage />
            </AdminRoute>
          } />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster />
    </>
  )
}
