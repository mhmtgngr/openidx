import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './lib/auth'
import { Layout } from './components/layout'
import { LoginPage } from './pages/login'
import { DashboardPage } from './pages/dashboard'
import { UsersPage } from './pages/users'
import { GroupsPage } from './pages/groups'
import { RolesPage } from './pages/roles'
import { ApplicationsPage } from './pages/applications'
import { AccessReviewsPage } from './pages/access-reviews'
import { ReviewDetailPage } from './pages/review-detail'
import { PoliciesPage } from './pages/policies'
import { AuditLogsPage } from './pages/audit-logs'
import { ComplianceReportsPage } from './pages/compliance-reports'
import { IdentityProvidersPage } from './pages/identity-providers'
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
          <Route path="users" element={<UsersPage />} />
          <Route path="groups" element={<GroupsPage />} />
          <Route path="roles" element={<RolesPage />} />
          <Route path="applications" element={<ApplicationsPage />} />
          <Route path="access-reviews" element={<AccessReviewsPage />} />
          <Route path="access-reviews/:id" element={<ReviewDetailPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="audit-logs" element={<AuditLogsPage />} />
          <Route path="compliance-reports" element={<ComplianceReportsPage />} />
          <Route path="identity-providers" element={<IdentityProvidersPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster />
    </>
  )
}
