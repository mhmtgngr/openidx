import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

// Mutable so each case can hand the guard a different token shape.
let mockRoles: string[] = []

vi.mock('./lib/auth', () => ({
  useAuth: () => ({
    user: { id: 'u1', name: 'Test', email: 't@example.com', roles: mockRoles },
    isAuthenticated: true,
    isLoading: false,
    // Present because the old implementation used it; a regression that goes
    // back to hasRole('admin') would find it here and fail the super_admin case
    // rather than quietly passing.
    hasRole: (r: string) => mockRoles.includes(r),
  }),
}))

vi.mock('@/lib/store', () => ({ useAppStore: () => ({ theme: 'light' }) }))

const { AdminRoute } = await import('./App')

function renderGuard() {
  return render(
    <MemoryRouter initialEntries={['/vault-secrets']}>
      <Routes>
        <Route
          path="/vault-secrets"
          element={
            <AdminRoute>
              <div>vault secrets</div>
            </AdminRoute>
          }
        />
        <Route path="/dashboard" element={<div>dashboard</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('AdminRoute', () => {
  beforeEach(() => {
    mockRoles = []
  })

  // The regression this test exists for. The backend issues tokens carrying
  // super_admin and nothing else (internal/auth/context_test.go pins it), and
  // the old guard asked roles.includes('admin') — so the most privileged
  // operator in the product was bounced off the pages only they should reach.
  it('admits super_admin, which does not carry the literal "admin" role', () => {
    mockRoles = ['super_admin']
    renderGuard()
    expect(screen.getByText('vault secrets')).toBeInTheDocument()
  })

  it('admits admin', () => {
    mockRoles = ['admin']
    renderGuard()
    expect(screen.getByText('vault secrets')).toBeInTheDocument()
  })

  it.each([['operator'], ['auditor'], ['user'], ['compliance_reader']])(
    'redirects %s to the dashboard',
    (role) => {
      mockRoles = [role]
      renderGuard()
      expect(screen.queryByText('vault secrets')).not.toBeInTheDocument()
      expect(screen.getByText('dashboard')).toBeInTheDocument()
    },
  )

  it('redirects a token with no roles at all', () => {
    mockRoles = []
    renderGuard()
    expect(screen.getByText('dashboard')).toBeInTheDocument()
  })

  // An unknown role must not accidentally clear the bar.
  it('redirects a role the hierarchy does not know', () => {
    mockRoles = ['billing_viewer']
    renderGuard()
    expect(screen.getByText('dashboard')).toBeInTheDocument()
  })
})
