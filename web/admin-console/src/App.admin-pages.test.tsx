import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Outlet } from 'react-router-dom'

// The pages whose APIs answer administrators only, reads included: the OAuth
// client and SAML service-provider management of internal/oauth, and the
// access service's routes and upstream pools. Anyone else who reached them
// got a page of failed requests. This drives App's own route table, so the
// guard is checked where it is wired rather than in a copy of it; the pages
// themselves are stubs, since what matters is whether they mount.
let mockRoles: string[] = []

vi.mock('./lib/auth', () => ({
  useAuth: () => ({
    user: { id: 'u1', name: 'Test', email: 't@example.com', roles: mockRoles, orgId: '' },
    isAuthenticated: true,
    isLoading: false,
    hasRole: (r: string) => mockRoles.includes(r),
  }),
}))
vi.mock('@/lib/store', () => ({ useAppStore: () => ({ theme: 'light' }) }))
// The layout's chrome is not under test; its outlet is.
vi.mock('@/components/layout', () => ({ Layout: () => <Outlet /> }))
vi.mock('./pages/dashboard', () => ({ DashboardPage: () => <div>dashboard page</div> }))
vi.mock('./pages/applications', () => ({ ApplicationsPage: () => <div>applications page</div> }))
vi.mock('./pages/saml-service-providers', () => ({ SAMLServiceProvidersPage: () => <div>saml providers page</div> }))
vi.mock('./pages/proxy-routes', () => ({ ProxyRoutesPage: () => <div>proxy routes page</div> }))
vi.mock('./pages/upstream-pools', () => ({ UpstreamPoolsPage: () => <div>upstream pools page</div> }))

const { default: App } = await import('./App')

const PAGES: Array<[string, string]> = [
  ['/applications', 'applications page'],
  ['/saml-service-providers', 'saml providers page'],
  ['/proxy-routes', 'proxy routes page'],
  ['/upstream-pools', 'upstream pools page'],
]

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

describe('admin-only pages', () => {
  beforeEach(() => {
    mockRoles = []
  })

  describe.each(PAGES)('%s', (path, page) => {
    it.each([['operator'], ['auditor'], ['user'], ['compliance_reader']])(
      'sends %s to the dashboard without mounting the page',
      async (role) => {
        mockRoles = [role]
        renderAt(path)
        expect(await screen.findByText('dashboard page')).toBeInTheDocument()
        expect(screen.queryByText(page)).not.toBeInTheDocument()
      },
    )

    it('sends a token with no roles to the dashboard', async () => {
      renderAt(path)
      expect(await screen.findByText('dashboard page')).toBeInTheDocument()
      expect(screen.queryByText(page)).not.toBeInTheDocument()
    })

    it.each([['admin'], ['super_admin']])('shows the page to %s', async (role) => {
      mockRoles = [role]
      renderAt(path)
      expect(await screen.findByText(page)).toBeInTheDocument()
      expect(screen.queryByText('dashboard page')).not.toBeInTheDocument()
    })
  })
})
