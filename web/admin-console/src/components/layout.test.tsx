import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// The organization selector acts in another organization, which only a
// platform admin may do: super_admin held in the install's default
// organization (lib/platform-admin.ts, middleware.IsPlatformAdmin). It used to
// show for any super_admin, and the API refuses the others' requests for
// another organization, so they got a console of failed requests.
const DEFAULT_ORG = '00000000-0000-0000-0000-000000000010'
const OTHER_ORG = '11111111-1111-1111-1111-111111111111'
let mockUser: { roles: string[]; orgId: string } = { roles: [], orgId: '' }

vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    user: { id: 'u1', name: 'Test User', email: 't@example.com', groups: [], permissions: [], ...mockUser },
    logout: vi.fn(),
    hasRole: (r: string) => mockUser.roles.includes(r),
  }),
}))

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn((url: string) =>
      Promise.resolve(url === '/api/v1/organizations' ? [{ id: 'o2', name: 'Globex', slug: 'globex' }] : {}),
    ),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../lib/store', () => ({
  useAppStore: () => ({
    viewMode: 'admin',
    setViewMode: vi.fn(),
    collapsedDomains: [],
    toggleDomain: vi.fn(),
    theme: 'light',
    setTheme: vi.fn(),
  }),
  useOrgStore: () => ({ selectedOrgSlug: null, setOrg: vi.fn() }),
}))

import { Layout } from './layout'
import { api } from '../lib/api'

function renderLayout() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <Layout />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Layout organization selector', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows the selector to super_admin of the default organization', async () => {
    mockUser = { roles: ['super_admin'], orgId: DEFAULT_ORG }
    renderLayout()
    expect(await screen.findByLabelText('Select organization')).toBeInTheDocument()
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/v1/organizations'))
  })

  it.each([
    ['super_admin of another organization', { roles: ['super_admin'], orgId: OTHER_ORG }],
    ['super_admin whose token names no organization', { roles: ['super_admin'], orgId: '' }],
    ['admin of the default organization', { roles: ['admin'], orgId: DEFAULT_ORG }],
    ['admin of another organization', { roles: ['admin'], orgId: OTHER_ORG }],
    ['user of the default organization', { roles: ['user'], orgId: DEFAULT_ORG }],
  ])('does not show it to a %s', async (_who, user) => {
    mockUser = user
    renderLayout()
    // The chrome has rendered; the selector is absent and never asked for the
    // organization list.
    expect(await screen.findByRole('button', { name: 'Toggle sidebar' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Select organization')).not.toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalledWith('/api/v1/organizations')
  })
})
