import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { OrganizationsPage } from './organizations'
import { api } from '../lib/api'

const acmeOrg = {
  id: 'org-1',
  name: 'Acme Inc',
  slug: 'acme',
  plan: 'enterprise',
  status: 'active',
  member_count: 42,
  max_users: 100,
  max_applications: 50,
  created_at: '2026-01-01T00:00:00Z',
}

const widgetsOrg = {
  id: 'org-2',
  name: 'Widgets Co',
  slug: 'widgets',
  plan: 'team',
  status: 'active',
  member_count: 8,
  max_users: 25,
  max_applications: 10,
  created_at: '2026-02-15T00:00:00Z',
}

// The backend returns bare JSON arrays (with an X-Total-Count header) for both
// the organization list and a group's members — not wrapped objects. Mocking the
// real contract is what makes these tests catch the wrapper-shape regression that
// previously left the org list rendering empty.
function routeGet(url: string) {
  if (url.includes('/organizations/')) {
    return Promise.resolve([])
  }
  if (url.includes('/organizations')) {
    return Promise.resolve([acmeOrg, widgetsOrg])
  }
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('OrganizationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Create Organization button', async () => {
    render(<OrganizationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Organizations')).toBeInTheDocument()
    expect(
      screen.getByText(/manage multi-tenant organizations/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create organization/i }),
    ).toBeInTheDocument()
  })

  it('lists the organization rows with their name, slug, plan, status, and member count', async () => {
    render(<OrganizationsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Acme Inc')).toBeInTheDocument()
    expect(screen.getByText('Widgets Co')).toBeInTheDocument()

    expect(screen.getByText('/acme')).toBeInTheDocument()
    expect(screen.getByText('/widgets')).toBeInTheDocument()

    expect(screen.getByText('enterprise')).toBeInTheDocument()
    expect(screen.getByText('team')).toBeInTheDocument()

    // "active" is rendered as the status badge.
    expect(screen.getAllByText('active').length).toBe(2)

    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('opens the Create Organization dialog when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<OrganizationsPage />, { wrapper: createWrapper() })
    await screen.findByText('Acme Inc')

    await user.click(screen.getByRole('button', { name: /create organization/i }))

    // Dialog renders its own "Create Organization" heading + form fields.
    expect(
      await screen.findByPlaceholderText(/organization name/i),
    ).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/org-slug/i)).toBeInTheDocument()
  })

  it('shows the empty state when there are no organizations', async () => {
    vi.mocked(api.get).mockResolvedValue([])

    render(<OrganizationsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no organizations found/i)).toBeInTheDocument()
    expect(
      screen.getByText(/create an organization to enable multi-tenancy/i),
    ).toBeInTheDocument()
  })
})
