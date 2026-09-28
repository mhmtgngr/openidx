import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }))
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast }),
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

  // Editing sends the limits the dialog shows -- they used to be dropped -- and
  // when the API refuses a change to a field only a platform admin may change,
  // the toast says so instead of failing without a reason.
  it('sends the limits with an edit and explains a platform-admin refusal', async () => {
    vi.mocked(api.put).mockRejectedValueOnce({
      response: { status: 403, data: { error: 'forbidden', fields: ['max_users'] } },
    })
    const user = userEvent.setup()
    render(<OrganizationsPage />, { wrapper: createWrapper() })
    await screen.findByText('Acme Inc')

    await user.click(screen.getAllByRole('button', { name: 'Edit Organization' })[0])
    await user.click(await screen.findByRole('button', { name: 'Update' }))

    await waitFor(() => expect(api.put).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.put).mock.calls[0]).toEqual([
      '/api/v1/organizations/org-1',
      { name: 'Acme Inc', plan: 'enterprise', status: 'active', max_users: 100, max_applications: 50 },
    ])
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({
        title: 'Failed to update organization',
        description: expect.stringMatching(/only a platform administrator/i),
      })),
    )
  })

  // Only the organization's own users can be added by its owners and admins;
  // the API answers another organization's user as no user at all, and the
  // toast says what that means.
  it('explains why a member could not be added', async () => {
    vi.mocked(api.post).mockRejectedValueOnce({ response: { status: 404, data: { error: 'user not found' } } })
    const user = userEvent.setup()
    render(<OrganizationsPage />, { wrapper: createWrapper() })
    await screen.findByText('Acme Inc')

    await user.click(screen.getByRole('button', { name: '42' }))
    await user.click(await screen.findByRole('button', { name: 'Add Member' }))
    await user.type(await screen.findByPlaceholderText('User UUID'), '6f1c1c52-5a0e-4d33-9f0c-0d1f5f4f1a11')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.post).mock.calls[0]).toEqual([
      '/api/v1/organizations/org-1/members',
      { user_id: '6f1c1c52-5a0e-4d33-9f0c-0d1f5f4f1a11', role: 'member' },
    ])
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({
        title: 'Failed to add member',
        description: 'No user with this ID belongs to this organization.',
      })),
    )
  })
})
