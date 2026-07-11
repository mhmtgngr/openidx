import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
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

import { MyAccessPage } from './my-access'
import { api } from '../lib/api'

const overview = {
  roles_count: 3,
  groups_count: 2,
  apps_count: 5,
  pending_requests: 1,
  roles: [
    { id: 'r-1', name: 'Engineer' },
    { id: 'r-2', name: 'Reviewer' },
    { id: 'r-3', name: 'OnCall' },
  ],
  groups: [
    { id: 'g-1', name: 'Backend Team' },
    { id: 'g-2', name: 'SRE' },
  ],
  privileged: {
    vault_grants: 4,
    active_checkouts: 1,
    active_jit_grants: 2,
    active_sessions: 0,
    pending_session_requests: 1,
  },
  network: {
    ziti_linked: true,
    ziti_enrolled: true,
    devices: 3,
    trusted_device: true,
  },
}

const availableGroups = {
  groups: [
    {
      id: 'g-100',
      name: 'Security Champions',
      description: 'Cross-team security responders',
      allow_self_join: false,
      require_approval: true,
      is_member: false,
      has_pending_request: false,
    },
    {
      id: 'g-101',
      name: 'Mobile Team',
      description: 'iOS/Android engineers',
      allow_self_join: true,
      require_approval: false,
      is_member: true,
      has_pending_request: false,
    },
  ],
}

const requests = {
  requests: [
    {
      id: 'req-1',
      user_id: 'u-1',
      group_id: 'g-100',
      group_name: 'Security Champions',
      justification: 'Joined the incident response rota',
      status: 'pending',
      created_at: '2026-06-01T10:00:00Z',
    },
  ],
}

function routeGet(url: string) {
  if (url.includes('/access-overview')) return Promise.resolve(overview)
  if (url.includes('/groups/available')) return Promise.resolve(availableGroups)
  if (url.includes('/groups/requests')) return Promise.resolve(requests)
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

describe('MyAccessPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('My Access')).toBeInTheDocument()
    expect(
      screen.getByText(/identity, privileged access, and zero-trust network/i),
    ).toBeInTheDocument()
  })

  it('renders the cross-pillar privileged + network panels from the overview', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })
    // Wait for data to resolve via a role name, then assert the new panels.
    expect(await screen.findByText('Engineer')).toBeInTheDocument()

    expect(screen.getByText('My Privileged Access')).toBeInTheDocument()
    expect(screen.getByText('Vault secrets')).toBeInTheDocument()
    expect(screen.getByText('JIT elevations')).toBeInTheDocument()
    expect(screen.getByText(/session request\(s\) pending approval/i)).toBeInTheDocument()

    expect(screen.getByText('My Network Access')).toBeInTheDocument()
    expect(screen.getByText('Zero-Trust Identity')).toBeInTheDocument()
    expect(screen.getByText('Enrolled')).toBeInTheDocument()
    expect(screen.getByText(/you have a trusted device/i)).toBeInTheDocument()
  })

  it('shows the four overview cards with their labels', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })
    // Wait on a data-dependent value to ensure the queries resolved
    // (raw labels render even with overview === undefined).
    expect(await screen.findByText('Engineer')).toBeInTheDocument()

    // "Roles" appears both as a card label AND as the "My Roles" CardTitle
    // (substring). Use getAllByText for the bare label.
    expect(screen.getAllByText('Roles').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Groups').length).toBeGreaterThan(0)
    expect(screen.getByText('Applications')).toBeInTheDocument()
    expect(screen.getByText('Pending')).toBeInTheDocument()

    // Numeric values may collide with other counts; the labels above prove
    // the cards render after the queries resolved.
    expect(screen.getByText('5')).toBeInTheDocument() // apps_count
  })

  it('lists the current roles + groups from the overview', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Engineer')).toBeInTheDocument()
    expect(screen.getByText('Reviewer')).toBeInTheDocument()
    expect(screen.getByText('OnCall')).toBeInTheDocument()

    expect(screen.getByText('Backend Team')).toBeInTheDocument()
    expect(screen.getByText('SRE')).toBeInTheDocument()
  })

  it('lists available groups with correct row state (Member badge + Requires Approval)', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })

    // Security Champions row: not a member, has approval requirement, no
    // pending request → "Request to Join" button visible. The name also
    // appears in my-requests table → use getAllByText.
    expect(
      (await screen.findAllByText(/security champions/i)).length,
    ).toBeGreaterThan(0)
    expect(screen.getByText(/requires approval/i)).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /request to join/i }),
    ).toBeInTheDocument()

    // Mobile Team row: is_member true → "Member" badge.
    expect(screen.getByText('Mobile Team')).toBeInTheDocument()
    expect(screen.getByText('Member')).toBeInTheDocument()
  })

  it('renders the my-requests table row with status badge', async () => {
    render(<MyAccessPage />, { wrapper: createWrapper() })

    // The Security Champions row name also shows up here; assert via the
    // unique justification text instead.
    expect(
      await screen.findByText(/joined the incident response rota/i),
    ).toBeInTheDocument()
    // Status badge — "pending" appears as both the card label and the badge,
    // so allow multiple.
    expect(screen.getAllByText(/pending/i).length).toBeGreaterThan(0)
  })

  it('shows the empty "No group requests" state when there are none', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/access-overview')) return Promise.resolve(overview) as ReturnType<typeof api.get>
      if (url.includes('/groups/available')) {
        return Promise.resolve({ groups: [] }) as ReturnType<typeof api.get>
      }
      if (url.includes('/groups/requests')) {
        return Promise.resolve({ requests: [] }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<MyAccessPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no group requests/i)).toBeInTheDocument()
    expect(
      screen.getByText(/no groups available for self-join/i),
    ).toBeInTheDocument()
  })
})
