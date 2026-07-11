import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
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

import { UserAccess360Page } from './user-access-360'
import { api } from '../lib/api'

const accessMap = {
  user: {
    id: 'u-1',
    username: 'alice',
    email: 'alice@example.com',
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    last_login_at: '2026-07-01T09:00:00Z',
  },
  iam: {
    roles: [{ id: 'r-1', name: 'DBA' }],
    groups: [{ id: 'g-1', name: 'Platform' }],
    active_sessions: 2,
    active_api_keys: 1,
    pending_access_requests: 0,
  },
  pam: {
    vault_grants: [
      { secret_id: 's-1', secret_name: 'prod-db-root', secret_type: 'password', actions: ['use', 'reveal'], via: 'role:DBA' },
    ],
    active_checkouts: [
      { id: 'co-1', secret_name: 'prod-db-root', mode: 'reveal', leased_at: '2026-07-11T10:00:00Z', expires_at: '2026-07-11T11:00:00Z' },
    ],
    active_jit_grants: [
      { id: 'j-1', role_name: 'break-glass-admin', expires_at: '2026-07-11T12:00:00Z' },
    ],
    active_sessions: [
      { id: 'gs-1', route_name: 'prod-jumphost', protocol: 'ssh', started_at: '2026-07-11T10:30:00Z', over_ziti: true },
    ],
    sessions_30d: 12,
    pending_session_requests: 0,
    pending_credential_requests: 0,
  },
  ziti: {
    identity: { ziti_id: 'z-1', name: 'alice', enrolled: true, attributes: ['Platform', 'device-trusted'] },
    devices: [
      { agent_id: 'agent-xyz', platform: 'linux', status: 'active', compliance_status: 'compliant', ziti_identity_id: 'zd-1', last_seen_at: '2026-07-11T10:00:00Z' },
    ],
    dial_policies: [{ name: 'platform-dial', services: ['prod-jumphost', 'prod-db'] }],
    reachable_services: ['prod-db', 'prod-jumphost'],
    trusted_device: true,
  },
  activity: [
    { source: 'ziti', event_type: 'circuit.created', actor_ip: '10.0.0.5', created_at: '2026-07-11T10:30:00Z' },
    { source: 'guacamole', event_type: 'session.started', created_at: '2026-07-11T10:31:00Z' },
  ],
  generated_at: '2026-07-11T10:32:00Z',
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/users/u-1/access-360']}>
        <Routes>
          <Route path="/users/:id/access-360" element={<UserAccess360Page />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('UserAccess360Page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/access-map')) return Promise.resolve(accessMap) as ReturnType<typeof api.get>
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })
  })

  it('renders the three pillars for the user', async () => {
    renderPage()
    expect(await screen.findByRole('heading', { name: 'alice' })).toBeInTheDocument()

    // IAM
    expect(screen.getByText('Identity (IAM)')).toBeInTheDocument()
    expect(screen.getByText('DBA')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()

    // PAM
    expect(screen.getByText('Privileged (PAM)')).toBeInTheDocument()
    expect(screen.getAllByText('prod-db-root').length).toBeGreaterThan(0)
    expect(screen.getByText('break-glass-admin')).toBeInTheDocument()

    // Ziti
    expect(screen.getByText('Network (Ziti)')).toBeInTheDocument()
    expect(screen.getByText('prod-db')).toBeInTheDocument()
    expect(screen.getByText('agent-xyz')).toBeInTheDocument()
  })

  it('flags a privileged session that rides the Ziti overlay', async () => {
    renderPage()
    expect(await screen.findByRole('heading', { name: 'alice' })).toBeInTheDocument()
    // The PAM⇄Ziti correlation: the ssh session is marked "over Ziti".
    expect(screen.getByText(/over ziti/i)).toBeInTheDocument()
  })

  it('shows cross-pillar activity from all sources', async () => {
    renderPage()
    expect(await screen.findByText('circuit.created')).toBeInTheDocument()
    expect(screen.getByText('session.started')).toBeInTheDocument()
  })

  it('opens the kill switch dialog and posts to the kill-switch endpoint', async () => {
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByRole('heading', { name: 'alice' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /kill switch/i }))
    // Dialog shows the live-severance summary.
    expect(await screen.findByText(/severs this user's live access across all three pillars/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /sever all access/i }))
    expect(api.post).toHaveBeenCalledWith(
      '/api/v1/access/users/u-1/kill-switch',
      expect.objectContaining({ disable_user: false }),
    )
  })
})
