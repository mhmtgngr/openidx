import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
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

import { MyPrivilegedAccessPage } from './my-privileged-access'
import { api } from '../lib/api'

// ──────────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────────

const openConnection = {
  route_id: 'route-open',
  name: 'staging-web',
  protocol: 'ssh',
  hostname: '10.0.0.7',
  port: 22,
  require_approval: false,
  record_session: false,
  credential_injected: true,
}

const gatedConnection = {
  route_id: 'route-gated',
  name: 'prod-db-bastion',
  protocol: 'rdp',
  hostname: '10.0.0.9',
  port: 3389,
  require_approval: true,
  record_session: true,
  credential_injected: true,
}

const approvedRequest = {
  id: 'req-approved',
  route_id: 'route-approved',
  route_name: 'prod-app-01',
  protocol: 'ssh',
  reason: 'deploy hotfix',
  status: 'approved',
  expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  created_at: '2026-07-08T10:00:00Z',
}

const pendingRequest = {
  id: 'req-pending',
  route_id: 'route-gated',
  route_name: 'prod-db-bastion',
  protocol: 'rdp',
  reason: 'quarterly audit',
  status: 'pending',
  created_at: '2026-07-08T11:00:00Z',
}

const fulfilledCheckout = {
  id: 'ar-1',
  resource_name: 'db-admin-password',
  resource_type: 'vault_credential',
  status: 'fulfilled',
  expires_at: new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
  created_at: '2026-07-08T09:00:00Z',
}

const roleRequest = {
  id: 'ar-2',
  resource_name: 'billing-admin',
  resource_type: 'role',
  status: 'fulfilled',
  created_at: '2026-07-08T09:00:00Z',
}

function routeGet(url: string) {
  if (url.includes('/my-connections')) {
    return Promise.resolve({ connections: [openConnection, gatedConnection] })
  }
  if (url.includes('/my-session-requests')) {
    return Promise.resolve({ requests: [approvedRequest, pendingRequest] })
  }
  if (url.includes('/governance/requests')) {
    return Promise.resolve({ requests: [fulfilledCheckout, roleRequest] })
  }
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

describe('MyPrivilegedAccessPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation(
      (url: string) => routeGet(url) as ReturnType<typeof api.get>,
    )
  })

  it('renders the page heading', async () => {
    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('My Privileged Access')).toBeInTheDocument()
  })

  it('lists available connections with PAM control badges', async () => {
    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('staging-web')).toBeInTheDocument()
    const gatedCells = screen.getAllByText('prod-db-bastion')
    expect(gatedCells.length).toBeGreaterThan(0)
    expect(screen.getByText('Approval required')).toBeInTheDocument()
    expect(screen.getByText('Recorded')).toBeInTheDocument()
  })

  it('Launch on an open connection calls connect and opens connect_url', async () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
    vi.mocked(api.post).mockResolvedValueOnce({
      connect_url: 'https://guac.example.com/#/client/abc',
    })

    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    await screen.findByText('staging-web')

    const launchBtns = screen.getAllByRole('button', { name: /launch/i })
    fireEvent.click(launchBtns[0]) // staging-web row (no approval required)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/connections/route-open/connect',
      )
    })
    await waitFor(() => {
      expect(openSpy).toHaveBeenCalledWith('https://guac.example.com/#/client/abc', '_blank')
    })

    openSpy.mockRestore()
  })

  it('gated connection without an approved request shows Request Access and submits a reason', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ request_id: 'req-new' })

    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    await screen.findByText('staging-web')

    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    expect(await screen.findByText('Request Session Access')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText(/why do you need this session/i), {
      target: { value: 'patch window' },
    })
    fireEvent.click(screen.getByRole('button', { name: /submit request/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/connections/route-gated/request',
        { reason: 'patch window' },
      )
    })
  })

  it('shows my session requests with status and a Launch button on the approved one', async () => {
    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('prod-app-01')).toBeInTheDocument()
    expect(screen.getByText('deploy hotfix')).toBeInTheDocument()
    expect(screen.getByText('approved')).toBeInTheDocument()
    expect(screen.getByText('pending')).toBeInTheDocument()
  })

  it('credential checkouts tab shows only vault_credential requests with Retrieve/Return', async () => {
    const user = userEvent.setup()
    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    await screen.findByText('staging-web')

    await user.click(screen.getByRole('tab', { name: /credential checkouts/i }))

    expect(await screen.findByText('db-admin-password')).toBeInTheDocument()
    expect(screen.queryByText('billing-admin')).toBeNull()
    expect(screen.getByRole('button', { name: /retrieve/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /return/i })).toBeInTheDocument()
  })

  it('Retrieve opens the one-shot dialog and calls the credential endpoint', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({ value: 's3cr3t-value' })

    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    await screen.findByText('staging-web')

    await user.click(screen.getByRole('tab', { name: /credential checkouts/i }))
    fireEvent.click(await screen.findByRole('button', { name: /retrieve/i }))
    fireEvent.click(await screen.findByRole('button', { name: /get credential/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/v1/governance/requests/ar-1/credential')
    })
    expect(await screen.findByTestId('retrieved-credential-value')).toHaveValue('s3cr3t-value')
  })

  it('Return confirms and calls the return endpoint', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({})

    render(<MyPrivilegedAccessPage />, { wrapper: createWrapper() })
    await screen.findByText('staging-web')

    await user.click(screen.getByRole('tab', { name: /credential checkouts/i }))
    fireEvent.click(await screen.findByRole('button', { name: /return/i }))

    expect(await screen.findByText('Return Credential?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^return$/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/v1/governance/requests/ar-1/return')
    })
  })
})
