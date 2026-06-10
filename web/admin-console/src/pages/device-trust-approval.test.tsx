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

import { DeviceTrustApprovalPage } from './device-trust-approval'
import { api } from '../lib/api'

const pendingRequest = {
  id: 'req-1',
  user_id: 'u-1',
  user_email: 'alice@example.com',
  user_name: 'Alice Anderson',
  device_name: 'Alice MacBook',
  device_type: 'laptop',
  ip_address: '203.0.113.10',
  justification: 'Onboarding — new corporate device',
  status: 'pending',
  created_at: '2026-06-09T00:00:00Z',
  updated_at: '2026-06-09T00:00:00Z',
}

const approvedRequest = {
  ...pendingRequest,
  id: 'req-2',
  user_email: 'bob@example.com',
  user_name: 'Bob Baxter',
  device_name: 'Bob iPhone',
  status: 'approved',
  reviewed_by: 'admin-1',
  reviewed_at: '2026-06-10T00:00:00Z',
  review_notes: 'Verified through helpdesk',
}

const settings = {
  require_approval: true,
  auto_approve_known_ips: true,
  auto_approve_corporate_devices: false,
}

function routeGet(url: string) {
  if (url.includes('/device-trust-requests/pending-count')) {
    return Promise.resolve({ count: 1 })
  }
  if (url.includes('/device-trust-settings')) return Promise.resolve(settings)
  if (url.includes('/device-trust-requests')) {
    return Promise.resolve({ requests: [pendingRequest, approvedRequest] })
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

describe('DeviceTrustApprovalPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Settings button', async () => {
    render(<DeviceTrustApprovalPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Device Trust Approval')).toBeInTheDocument()
    expect(
      screen.getByText(/review and approve device trust requests/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /settings/i })).toBeInTheDocument()
  })

  it('shows the three stat cards (Pending / Approval Required / Auto-Approve)', async () => {
    render(<DeviceTrustApprovalPage />, { wrapper: createWrapper() })
    // Wait for the settings query to resolve so the derived "Yes" /
    // "Known IPs" copy is in the DOM.
    expect(await screen.findByText('Pending Requests')).toBeInTheDocument()
    expect(screen.getByText('Approval Required')).toBeInTheDocument()
    expect(screen.getByText('Auto-Approve')).toBeInTheDocument()

    // require_approval=true → "Yes" (find rather than get because it
    // may render after the settings query resolves)
    expect(await screen.findByText('Yes')).toBeInTheDocument()
    // auto_approve_known_ips=true → "Known IPs" surfaces in the auto-
    // approve summary line. Use getAllByText since the same phrase
    // appears in the Settings dialog when it's open.
    expect(screen.getAllByText(/known ips/i).length).toBeGreaterThan(0)
  })

  it('lists trust requests with user email and device name', async () => {
    render(<DeviceTrustApprovalPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    expect(screen.getByText('Alice MacBook')).toBeInTheDocument()
    expect(screen.getByText('Bob iPhone')).toBeInTheDocument()
    // Both rows show the same IP from the fixture (both pending +
    // approved share an IP), so disambiguate.
    expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0)
  })

  it('opens the Settings dialog when the Settings button is clicked', async () => {
    const user = userEvent.setup()
    render(<DeviceTrustApprovalPage />, { wrapper: createWrapper() })
    await screen.findByText('Device Trust Approval')

    await user.click(screen.getByRole('button', { name: /settings/i }))
    // The Settings dialog title reads "Device Trust Settings" — that's
    // the only place that exact phrase appears (the trigger button is
    // just "Settings").
    expect(
      await screen.findByText('Device Trust Settings'),
    ).toBeInTheDocument()
  })
})
