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

import MFAManagementPage from './mfa-management'
import { api } from '../lib/api'

const stats = {
  total_users: 250,
  mfa_enabled_count: 175,
  totp_count: 120,
  sms_count: 30,
  email_otp_count: 45,
  push_count: 20,
  webauthn_count: 80,
}

const policy = {
  id: 'pol-1',
  name: 'Admin role — TOTP required',
  description: 'Admins must enroll TOTP before login',
  enabled: true,
  priority: 100,
  conditions: { role: 'admin' },
  required_methods: ['totp'],
  grace_period_hours: 24,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const userMFA = {
  user_id: 'u-1',
  username: 'alice',
  email: 'alice@example.com',
  totp_enabled: true,
  sms_enabled: false,
  email_otp_enabled: false,
  push_enabled: false,
  webauthn_enabled: true,
}

function routeGet(url: string) {
  if (url.includes('/enrollment-stats')) return Promise.resolve(stats)
  if (url.includes('/policies')) return Promise.resolve({ policies: [policy], total: 1, page: 1, page_size: 20 })
  // The user-status endpoint lives at /api/v1/mfa/user-status — not /users.
  if (url.includes('/user-status')) return Promise.resolve({ users: [userMFA], total: 1, page: 1, page_size: 20 })
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

describe('MFAManagementPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + all three tabs', async () => {
    render(<MFAManagementPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('MFA Management')).toBeInTheDocument()
    expect(
      screen.getByText(/manage multi-factor authentication enrollment, policies, and user status/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /enrollment overview/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /mfa policies/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /user mfa status/i })).toBeInTheDocument()
  })

  it('shows the per-method enrollment counts on the default Enrollment Overview tab', async () => {
    render(<MFAManagementPage />, { wrapper: createWrapper() })
    // findByText polls until the stats query resolves (title renders
    // before the query completes, so awaiting the title isn't enough).
    expect(await screen.findByText('250')).toBeInTheDocument()
    expect(screen.getByText('175')).toBeInTheDocument()
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.getByText('30')).toBeInTheDocument()
    expect(screen.getByText('80')).toBeInTheDocument()
    // Card titles
    expect(screen.getByText('Total Users')).toBeInTheDocument()
    expect(screen.getByText(/mfa enabled \(70%\)/i)).toBeInTheDocument() // 175/250 = 70%
    expect(screen.getByText('TOTP Enrolled')).toBeInTheDocument()
    expect(screen.getByText('WebAuthn Enrolled')).toBeInTheDocument()
  })

  it('switches to the MFA Policies tab and surfaces the policy + Create Policy button', async () => {
    const user = userEvent.setup()
    render(<MFAManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('MFA Management')

    // Radix Tabs: userEvent.click is required (fireEvent leaves the tab
    // data-state="inactive" and the content never mounts).
    await user.click(screen.getByRole('tab', { name: /mfa policies/i }))
    expect(await screen.findByText('Admin role — TOTP required')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /create policy/i })).toBeInTheDocument()
  })

  it('switches to the User MFA Status tab and shows the user row', async () => {
    const user = userEvent.setup()
    render(<MFAManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('MFA Management')

    await user.click(screen.getByRole('tab', { name: /user mfa status/i }))
    // username and email both render in the row
    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
  })

  it('renders the empty-policies state when the policies API returns nothing', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/policies')) {
        return Promise.resolve({ policies: [], total: 0, page: 1, page_size: 20 }) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<MFAManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('MFA Management')

    await user.click(screen.getByRole('tab', { name: /mfa policies/i }))
    expect(await screen.findByText('No MFA policies configured')).toBeInTheDocument()
  })
})
