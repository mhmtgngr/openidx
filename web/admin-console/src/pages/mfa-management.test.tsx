import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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

  // What a policy enforces at password sign-in: required methods, with a grace
  // period to add one, or any enrolled factor when none is required. Conditions
  // are not enforced, so the form does not offer them (#990).
  describe('what a policy enforces', () => {
    const plain = {
      ...policy,
      id: 'pol-2',
      name: 'Second factor for everyone',
      conditions: {},
      required_methods: [],
      grace_period_hours: 0,
    }
    const withPolicies = (policies: unknown[]) =>
      vi.mocked(api.get).mockImplementation((url: string) => {
        if (url.includes('/policies')) {
          return Promise.resolve({ policies, total: policies.length, page: 1, page_size: 20 }) as ReturnType<typeof api.get>
        }
        return routeGet(url) as ReturnType<typeof api.get>
      })
    const openPoliciesTab = async (user: ReturnType<typeof userEvent.setup>) => {
      render(<MFAManagementPage />, { wrapper: createWrapper() })
      await screen.findByText('MFA Management')
      await user.click(screen.getByRole('tab', { name: /mfa policies/i }))
    }
    const openCreate = async (user: ReturnType<typeof userEvent.setup>) => {
      withPolicies([])
      await openPoliciesTab(user)
      await user.click(await screen.findByRole('button', { name: /create policy/i }))
      await user.type(screen.getByPlaceholderText(/second factor for everyone/i), 'Strong sign-in')
      return screen.getByRole('dialog')
    }

    it('lists each policy with its required methods and grace period', async () => {
      const user = userEvent.setup()
      withPolicies([policy, plain])
      await openPoliciesTab(user)
      expect(await screen.findByRole('columnheader', { name: /required methods/i })).toBeInTheDocument()
      expect(screen.getByRole('columnheader', { name: /grace period/i })).toBeInTheDocument()
      const strict = screen.getByText('Admin role — TOTP required').closest('tr') as HTMLElement
      expect(within(strict).getByText('TOTP')).toBeInTheDocument()
      expect(within(strict).getByText('24 h')).toBeInTheDocument()
      const any = screen.getByText('Second factor for everyone').closest('tr') as HTMLElement
      expect(within(any).getByText('Any enrolled factor')).toBeInTheDocument()
    })

    it('flags a policy that stores conditions, and only that one', async () => {
      const user = userEvent.setup()
      withPolicies([policy, plain])
      await openPoliciesTab(user)
      await screen.findByText('Second factor for everyone')
      expect(screen.getAllByText('stored conditions not enforced')).toHaveLength(1)
      const flagged = screen.getByText('Admin role — TOTP required').closest('tr')
      expect(flagged).toHaveTextContent('stored conditions not enforced')
    })

    it('toggles a policy by sending only enabled', async () => {
      const user = userEvent.setup()
      withPolicies([policy])
      await openPoliciesTab(user)
      await user.click(await screen.findByRole('switch', { name: /enable policy admin role/i }))
      expect(api.put).toHaveBeenCalledWith('/api/v1/mfa/policies/pol-1', { enabled: false })
    })

    it('creates a policy that requires methods, with a grace period to add one', async () => {
      const user = userEvent.setup()
      const dialog = await openCreate(user)
      await user.click(within(dialog).getByRole('checkbox', { name: 'WebAuthn' }))
      await user.click(within(dialog).getByRole('checkbox', { name: 'TOTP' }))
      const grace = within(dialog).getByLabelText(/grace period/i)
      expect(grace).toBeEnabled()
      await user.clear(grace)
      await user.type(grace, '72')
      await user.click(within(dialog).getByRole('button', { name: /^create policy$/i }))
      expect(api.post).toHaveBeenCalledWith('/api/v1/mfa/policies', {
        name: 'Strong sign-in',
        description: '',
        enabled: true,
        priority: 100,
        required_methods: ['totp', 'webauthn'],
        grace_period_hours: 72,
      })
    })

    it('creates a policy that accepts any factor, with no grace period', async () => {
      const user = userEvent.setup()
      const dialog = await openCreate(user)
      expect(within(dialog).getByLabelText(/grace period/i)).toBeDisabled()
      expect(within(dialog).queryByText(/conditions/i, { selector: 'label' })).not.toBeInTheDocument()
      await user.click(within(dialog).getByRole('button', { name: /^create policy$/i }))
      expect(api.post).toHaveBeenCalledWith('/api/v1/mfa/policies', {
        name: 'Strong sign-in',
        description: '',
        enabled: true,
        priority: 100,
        required_methods: [],
        grace_period_hours: 0,
      })
    })

    it('unchecking the last method clears the grace period', async () => {
      const user = userEvent.setup()
      const dialog = await openCreate(user)
      await user.click(within(dialog).getByRole('checkbox', { name: 'TOTP' }))
      const grace = within(dialog).getByLabelText(/grace period/i)
      await user.clear(grace)
      await user.type(grace, '48')
      await user.click(within(dialog).getByRole('checkbox', { name: 'TOTP' }))
      expect(grace).toBeDisabled()
      expect(grace).toHaveValue(0)
    })

    it('will not save a grace period the API refuses', async () => {
      const user = userEvent.setup()
      const dialog = await openCreate(user)
      await user.click(within(dialog).getByRole('checkbox', { name: 'TOTP' }))
      const grace = within(dialog).getByLabelText(/grace period/i)
      await user.clear(grace)
      await user.type(grace, '721')
      expect(within(dialog).getByText(/whole number of hours from 0 to 720/i)).toBeInTheDocument()
      expect(within(dialog).getByRole('button', { name: /^create policy$/i })).toBeDisabled()
    })

    it('saves an edited policy with its methods and grace period, and without its conditions', async () => {
      const user = userEvent.setup()
      withPolicies([policy])
      await openPoliciesTab(user)
      const row = (await screen.findByText('Admin role — TOTP required')).closest('tr') as HTMLElement
      await user.click(within(row).getAllByRole('button')[0])
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByText(/they are not enforced/i)).toBeInTheDocument()
      expect(within(dialog).getByRole('checkbox', { name: 'TOTP' })).toBeChecked()
      expect(within(dialog).queryByText(/starts every user's grace period again/i)).not.toBeInTheDocument()
      await user.click(within(dialog).getByRole('button', { name: /update policy/i }))
      expect(api.put).toHaveBeenCalledWith('/api/v1/mfa/policies/pol-1', {
        name: policy.name,
        description: policy.description,
        enabled: true,
        priority: 100,
        required_methods: ['totp'],
        grace_period_hours: 24,
      })
    })

    it('warns that changing the methods starts every grace period again', async () => {
      const user = userEvent.setup()
      withPolicies([policy])
      await openPoliciesTab(user)
      const row = (await screen.findByText('Admin role — TOTP required')).closest('tr') as HTMLElement
      await user.click(within(row).getAllByRole('button')[0])
      const dialog = await screen.findByRole('dialog')
      await user.click(within(dialog).getByRole('checkbox', { name: 'WebAuthn' }))
      expect(within(dialog).getByText(/starts every user's grace period again/i)).toBeInTheDocument()
    })
  })
})
