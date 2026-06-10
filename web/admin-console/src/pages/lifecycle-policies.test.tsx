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

import { LifecyclePoliciesPage } from './lifecycle-policies'
import { api } from '../lib/api'

const enabledPolicy = {
  id: 'lp-1',
  name: 'Suspend dormant accounts',
  policy_type: 'dormant_user',
  description: 'Suspend accounts that have not logged in for 90 days',
  enabled: true,
  threshold_days: 90,
  schedule: 'daily',
  grace_period_days: 7,
  last_run_at: '2026-06-01T00:00:00Z',
}

const disabledPolicy = {
  id: 'lp-2',
  name: 'Archive ex-employees',
  policy_type: 'offboarded_user',
  description: 'Archive accounts of offboarded employees',
  enabled: false,
  threshold_days: 30,
  schedule: 'weekly',
  grace_period_days: 0,
  last_run_at: null,
}

function routeGet(url: string) {
  if (url.includes('/lifecycle-policies') && !url.includes('/executions')) {
    return Promise.resolve({ data: [enabledPolicy, disabledPolicy] })
  }
  if (url.includes('/executions')) {
    return Promise.resolve({ data: [] })
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

describe('LifecyclePoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Create Policy toggle', async () => {
    render(<LifecyclePoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Lifecycle Policies')).toBeInTheDocument()
    expect(
      screen.getByText(/automated de-provisioning and account lifecycle management/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create policy/i }),
    ).toBeInTheDocument()
  })

  it('renders each policy row with name + Enabled/Disabled badge', async () => {
    render(<LifecyclePoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Suspend dormant accounts')).toBeInTheDocument()
    expect(screen.getByText('Archive ex-employees')).toBeInTheDocument()

    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('shows the policy count label "Policies (2)" matching the fixture', async () => {
    render(<LifecyclePoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/policies \(2\)/i)).toBeInTheDocument()
  })

  it('opens the New Lifecycle Policy form when Create Policy is clicked', async () => {
    const user = userEvent.setup()
    render(<LifecyclePoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Suspend dormant accounts')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    expect(await screen.findByText(/new lifecycle policy/i)).toBeInTheDocument()
  })

  it('renders the empty state when no policies are configured', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: [] })

    render(<LifecyclePoliciesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no lifecycle policies configured/i),
    ).toBeInTheDocument()
  })
})
