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

import { RiskPoliciesPage } from './risk-policies'
import { api } from '../lib/api'

const highRiskPolicy = {
  id: 'rp-1',
  name: 'High Risk Block',
  description: 'Block login when risk >= 80',
  conditions: { risk_score_min: 80, risk_score_max: 100 },
  // The page reads policy.actions (plural) — see getDecisionBadge call.
  actions: { deny: true, step_up: false, require_mfa: false },
  enabled: true,
  priority: 100,
}

const lowRiskPolicy = {
  id: 'rp-2',
  name: 'Low Risk Allow',
  description: 'Allow login when risk < 30',
  conditions: { risk_score_min: 0, risk_score_max: 30 },
  actions: { deny: false, step_up: false, require_mfa: false },
  enabled: true,
  priority: 0,
}

const stats = {
  stats: {
    high_risk_logins_today: 12,
    avg_risk_score_today: 24.5,
    new_devices_today: 5,
    failed_logins_today: 18,
    total_devices: 350,
    trusted_devices: 200,
  },
}

function routeGet(url: string) {
  if (url.includes('/risk/policies')) {
    return Promise.resolve({ policies: [highRiskPolicy, lowRiskPolicy] })
  }
  if (url.includes('/risk/stats')) return Promise.resolve(stats)
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

describe('RiskPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Create Policy / Test buttons', async () => {
    render(<RiskPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Risk-Based MFA Policies')).toBeInTheDocument()
    expect(
      screen.getByText(/configure adaptive authentication based on risk factors/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create policy/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /test evaluation/i }),
    ).toBeInTheDocument()
  })

  it('shows the six stat cards', async () => {
    render(<RiskPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('High Risk Today')).toBeInTheDocument()
    expect(screen.getByText('Avg Risk Score')).toBeInTheDocument()
    expect(screen.getByText('New Devices')).toBeInTheDocument()
    expect(screen.getByText('Failed Logins')).toBeInTheDocument()
    expect(screen.getByText('Total Devices')).toBeInTheDocument()
    expect(screen.getByText('Trusted')).toBeInTheDocument()
  })

  it('renders policy rows by name', async () => {
    render(<RiskPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('High Risk Block')).toBeInTheDocument()
    expect(screen.getByText('Low Risk Allow')).toBeInTheDocument()
  })
})
