import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { PoliciesPage } from './policies'
import { api } from '../lib/api'

const sodPolicy = {
  id: 'pol-1',
  name: 'SoD - Finance/Approver',
  description: 'Prevents one user from holding both finance and approver roles',
  type: 'separation_of_duty',
  enabled: true,
  priority: 100,
  rules: [],
  created_at: '2026-01-01T00:00:00Z',
}

const riskPolicy = {
  id: 'pol-2',
  name: 'Risk-based - Off-hours Access',
  description: 'Step up auth outside business hours',
  type: 'risk_based',
  enabled: false,
  priority: 50,
  rules: [],
  created_at: '2026-02-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('PoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [sodPolicy, riskPolicy] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the heading + subtitle + Create Policy button', async () => {
    render(<PoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Policies')).toBeInTheDocument()
    expect(
      screen.getByText(/manage access control policies/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create policy/i }),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards (SoD / Risk-based / Active / Total)', async () => {
    render(<PoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Policies')

    expect(screen.getByText('SoD Policies')).toBeInTheDocument()
    // "Risk-based" also appears as a substring of the row policy name
    // "Risk-based - Off-hours Access" → use getAllByText.
    expect(screen.getAllByText(/risk-based/i).length).toBeGreaterThan(0)
    // "Active" collides with row status badge — use getAllByText.
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0)
    expect(screen.getByText('Total Policies')).toBeInTheDocument()
  })

  it('renders policy rows with their name', async () => {
    render(<PoliciesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/sod - finance\/approver/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/risk-based - off-hours access/i),
    ).toBeInTheDocument()
  })

  it('opens the Create Policy dialog when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<PoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Policies')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    // The dialog has a unique placeholder copy for the name input.
    expect(
      await screen.findByPlaceholderText(/sod - finance\/approver/i),
    ).toBeInTheDocument()
  })

  it('shows the "No policies found" empty state when the catalog is empty', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '0' },
    })

    render(<PoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no policies found/i)).toBeInTheDocument()
    expect(
      screen.getByText(/create a policy to get started with access control/i),
    ).toBeInTheDocument()
  })

  it('exposes the policy search input', async () => {
    render(<PoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Policies')

    expect(
      screen.getByPlaceholderText(/search policies/i),
    ).toBeInTheDocument()
  })
})
