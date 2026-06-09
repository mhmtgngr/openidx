import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { CertificationCampaignsPage } from './certification-campaigns'
import { api } from '../lib/api'

const campaign = {
  id: 'cmp-1',
  name: 'Q1 User Access Review',
  description: 'Quarterly review of all user role assignments',
  type: 'user_access',
  schedule: 'quarterly',
  status: 'active',
  reviewer_strategy: 'manager',
  auto_revoke: true,
  grace_period_days: 7,
  duration_days: 30,
  last_run_at: '2026-01-01T00:00:00Z',
  next_run_at: '2026-04-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const pausedCampaign = {
  ...campaign,
  id: 'cmp-2',
  name: 'On-hold Quarterly Review',
  status: 'paused',
  next_run_at: null,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('CertificationCampaignsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [campaign, pausedCampaign],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the page heading and create button', async () => {
    render(<CertificationCampaignsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Certification Campaigns')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create campaign/i }),
    ).toBeInTheDocument()
  })

  it('shows the active / paused / scheduled stats cards', async () => {
    render(<CertificationCampaignsPage />, { wrapper: createWrapper() })
    // The card values are derived from `campaigns.filter(...)`, so they
    // reflect the fixture: 1 active, 1 paused, 1 scheduled (the one with
    // next_run_at set).
    await screen.findByText('Certification Campaigns')
    expect(screen.getByText('Active Campaigns')).toBeInTheDocument()
    expect(screen.getByText('Paused')).toBeInTheDocument()
    expect(screen.getByText('Scheduled')).toBeInTheDocument()
  })

  it('lists the campaigns in the table', async () => {
    render(<CertificationCampaignsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Q1 User Access Review')).toBeInTheDocument()
    expect(screen.getByText('On-hold Quarterly Review')).toBeInTheDocument()
  })

  it('opens the create-campaign modal when Create Campaign is clicked', async () => {
    const user = userEvent.setup()
    render(<CertificationCampaignsPage />, { wrapper: createWrapper() })
    await screen.findByText('Q1 User Access Review')

    await user.click(screen.getByRole('button', { name: /create campaign/i }))
    // The modal renders a campaign-name input field; if it appears the
    // modal opened. Using the placeholder for stability across UI changes.
    expect(
      await screen.findByPlaceholderText(/q1 2026 access certification/i),
    ).toBeInTheDocument()
  })

  it('renders an empty state when no campaigns exist', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [], headers: {} })
    render(<CertificationCampaignsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('No campaigns found')).toBeInTheDocument()
    expect(screen.queryByText('Q1 User Access Review')).not.toBeInTheDocument()
  })
})
