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

import { PrivacyDashboardPage } from './privacy-dashboard'
import { api } from '../lib/api'

const dashboard = {
  total_consents: 532,
  active_dsars: 4,
  overdue_dsars: 1,
  total_assessments: 12,
  consent_breakdown: [
    { consent_type: 'analytics', granted: 200, revoked: 30 },
    { consent_type: 'marketing_email', granted: 150, revoked: 50 },
  ],
  recent_dsars: [
    {
      id: 'dsar-1',
      type: 'access',
      user_email: 'alice@example.com',
      status: 'pending',
      created_at: '2026-06-01T00:00:00Z',
    },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('PrivacyDashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(dashboard)
  })

  it('renders the heading + subtitle', async () => {
    render(<PrivacyDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Privacy Dashboard')).toBeInTheDocument()
    expect(
      screen.getByText(/gdpr compliance overview and data subject request management/i),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards with values', async () => {
    render(<PrivacyDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Total Consents')).toBeInTheDocument()
    expect(screen.getByText('Active DSARs')).toBeInTheDocument()
    expect(screen.getByText('Overdue DSARs')).toBeInTheDocument()
    expect(screen.getByText('Impact Assessments')).toBeInTheDocument()

    expect(screen.getByText('532')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
  })

  it('renders the Quick Actions card with all three buttons', async () => {
    render(<PrivacyDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Quick Actions')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /view all dsars/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /manage consents/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /retention policies/i }),
    ).toBeInTheDocument()
  })

  it('shows the consent breakdown rows', async () => {
    render(<PrivacyDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Consent Breakdown')).toBeInTheDocument()
    // consent_type "analytics" rendered with .capitalize CSS — raw text is 'analytics'.
    expect(screen.getByText('analytics')).toBeInTheDocument()
    expect(screen.getByText(/marketing email/i)).toBeInTheDocument()
  })

  it('renders the empty states when data is empty', async () => {
    vi.mocked(api.get).mockResolvedValue({
      total_consents: 0,
      active_dsars: 0,
      overdue_dsars: 0,
      total_assessments: 0,
      consent_breakdown: [],
      recent_dsars: [],
    })

    render(<PrivacyDashboardPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no consent data available/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/no recent dsars/i)).toBeInTheDocument()
  })
})
