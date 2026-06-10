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

import { ComplianceReportsPage } from './compliance-reports'
import { api } from '../lib/api'

const soc2Report = {
  id: 'rep-1',
  name: 'Q1 2026 SOC 2 Type II',
  type: 'soc2',
  framework: 'SOC 2',
  status: 'completed',
  start_date: '2026-01-01T00:00:00Z',
  end_date: '2026-03-31T23:59:59Z',
  generated_at: '2026-04-01T00:00:00Z',
  generated_by: 'admin-1',
  summary: {
    total_controls: 100,
    passed_controls: 95,
    failed_controls: 2,
    partial_controls: 1,
    not_applicable: 2,
  },
  findings: [],
}

const iso27001Report = {
  ...soc2Report,
  id: 'rep-2',
  name: 'Q1 2026 ISO 27001:2022',
  type: 'iso27001',
  framework: 'ISO 27001',
  status: 'completed',
}

const generatingReport = {
  ...soc2Report,
  id: 'rep-3',
  name: 'Q2 2026 SOC 2 Type II (in progress)',
  type: 'soc2',
  status: 'generating',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ComplianceReportsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [soc2Report, iso27001Report, generatingReport],
      headers: { 'x-total-count': '3' },
    })
  })

  it('renders the heading + subtitle + Generate Report button', async () => {
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Compliance Reports')).toBeInTheDocument()
    expect(
      screen.getByText(/generate and view compliance reports/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /generate report/i })).toBeInTheDocument()
  })

  it('shows the four summary cards (SOC 2 / ISO 27001 / Completed / Total)', async () => {
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Reports')

    expect(screen.getByText('SOC 2 Reports')).toBeInTheDocument()
    expect(screen.getByText('ISO 27001 Reports')).toBeInTheDocument()
    expect(screen.getByText('Completed')).toBeInTheDocument()
    expect(screen.getByText('Total Reports')).toBeInTheDocument()
  })

  it('lists reports with their names and frameworks', async () => {
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Q1 2026 SOC 2 Type II')).toBeInTheDocument()
    expect(screen.getByText('Q1 2026 ISO 27001:2022')).toBeInTheDocument()
    expect(
      screen.getByText('Q2 2026 SOC 2 Type II (in progress)'),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no reports exist', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [], headers: {} })
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('No compliance reports yet')).toBeInTheDocument()
    // The empty state surfaces a secondary CTA
    expect(
      screen.getByRole('button', { name: /generate first report/i }),
    ).toBeInTheDocument()
  })

  it('opens the Generate Report modal when the trigger is clicked', async () => {
    const user = userEvent.setup()
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Reports')

    await user.click(screen.getByRole('button', { name: /^generate report$/i }))
    // The modal renders a date range form; both Start Date and End Date
    // labels should be present once it opens. Looking for a stable
    // text rather than dialog-title (which often duplicates the
    // trigger button's name).
    expect(await screen.findByText(/start date/i)).toBeInTheDocument()
    expect(screen.getByText(/end date/i)).toBeInTheDocument()
  })

  it('shows the Report History card title', async () => {
    render(<ComplianceReportsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Report History')).toBeInTheDocument()
  })
})
