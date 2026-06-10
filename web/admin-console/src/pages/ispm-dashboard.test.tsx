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

import { ISPMDashboardPage } from './ispm-dashboard'
import { api } from '../lib/api'

const score = {
  overall_score: 72,
  snapshot_date: '2026-06-09',
  category_scores: {
    authentication: 85,
    authorization: 70,
    lifecycle: 60,
  },
  total_findings: 24,
  critical_findings: 2,
  high_findings: 5,
  medium_findings: 10,
  low_findings: 7,
}

const findings = {
  data: [
    {
      id: 'f-1',
      title: 'Inactive admin accounts',
      category: 'lifecycle',
      severity: 'critical',
      status: 'open',
      created_at: '2026-06-01T00:00:00Z',
    },
  ],
}

const rules = {
  data: [
    {
      id: 'r-1',
      name: 'Detect inactive admin accounts',
      category: 'lifecycle',
      severity: 'critical',
      enabled: true,
    },
  ],
}

function routeGet(url: string) {
  if (url.includes('/ispm/score')) return Promise.resolve(score)
  if (url.includes('/ispm/findings')) return Promise.resolve(findings)
  if (url.includes('/ispm/rules')) return Promise.resolve(rules)
  if (url.includes('/ispm/trends')) return Promise.resolve({ data: [] })
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

describe('ISPMDashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Run Scan button', async () => {
    render(<ISPMDashboardPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Identity Security Posture'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/monitor and improve your organization's identity security hygiene/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /run scan/i }),
    ).toBeInTheDocument()
  })

  it('shows the Overall Posture Score + Category Breakdown + Open Findings cards', async () => {
    render(<ISPMDashboardPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Overall Posture Score'),
    ).toBeInTheDocument()
    expect(screen.getByText('Category Breakdown')).toBeInTheDocument()
    expect(screen.getByText('Open Findings')).toBeInTheDocument()

    // Severity breakdown badges + counts.
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument() // critical
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument() // high
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument() // medium
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument() // low
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.getByText('24')).toBeInTheDocument() // total
  })

  it('renders the snapshot date in the overall score card', async () => {
    render(<ISPMDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('2026-06-09')).toBeInTheDocument()
  })
})
