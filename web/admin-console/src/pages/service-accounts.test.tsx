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

import { ServiceAccountsPage } from './service-accounts'
import { api } from '../lib/api'

const ciAccount = {
  id: 'sa-1',
  name: 'ci-runner',
  description: 'GitHub Actions deployment runner',
  status: 'active',
  created_at: '2026-01-15T00:00:00Z',
}

const monitoringAccount = {
  id: 'sa-2',
  name: 'prometheus-scraper',
  description: 'Prometheus metrics scraper',
  status: 'disabled',
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

describe('ServiceAccountsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      service_accounts: [ciAccount, monitoringAccount],
      total: 2,
    })
  })

  it('renders the heading + subtitle + Create Service Account button', async () => {
    render(<ServiceAccountsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Service Accounts')).toBeInTheDocument()
    expect(
      screen.getByText(/manage service accounts and their api keys/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create service account/i }),
    ).toBeInTheDocument()
  })

  it('renders the search input + account cards with name/description/status', async () => {
    render(<ServiceAccountsPage />, { wrapper: createWrapper() })

    // The search input renders synchronously; await on a data-dependent
    // row to ensure the query resolved.
    expect(await screen.findByText('ci-runner')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/search service accounts/i),
    ).toBeInTheDocument()

    expect(screen.getByText('prometheus-scraper')).toBeInTheDocument()

    expect(
      screen.getByText(/github actions deployment runner/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/prometheus metrics scraper/i),
    ).toBeInTheDocument()

    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('disabled')).toBeInTheDocument()
  })

  it('each account row exposes an API Keys toggle button', async () => {
    render(<ServiceAccountsPage />, { wrapper: createWrapper() })
    await screen.findByText('ci-runner')

    // One "API Keys" button per row.
    expect(screen.getAllByRole('button', { name: /^api keys$/i }).length).toBe(2)
  })

  it('opens the Create Service Account dialog when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<ServiceAccountsPage />, { wrapper: createWrapper() })
    await screen.findByText('ci-runner')

    await user.click(screen.getByRole('button', { name: /create service account/i }))

    expect(
      await screen.findByPlaceholderText(/my-service-account/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/description of the service account/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no service accounts exist', async () => {
    vi.mocked(api.get).mockResolvedValue({ service_accounts: [], total: 0 })

    render(<ServiceAccountsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no service accounts found/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/create a service account for programmatic access/i),
    ).toBeInTheDocument()
  })
})
