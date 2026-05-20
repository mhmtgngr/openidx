import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({})),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { AuditLogsPage } from '../pages/audit-logs'
import { api } from '../lib/api'

const mockAuditEvents = [
  {
    id: '1',
    event_type: 'authentication',
    category: 'auth',
    action: 'login',
    actor_id: 'johndoe1-abcd-efgh-ijkl-mnopqrstuvwx',
    actor_type: 'user',
    actor_ip: '10.0.0.1',
    outcome: 'success',
    timestamp: '2024-03-27T10:00:00Z',
  },
]

const mockStatistics = {
  total_events: 1,
  by_type: { authentication: 1 },
  by_outcome: { success: 1 },
  by_category: { auth: 1 },
  events_per_day: [{ date: '2024-03-27', count: 1 }],
  failed_auth_count: 0,
  success_rate: 100,
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuditLogsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockStatistics)
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: mockAuditEvents, headers: { 'x-total-count': '1' } })
  })

  it('renders the audit logs page heading', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Audit Logs/i })).toBeInTheDocument()
    })
  })

  it('displays audit events list', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      // Actor column renders the truncated actor_id (first 8 chars + ellipsis)
      expect(screen.getByText('johndoe1...')).toBeInTheDocument()
      expect(screen.getByText('login')).toBeInTheDocument()
    })
  })

  it('has search functionality', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      const searchInput = screen.queryByPlaceholderText(/search/i)
      expect(searchInput).toBeInTheDocument()
    })
  })
})
