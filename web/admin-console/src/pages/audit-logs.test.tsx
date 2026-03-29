import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { AuditLogsPage } from '../pages/audit-logs'
import { api } from '../lib/api'

const mockAuditEvents = {
  events: [
    {
      id: '1',
      event_type: 'authentication',
      action: 'login',
      actor_name: 'john.doe',
      outcome: 'success',
      timestamp: '2024-03-27T10:00:00Z',
    },
  ],
  total: 1,
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

    vi.mocked(api.get).mockResolvedValue(mockAuditEvents)
  })

  it('renders the audit logs page heading', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/Audit/i)).toBeInTheDocument()
    })
  })

  it('displays audit events list', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('john.doe')).toBeInTheDocument()
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
