import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { ApplicationsPage } from '../pages/applications'
import { api } from '../lib/api'

const mockApplications = [
  {
    id: '1',
    name: 'Test App',
    description: 'A test application',
    client_id: 'test-client-id',
    created_at: '2024-01-01T00:00:00Z',
    enabled: true,
  },
]

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

describe('ApplicationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockApplications)
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: mockApplications, headers: {} })
  })

  it('renders the applications page heading', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Applications')).toBeInTheDocument()
    })
  })

  it('displays application list', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Test App')).toBeInTheDocument()
    })
  })

  it('has add application button', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      const addButton = screen.queryByRole('button', { name: /register application/i })
      expect(addButton).toBeInTheDocument()
    })
  })
})
