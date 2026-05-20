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
    patch: vi.fn(() => Promise.resolve({})),
  },
}))

// Mock toast hook
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

// Mock auth hook (component reads user.id for reviewer assignment)
vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    user: { id: 'reviewer-1', username: 'reviewer', email: 'reviewer@example.com' },
    isAuthenticated: true,
    isLoading: false,
  }),
}))

// Import after mocks
import { AccessReviewsPage } from '../pages/access-reviews'
import { api } from '../lib/api'

const mockReviews = [
  {
    id: '1',
    name: 'Q1 2024 Access Review',
    description: 'Quarterly access review for all users',
    status: 'active',
    start_date: '2024-01-01T00:00:00Z',
    end_date: '2024-01-31T23:59:59Z',
    total_items: 50,
    completed_items: 25,
    created_at: '2023-12-15T00:00:00Z',
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

describe('AccessReviewsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockReviews)
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: mockReviews, headers: {} })
  })

  it('renders the access reviews page heading', async () => {
    const wrapper = createWrapper()

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Access Reviews/i })).toBeInTheDocument()
    })
  })

  it('displays access review list', async () => {
    const wrapper = createWrapper()

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Q1 2024 Access Review')).toBeInTheDocument()
    })
  })

  it('displays review descriptions', async () => {
    const wrapper = createWrapper()

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/Quarterly access review/i)).toBeInTheDocument()
    })
  })

  it('has create review button', async () => {
    const wrapper = createWrapper()

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      const createButton = screen.queryByRole('button', { name: /create/i })
      expect(createButton).toBeInTheDocument()
    })
  })

  it('shows empty state when no reviews exist', async () => {
    const wrapper = createWrapper()

    vi.mocked(api.get).mockResolvedValue([])
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [], headers: {} })

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/No access reviews/i)).toBeInTheDocument()
    })
  })

  it('displays date range for reviews', async () => {
    const wrapper = createWrapper()

    render(<AccessReviewsPage />, { wrapper })

    await waitFor(() => {
      const dates = screen.queryAllByText(/\d{4}/)
      expect(dates.length).toBeGreaterThan(0)
    })
  })
})
