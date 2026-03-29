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

// Mock toast hook
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

// Import after mocks
import { GroupsPage } from '../pages/groups'
import { api } from '../lib/api'

const mockGroups = [
  {
    id: '1',
    name: 'Administrators',
    description: 'System administrators with full access',
    member_count: 5,
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    name: 'Developers',
    description: 'Development team members',
    member_count: 15,
    created_at: '2024-01-02T00:00:00Z',
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

describe('GroupsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    // Mock getWithHeaders with proper response
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: mockGroups,
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the groups page heading', async () => {
    const wrapper = createWrapper()

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Groups')).toBeInTheDocument()
    })
  })

  it('displays group list', async () => {
    const wrapper = createWrapper()

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Administrators')).toBeInTheDocument()
      expect(screen.getByText('Developers')).toBeInTheDocument()
    })
  })

  it('displays group descriptions', async () => {
    const wrapper = createWrapper()

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/System administrators/i)).toBeInTheDocument()
      expect(screen.getByText(/Development team/i)).toBeInTheDocument()
    })
  })

  it('displays member count for each group', async () => {
    const wrapper = createWrapper()

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/5/)).toBeInTheDocument()
      expect(screen.getByText(/15/)).toBeInTheDocument()
    })
  })

  it('has add group button', async () => {
    const wrapper = createWrapper()

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      const addButton = screen.queryByRole('button', { name: /add/i })
      expect(addButton).toBeInTheDocument()
    })
  })

  it('shows empty state when no groups exist', async () => {
    const wrapper = createWrapper()

    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [],
      headers: { 'x-total-count': '0' },
    })

    render(<GroupsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/No groups/i)).toBeInTheDocument()
    })
  })
})
