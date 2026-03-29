import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock must be at top level with factory function
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
    postFormData: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

// Import after mocks
import { UsersPage } from '../pages/users'
import { api } from '../lib/api'

const mockUsers = [
  {
    id: '1',
    username: 'john.doe',
    email: 'john@example.com',
    first_name: 'John',
    last_name: 'Doe',
    enabled: true,
    email_verified: true,
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    username: 'jane.smith',
    email: 'jane@example.com',
    first_name: 'Jane',
    last_name: 'Smith',
    enabled: false,
    email_verified: false,
    created_at: '2024-01-02T00:00:00Z',
  },
]

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('UsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    // Mock API responses
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: mockUsers,
      headers: { 'x-total-count': '2' },
    })
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/roles')) return Promise.resolve([])
      if (url.includes('/ziti')) return Promise.resolve({})
      return Promise.resolve([])
    })
  })

  it('renders the users page heading', async () => {
    const wrapper = createWrapper()

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Users')).toBeInTheDocument()
    })
  })

  it('renders action buttons', async () => {
    const wrapper = createWrapper()

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Export CSV')).toBeInTheDocument()
      expect(screen.getByText('Import CSV')).toBeInTheDocument()
      expect(screen.getByText('Add User')).toBeInTheDocument()
    })
  })

  it('renders search input', async () => {
    const wrapper = createWrapper()

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      const searchInput = screen.getByPlaceholderText('Search users...')
      expect(searchInput).toBeInTheDocument()
    })
  })

  it('opens add user modal when Add User button is clicked', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Add User')).toBeInTheDocument()
    })

    await user.click(screen.getByText('Add User'))

    await waitFor(() => {
      expect(screen.getByText('Add New User')).toBeInTheDocument()
    })
  })

  it('shows empty state when no users found', async () => {
    const wrapper = createWrapper()

    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [],
      headers: { 'x-total-count': '0' },
    })

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('No users found')).toBeInTheDocument()
    })
  })

  it('displays users table when data is loaded', async () => {
    const wrapper = createWrapper()

    // Reset mock to default state
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: mockUsers,
      headers: { 'x-total-count': '2' },
    })

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      // Username is shown as @username in the second line
      expect(screen.getByText('@john.doe')).toBeInTheDocument()
      expect(screen.getByText('@jane.smith')).toBeInTheDocument()
    }, { timeout: 5000 })
  })

  it('displays user status badges', async () => {
    const wrapper = createWrapper()

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument()
      expect(screen.getByText('Disabled')).toBeInTheDocument()
    })
  })

  it('handles search input', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<UsersPage />, { wrapper })

    const searchInput = screen.getByPlaceholderText('Search users...')
    await user.type(searchInput, 'john')

    expect(searchInput).toHaveValue('john')
  })

  it('opens import modal when Import CSV button is clicked', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<UsersPage />, { wrapper })

    await user.click(screen.getByText('Import CSV'))

    await waitFor(() => {
      expect(screen.getByText('Import Users from CSV')).toBeInTheDocument()
    })
  })

  it('shows pagination when total users exceeds page size', async () => {
    const wrapper = createWrapper()

    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: mockUsers,
      headers: { 'x-total-count': '25' },
    })

    render(<UsersPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/Showing/i)).toBeInTheDocument()
      expect(screen.getByText('Previous')).toBeInTheDocument()
      expect(screen.getByText('Next')).toBeInTheDocument()
    })
  })
})
