import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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

// Mock toast hook. One spy for every render, so a test can read what the
// page told the user.
const toastMock = vi.hoisted(() => vi.fn())
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}))

// Import after mocks
import { RolesPage } from '../pages/roles'
import { api } from '../lib/api'

const mockRoles = [
  {
    id: '1',
    name: 'admin',
    description: 'Full system administrator',
    is_composite: false,
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    name: 'user',
    description: 'Regular user access',
    is_composite: false,
    created_at: '2024-01-01T00:00:00Z',
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

describe('RolesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    // Mock getWithHeaders with proper response
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: mockRoles,
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the roles page heading', async () => {
    const wrapper = createWrapper()

    render(<RolesPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Roles')).toBeInTheDocument()
    })
  })

  it('displays role descriptions', async () => {
    const wrapper = createWrapper()

    render(<RolesPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('admin')).toBeInTheDocument()
      expect(screen.getByText('user')).toBeInTheDocument()
    })
  })

  it('has add role button', async () => {
    const wrapper = createWrapper()

    render(<RolesPage />, { wrapper })

    await waitFor(() => {
      const addButton = screen.queryByRole('button', { name: /add/i })
      expect(addButton).toBeInTheDocument()
    })
  })

  it('shows empty state when no roles exist', async () => {
    const wrapper = createWrapper()

    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [],
      headers: { 'x-total-count': '0' },
    })

    render(<RolesPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText(/No roles/i)).toBeInTheDocument()
    })
  })

  it('displays roles in a list or table', async () => {
    const wrapper = createWrapper()

    render(<RolesPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('admin')).toBeInTheDocument()
    })
  })

  // The identity API refuses the role name super_admin outside the install's
  // default organization. The page says why, rather than "Request failed with
  // status code 400"; any other failure keeps its own message.
  describe('the reserved role name', () => {
    const refusal = (code: string) =>
      Object.assign(new Error('Request failed with status code 400'), {
        isAxiosError: true,
        response: { status: 400, data: { error: code } },
      })

    const createRole = async (name: string) => {
      const user = userEvent.setup()
      render(<RolesPage />, { wrapper: createWrapper() })
      await user.click(await screen.findByRole('button', { name: /add role/i }))
      await user.type(await screen.findByLabelText(/role name/i), name)
      await user.click(screen.getByRole('button', { name: /create role/i }))
    }

    it('explains a refused super_admin', async () => {
      vi.mocked(api.post).mockRejectedValue(refusal('reserved_role_name'))
      await createRole('super_admin')

      await waitFor(() => expect(toastMock).toHaveBeenCalled())
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: 'destructive',
          description: expect.stringMatching(/reserved for the platform administrators of the default organization/i),
        }),
      )
    })

    it('keeps the generic message for any other failure', async () => {
      vi.mocked(api.post).mockRejectedValue(refusal('something_else'))
      await createRole('operations')

      await waitFor(() => expect(toastMock).toHaveBeenCalled())
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ description: 'Failed to create role: Request failed with status code 400' }),
      )
    })
  })
})
