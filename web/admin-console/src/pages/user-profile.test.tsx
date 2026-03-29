import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the auth library
vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    user: { id: '1', username: 'testuser', email: 'test@example.com' },
  }),
}))

// Mock the API module - need to handle all the different API calls
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({})),
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

// Mock QRCode component
vi.mock('qrcode.react', () => ({
  QRCodeSVG: () => <div data-testid="qrcode">QR Code</div>,
}))

// Import after mocks
import { UserProfilePage } from '../pages/user-profile'
import { api } from '../lib/api'

const mockProfile = {
  id: '1',
  username: 'testuser',
  email: 'test@example.com',
  firstName: 'Test',
  lastName: 'User',
  enabled: true,
  emailVerified: true,
  mfaEnabled: false,
  mfaMethods: [],
  createdAt: '2024-01-01T00:00:00Z',
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

describe('UserProfilePage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    // Simple mock that returns the profile for all requests
    // The page has many different API calls, so we just return a basic response
    vi.mocked(api.get).mockResolvedValue(mockProfile)
  })

  it('renders without crashing', () => {
    const wrapper = createWrapper()

    render(<UserProfilePage />, { wrapper })
    // Just check that it renders without errors
    expect(document.body).toBeInTheDocument()
  })

  it('renders the user profile component', () => {
    const wrapper = createWrapper()

    render(<UserProfilePage />, { wrapper })

    // Component should render
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })
})
