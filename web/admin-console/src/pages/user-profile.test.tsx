import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

    // The page issues many GET queries with different expected shapes:
    // the profile/password-info/mfa-methods endpoints return objects, while the
    // sessions / trusted-browsers / tokens / consents endpoints return arrays.
    // Return the right shape per URL so list consumers (.filter/.map) don't crash.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/v1/identity/users/me') return Promise.resolve(mockProfile)
      if (url.includes('/password-info')) {
        return Promise.resolve({
          source: 'local',
          is_ldap: false,
          is_azure_ad: false,
          is_directory_managed: false,
          password_must_change: false,
        })
      }
      if (url.includes('/mfa/methods')) {
        return Promise.resolve({ methods: {}, enabled_count: 0, mfa_enabled: false })
      }
      // Array-returning endpoints: sessions, trusted-browsers, tokens, consents
      return Promise.resolve([])
    })
  })

  it('renders without crashing', () => {
    const wrapper = createWrapper()

    render(<UserProfilePage />, { wrapper })
    // Just check that it renders without errors
    expect(document.body).toBeInTheDocument()
  })

  it('renders the user profile component', async () => {
    const wrapper = createWrapper()

    render(<UserProfilePage />, { wrapper })

    // The profile query resolves asynchronously; once it does the page
    // renders the "My Profile" heading inside the .space-y-6 container.
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /My Profile/i })).toBeInTheDocument()
    })
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })
})
