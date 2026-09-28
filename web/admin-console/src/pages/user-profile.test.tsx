import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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
const { toastMock } = vi.hoisted(() => ({ toastMock: vi.fn() }))
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: toastMock,
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

  // The identity service refuses a change to the account's second factors, or
  // its address, until the request carries proof from the account holder
  // (internal/identity/factor_proof.go). The page asks for it and sends it.
  const refusal = (error: string, accepts: string[]) => ({
    response: { status: 403, data: { error, error_description: 'x', accepts } },
  })

  const withMFA = () =>
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === '/api/v1/identity/users/me') return Promise.resolve({ ...mockProfile, mfaEnabled: true })
      if (url.includes('/password-info')) return Promise.resolve({ source: 'local', password_must_change: false })
      if (url.includes('/mfa/methods')) return Promise.resolve({ methods: { totp: true }, enabled_count: 1, mfa_enabled: true })
      return Promise.resolve([])
    })

  const openDisable = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(await screen.findByRole('tab', { name: /security/i }))
    await user.click(await screen.findByRole('button', { name: 'Disable MFA' }))
    const confirm = await screen.findByRole('alertdialog')
    await user.click(within(confirm).getByRole('button', { name: 'Disable MFA' }))
  }

  it('asks for a code or the password before disabling MFA, and sends it', async () => {
    const user = userEvent.setup()
    withMFA()
    vi.mocked(api.post).mockImplementation((url: string, body?: unknown) => {
      const proof = body as { totp_code?: string; current_password?: string } | undefined
      if (url.endsWith('/users/me/mfa/disable') && !proof?.totp_code && !proof?.current_password) {
        return Promise.reject(refusal('reauthentication_required', ['current_password', 'totp_code']))
      }
      return Promise.resolve({})
    })
    render(<UserProfilePage />, { wrapper: createWrapper() })

    await openDisable(user)
    const prompt = await screen.findByRole('dialog')
    expect(prompt).toHaveTextContent('Enter your current password, or a code from your authenticator app')
    await user.type(within(prompt).getByLabelText('Authenticator code'), '123456')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))

    await waitFor(() =>
      expect(api.post).toHaveBeenLastCalledWith('/api/v1/identity/users/me/mfa/disable', { totp_code: '123456' }),
    )
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('shows a clear error when the proof is wrong, and does not disable MFA', async () => {
    const user = userEvent.setup()
    withMFA()
    vi.mocked(api.post).mockImplementation((url: string, body?: unknown) => {
      if (!url.endsWith('/users/me/mfa/disable')) return Promise.resolve({})
      const proof = body as { current_password?: string } | undefined
      return Promise.reject(
        refusal(proof?.current_password ? 'reauthentication_failed' : 'reauthentication_required', ['current_password']),
      )
    })
    render(<UserProfilePage />, { wrapper: createWrapper() })

    await openDisable(user)
    const prompt = await screen.findByRole('dialog')
    await user.type(within(prompt).getByLabelText('Current password'), 'not-my-password')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))

    expect(await within(await screen.findByRole('dialog')).findByRole('alert')).toHaveTextContent(
      'That password is not correct.',
    )
    expect(toastMock).not.toHaveBeenCalledWith(expect.objectContaining({ description: 'MFA disabled' }))
  })

  it('asks for the password when the address changes, and not for a name', async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockImplementation((_url: string, body?: unknown) => {
      const update = body as { email?: string; current_password?: string }
      if (update.email !== mockProfile.email && !update.current_password) {
        return Promise.reject(refusal('reauthentication_required', ['current_password']))
      }
      return Promise.resolve({ ...mockProfile, ...update })
    })
    render(<UserProfilePage />, { wrapper: createWrapper() })

    const first = await screen.findByLabelText('First Name')
    await user.clear(first)
    await user.type(first, 'Renamed')
    await user.click(screen.getByRole('button', { name: 'Update Profile' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenLastCalledWith('/api/v1/identity/users/me', {
        firstName: 'Renamed', lastName: 'User', email: 'test@example.com',
      }),
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    const email = screen.getByLabelText('Email')
    await user.clear(email)
    await user.type(email, 'moved@example.com')
    await user.click(screen.getByRole('button', { name: 'Update Profile' }))
    const prompt = await screen.findByRole('dialog')
    await user.type(within(prompt).getByLabelText('Current password'), 'my-password')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenLastCalledWith('/api/v1/identity/users/me', {
        firstName: 'Renamed', lastName: 'User', email: 'moved@example.com', current_password: 'my-password',
      }),
    )
  })
})
