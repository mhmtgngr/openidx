import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { LoginPage } from './login'

// Mock the auth library - use the same path as the component
vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    login: vi.fn(),
    isAuthenticated: false,
    isLoading: false,
  }),
}))

// Mock the API library - use factory to avoid hoisting issues
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getIdentityProviders: vi.fn(() => Promise.resolve([])),
  },
  baseURL: 'http://localhost:8001',
  IdentityProvider: {},
  getOAuthURL: vi.fn(() => 'http://localhost:8001'),
}))

// Mock WebAuthn functions - use the same path as the component
vi.mock('../lib/webauthn', () => ({
  decodeCredentialRequestOptions: vi.fn((x) => x),
  serializeAssertionResponse: vi.fn(() => '{}'),
}))

// Mock QRCode component
vi.mock('qrcode.react', () => ({
  QRCodeSVG: () => <div data-testid="qrcode">QR Code</div>,
}))

// Mock social provider icons - use the same path as the component
vi.mock('../components/icons/social-providers', () => ({
  getProviderIcon: () => null,
}))

// Mock window.location
const mockLocation = {
  hostname: 'localhost',
  search: '',
  href: 'http://localhost:5173/login',
}

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
})

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // Reset location search
    window.location.search = ''
  })

  const renderWithRouter = (component: React.ReactNode) => {
    return render(<MemoryRouter>{component}</MemoryRouter>)
  }

  it('renders the login card', () => {
    renderWithRouter(<LoginPage />)
    // Use getAllByText since OpenIDX appears multiple times
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
    expect(screen.getByText('Identity & Access Management Platform')).toBeInTheDocument()
  })

  it('renders footer links', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText('Privacy')).toBeInTheDocument()
    expect(screen.getByText('Terms')).toBeInTheDocument()
    expect(screen.getByText('Help')).toBeInTheDocument()
  })

  it('renders powered by footer', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText(/powered by/i)).toBeInTheDocument()
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
  })

  it('renders the shield icon container in the card header', () => {
    renderWithRouter(<LoginPage />)
    // The shield icon should be present (class from lucide)
    const cardHeader = document.querySelector('.bg-gradient-to-br')
    expect(cardHeader).toBeInTheDocument()
  })

  it('displays sign-in text', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText(/Sign in to access your OpenIDX admin console/i)).toBeInTheDocument()
  })

  // The "trust this browser" choice must ride along with the MFA verification:
  // that request is the only one the server can act on (it still holds the MFA
  // session), and it is what actually writes the trusted_browsers row. The old
  // post-verification prompt POSTed to the identity API with no access token,
  // so it always 401'd and no browser was ever trusted.
  describe('MFA trust-this-browser', () => {
    const fetchMock = vi.fn()

    beforeEach(() => {
      sessionStorage.setItem('oidc_login_session', 'test-session')
      fetchMock.mockReset()
      vi.stubGlobal('fetch', fetchMock)
    })

    afterEach(() => {
      sessionStorage.clear()
      vi.unstubAllGlobals()
    })

    const jsonOnce = (body: unknown) =>
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok: true, json: () => Promise.resolve(body) } as Response)
      )

    const reachMFAScreen = async (canTrustBrowser: boolean) => {
      jsonOnce({
        mfa_required: true,
        mfa_session: 'mfa-session-1',
        mfa_methods: ['totp'],
        can_trust_browser: canTrustBrowser,
      })
      const user = userEvent.setup()
      renderWithRouter(<LoginPage />)
      await user.type(screen.getByLabelText(/username or email/i), 'testuser')
      await user.type(screen.getByLabelText(/^password$/i), 'password123')
      await user.click(screen.getByRole('button', { name: /sign in$/i }))
      await screen.findByLabelText(/verification code/i)
      return user
    }

    it('sends trust_browser with the verification when the user opts in', async () => {
      const user = await reachMFAScreen(true)

      await user.click(screen.getByRole('checkbox', { name: /trust this browser/i }))

      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=abc' })
      await user.type(screen.getByLabelText(/verification code/i), '123456')
      await user.click(screen.getByRole('button', { name: /^verify$/i }))

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledTimes(2)
      })
      const [url, init] = fetchMock.mock.calls[1]
      expect(String(url)).toContain('/oauth/mfa-verify')
      expect(JSON.parse((init as RequestInit).body as string)).toMatchObject({
        mfa_session: 'mfa-session-1',
        code: '123456',
        trust_browser: true,
      })
    })

    it('defaults to not trusting the browser', async () => {
      const user = await reachMFAScreen(true)

      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=abc' })
      await user.type(screen.getByLabelText(/verification code/i), '123456')
      await user.click(screen.getByRole('button', { name: /^verify$/i }))

      await waitFor(() => {
        expect(fetchMock).toHaveBeenCalledTimes(2)
      })
      const [, init] = fetchMock.mock.calls[1]
      expect(JSON.parse((init as RequestInit).body as string).trust_browser).toBe(false)
    })

    it('hides the option when the browser is already trusted', async () => {
      await reachMFAScreen(false)
      expect(screen.queryByRole('checkbox', { name: /trust this browser/i })).not.toBeInTheDocument()
    })
  })
})
