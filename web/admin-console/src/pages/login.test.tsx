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

  it('renders footer links that go somewhere real', () => {
    renderWithRouter(<LoginPage />)
    // The old Privacy/Terms/Help trio was link-styled text with no
    // destinations; the footer now links to pages that actually exist.
    expect(screen.getByRole('link', { name: /documentation/i })).toHaveAttribute(
      'href',
      expect.stringContaining('mhmtgngr.github.io/openidx'),
    )
    expect(screen.getByRole('link', { name: /^security$/i })).toHaveAttribute(
      'href',
      expect.stringContaining('SECURITY.md'),
    )
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

  // THE BOT GATE'S CHALLENGE, FROM THE SIDE THE PERSON SEES.
  //
  // internal/botgate refuses a login with 403 challenge_required once an
  // account name has collected enough failures from anywhere. The refusal used
  // to be the whole story: the page printed "complete the verification
  // challenge" and offered nothing to complete, so the only move left was to
  // try again into the counter that had just refused. These cases are the two
  // halves of the fix, and the second is the one that keeps it honest.
  describe('bot gate challenge', () => {
    const fetchMock = vi.fn()
    const renderWidget = vi.fn()

    beforeEach(() => {
      sessionStorage.setItem('oidc_login_session', 'test-session')
      fetchMock.mockReset()
      renderWidget.mockReset()
      vi.stubGlobal('fetch', fetchMock)
      // Stand in for the script Cloudflare would have loaded. Its presence is
      // what the component checks, so nothing here reaches the network.
      vi.stubGlobal('turnstile', {
        render: renderWidget.mockImplementation(
          (_el: HTMLElement, opts: { sitekey: string; callback: (token: string) => void }) => {
            ;(window as unknown as { __solve: (t: string) => void }).__solve = opts.callback
            return 'widget-1'
          },
        ),
        remove: vi.fn(),
      })
    })

    afterEach(() => {
      sessionStorage.clear()
      vi.unstubAllGlobals()
    })

    const refuse = (body: unknown) =>
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok: false, status: 403, json: () => Promise.resolve(body) } as Response)
      )

    const submitCredentials = async () => {
      const user = userEvent.setup()
      renderWithRouter(<LoginPage />)
      await user.type(screen.getByLabelText(/username or email/i), 'testuser')
      await user.type(screen.getByLabelText(/^password$/i), 'password123')
      await user.click(screen.getByRole('button', { name: /sign in$/i }))
      return user
    }

    it('renders the challenge and resubmits the same credentials with the token', async () => {
      refuse({
        error: 'challenge_required',
        error_description: 'Too many failed attempts for this account. Complete the verification challenge and try again.',
        site_key: '1x00000000000000000000AA',
      })
      await submitCredentials()

      await screen.findByTestId('turnstile-challenge')
      await waitFor(() => expect(renderWidget).toHaveBeenCalledTimes(1))
      expect(renderWidget.mock.calls[0][1]).toMatchObject({ sitekey: '1x00000000000000000000AA' })

      // Solving it must resend the credentials the person already typed: the
      // gate refused BEFORE the password was checked, so nothing about them
      // was wrong, and retyping would punish them for someone else's guessing.
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok: true, json: () => Promise.resolve({ redirect_url: 'https://app.example.com/cb?code=abc' }) } as Response)
      )
      ;(window as unknown as { __solve: (t: string) => void }).__solve('solved-token')

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
      const [url, init] = fetchMock.mock.calls[1]
      expect(String(url)).toContain('/oauth/login')
      expect(JSON.parse((init as RequestInit).body as string)).toMatchObject({
        username: 'testuser',
        password: 'password123',
        challenge_token: 'solved-token',
      })
    })

    it('shows no widget when the refusal carries no site key', async () => {
      // The deployment shape that shipped: the gate enforces, no Turnstile is
      // configured, and the server says to wait. A widget here would be one
      // the server cannot check -- solving it would land back on this same
      // refusal, which reads as a broken login rather than a lockout.
      refuse({
        error: 'challenge_required',
        error_description: 'Too many failed attempts for this account. Wait a few minutes before trying again.',
      })
      await submitCredentials()

      await screen.findByText(/wait a few minutes/i)
      expect(screen.queryByTestId('turnstile-challenge')).not.toBeInTheDocument()
      expect(renderWidget).not.toHaveBeenCalled()
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('leaves an ordinary failure alone', async () => {
      // Vacuity guard: if the page rendered the widget on any 403, the case
      // above would pass for the wrong reason.
      refuse({ error: 'invalid_grant', error_description: 'Invalid username or password' })
      await submitCredentials()

      await screen.findByText(/invalid username or password/i)
      expect(screen.queryByTestId('turnstile-challenge')).not.toBeInTheDocument()
    })
  })
})
