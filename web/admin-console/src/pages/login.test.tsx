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

  // The server pauses code issuance with a consent challenge when the
  // application requires the user's approval (require_consent) and none is on
  // record. Until finishAuth existed the page checked only redirect_url, so
  // that 200 left it silent: no error, no redirect, no screen, and nothing
  // ever posted to /oauth/consent. These tests pin the screen, both decisions,
  // and that the challenge is honoured whichever path produced it.
  describe('consent challenge', () => {
    const fetchMock = vi.fn()

    const challenge = {
      consent_required: true,
      consent_session: 'consent-1',
      client_id: 'crm',
      client_name: 'Acme CRM',
      scopes: ['openid', 'profile', 'email'],
    }

    beforeEach(() => {
      sessionStorage.setItem('oidc_login_session', 'test-session')
      fetchMock.mockReset()
      vi.stubGlobal('fetch', fetchMock)
      mockLocation.href = 'http://localhost:5173/login'
    })

    afterEach(() => {
      sessionStorage.clear()
      vi.unstubAllGlobals()
    })

    const jsonOnce = (body: unknown, ok = true) =>
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok, json: () => Promise.resolve(body) } as Response)
      )

    const signIn = async () => {
      const user = userEvent.setup()
      renderWithRouter(<LoginPage />)
      await user.type(screen.getByLabelText(/username or email/i), 'testuser')
      await user.type(screen.getByLabelText(/^password$/i), 'password123')
      await user.click(screen.getByRole('button', { name: /sign in$/i }))
      return user
    }

    const reachConsentScreen = async () => {
      jsonOnce(challenge)
      const user = await signIn()
      await screen.findByRole('button', { name: /^allow$/i })
      return user
    }

    it('renders the application and the requested scopes instead of going silent', async () => {
      await reachConsentScreen()
      expect(screen.getByText(/Acme CRM/)).toBeInTheDocument()
      for (const scope of challenge.scopes) {
        expect(screen.getByText(scope)).toBeInTheDocument()
      }
      expect(screen.getByRole('button', { name: /^deny$/i })).toBeInTheDocument()
      // Nothing was posted and nothing was followed until the person decides.
      expect(fetchMock).toHaveBeenCalledTimes(1)
      expect(mockLocation.href).toBe('http://localhost:5173/login')
    })

    it('allowing posts approve=true to /oauth/consent and follows the redirect', async () => {
      const user = await reachConsentScreen()
      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=abc&state=st' })
      await user.click(screen.getByRole('button', { name: /^allow$/i }))

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
      const [url, init] = fetchMock.mock.calls[1]
      expect(String(url)).toContain('/oauth/consent')
      expect(JSON.parse((init as RequestInit).body as string)).toEqual({
        consent_session: 'consent-1',
        approve: true,
      })
      await waitFor(() =>
        expect(mockLocation.href).toBe('https://app.example.com/callback?code=abc&state=st')
      )
      // The pending login_session marker is cleared like any other completion.
      expect(sessionStorage.getItem('oidc_login_session')).toBeNull()
    })

    it('denying posts approve=false and follows the error redirect to the client', async () => {
      const user = await reachConsentScreen()
      jsonOnce({ redirect_url: 'https://app.example.com/callback?error=access_denied&state=st' })
      await user.click(screen.getByRole('button', { name: /^deny$/i }))

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
      const [, init] = fetchMock.mock.calls[1]
      expect(JSON.parse((init as RequestInit).body as string)).toEqual({
        consent_session: 'consent-1',
        approve: false,
      })
      await waitFor(() =>
        expect(mockLocation.href).toBe('https://app.example.com/callback?error=access_denied&state=st')
      )
    })

    it('a refused decision drops the one-time challenge and says so', async () => {
      const user = await reachConsentScreen()
      jsonOnce({ error: 'invalid_request', error_description: 'invalid or expired consent session' }, false)
      await user.click(screen.getByRole('button', { name: /^allow$/i }))

      await screen.findByText(/invalid or expired consent session/i)
      expect(screen.queryByRole('button', { name: /^allow$/i })).not.toBeInTheDocument()
      expect(mockLocation.href).toBe('http://localhost:5173/login')
    })

    it('a challenge returned after MFA verification is rendered too', async () => {
      jsonOnce({ mfa_required: true, mfa_session: 'mfa-1', mfa_methods: ['totp'] })
      const user = await signIn()
      await screen.findByLabelText(/verification code/i)

      jsonOnce(challenge)
      await user.type(screen.getByLabelText(/verification code/i), '123456')
      await user.click(screen.getByRole('button', { name: /^verify$/i }))

      await screen.findByRole('button', { name: /^allow$/i })
      expect(screen.getByText(/Acme CRM/)).toBeInTheDocument()
      expect(mockLocation.href).toBe('http://localhost:5173/login')
    })

    it('a plain redirect_url still redirects (control)', async () => {
      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=xyz' })
      await signIn()
      await waitFor(() => expect(mockLocation.href).toBe('https://app.example.com/callback?code=xyz'))
      expect(screen.queryByRole('button', { name: /^allow$/i })).not.toBeInTheDocument()
    })

    // Census: every completion path must hand its response to finishAuth.
    // A path that follows redirect_url on its own is exactly the shape of the
    // defect this block exists for, so the source is read and counted.
    it('no completion path follows redirect_url on its own', async () => {
      const source = (await import('./login.tsx?raw')).default as string
      // finishAuth follows a redirect, or holds it for the MFA policy's notice
      // and the notice's Continue button follows what finishAuth held.
      const directRedirects = source.match(/completeOIDCRedirect\(/g) ?? []
      expect(directRedirects, 'completeOIDCRedirect is called from finishAuth and the notice it holds').toHaveLength(2)
      expect(source.match(/completeOIDCRedirect\(pendingRedirect\.url\)/g) ?? []).toHaveLength(1)
      const redirectReads = source.match(/\.redirect_url\b/g) ?? []
      expect(redirectReads, 'redirect_url is read inside finishAuth only').toHaveLength(3)
      expect(source.match(/finishAuth\(/g) ?? [], 'seven completion paths, the consent decision and the browser-session resume').toHaveLength(9)
    })
  })

  // An MFA policy that requires particular methods tells a user who has none
  // of them by when to add one, and after that lets them in only with an
  // administrator's bypass code. The notice rides on the challenge and on the
  // response that completes the sign-in (mfa_enrollment_due).
  describe('MFA policy notice', () => {
    const fetchMock = vi.fn()
    const due = { methods: ['webauthn'], deadline: '2026-10-01T12:00:00Z' }

    beforeEach(() => {
      sessionStorage.setItem('oidc_login_session', 'test-session')
      fetchMock.mockReset()
      vi.stubGlobal('fetch', fetchMock)
      mockLocation.href = 'http://localhost:5173/login'
    })

    afterEach(() => {
      sessionStorage.clear()
      vi.unstubAllGlobals()
    })

    const jsonOnce = (body: unknown, ok = true) =>
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok, json: () => Promise.resolve(body) } as Response)
      )

    const signIn = async () => {
      const user = userEvent.setup()
      renderWithRouter(<LoginPage />)
      await user.type(screen.getByLabelText(/username or email/i), 'testuser')
      await user.type(screen.getByLabelText(/^password$/i), 'password123')
      await user.click(screen.getByRole('button', { name: /sign in$/i }))
      return user
    }

    it('the MFA screen says which method is due, and by when', async () => {
      jsonOnce({ mfa_required: true, mfa_session: 'mfa-1', mfa_methods: ['totp'], mfa_enrollment_due: due })
      await signIn()
      await screen.findByLabelText(/verification code/i)
      const notice = screen.getByRole('status')
      expect(notice).toHaveTextContent(/requires Security Key to sign in/i)
      expect(notice).toHaveTextContent(/add one before/i)
    })

    it('a challenge without the notice shows none (control)', async () => {
      jsonOnce({ mfa_required: true, mfa_session: 'mfa-1', mfa_methods: ['totp'] })
      await signIn()
      await screen.findByLabelText(/verification code/i)
      expect(screen.queryByRole('status')).not.toBeInTheDocument()
    })

    it('holds the redirect until the notice is read', async () => {
      jsonOnce({ mfa_required: true, mfa_session: 'mfa-1', mfa_methods: ['totp'], mfa_enrollment_due: due })
      const user = await signIn()
      await screen.findByLabelText(/verification code/i)

      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=abc', mfa_enrollment_due: due })
      await user.type(screen.getByLabelText(/verification code/i), '123456')
      await user.click(screen.getByRole('button', { name: /^verify$/i }))

      await screen.findByText(/add a sign-in method/i)
      expect(mockLocation.href).toBe('http://localhost:5173/login')
      await user.click(screen.getByRole('button', { name: /^continue$/i }))
      expect(mockLocation.href).toBe('https://app.example.com/callback?code=abc')
      expect(sessionStorage.getItem('oidc_login_session')).toBeNull()
    })

    it('a sign-in with no challenge shows the notice before the redirect too', async () => {
      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=xyz', mfa_enrollment_due: due })
      const user = await signIn()
      await screen.findByText(/add a sign-in method/i)
      expect(mockLocation.href).toBe('http://localhost:5173/login')
      await user.click(screen.getByRole('button', { name: /^continue$/i }))
      expect(mockLocation.href).toBe('https://app.example.com/callback?code=xyz')
    })

    it('after the grace period, a bypass code of letters and digits can be entered and sent', async () => {
      jsonOnce({
        mfa_required: true,
        mfa_session: 'mfa-1',
        mfa_methods: ['bypass'],
        mfa_enrollment_due: { ...due, overdue: true },
      })
      const user = await signIn()
      const input = await screen.findByLabelText(/verification code/i)
      expect(screen.getByRole('status')).toHaveTextContent(/the time to add one has passed/i)
      expect(screen.getByText(/enter the bypass code an administrator gave you/i)).toBeInTheDocument()

      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=abc', mfa_enrollment_due: { ...due, overdue: true } })
      await user.type(input, 'Ab3-_xYz9Qw2Er5T')
      expect(input).toHaveValue('Ab3-_xYz9Qw2Er5T')
      await user.click(screen.getByRole('button', { name: /^verify$/i }))

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
      const [url, init] = fetchMock.mock.calls[1]
      expect(String(url)).toContain('/oauth/mfa-verify')
      expect(JSON.parse((init as RequestInit).body as string)).toMatchObject({
        mfa_session: 'mfa-1',
        code: 'Ab3-_xYz9Qw2Er5T',
        method: 'bypass',
      })
      await screen.findByText(/add a sign-in method/i)
    })

    it('a one-time code is still six digits (control)', async () => {
      jsonOnce({ mfa_required: true, mfa_session: 'mfa-1', mfa_methods: ['totp'] })
      const user = await signIn()
      const input = await screen.findByLabelText(/verification code/i)
      await user.type(input, 'Ab-_x12345678')
      expect(input).toHaveValue('123456')
    })

    it('a refusal after the grace period says why', async () => {
      jsonOnce(
        {
          error: 'mfa_enrollment_required',
          error_description:
            'Your organization requires one of these sign-in methods: webauthn. The time to add one has passed. Ask an administrator for a bypass code, sign in with it, and add one.',
          required_methods: ['webauthn'],
        },
        false,
      )
      await signIn()
      expect(await screen.findByText(/the time to add one has passed/i)).toBeInTheDocument()
      expect(mockLocation.href).toBe('http://localhost:5173/login')
    })
  })

  // A sign-in link that cannot finish the sign-in (a second factor is needed,
  // or a policy's grace period is over) comes back here with ?error= and the
  // pending request's login_session, so the person can continue with their
  // password.
  describe('a sign-in link sent back', () => {
    afterEach(() => {
      sessionStorage.clear()
      window.location.search = ''
    })

    it('says why, and keeps the pending request', async () => {
      window.location.search = '?login_session=ls-link-1&error=mfa_required'
      renderWithRouter(<LoginPage />)
      expect(await screen.findByText(/needs a second factor, and a sign-in link cannot ask for one/i)).toBeInTheDocument()
      expect(sessionStorage.getItem('oidc_login_session')).toBe('ls-link-1')
    })

    it('says when the time to add a required method has passed', async () => {
      window.location.search = '?login_session=ls-link-2&error=mfa_enrollment_required'
      renderWithRouter(<LoginPage />)
      expect(await screen.findByText(/the time to add one has passed/i)).toBeInTheDocument()
    })

    it('an error it does not know says nothing (control)', () => {
      window.location.search = '?error=something_else'
      renderWithRouter(<LoginPage />)
      expect(screen.queryByText(/sign-in link/i)).not.toBeInTheDocument()
    })
  })

  // /oauth/authorize appends resume=1 when the browser holds a live session
  // that could not be carried straight to a code because this page has a
  // screen to show. The page then completes the pending request from that
  // session instead of asking for a password; a refusal leaves the form.
  describe('browser-session resume', () => {
    const fetchMock = vi.fn()

    const challenge = {
      consent_required: true,
      consent_session: 'consent-9',
      client_id: 'crm',
      client_name: 'Acme CRM',
      scopes: ['openid'],
    }

    beforeEach(() => {
      fetchMock.mockReset()
      vi.stubGlobal('fetch', fetchMock)
      mockLocation.href = 'http://localhost:5173/login'
    })

    afterEach(() => {
      sessionStorage.clear()
      vi.unstubAllGlobals()
      window.location.search = ''
    })

    const jsonOnce = (body: unknown, ok = true) =>
      fetchMock.mockImplementationOnce(() =>
        Promise.resolve({ ok, status: ok ? 200 : 401, json: () => Promise.resolve(body) } as Response)
      )

    it('with the hint, completes from the session and renders the consent screen — no password', async () => {
      window.location.search = '?login_session=ls-1&resume=1'
      jsonOnce(challenge)
      renderWithRouter(<LoginPage />)

      await screen.findByRole('button', { name: /^allow$/i })
      expect(screen.getByText(/Acme CRM/)).toBeInTheDocument()
      expect(fetchMock).toHaveBeenCalledTimes(1)
      const [url, init] = fetchMock.mock.calls[0]
      expect(String(url)).toContain('/oauth/login/resume')
      expect(JSON.parse((init as RequestInit).body as string)).toEqual({ login_session: 'ls-1' })
      // The pending login_session is still the page's for the decision.
      expect(sessionStorage.getItem('oidc_login_session')).toBe('ls-1')
    })

    it('with the hint, follows a redirect_url straight away', async () => {
      window.location.search = '?login_session=ls-2&resume=1'
      jsonOnce({ redirect_url: 'https://app.example.com/callback?code=sso' })
      renderWithRouter(<LoginPage />)
      await waitFor(() => expect(mockLocation.href).toBe('https://app.example.com/callback?code=sso'))
    })

    it('a 401 login_required leaves the form exactly as it is', async () => {
      window.location.search = '?login_session=ls-3&resume=1'
      // A refusal is never acted on, whatever its body says: an error
      // response that happened to carry a redirect_url must not drive the
      // browser anywhere.
      jsonOnce(
        {
          error: 'login_required',
          error_description: 'the client asked for an interactive login',
          redirect_url: 'https://app.example.com/callback?error=must_not_be_followed',
        },
        false,
      )
      renderWithRouter(<LoginPage />)

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
      await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
      expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /^allow$/i })).not.toBeInTheDocument()
      expect(screen.queryByText(/interactive login/i)).not.toBeInTheDocument()
      expect(mockLocation.href).toBe('http://localhost:5173/login')
    })

    it('without the hint, nothing is asked of the server (control)', async () => {
      window.location.search = '?login_session=ls-4'
      renderWithRouter(<LoginPage />)
      expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument()
      await new Promise((r) => setTimeout(r, 20))
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('the hint is read from the URL, never from a stored login_session', async () => {
      sessionStorage.setItem('oidc_login_session', 'ls-old')
      window.location.search = '?resume=1'
      renderWithRouter(<LoginPage />)
      await new Promise((r) => setTimeout(r, 20))
      expect(fetchMock).not.toHaveBeenCalled()
    })
  })
})
