import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  baseURL: 'http://test',
}))

vi.mock('qrcode.react', () => ({
  QRCodeSVG: ({ value }: { value: string }) => <div data-testid="qrcode">{value}</div>,
}))

import { AcceptInvitePage } from './accept-invite'

const originalFetch = globalThis.fetch

type Call = { url: string; body: unknown }

function mockFetch(responses: Array<{ status: number; body: unknown }>) {
  const calls: Call[] = []
  ;(globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: string, init: { body: string }) => {
    calls.push({ url, body: JSON.parse(init.body) })
    const next = responses.shift() ?? { status: 500, body: {} }
    return { ok: next.status < 300, status: next.status, json: async () => next.body }
  })
  return calls
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AcceptInvitePage />
    </MemoryRouter>,
  )
}

async function fillAccount(user: ReturnType<typeof userEvent.setup>, confirm = 'Str0ng-pass!') {
  await user.type(screen.getByLabelText('Username'), 'mert')
  await user.type(screen.getByLabelText('First name'), 'Mert')
  await user.type(screen.getByLabelText('Password'), 'Str0ng-pass!')
  await user.type(screen.getByLabelText('Confirm password'), confirm)
  await user.click(screen.getByRole('button', { name: 'Create account' }))
}

describe('AcceptInvitePage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })
  afterEach(() => {
    ;(globalThis as unknown as { fetch: typeof originalFetch }).fetch = originalFetch
  })

  it('says the link is invalid when it carries no token', () => {
    renderAt('/accept-invite')
    expect(screen.getByText(/invitation link is invalid or incomplete/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create account' })).not.toBeInTheDocument()
  })

  it('refuses mismatched passwords without calling the server', async () => {
    const user = userEvent.setup()
    const calls = mockFetch([])
    renderAt('/accept-invite?token=tok-1')
    await fillAccount(user, 'something-else')
    expect(await screen.findByText('Passwords do not match')).toBeInTheDocument()
    expect(calls).toHaveLength(0)
  })

  it('finishes an internal invitation at the acceptance', async () => {
    const user = userEvent.setup()
    const calls = mockFetch([{ status: 201, body: { message: 'Account created successfully', user_id: 'u-1' } }])
    renderAt('/accept-invite?token=tok-int')
    await fillAccount(user)
    expect(await screen.findByText(/your account is ready/i)).toBeInTheDocument()
    expect(calls).toEqual([{
      url: 'http://test/api/v1/identity/invitations/tok-int/accept',
      body: { username: 'mert', password: 'Str0ng-pass!', first_name: 'Mert', last_name: '' },
    }])
    expect(screen.queryByLabelText('Code from the authenticator app')).not.toBeInTheDocument()
  })

  it('holds an external invitation until the authenticator code is confirmed', async () => {
    const user = userEvent.setup()
    const calls = mockFetch([
      {
        status: 201,
        body: {
          user_id: 'u-ext',
          status: 'pending_mfa',
          mfa: { method: 'totp', secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/OpenIDX:mert?secret=JBSWY3DPEHPK3PXP' },
        },
      },
      { status: 400, body: { error: 'the code does not match; check the authenticator app\'s clock and try again' } },
      { status: 200, body: { status: 'active' } },
    ])
    renderAt('/accept-invite?token=tok-ext')
    await fillAccount(user)

    // The account is not ready yet: the page shows the authenticator setup.
    expect(await screen.findByTestId('qrcode')).toHaveTextContent('otpauth://totp/OpenIDX:mert')
    expect(screen.getByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP')
    expect(screen.queryByText(/your account is active/i)).not.toBeInTheDocument()

    const code = screen.getByLabelText('Code from the authenticator app')
    await user.type(code, '000000')
    await user.click(screen.getByRole('button', { name: 'Activate account' }))
    expect(await screen.findByText(/the code does not match/i)).toBeInTheDocument()
    expect(screen.queryByText(/your account is active/i)).not.toBeInTheDocument()

    await user.clear(code)
    await user.type(code, '123456')
    await user.click(screen.getByRole('button', { name: 'Activate account' }))
    expect(await screen.findByText(/your account is active/i)).toBeInTheDocument()

    expect(calls.slice(1)).toEqual([
      { url: 'http://test/api/v1/identity/invitations/tok-ext/mfa', body: { secret: 'JBSWY3DPEHPK3PXP', code: '000000' } },
      { url: 'http://test/api/v1/identity/invitations/tok-ext/mfa', body: { secret: 'JBSWY3DPEHPK3PXP', code: '123456' } },
    ])
  })

  it("shows the server's refusal of a spent or expired invitation", async () => {
    const user = userEvent.setup()
    mockFetch([{ status: 400, body: { error: 'invalid or expired invitation' } }])
    renderAt('/accept-invite?token=tok-old')
    await fillAccount(user)
    expect(await screen.findByText('invalid or expired invitation')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create account' })).toBeInTheDocument()
  })
})
