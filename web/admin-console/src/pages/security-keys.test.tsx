import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  api: {
    getWebAuthnCredentials: vi.fn(),
    beginWebAuthnRegistration: vi.fn(),
    finishWebAuthnRegistration: vi.fn(),
    deleteWebAuthnCredential: vi.fn(),
  },
}))

vi.mock('../lib/webauthn', () => ({
  decodeCredentialCreationOptions: vi.fn(),
  serializeAttestationResponse: vi.fn(),
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { SecurityKeysPage } from './security-keys'
import { api } from '../lib/api'

const yubiKey = {
  id: 'cred-1',
  user_id: 'u-1',
  credential_id: 'cid-abc',
  aaguid: '00000000-0000-0000-0000-000000000000',
  name: 'YubiKey 5C',
  created_at: '2026-01-15T00:00:00Z',
  last_used_at: '2026-06-01T00:00:00Z',
  sign_count: 12,
}

describe('SecurityKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // The page checks window.PublicKeyCredential — set a truthy stub so
    // the WebAuthn-supported branch (with the Register button) renders.
    ;(window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential = function () {}
    vi.mocked(api.getWebAuthnCredentials).mockResolvedValue([yubiKey])
  })

  it('renders the heading + subtitle + Register Security Key button (WebAuthn-supported)', async () => {
    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText('Security Keys')).toBeInTheDocument()
    expect(
      screen.getByText(/manage your webauthn\/fido2 security keys for passwordless authentication/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /register security key/i }),
    ).toBeInTheDocument()
  })

  it('lists each registered credential with its name + registration line', async () => {
    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText('YubiKey 5C')).toBeInTheDocument()
    // The card description renders "1 security key registered" — assert
    // via that line so we don't fight the text fragmentation in the
    // metadata row.
    expect(
      screen.getByText(/1 security key registered/i),
    ).toBeInTheDocument()
  })

  it('opens the registration card when the Register button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )
    await screen.findByText('YubiKey 5C')

    await user.click(screen.getByRole('button', { name: /register security key/i }))

    expect(
      await screen.findByText(/register new security key/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/yubikey 5c, titan key/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no credentials are registered', async () => {
    vi.mocked(api.getWebAuthnCredentials).mockResolvedValue([])

    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )

    expect(
      await screen.findByText(/no security keys registered yet/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/register a fido2\/webauthn security key for passwordless sign-in/i),
    ).toBeInTheDocument()
  })

  it('shows the unsupported-browser banner when WebAuthn is unavailable', async () => {
    ;(window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential = undefined

    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )

    expect(
      await screen.findByText(/your browser does not support webauthn/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /register security key/i }),
    ).not.toBeInTheDocument()
  })

  // Removing a key is a change to the account's second factors: the identity
  // service refuses it until the request carries the account's password
  // (internal/identity/factor_proof.go), and the page asks for it.
  it('asks for the password before removing a key, and sends it with the request', async () => {
    const user = userEvent.setup()
    vi.mocked(api.deleteWebAuthnCredential).mockImplementation((_id: string, proof?: { current_password?: string }) =>
      proof?.current_password
        ? Promise.resolve()
        : Promise.reject({
            response: { status: 403, data: { error: 'reauthentication_required', accepts: ['current_password'] } },
          }),
    )
    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )
    await screen.findByText('YubiKey 5C')

    await user.click(screen.getByRole('button', { name: 'Remove security key' }))
    const prompt = await screen.findByRole('dialog')
    expect(prompt).toHaveTextContent('Enter your current password to make this change.')
    await user.type(within(prompt).getByLabelText('Current password'), 'my-password')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(screen.queryByText('YubiKey 5C')).not.toBeInTheDocument())
    expect(api.deleteWebAuthnCredential).toHaveBeenLastCalledWith('cred-1', { current_password: 'my-password' })
  })

  it('keeps the key when the prompt is closed', async () => {
    const user = userEvent.setup()
    vi.mocked(api.deleteWebAuthnCredential).mockRejectedValue({
      response: { status: 403, data: { error: 'reauthentication_required', accepts: ['current_password'] } },
    })
    render(
      <MemoryRouter>
        <SecurityKeysPage />
      </MemoryRouter>,
    )
    await screen.findByText('YubiKey 5C')

    await user.click(screen.getByRole('button', { name: 'Remove security key' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('YubiKey 5C')).toBeInTheDocument()
    expect(api.deleteWebAuthnCredential).toHaveBeenCalledTimes(1)
  })
})
