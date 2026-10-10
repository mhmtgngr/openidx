import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

const toastSpy = vi.fn()
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: toastSpy }),
}))

import { SignInMethodsCard, type SignInMethods } from './sign-in-methods-card'
import { api } from '../lib/api'

const base = '/api/v1/identity/users/u-1/sign-in-methods'

const methods: SignInMethods = {
  user_id: 'u-1',
  stale_after_days: 30,
  totp: { enabled: true, enrolled_at: '2026-01-01T00:00:00Z', last_used_at: '2026-09-01T00:00:00Z' },
  webauthn: [{ id: 'k-1', name: 'YubiKey', backup_eligible: false, created_at: '2026-02-01T00:00:00Z' }],
  push_devices: [
    {
      id: 'p-1',
      device_name: 'Old Pixel',
      platform: 'android',
      status: 'stale',
      agent_linked: true,
      created_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-06-01T00:00:00Z',
    },
    {
      id: 'p-2',
      device_name: 'Lost iPhone',
      platform: 'ios',
      status: 'disabled',
      agent_linked: false,
      created_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-03-01T00:00:00Z',
      disabled_at: '2026-06-01T00:00:00Z',
      disabled_reason: 'stale',
    },
  ],
  backup_codes_remaining: 3,
  email: { enabled: true, address: 'ayse@corp.example' },
  sms: null,
  summary: { usable_factors: 3, only_stale_push: false },
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <SignInMethodsCard userId="u-1" />
    </QueryClientProvider>,
  )
}

function row(name: string): HTMLElement {
  const el = screen.getByText(name).closest('li')
  if (!el) throw new Error(`no row for ${name}`)
  return el as HTMLElement
}

describe('SignInMethodsCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue(methods as never)
  })

  it('lists every method, with when each phone was last seen and its status', async () => {
    renderCard()
    expect(await screen.findByText('Authenticator app')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith(base)
    expect(screen.getByText('YubiKey')).toBeInTheDocument()
    expect(screen.getByText('Email code')).toBeInTheDocument()
    expect(screen.getByText('3 unused codes left')).toBeInTheDocument()

    const stale = row('Old Pixel')
    expect(within(stale).getByText('Not seen recently')).toBeInTheDocument()
    expect(within(stale).getByText(/last seen/)).toBeInTheDocument()
    expect(within(stale).getByRole('button', { name: 'Disable Old Pixel' })).toBeInTheDocument()

    const disabled = row('Lost iPhone')
    expect(within(disabled).getByText('Disabled')).toBeInTheDocument()
    expect(within(disabled).getByText(/disabled automatically/)).toBeInTheDocument()
    // Already disabled: only removal is offered.
    expect(within(disabled).queryByRole('button', { name: /^Disable/ })).not.toBeInTheDocument()
  })

  it('warns when a stale phone is the only way in', async () => {
    vi.mocked(api.get).mockResolvedValue({
      ...methods,
      totp: null,
      webauthn: [],
      email: null,
      summary: { usable_factors: 0, only_stale_push: true },
    } as never)
    renderCard()
    expect(await screen.findByRole('alert')).toHaveTextContent(/not been seen in over 30 days/)
  })

  it('disables a phone after confirmation', async () => {
    const user = userEvent.setup()
    renderCard()
    await screen.findByText('Old Pixel')
    await user.click(screen.getByRole('button', { name: 'Disable Old Pixel' }))
    await user.click(await screen.findByRole('button', { name: 'Disable' }))
    expect(api.post).toHaveBeenCalledWith(`${base}/push/p-1/disable`)
    expect(toastSpy).toHaveBeenCalledWith({ title: 'Phone disabled' })
  })

  it('removes a security key and the authenticator app through their own routes', async () => {
    const user = userEvent.setup()
    renderCard()
    await screen.findByText('YubiKey')
    await user.click(screen.getByRole('button', { name: 'Remove YubiKey' }))
    await user.click(await screen.findByRole('button', { name: 'Remove' }))
    expect(api.delete).toHaveBeenCalledWith(`${base}/webauthn/k-1`)

    await user.click(screen.getByRole('button', { name: 'Remove Authenticator app' }))
    await user.click(await screen.findByRole('button', { name: 'Remove' }))
    expect(api.delete).toHaveBeenCalledWith(`${base}/totp`)
  })

  it('says so when the person has no second factor', async () => {
    vi.mocked(api.get).mockResolvedValue({} as never)
    renderCard()
    expect(await screen.findByText(/signs in with a password alone/)).toBeInTheDocument()
  })
})
