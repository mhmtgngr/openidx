import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

import { LinkedAccountsCard } from './linked-accounts-card'
import { api } from '../lib/api'

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <LinkedAccountsCard />
    </QueryClientProvider>,
  )
}

// Route the two reads this card performs. Returning by URL keeps the tests
// honest about which endpoint supplies which piece of the screen.
function mockReads(links: unknown[], providers: unknown[]) {
  ;(api.get as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
    if (url.includes('identity-links')) return Promise.resolve({ data: links })
    if (url.includes('/providers')) return Promise.resolve(providers)
    return Promise.resolve({})
  })
}

describe('LinkedAccountsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('tells a user with no connected accounts what they can do', async () => {
    mockReads([], [])
    renderCard()
    expect(await screen.findByText(/you sign in with your work account only/i)).toBeInTheDocument()
  })

  it('lists a connected account with a way to remove it', async () => {
    mockReads(
      [
        {
          id: 'link-1',
          provider_id: 'p-1',
          provider_name: 'Google',
          external_email: 'ayse@example.com',
          display_name: 'Ayse',
          linked_at: '2026-01-01T00:00:00Z',
          last_used_at: '2026-02-01T00:00:00Z',
        },
      ],
      [],
    )
    renderCard()

    expect(await screen.findByText('Google')).toBeInTheDocument()
    expect(screen.getByText(/ayse@example.com/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /remove/i })).toBeInTheDocument()
  })

  it('offers only providers that are not already connected', async () => {
    mockReads(
      [
        {
          id: 'link-1',
          provider_id: 'p-1',
          provider_name: 'Google',
          external_email: 'ayse@example.com',
          display_name: null,
          linked_at: '2026-01-01T00:00:00Z',
          last_used_at: null,
        },
      ],
      [
        { id: 'p-1', name: 'Google' },
        { id: 'p-2', name: 'Microsoft' },
      ],
    )
    renderCard()

    expect(await screen.findByRole('button', { name: /connect microsoft/i })).toBeInTheDocument()
    // Offering to connect an account that is already connected would be a dead end.
    expect(screen.queryByRole('button', { name: /connect google/i })).not.toBeInTheDocument()
  })

  it('starts linking through the authenticated start endpoint', async () => {
    mockReads([], [{ id: 'p-2', name: 'Microsoft' }])
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue({
      authorization_url: 'https://idp.example.com/authorize?state=abc',
    })

    // window.location is not assignable under jsdom; capture the navigation.
    const original = window.location
    // @ts-expect-error jsdom location replacement
    delete window.location
    // @ts-expect-error minimal stub
    window.location = { href: '' }

    renderCard()
    await userEvent.click(await screen.findByRole('button', { name: /connect microsoft/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/oauth/social/link/p-2/start', {})
    })
    expect(window.location.href).toBe('https://idp.example.com/authorize?state=abc')

    // @ts-expect-error restore
    window.location = original
  })

  it('keeps connected accounts visible when the provider list cannot be read', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('identity-links')) {
        return Promise.resolve({
          data: [
            {
              id: 'link-1',
              provider_id: 'p-1',
              provider_name: 'Google',
              external_email: 'ayse@example.com',
              display_name: null,
              linked_at: '2026-01-01T00:00:00Z',
              last_used_at: null,
            },
          ],
        })
      }
      return Promise.reject(new Error('providers unavailable'))
    })

    renderCard()
    expect(await screen.findByText('Google')).toBeInTheDocument()
  })

  // Connecting or removing a sign-in account needs the account holder: when the
  // server asks for the password, the card asks for it and sends it.
  const refusal = {
    response: { status: 403, data: { error: 'reauthentication_required', accepts: ['current_password'] } },
  }
  const connected = [
    {
      id: 'link-1',
      provider_id: 'p-1',
      provider_name: 'Google',
      external_email: 'ayse@example.com',
      display_name: null,
      linked_at: '2026-01-01T00:00:00Z',
      last_used_at: null,
    },
  ]

  it('asks for the password to remove an account, and sends it', async () => {
    const user = userEvent.setup()
    mockReads(connected, [])
    ;(api.delete as ReturnType<typeof vi.fn>).mockImplementation(
      (_url: string, config?: { data?: { current_password?: string } }) =>
        config?.data?.current_password ? Promise.resolve({}) : Promise.reject(refusal),
    )
    renderCard()
    await user.click(await screen.findByRole('button', { name: /remove/i }))
    const prompt = await screen.findByRole('dialog')
    await user.type(within(prompt).getByLabelText('Current password'), 'secret-pw')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(api.delete).toHaveBeenLastCalledWith('/api/v1/identity/users/me/identity-links/link-1', {
        data: { current_password: 'secret-pw' },
      }),
    )
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('asks for the password to connect an account, and sends it', async () => {
    const user = userEvent.setup()
    mockReads([], [{ id: 'p-2', name: 'Microsoft' }])
    ;(api.post as ReturnType<typeof vi.fn>).mockImplementation(
      (_url: string, body?: { current_password?: string }) =>
        body?.current_password ? Promise.resolve({ authorization_url: '' }) : Promise.reject(refusal),
    )
    renderCard()
    await user.click(await screen.findByRole('button', { name: /connect microsoft/i }))
    const prompt = await screen.findByRole('dialog')
    await user.type(within(prompt).getByLabelText('Current password'), 'secret-pw')
    await user.click(within(prompt).getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenLastCalledWith('/oauth/social/link/p-2/start', { current_password: 'secret-pw' }),
    )
  })

  it('closing the prompt removes nothing', async () => {
    const user = userEvent.setup()
    mockReads(connected, [])
    ;(api.delete as ReturnType<typeof vi.fn>).mockRejectedValue(refusal)
    renderCard()
    await user.click(await screen.findByRole('button', { name: /remove/i }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(api.delete).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Google')).toBeInTheDocument()
  })
})
