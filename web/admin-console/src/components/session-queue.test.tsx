import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    pam: {
      listRequests: vi.fn(),
      approveRequest: vi.fn(),
      denyRequest: vi.fn(),
      listSponsoredRequests: vi.fn(),
      approveSponsoredRequest: vi.fn(),
      denySponsoredRequest: vi.fn(),
      listPendingModeration: vi.fn(),
      joinModeration: vi.fn(),
      listSponsoredModeration: vi.fn(),
      joinSponsoredModeration: vi.fn(),
      listModerating: vi.fn(),
      watchModeration: vi.fn(),
      endModeration: vi.fn(),
      listSponsoredSessions: vi.fn(),
      watchSponsoredSession: vi.fn(),
      endSponsoredSession: vi.fn(),
    },
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { SessionQueue } from './session-queue'
import { api } from '../lib/api'

const pam = api.pam as unknown as Record<string, ReturnType<typeof vi.fn>>

const launch = (id: string, requester: string, external: boolean) => ({
  id, entry_id: 'e-' + id, entry_name: 'db-' + id, entry_type: 'ssh', requester_id: 'u-' + id,
  requester, external, status: 'pending', reason: 'patching', created_at: '2026-10-02T10:00:00Z',
})

function renderQueue(isAdmin: boolean) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}><SessionQueue isAdmin={isAdmin} /></QueryClientProvider>,
  )
}

const row = (text: string) => screen.getByText(text).closest('tr') as HTMLElement

describe('SessionQueue', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // An administrator who also sponsors one vendor user: their request comes
    // back on both routes, and another vendor user's on the administrators'
    // route only.
    pam.listRequests.mockResolvedValue({ requests: [
      launch('own', 'ops@example.test', false),
      launch('mine', 'vendor@supplier.example.test', true),
      launch('theirs', 'other-vendor@supplier.example.test', true),
    ] })
    pam.listSponsoredRequests.mockResolvedValue({ requests: [launch('mine', 'vendor@supplier.example.test', true)] })
    pam.listPendingModeration.mockResolvedValue({ pending: [
      { id: 'mod-route', connection: 'jump.example.test', requester_id: 'u1', requester: 'ops@example.test', created_at: '2026-10-02T10:00:00Z' },
    ] })
    pam.listSponsoredModeration.mockResolvedValue({ pending: [
      { id: 'mod-vendor', entry_id: 'e1', entry_name: 'prod-db', user_id: 'u2', user: 'vendor@supplier.example.test', created_at: '2026-10-02T10:00:00Z' },
    ] })
    pam.listModerating.mockResolvedValue({ moderations: [
      { id: 'held', entry_id: 'e3', entry_name: 'jump-03', requester_id: 'u3', requester: 'dev@example.test', session_live: true },
    ] })
    pam.listSponsoredSessions.mockResolvedValue({ sessions: [
      { id: 's1', entry_id: 'e1', entry_name: 'prod-db', user_id: 'u2', user: 'vendor-live@supplier.example.test', started_at: '2026-10-02T10:00:00Z', recorded: true },
    ] })
    for (const fn of ['approveRequest', 'denyRequest', 'approveSponsoredRequest', 'denySponsoredRequest',
      'joinModeration', 'joinSponsoredModeration', 'endModeration', 'endSponsoredSession']) {
      pam[fn].mockResolvedValue({ status: 'ok' })
    }
    pam.watchModeration.mockResolvedValue({ share_url: 'https://broker.example.test/share/m', read_only: true })
    pam.watchSponsoredSession.mockResolvedValue({ share_url: 'https://broker.example.test/share/s', read_only: true })
    window.open = vi.fn()
  })

  it('decides a launch on the route the caller may decide it on', async () => {
    renderQueue(true)
    await screen.findByText('db-own')
    // Their own vendor user's request, on the sponsor's route.
    fireEvent.click(within(row('db-mine')).getByRole('button', { name: /approve/i }))
    await waitFor(() => expect(pam.approveSponsoredRequest).toHaveBeenCalledWith('mine'))
    // An internal user's, on the administrators'.
    fireEvent.click(within(row('db-own')).getByRole('button', { name: /approve/i }))
    await waitFor(() => expect(pam.approveRequest).toHaveBeenCalledWith('own'))
    expect(pam.approveRequest).not.toHaveBeenCalledWith('mine')
  })

  it('offers only Deny on a vendor user the caller does not sponsor', async () => {
    renderQueue(true)
    await screen.findByText('db-theirs')
    const theirs = row('db-theirs')
    expect(within(theirs).getByRole('button', { name: /approve/i })).toBeDisabled()
    expect(within(theirs).getByText('Only their sponsor can approve')).toBeInTheDocument()
    fireEvent.click(within(theirs).getByRole('button', { name: /deny/i }))
    await waitFor(() => expect(pam.denyRequest).toHaveBeenCalledWith('theirs'))
  })

  it('joins a moderation on the route the caller may join it on', async () => {
    renderQueue(true)
    await screen.findByText('jump.example.test')
    fireEvent.click(within(row('jump.example.test')).getByRole('button', { name: /join as moderator/i }))
    await waitFor(() => expect(pam.joinModeration).toHaveBeenCalledWith('mod-route'))
    const vendorRow = screen.getAllByText('prod-db').map((el) => el.closest('tr') as HTMLElement)
      .find((tr) => within(tr).queryByRole('button', { name: /join as moderator/i }))!
    fireEvent.click(within(vendorRow).getByRole('button', { name: /join as moderator/i }))
    await waitFor(() => expect(pam.joinSponsoredModeration).toHaveBeenCalledWith('mod-vendor'))
  })

  it('watches and ends a moderated session and a sponsored one', async () => {
    renderQueue(false)
    await screen.findByText('jump-03')
    fireEvent.click(within(row('jump-03')).getByRole('button', { name: /watch/i }))
    await waitFor(() => expect(window.open).toHaveBeenCalledWith('https://broker.example.test/share/m', '_blank', 'noopener,noreferrer'))
    fireEvent.click(within(row('jump-03')).getByRole('button', { name: /^end$/i }))
    await waitFor(() => expect(pam.endModeration).toHaveBeenCalledWith('held'))

    const live = row('vendor-live@supplier.example.test')
    fireEvent.click(within(live).getByRole('button', { name: /watch/i }))
    await waitFor(() => expect(pam.watchSponsoredSession).toHaveBeenCalledWith('s1'))
    fireEvent.click(within(live).getByRole('button', { name: /^end$/i }))
    await waitFor(() => expect(pam.endSponsoredSession).toHaveBeenCalledWith('s1'))
  })

  it('asks a non-administrator only for what they sponsor', async () => {
    renderQueue(false)
    await screen.findByText('jump-03')
    expect(pam.listRequests).not.toHaveBeenCalled()
    expect(pam.listPendingModeration).not.toHaveBeenCalled()
    expect(screen.queryByText('db-own')).not.toBeInTheDocument()
    expect(screen.getByText('db-mine')).toBeInTheDocument()
  })
})
