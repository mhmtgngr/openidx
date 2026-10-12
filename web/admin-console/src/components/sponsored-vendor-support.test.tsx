import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
  baseURL: 'https://idp.example.test',
}))
const toast = vi.fn()
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast }) }))
type RelayProps = { wsUrl: string; mode: string; resolveWsUrl?: () => Promise<string> }
const relay = vi.fn<(props: RelayProps) => void>()
vi.mock('./remote-support/relay-renderer', () => ({
  RelayRenderer: (props: RelayProps) => {
    relay(props)
    return <div data-testid="relay">{props.mode}</div>
  },
}))

import { SponsoredVendorSupport } from './sponsored-vendor-support'
import { api } from '../lib/api'

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <SponsoredVendorSupport />
    </QueryClientProvider>,
  )
}

const session = {
  id: 's-1', agent_id: 'a-1', device_name: 'PLANT-PC', technician: 'tech@supplier.test',
  engagement_title: 'Printer fix', status: 'active', consent_status: 'granted',
  started_at: '2026-10-12T08:00:00Z', watch_ws: '/api/v1/access/remote-support/sponsored/sessions/s-1/watch',
}
const ticketPath = '/api/v1/access/remote-support/sponsored/sessions/s-1/watch-ticket'
const ticket = (tok: string) => ({
  ticket: tok, expires_in: 60, watch_ws: `/api/v1/access/remote-support/sponsored/sessions/s-1/watch?ticket=${tok}`,
})

describe('SponsoredVendorSupport', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.post).mockResolvedValue({})
  })

  it('renders nothing for someone who sponsors no one', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [] })
    const { container } = renderCard()
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('asks for a watch ticket, then watches in the view-only viewer on the ticketed socket', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [session] })
    vi.mocked(api.post).mockResolvedValueOnce(ticket('t-1'))
    const user = userEvent.setup()
    renderCard()
    await user.click(await screen.findByRole('button', { name: /Watch/ }))
    expect(api.post).toHaveBeenCalledWith(ticketPath, {})
    expect(await screen.findByTestId('relay')).toHaveTextContent('view')
    const props = relay.mock.lastCall![0]
    expect(props).toEqual(expect.objectContaining({
      mode: 'view',
      wsUrl: 'wss://idp.example.test/api/v1/access/remote-support/sponsored/sessions/s-1/watch?ticket=t-1',
    }))

    // A reconnect cannot reuse a spent ticket: it asks for a new one.
    vi.mocked(api.post).mockResolvedValueOnce(ticket('t-2'))
    await expect(props.resolveWsUrl!()).resolves.toBe(
      'wss://idp.example.test/api/v1/access/remote-support/sponsored/sessions/s-1/watch?ticket=t-2')
    expect(api.post).toHaveBeenLastCalledWith(ticketPath, {})
  })

  it('shows the step-up refusal and opens no viewer when the ticket is refused', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [session] })
    vi.mocked(api.post).mockRejectedValueOnce({
      response: { status: 403, data: { error: 'step_up_required', error_description: 'this action requires a recently verified second factor' } },
    })
    const user = userEvent.setup()
    renderCard()
    await user.click(await screen.findByRole('button', { name: /Watch/ }))
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({
      description: 'this action requires a recently verified second factor', variant: 'destructive',
    })))
    expect(screen.queryByTestId('relay')).not.toBeInTheDocument()
  })

  it('ends a session', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [session] })
    const user = userEvent.setup()
    renderCard()
    await user.click(await screen.findByRole('button', { name: /End/ }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/access/remote-support/sponsored/sessions/s-1/end', {}))
  })
})
