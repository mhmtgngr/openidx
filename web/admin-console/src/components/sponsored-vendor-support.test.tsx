import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
  baseURL: 'https://idp.example.test',
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))
const relay = vi.fn()
vi.mock('./remote-support/relay-renderer', () => ({
  RelayRenderer: (props: { wsUrl: string; mode: string }) => {
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

  it('watches a session in the view-only viewer on the watch socket', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [session] })
    const user = userEvent.setup()
    renderCard()
    await user.click(await screen.findByRole('button', { name: /Watch/ }))
    expect(await screen.findByTestId('relay')).toHaveTextContent('view')
    expect(relay).toHaveBeenLastCalledWith(expect.objectContaining({
      mode: 'view',
      wsUrl: 'wss://idp.example.test/api/v1/access/remote-support/sponsored/sessions/s-1/watch',
    }))
  })

  it('ends a session', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [session] })
    const user = userEvent.setup()
    renderCard()
    await user.click(await screen.findByRole('button', { name: /End/ }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/access/remote-support/sponsored/sessions/s-1/end', {}))
  })
})
