import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { RolloutAssistantSection, type RolloutAssessment } from './rollout-assistant-section'
import { api } from '../lib/api'

const get = vi.mocked(api.get)
const post = vi.mocked(api.post)

const ready: RolloutAssessment = {
  target: '0.6.0',
  target_source: 'pin',
  verdict: {
    status: 'ready',
    reasons: ['READY', 'OFFLINE_IGNORED'],
    counts: { in_ring: 10, on_target: 10, behind: 0, failed: 0, offline: 2 },
  },
  pending: [{ id: 'p1', kind: 'rollout_advance', params: { action: 'advance', percent: 50 }, reasons: ['READY'] }],
}

function mount(a: RolloutAssessment) {
  get.mockResolvedValue(a as never)
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RolloutAssistantSection />
    </QueryClientProvider>,
  )
}

describe('RolloutAssistantSection', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
  })

  it('says how the rollout is going and offers the one step the rules recommend', async () => {
    mount(ready)
    expect(await screen.findByText('Ready for the next step')).toBeInTheDocument()
    expect(screen.getByText(/10 of 10 devices in the rollout are on the target/)).toBeInTheDocument()
    expect(screen.getByText('Devices that are offline are not waited for.')).toBeInTheDocument()
    expect(screen.getByText('Widen the rollout to 50% of the fleet')).toBeInTheDocument()
  })

  it('approves through the server, which re-checks, and does not apply anything itself', async () => {
    post.mockResolvedValue({} as never)
    mount(ready)
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/v1/access/agent/rollout/proposals/p1/approve', {}))
  })

  it('a failing rollout is shown as failing, with a pause to approve', async () => {
    mount({
      ...ready,
      verdict: { status: 'unhealthy', reasons: ['FAILURES'], counts: { in_ring: 10, on_target: 8, behind: 0, failed: 2, offline: 0 } },
      pending: [{ id: 'p2', kind: 'rollout_pause', params: { action: 'pause' }, reasons: ['FAILURES'] }],
    })
    expect(await screen.findByText('Failing')).toBeInTheDocument()
    expect(screen.getByText('Too many devices failed to update.')).toBeInTheDocument()
    expect(screen.getByText('Pause the rollout')).toBeInTheDocument()
  })

  it('with no target it says so and proposes nothing', async () => {
    mount({ target: '', target_source: '', verdict: { status: 'no_target', reasons: ['NO_TARGET'], counts: { in_ring: 0, on_target: 0, behind: 0, failed: 0, offline: 0 } }, pending: [] })
    expect(await screen.findByText('No target')).toBeInTheDocument()
    expect(screen.getByText('Nothing to decide right now.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
  })
})
