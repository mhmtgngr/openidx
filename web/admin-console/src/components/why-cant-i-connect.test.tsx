import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { post: vi.fn() },
}))

import { WhyCantIConnect, type MyDiagnosis } from './why-cant-i-connect'
import { api } from '../lib/api'

const post = vi.mocked(api.post)

function answer(causes: string[], extra: Partial<MyDiagnosis> = {}): MyDiagnosis {
  return {
    agent_id: 'agent-1',
    generated_at: '2026-11-16T14:05:00Z',
    verdict: {
      healthy: causes.length === 0,
      causes: causes.map((code) => ({ code, source: 'server', fixes: [] })),
    },
    ...extra,
  }
}

function mount(agentId?: string) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <WhyCantIConnect agentId={agentId} />
    </QueryClientProvider>,
  )
}

describe('WhyCantIConnect', () => {
  // Braces matter: a function returned from beforeEach is run as a teardown.
  beforeEach(() => {
    post.mockReset()
  })

  it('asks about the named device and words the causes, the leading one first', async () => {
    post.mockResolvedValue(answer(['CLOCK_SKEW', 'TUNNEL_DOWN']))
    mount('agent-1')
    await userEvent.click(screen.getByRole('button', { name: 'Check my device' }))

    expect(post).toHaveBeenCalledWith('/api/v1/access/my/diagnose', { agent_id: 'agent-1' })
    const items = await screen.findAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent("The device's clock is wrong by more than five minutes.")
    expect(items[0]).toHaveTextContent('Turn on automatic date and time')
    expect(items[1]).toHaveTextContent('The secure tunnel on the device is not working.')
    // No bundle from the device: the answer says how to get a more exact one.
    expect(screen.getByText(/openidx-agent doctor/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeInTheDocument()
  })

  it('says so when nothing is wrong, and asks about no device in particular by default', async () => {
    post.mockResolvedValue(answer([], { bundle_at: '2026-11-16T14:04:00Z' }))
    mount()
    await userEvent.click(screen.getByRole('button', { name: 'Check my device' }))

    expect(post).toHaveBeenCalledWith('/api/v1/access/my/diagnose', {})
    expect(await screen.findByText('No problem found.')).toBeInTheDocument()
    expect(screen.queryByRole('listitem')).not.toBeInTheDocument()
    expect(screen.queryByText(/openidx-agent doctor/)).not.toBeInTheDocument()
  })

  it('never shows a raw code for a cause it has no words for', async () => {
    post.mockResolvedValue(answer(['SOMETHING_NEWER_THAN_THIS_BUILD']))
    mount()
    await userEvent.click(screen.getByRole('button', { name: 'Check my device' }))

    expect(await screen.findByText('We could not tell what is wrong from here.')).toBeInTheDocument()
    expect(screen.queryByText(/SOMETHING_NEWER/)).not.toBeInTheDocument()
  })

  it('reports a failed check as a failure, not as good news', async () => {
    post.mockRejectedValue(new Error('500'))
    mount()
    await userEvent.click(screen.getByRole('button', { name: 'Check my device' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('The check could not be completed.')
    expect(screen.queryByText('No problem found.')).not.toBeInTheDocument()
  })
})
