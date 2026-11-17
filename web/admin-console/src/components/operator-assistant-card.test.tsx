import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), post: vi.fn() } }))

import { OperatorAssistantCard } from './operator-assistant-card'
import { api } from '../lib/api'

const get = vi.mocked(api.get)
const post = vi.mocked(api.post)

function mount(settings: object) {
  get.mockResolvedValue(settings as never)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const spy = vi.spyOn(client, 'invalidateQueries')
  render(
    <QueryClientProvider client={client}>
      <OperatorAssistantCard />
    </QueryClientProvider>,
  )
  return spy
}

describe('OperatorAssistantCard', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
  })

  it('asks the operator endpoint and refreshes the plans and the rollout after the answer', async () => {
    post.mockResolvedValue({ session_id: 's1', reply: 'I made a plan; an administrator must approve it.', assistant: true } as never)
    const spy = mount({ provider: 'anthropic', effective_mode: 'observe', kill_switch: false })
    await userEvent.type(await screen.findByLabelText('Operations assistant'), 'open the wiki to engineering')
    await userEvent.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/v1/access/assist/operator/messages',
      expect.objectContaining({ message: 'open the wiki to engineering' })))
    expect(await screen.findByText('I made a plan; an administrator must approve it.')).toBeInTheDocument()
    expect(spy).toHaveBeenCalledWith({ queryKey: ['access-plans'] })
    expect(spy).toHaveBeenCalledWith({ queryKey: ['agent-rollout'] })
  })

  it('is not shown without a model, with the assistant off, or under the kill switch', async () => {
    for (const s of [
      { provider: 'none', effective_mode: 'observe' },
      { provider: 'anthropic', effective_mode: 'off' },
      { provider: 'anthropic', effective_mode: 'observe', kill_switch: true },
    ]) {
      const { unmount } = (() => {
        get.mockResolvedValue(s as never)
        return render(
          <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
            <OperatorAssistantCard />
          </QueryClientProvider>,
        )
      })()
      await waitFor(() => expect(get).toHaveBeenCalled())
      expect(screen.queryByLabelText('Operations assistant')).not.toBeInTheDocument()
      unmount()
    }
  })

  it('says so when the assistant could not answer', async () => {
    post.mockResolvedValue({ assistant: false, degraded: true } as never)
    mount({ provider: 'anthropic', effective_mode: 'tier0' })
    await userEvent.type(await screen.findByLabelText('Operations assistant'), 'hello')
    await userEvent.click(screen.getByRole('button', { name: 'Send' }))
    expect(await screen.findByText('The assistant could not answer just now.')).toBeInTheDocument()
  })
})
