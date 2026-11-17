import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { AccessPlansSection, type AccessPlan } from './access-plans-section'
import { api } from '../lib/api'

const get = vi.mocked(api.get)
const post = vi.mocked(api.post)

const pending: AccessPlan = {
  id: 'p1',
  status: 'pending',
  resource: { id: 'r1', name: 'Wiki' },
  group: { id: 'g1', name: 'Engineering', members: 8 },
  plan: { status: 'ready', blockers: [], notes: [], risks: ['PRIVILEGED_RESOURCE'] },
  now: { checked: true, allowed: false, why: 'Wiki: not assigned' },
}

function mount(plans: AccessPlan[] = []) {
  get.mockResolvedValue({ plans } as never)
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <AccessPlansSection />
    </QueryClientProvider>,
  )
}

describe('AccessPlansSection', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
  })

  it('shows a plan before anything changes, with its risks and what a member can do today', async () => {
    post.mockResolvedValue(pending as never)
    mount()
    await userEvent.type(await screen.findByLabelText('Application (name or id)'), 'Wiki')
    await userEvent.type(screen.getByLabelText('Group (name or id)'), 'Engineering')
    await userEvent.click(screen.getByRole('button', { name: 'Make a plan' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/v1/access/plans', { resource: 'Wiki', group: 'Engineering' }))
    expect(await screen.findByText('Give group "Engineering" access to "Wiki"')).toBeInTheDocument()
    expect(screen.getByText(/privileged resource/)).toBeInTheDocument()
    expect(screen.getByText(/cannot open it: Wiki: not assigned/)).toBeInTheDocument()
  })

  it('a plan that cannot be done says why', async () => {
    post.mockRejectedValue({
      response: { status: 422, data: { ...pending, id: undefined, status: 'blocked', plan: { status: 'blocked', blockers: ['GROUP_NOT_FOUND'], notes: [], risks: [] }, group: { id: '', name: '', members: 0 } } },
    })
    mount()
    await userEvent.type(await screen.findByLabelText('Application (name or id)'), 'Wiki')
    await userEvent.type(screen.getByLabelText('Group (name or id)'), 'nope')
    await userEvent.click(screen.getByRole('button', { name: 'Make a plan' }))
    expect(await screen.findByText('There is no such group in this organization.')).toBeInTheDocument()
    expect(screen.getByText('Cannot be done')).toBeInTheDocument()
  })

  it('approves through the server and offers an undo for what was granted', async () => {
    post.mockResolvedValue({} as never)
    mount([pending, { ...pending, id: 'p2', status: 'applied', outcome: { granted: true, after: { checked: true, allowed: true } } }])
    await userEvent.click(await screen.findByRole('button', { name: 'Approve and apply' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/v1/access/plans/p1/approve', {}))
    expect(screen.getByText('Checked after the change: a member of the group can open it.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/v1/access/plans/p2/undo', {}))
  })
})
