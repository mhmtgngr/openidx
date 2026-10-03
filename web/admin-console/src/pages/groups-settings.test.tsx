import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// The Groups page's settings dialog: self-join, approval and the member cap.
// The identity service reads and returns them as the group attributes
// allowSelfJoin, requireApproval and maxMembers, and keeps any an update
// leaves out. So the dialog shows what is stored, sends what it changes, and
// the edit dialog, which does not show them, does not send them.

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { GroupsPage } from './groups'
import { api } from '../lib/api'

const groups = [
  {
    id: 'g-capped',
    displayName: 'on-call',
    attributes: { description: 'Pager rota', allowSelfJoin: 'true', maxMembers: '12' },
    members: [],
  },
]

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <GroupsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function openMenuItem(user: ReturnType<typeof userEvent.setup>, item: RegExp) {
  const row = (await screen.findByText('on-call')).closest('tr')!
  const trigger = within(row).getAllByRole('button').find((b) => b.getAttribute('aria-haspopup') === 'menu')!
  await user.click(trigger)
  await user.click(await screen.findByRole('menuitem', { name: item }))
  return screen.findByRole('dialog')
}

function sentAttributes(): Record<string, string> {
  const [url, body] = vi.mocked(api.put).mock.calls[0] as [string, { attributes?: Record<string, string> }]
  expect(url).toBe('/api/v1/identity/groups/g-capped')
  return body.attributes ?? {}
}

describe('GroupsPage: group settings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: groups, headers: { 'x-total-count': '1' } } as never)
    vi.mocked(api.put).mockImplementation((_url: string, body: unknown) =>
      Promise.resolve({ id: 'g-capped', ...(body as object) }) as never)
  })

  it('shows the stored settings and sends the ones it changes', async () => {
    const user = userEvent.setup()
    renderPage()
    const dialog = await openMenuItem(user, /group settings/i)

    const selfJoin = within(dialog).getByLabelText('Allow users to join without approval') as HTMLInputElement
    const approval = within(dialog).getByLabelText('Require admin approval for new members') as HTMLInputElement
    const cap = within(dialog).getByLabelText('Maximum Members (optional)') as HTMLInputElement
    expect(selfJoin.checked).toBe(true)
    expect(approval.checked).toBe(false)
    expect(cap.value).toBe('12')

    await user.click(approval)
    await user.clear(cap)
    await user.type(cap, '25')
    await user.click(within(dialog).getByRole('button', { name: /save settings/i }))

    await waitFor(() => expect(api.put).toHaveBeenCalled())
    expect(sentAttributes()).toMatchObject({ allowSelfJoin: 'true', requireApproval: 'true', maxMembers: '25' })
  })

  it('clears the member cap when the field is emptied', async () => {
    const user = userEvent.setup()
    renderPage()
    const dialog = await openMenuItem(user, /group settings/i)

    await user.clear(within(dialog).getByLabelText('Maximum Members (optional)'))
    await user.click(within(dialog).getByRole('button', { name: /save settings/i }))

    await waitFor(() => expect(api.put).toHaveBeenCalled())
    expect(sentAttributes().maxMembers).toBe('')
  })

  it('leaves the settings alone when the edit dialog saves', async () => {
    const user = userEvent.setup()
    renderPage()
    const dialog = await openMenuItem(user, /edit group/i)
    await user.click(within(dialog).getByRole('button', { name: /update group/i }))

    await waitFor(() => expect(api.put).toHaveBeenCalled())
    const attrs = sentAttributes()
    expect(attrs).not.toHaveProperty('allowSelfJoin')
    expect(attrs).not.toHaveProperty('requireApproval')
    expect(attrs).not.toHaveProperty('maxMembers')
  })
})
