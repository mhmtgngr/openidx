import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Invariant I3 of the third-party access framework on the Groups page: the
// page shows which groups are open to external (vendor) users, sets the flag
// only when the form names it, and shows the identity service's reason when
// it refuses to close a group that still has an external member.

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }))

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
  useToast: () => ({ toast }),
}))

import { GroupsPage } from './groups'
import { api } from '../lib/api'

const groups = [
  { id: 'g-open', displayName: 'vendor-support', attributes: { description: 'Field service', externalAllowed: 'true' }, members: [] },
  { id: 'g-closed', displayName: 'finance', attributes: { description: 'Finance team', externalAllowed: 'false' }, members: [] },
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

async function openRowMenu(user: ReturnType<typeof userEvent.setup>, groupName: string) {
  const row = (await screen.findByText(groupName)).closest('tr')!
  const trigger = within(row).getAllByRole('button').find((b) => b.getAttribute('aria-haspopup') === 'menu')!
  await user.click(trigger)
}

describe('GroupsPage: groups open to external users', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: groups, headers: { 'x-total-count': '2' } } as never)
    vi.mocked(api.put).mockImplementation((_url: string, body: unknown) =>
      Promise.resolve({ id: 'g-open', ...(body as object) }) as never)
  })

  it('marks only the groups opened to external users', async () => {
    renderPage()
    const open = (await screen.findByText('vendor-support')).closest('tr')!
    const closed = screen.getByText('finance').closest('tr')!
    expect(within(open).getByText('External users')).toBeInTheDocument()
    expect(within(closed).queryByText('External users')).not.toBeInTheDocument()
  })

  it('edits the flag and sends it as the attribute the identity service reads', async () => {
    const user = userEvent.setup()
    renderPage()
    await openRowMenu(user, 'vendor-support')
    await user.click(await screen.findByRole('menuitem', { name: /edit group/i }))

    const dialog = await screen.findByRole('dialog')
    const flag = within(dialog).getByLabelText('Open to external (vendor) users') as HTMLInputElement
    expect(flag.checked).toBe(true)
    await user.click(flag)
    await user.click(within(dialog).getByRole('button', { name: /update group/i }))

    await waitFor(() => expect(api.put).toHaveBeenCalled())
    const [url, body] = vi.mocked(api.put).mock.calls[0] as [string, { attributes: Record<string, string> }]
    expect(url).toBe('/api/v1/identity/groups/g-open')
    expect(body.attributes.externalAllowed).toBe('false')
  })

  it('leaves the flag alone when the form does not name it', async () => {
    const user = userEvent.setup()
    renderPage()
    await openRowMenu(user, 'vendor-support')
    await user.click(await screen.findByRole('menuitem', { name: /group settings/i }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: /save settings/i }))

    await waitFor(() => expect(api.put).toHaveBeenCalled())
    const [, body] = vi.mocked(api.put).mock.calls[0] as [string, { attributes?: Record<string, string> }]
    expect(body.attributes ?? {}).not.toHaveProperty('externalAllowed')
  })

  it("shows the identity service's reason when it refuses to close the group", async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockRejectedValueOnce(Object.assign(new Error('Request failed with status code 409'), {
      response: { data: { error: 'remove the external members before closing this group to external users', code: 'external_group_has_members' } },
    }))
    renderPage()
    await openRowMenu(user, 'vendor-support')
    await user.click(await screen.findByRole('menuitem', { name: /edit group/i }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByLabelText('Open to external (vendor) users'))
    await user.click(within(dialog).getByRole('button', { name: /update group/i }))

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({
        variant: 'destructive',
        description: expect.stringContaining('remove the external members before closing this group to external users'),
      })),
    )
  })
})
