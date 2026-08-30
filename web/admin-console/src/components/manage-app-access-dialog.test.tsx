import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(() => Promise.resolve({})),
    post: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { ManageAppAccessDialog } from './manage-app-access-dialog'
import { api } from '../lib/api'

function wrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  )
}

describe('ManageAppAccessDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/assignments')) {
        return Promise.resolve({
          assignments: [
            { principal_type: 'group', principal_id: 'g1', principal_name: 'Engineers', assigned_at: '' },
          ],
        })
      }
      if (url.includes('/groups')) return Promise.resolve([{ id: 'g1', displayName: 'Engineers' }])
      if (url.includes('/users')) return Promise.resolve([{ id: 'u1', userName: 'alice' }])
      return Promise.resolve([])
    })
  })

  it('lists current assignees, including group grants', async () => {
    render(
      <ManageAppAccessDialog appId="app-1" appName="Grafana" open onOpenChange={() => {}} />,
      { wrapper: wrapper() },
    )
    expect(await screen.findByText(/Manage access — Grafana/)).toBeInTheDocument()
    // the group grant is listed by name, proving group assignments surface here
    await waitFor(() => expect(screen.getByText('Engineers')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /Assign/ })).toBeInTheDocument()
  })

  // --- require_assignment: the only control that can lock users out of an app ---

  // Renders every assignment response through one helper so each test states
  // only what it cares about: how many principals the application has.
  function withAssignees(n: number) {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/assignments')) {
        return Promise.resolve({
          assignments: Array.from({ length: n }, (_, i) => ({
            principal_type: 'group',
            principal_id: `g${i}`,
            principal_name: `Group ${i}`,
            assigned_at: '',
          })),
        })
      }
      if (url.includes('/groups')) return Promise.resolve([])
      if (url.includes('/users')) return Promise.resolve([])
      return Promise.resolve([])
    })
  }

  it('renders the require-assignment checkbox with the current value and toggles it off', async () => {
    withAssignees(1)
    render(
      <ManageAppAccessDialog
        appId="app-1"
        appName="Grafana"
        requireAssignment
        open
        onOpenChange={() => {}}
      />,
      { wrapper: wrapper() },
    )

    const box = (await screen.findByLabelText(/Require assignment to sign in/)) as HTMLInputElement
    expect(box.checked).toBe(true)
    expect(
      screen.getByText(/only users or groups assigned above can obtain a token/i),
    ).toBeInTheDocument()

    // Turning the gate OFF never locks anyone out, so it saves with no prompt.
    fireEvent.click(box)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/applications/app-1', {
        require_assignment: false,
      }),
    )
  })

  it('warns before enabling with zero assignments, and declining does not save', async () => {
    withAssignees(0)
    render(
      <ManageAppAccessDialog appId="app-1" appName="Grafana" open onOpenChange={() => {}} />,
      { wrapper: wrapper() },
    )

    const box = (await screen.findByLabelText(/Require assignment to sign in/)) as HTMLInputElement
    expect(box.checked).toBe(false)
    // The empty-list state is visible in the same view as the checkbox.
    await waitFor(() =>
      expect(screen.getByText(/No principals are assigned/)).toBeInTheDocument(),
    )

    fireEvent.click(box)

    // The confirmation names the application, so an admin with several dialogs
    // open cannot lock out the wrong one.
    expect(await screen.findByText(/Require assignment for Grafana\?/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Cancel/ }))

    await waitFor(() =>
      expect(screen.queryByText(/Require assignment for Grafana\?/)).not.toBeInTheDocument(),
    )
    expect(api.put).not.toHaveBeenCalled()
  })

  it('enables without a prompt when principals are already assigned', async () => {
    withAssignees(2)
    render(
      <ManageAppAccessDialog appId="app-9" appName="Grafana" open onOpenChange={() => {}} />,
      { wrapper: wrapper() },
    )

    const box = await screen.findByLabelText(/Require assignment to sign in/)
    // The count an admin needs before flipping the gate is already on screen.
    await waitFor(() =>
      expect(screen.getByText(/2 principals assigned and would keep access/)).toBeInTheDocument(),
    )

    fireEvent.click(box)

    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/applications/app-9', {
        require_assignment: true,
      }),
    )
    expect(screen.queryByText(/Require assignment for Grafana\?/)).not.toBeInTheDocument()
  })
})
