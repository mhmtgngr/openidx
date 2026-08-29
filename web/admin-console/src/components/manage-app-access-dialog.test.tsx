import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
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
})
