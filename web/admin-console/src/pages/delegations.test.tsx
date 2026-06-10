import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { DelegationsPage } from './delegations'
import { api } from '../lib/api'

const enabledDelegation = {
  id: 'del-1',
  delegate_id: 'u-2',
  delegate_name: 'Bob Baxter',
  delegated_by: 'u-1',
  delegated_by_name: 'Alice Anderson',
  scope_type: 'group',
  scope_id: 'grp-eng',
  scope_name: 'Engineering',
  permissions: ['users:read', 'groups:read'],
  enabled: true,
  expires_at: '2026-12-31T00:00:00Z',
  created_at: '2026-06-01T00:00:00Z',
}

const disabledDelegation = {
  ...enabledDelegation,
  id: 'del-2',
  delegate_id: 'u-3',
  delegate_name: 'Carol Carter',
  scope_type: 'application',
  scope_id: 'app-hr',
  scope_name: 'HR Portal',
  permissions: ['applications:read'],
  enabled: false,
  expires_at: undefined as string | undefined,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DelegationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // The queryFn calls api.getWithHeaders and reads `.data` directly as
    // the delegations array. Mock the bare-array shape (matching
    // abac-policies pattern).
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [enabledDelegation, disabledDelegation] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the heading + subtitle + Add Delegation button', async () => {
    render(<DelegationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Delegated Administration')).toBeInTheDocument()
    expect(
      screen.getByText(/manage delegated admin permissions for users/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add delegation/i }),
    ).toBeInTheDocument()
  })

  it('lists each delegation with delegate name, scope type, and scope name', async () => {
    render(<DelegationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Bob Baxter')).toBeInTheDocument()
    expect(screen.getByText('Carol Carter')).toBeInTheDocument()

    // Scope types — Group / Application
    expect(screen.getByText(/^group$/i)).toBeInTheDocument()
    expect(screen.getByText(/^application$/i)).toBeInTheDocument()

    // Scope names from the fixture
    expect(screen.getByText('Engineering')).toBeInTheDocument()
    expect(screen.getByText('HR Portal')).toBeInTheDocument()
  })

  it('renders the empty state when no delegations exist', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: {},
    })
    render(<DelegationsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('No delegations found')).toBeInTheDocument()
    expect(
      screen.getByText(/create a delegation to grant scoped admin permissions/i),
    ).toBeInTheDocument()
  })

  it('shows the scope-type filter Select with its initial "All scope types" value', async () => {
    render(<DelegationsPage />, { wrapper: createWrapper() })
    await screen.findByText('Delegated Administration')
    expect(screen.getByText('All scope types')).toBeInTheDocument()
  })

  it('opens the Add Delegation dialog when the button is clicked', async () => {
    const user = userEvent.setup()
    render(<DelegationsPage />, { wrapper: createWrapper() })
    await screen.findByText('Delegated Administration')

    await user.click(screen.getByRole('button', { name: /add delegation/i }))
    // The dialog renders a "Delegate User ID *" Label that's unique
    // to the create dialog (the edit dialog skips that field).
    expect(
      await screen.findByText(/delegate user id/i),
    ).toBeInTheDocument()
  })
})
