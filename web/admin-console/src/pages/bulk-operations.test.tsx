import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { BulkOperationsPage } from './bulk-operations'
import { api } from '../lib/api'

const completedOp = {
  id: 'op-1',
  type: 'assign_role',
  status: 'completed',
  total_items: 25,
  processed_items: 25,
  success_count: 24,
  error_count: 1,
  errors: [{ user_id: 'u-x', error: 'directory sync failed' }],
  parameters: { role_id: 'role-eng' },
  created_by: 'admin-1',
  created_at: '2026-06-09T08:00:00Z',
}

const runningOp = {
  id: 'op-2',
  type: 'disable_users',
  status: 'running',
  total_items: 100,
  processed_items: 42,
  success_count: 42,
  error_count: 0,
  errors: [],
  parameters: {},
  created_by: 'admin-1',
  created_at: '2026-06-09T09:00:00Z',
}

const role = { id: 'role-eng', name: 'Engineering' }
const group = { id: 'grp-eng', name: 'Engineering' }

function routeGet(url: string) {
  if (url.includes('/admin/bulk-operations/export/users')) {
    return Promise.resolve('id,email\n' as unknown as ReturnType<typeof api.get>)
  }
  if (url.includes('/admin/bulk-operations')) {
    return Promise.resolve({ data: [completedOp, runningOp] })
  }
  if (url.includes('/identity/roles')) return Promise.resolve({ data: [role] })
  if (url.includes('/identity/groups')) return Promise.resolve({ data: [group] })
  return Promise.resolve({ data: [] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('BulkOperationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Export Users CSV button', async () => {
    render(<BulkOperationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Bulk Operations')).toBeInTheDocument()
    expect(
      screen.getByText(/perform operations on multiple users at once/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /export users csv/i }),
    ).toBeInTheDocument()
  })

  it('shows the New Bulk Operation form section', async () => {
    render(<BulkOperationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('New Bulk Operation')).toBeInTheDocument()
    expect(screen.getByText('Operation Type')).toBeInTheDocument()
  })

  it('lists prior operations with their type label, status badge, and progress counts', async () => {
    render(<BulkOperationsPage />, { wrapper: createWrapper() })
    // Operation Type labels are resolved through operationTypes;
    // assign_role -> "Assign Role" etc. The labels also appear as
    // <option>s in the New Operation form's <select>, so disambiguate.
    await screen.findByText('Operation History')
    expect(screen.getAllByText('Assign Role').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Disable Users').length).toBeGreaterThan(0)

    // Status badges
    expect(screen.getByText('completed')).toBeInTheDocument()
    expect(screen.getByText('running')).toBeInTheDocument()

    // Progress counts: "25/25 processed", "42/100 processed"
    expect(screen.getByText('25/25 processed')).toBeInTheDocument()
    expect(screen.getByText('42/100 processed')).toBeInTheDocument()

    // Success/error inline counts
    expect(screen.getByText('24 ok')).toBeInTheDocument()
    expect(screen.getByText('1 errors')).toBeInTheDocument()
  })

  it('shows the Operation History card title', async () => {
    render(<BulkOperationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Operation History')).toBeInTheDocument()
  })

  it('shows the empty state when no operations exist', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/admin/bulk-operations')) {
        return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<BulkOperationsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no bulk operations yet/i)).toBeInTheDocument()
  })
})
