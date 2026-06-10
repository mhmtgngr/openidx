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

import { AdminAuditLogPage } from './admin-audit-log'
import { api } from '../lib/api'

const createEntry = {
  id: 'evt-1',
  actor_id: 'admin-1',
  actor_email: 'alice.admin@example.com',
  action: 'create',
  target_type: 'user',
  target_id: 'u-9',
  target_label: 'new-user@example.com',
  timestamp: '2026-06-09T10:00:00Z',
  before_state: undefined,
  after_state: { enabled: true },
  metadata: { ip: '203.0.113.5' },
}

const deleteEntry = {
  id: 'evt-2',
  actor_id: 'admin-2',
  actor_email: 'bob.admin@example.com',
  action: 'delete',
  target_type: 'role',
  target_id: 'role-x',
  target_label: 'legacy-readonly-role',
  timestamp: '2026-06-09T09:30:00Z',
  before_state: { name: 'legacy-readonly-role' },
  after_state: undefined,
  metadata: undefined,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AdminAuditLogPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      items: [createEntry, deleteEntry],
      total: 2,
    })
  })

  it('renders the heading + subtitle + Export CSV button', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()
    expect(
      screen.getByText(/track administrative operations and configuration changes/i),
    ).toBeInTheDocument()
    // Export CSV becomes enabled once entries arrive.
    expect(
      await screen.findByRole('button', { name: /export csv/i }),
    ).toBeInTheDocument()
  })

  it('exposes the four filter controls (Actor / Action / Target Type / date)', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()

    // Filter labels render
    expect(screen.getByText('Actor')).toBeInTheDocument()
    expect(screen.getByText('Action')).toBeInTheDocument()
    expect(screen.getByText('Target Type')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/email or id/i),
    ).toBeInTheDocument()
  })

  it('lists each entry with actor email, action, and target label', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('alice.admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob.admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('new-user@example.com')).toBeInTheDocument()
    expect(screen.getByText('legacy-readonly-role')).toBeInTheDocument()
  })

  it('shows the table column headers (Actor / Action / Target Type / Target / Date)', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    // Wait for one of the entries to make sure the table actually rendered.
    await screen.findByText('alice.admin@example.com')

    // "Actor" / "Action" / "Target Type" also exist as filter labels, so
    // disambiguate via getAllByText.
    expect(screen.getAllByText('Actor').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Action').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Target Type').length).toBeGreaterThan(0)
    expect(screen.getByText('Target')).toBeInTheDocument()
    expect(screen.getByText('Date')).toBeInTheDocument()
  })

  it('renders an empty list area when no events match', async () => {
    vi.mocked(api.get).mockResolvedValue({ items: [], total: 0 })
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()
    // With zero rows, none of the fixture emails are in the DOM.
    expect(screen.queryByText('alice.admin@example.com')).not.toBeInTheDocument()
  })
})
