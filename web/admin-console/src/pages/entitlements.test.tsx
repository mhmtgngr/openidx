import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { EntitlementsPage } from './entitlements'
import { api } from '../lib/api'

const roleEntitlement = {
  id: 'role-admin',
  name: 'Administrator',
  type: 'role',
  description: 'Full administrative access',
  member_count: 4,
  risk_level: 'high',
  tags: ['privileged'],
  review_required: true,
  last_reviewed_at: '2026-01-01T00:00:00Z',
}

const groupEntitlement = {
  id: 'grp-eng',
  name: 'Engineering',
  type: 'group',
  description: 'Engineering team',
  member_count: 42,
  risk_level: 'medium',
  tags: ['org'],
  review_required: false,
}

const appEntitlement = {
  id: 'app-hr',
  name: 'HR Portal',
  type: 'application',
  description: 'Employee onboarding and HR processes',
  member_count: 17,
  risk_level: 'low',
  tags: [],
  review_required: false,
}

const stats = {
  total_entitlements: 12,
  by_type: { role: 5, group: 4, application: 3 },
  by_risk_level: { low: 6, medium: 3, high: 2, critical: 1 },
  orphan_count: 2,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('EntitlementsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/entitlements/stats')) {
        return Promise.resolve(stats) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
    })
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [roleEntitlement, groupEntitlement, appEntitlement] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '3' },
    })
  })

  it('renders the heading + subtitle', async () => {
    render(<EntitlementsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Entitlement Catalog')).toBeInTheDocument()
    expect(
      screen.getByText(/unified view of roles, groups, and application entitlements/i),
    ).toBeInTheDocument()
  })

  it('shows the four stat cards (total / by type / high-critical / orphan)', async () => {
    render(<EntitlementsPage />, { wrapper: createWrapper() })
    // Wait for the stats query to resolve.
    expect(await screen.findByText('Total Entitlements')).toBeInTheDocument()
    expect(screen.getByText('Roles / Groups / Apps')).toBeInTheDocument()
    expect(screen.getByText('High/Critical Risk')).toBeInTheDocument()
    expect(screen.getByText('Orphan Entitlements')).toBeInTheDocument()

    // Derived values from the fixture.
    expect(screen.getByText('12')).toBeInTheDocument() // total
    expect(screen.getByText('5 / 4 / 3')).toBeInTheDocument() // role/group/app
    expect(screen.getByText('3')).toBeInTheDocument() // high+critical = 2+1
    expect(screen.getByText('2')).toBeInTheDocument() // orphan_count
  })

  it('lists entitlement rows with name + type-derived data', async () => {
    render(<EntitlementsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Administrator')).toBeInTheDocument()
    expect(screen.getByText('Engineering')).toBeInTheDocument()
    expect(screen.getByText('HR Portal')).toBeInTheDocument()
  })

  it('shows the entitlement descriptions in the rows', async () => {
    render(<EntitlementsPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/full administrative access/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/employee onboarding and hr processes/i),
    ).toBeInTheDocument()
  })

  it('renders the empty catalog table when no entitlements match', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '0' },
    })
    render(<EntitlementsPage />, { wrapper: createWrapper() })

    // The page renders fine and shows the stats cards even with no rows;
    // the empty rows just means the row names aren't present.
    expect(await screen.findByText('Entitlement Catalog')).toBeInTheDocument()
    expect(screen.queryByText('Administrator')).not.toBeInTheDocument()
  })
})
