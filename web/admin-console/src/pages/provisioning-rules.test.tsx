import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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

import { ProvisioningRulesPage } from './provisioning-rules'
import { api } from '../lib/api'

const rule1 = {
  id: 'r-1',
  name: 'Onboard Engineers',
  description: 'Add engineers to engineering groups',
  trigger: 'user_created',
  conditions: [{ field: 'department', operator: 'equals', value: 'engineering' }],
  actions: [{ type: 'add_to_group', target: 'engineering' }],
  priority: 100,
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
}

const rule2 = {
  id: 'r-2',
  name: 'Offboard Departed',
  description: 'Disable accounts on departure',
  trigger: 'user_updated',
  conditions: [],
  actions: [],
  priority: 50,
  enabled: false,
  created_at: '2026-02-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ProvisioningRulesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [rule1, rule2] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the heading + Add Rule button', async () => {
    render(<ProvisioningRulesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Provisioning Rules')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add rule/i }),
    ).toBeInTheDocument()
  })

  it('renders the Automated Provisioning Rules card', async () => {
    render(<ProvisioningRulesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Automated Provisioning Rules'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/define rules to automate user provisioning based on triggers and conditions/i),
    ).toBeInTheDocument()
  })

  it('lists rule rows with their name + Enabled badge', async () => {
    render(<ProvisioningRulesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Onboard Engineers')).toBeInTheDocument()
    expect(screen.getByText('Offboard Departed')).toBeInTheDocument()
    // "Enabled" appears as both the column header and the row badge.
    expect(screen.getAllByText('Enabled').length).toBeGreaterThan(0)
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('opens the Add Rule modal when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<ProvisioningRulesPage />, { wrapper: createWrapper() })
    await screen.findByText('Onboard Engineers')

    await user.click(screen.getByRole('button', { name: /add rule/i }))

    expect(
      await screen.findByPlaceholderText(/^rule name$/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/^rule description$/i),
    ).toBeInTheDocument()
  })

  it('shows the empty "No provisioning rules found." row when there are none', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '0' },
    })

    render(<ProvisioningRulesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no provisioning rules found\./i),
    ).toBeInTheDocument()
  })
})
