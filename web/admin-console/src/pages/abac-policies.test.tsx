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

import { ABACPoliciesPage } from './abac-policies'
import { api } from '../lib/api'

const allowPolicy = {
  id: 'pol-1',
  name: 'Engineering-only resources',
  description: 'Allow engineering team to access internal tooling',
  resource_type: 'application',
  resource_id: 'eng-tools',
  conditions: [
    { attribute: 'group', operator: 'in', value: 'engineering' },
    { attribute: 'mfa_enabled', operator: 'eq', value: 'true' },
  ],
  effect: 'allow',
  priority: 100,
  enabled: true,
  created_at: '2026-06-01T00:00:00Z',
  updated_at: '2026-06-01T00:00:00Z',
}

const denyPolicy = {
  id: 'pol-2',
  name: 'Block contractor access to PII',
  description: 'Deny contractors access to PII-classified resources',
  resource_type: 'role',
  conditions: [{ attribute: 'employment_type', operator: 'eq', value: 'contractor' }],
  effect: 'deny',
  priority: 90,
  enabled: false,
  created_at: '2026-06-02T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ABACPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // The page's queryFn re-wraps the API response: it reads `data` (a
    // bare ABACPolicy[]) and `x-total-count` and returns
    // `{ items, total }`. So the mock returns the array directly under
    // `data`, not pre-wrapped.
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [allowPolicy, denyPolicy] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the heading + subtitle + Test Policy and Create Policy buttons', async () => {
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('ABAC Policies')).toBeInTheDocument()
    expect(
      screen.getByText(/attribute-based access control policies for fine-grained resource authorization/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /test policy/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /create policy/i })).toBeInTheDocument()
  })

  it('shows the policy count + each row with name, description, resource type, condition count, and effect badge', async () => {
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Engineering-only resources')).toBeInTheDocument()
    expect(screen.getByText('Block contractor access to PII')).toBeInTheDocument()

    // Descriptions
    expect(
      screen.getByText(/allow engineering team to access internal tooling/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/deny contractors access to pii-classified resources/i),
    ).toBeInTheDocument()

    // Resource types
    expect(screen.getByText('application')).toBeInTheDocument()
    expect(screen.getByText('role')).toBeInTheDocument()

    // Condition counts — allow=2 conditions, deny=1 condition
    expect(screen.getByText('2 conditions')).toBeInTheDocument()
    expect(screen.getByText('1 condition')).toBeInTheDocument()

    // Effect badges (the badge text is the literal value)
    expect(screen.getByText('allow')).toBeInTheDocument()
    expect(screen.getByText('deny')).toBeInTheDocument()

    // Page count line ("2 policies")
    expect(screen.getByText(/^2 policies$/i)).toBeInTheDocument()
  })

  it('opens the Create dialog when Create Policy is clicked', async () => {
    const user = userEvent.setup()
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('ABAC Policies')

    await user.click(screen.getByRole('button', { name: /create policy/i }))
    // The form's Name field has this stable placeholder — anchor on it
    // rather than the dialog title (which collides with the trigger
    // button's accessible name).
    expect(
      await screen.findByPlaceholderText(/^policy name$/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/^policy description\.\.\.$/i),
    ).toBeInTheDocument()
  })

  it('opens the Test Policy dialog when Test Policy is clicked', async () => {
    const user = userEvent.setup()
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('ABAC Policies')

    await user.click(screen.getByRole('button', { name: /test policy/i }))
    // The test dialog has a Resource ID input with this placeholder
    expect(
      await screen.findByPlaceholderText(/^resource id$/i),
    ).toBeInTheDocument()
  })

  it('renders the empty state when no policies exist', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: {},
    })
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('No ABAC policies found')).toBeInTheDocument()
    // The empty-line count reads "0 policies"
    expect(screen.getByText(/^0 policies$/i)).toBeInTheDocument()
  })

  it('shows the resource-type filter trigger with its placeholder', async () => {
    render(<ABACPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('ABAC Policies')
    // The Select trigger uses "All Resource Types" as its placeholder/initial value
    expect(screen.getByText('All Resource Types')).toBeInTheDocument()
  })
})
