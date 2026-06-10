import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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

import { ApprovalPoliciesPage } from './approval-policies'
import { api } from '../lib/api'

const enabledPolicy = {
  id: 'pol-1',
  name: 'Role grant — manager + security',
  resource_type: 'role',
  approval_steps: [
    { approver_id: 'mgr-1', role: 'manager' },
    { approver_id: 'sec-1', role: 'security' },
  ],
  max_wait_hours: 72,
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const disabledPolicy = {
  id: 'pol-2',
  name: 'Application access — sandbox',
  resource_type: 'application',
  approval_steps: [{ approver_id: 'mgr-1', role: 'manager' }],
  max_wait_hours: 24,
  enabled: false,
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ApprovalPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ policies: [enabledPolicy, disabledPolicy] })
  })

  it('renders the page heading + subtitle + Create Policy button', async () => {
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Approval Policies')).toBeInTheDocument()
    expect(
      screen.getByText(/define approval workflows for access requests/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /create policy/i })).toBeInTheDocument()
  })

  it('lists each policy with its name, resource type, step count, max wait, and status', async () => {
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Role grant — manager + security')).toBeInTheDocument()
    expect(screen.getByText('Application access — sandbox')).toBeInTheDocument()
    // Steps count rendering: "2 steps" / "1 steps"
    expect(screen.getByText('2 steps')).toBeInTheDocument()
    expect(screen.getByText('1 steps')).toBeInTheDocument()
    // Max wait hours
    expect(screen.getByText('72h')).toBeInTheDocument()
    expect(screen.getByText('24h')).toBeInTheDocument()
    // Status badges
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('renders the empty state when no policies exist', async () => {
    vi.mocked(api.get).mockResolvedValue({ policies: [] })
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('No policies defined')).toBeInTheDocument()
    // Policies still aren't in the DOM
    expect(screen.queryByText('Role grant — manager + security')).not.toBeInTheDocument()
  })

  it('opens an empty Create dialog when Create Policy is clicked', async () => {
    const user = userEvent.setup()
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Approval Policies')

    await user.click(screen.getByRole('button', { name: /create policy/i }))
    // Dialog title text — distinct from the edit-mode title
    expect(await screen.findByText('Create Approval Policy')).toBeInTheDocument()
    // Name input renders with its placeholder
    expect(screen.getByPlaceholderText(/policy name/i)).toBeInTheDocument()
    // Save button reads "Create" in create mode (not "Update")
    expect(screen.getByRole('button', { name: /^create$/i })).toBeInTheDocument()
  })

  it('opens an Edit dialog with the existing values prefilled when the pencil is clicked', async () => {
    const user = userEvent.setup()
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Role grant — manager + security')

    // Each row has a Pencil button (no accessible name) and a Trash button.
    // The Pencil is the first of the two action buttons in that row — we
    // grab it by hunting for an SVG with the lucide-pencil class.
    const editButtons = document.querySelectorAll('button > svg.lucide-pencil')
    expect(editButtons.length).toBeGreaterThan(0)
    await user.click(editButtons[0]!.parentElement as HTMLElement)

    expect(await screen.findByText('Edit Policy')).toBeInTheDocument()
    // The Name input is now prefilled with the first policy's name
    expect(screen.getByDisplayValue('Role grant — manager + security')).toBeInTheDocument()
    // Save button reads "Update" in edit mode
    expect(screen.getByRole('button', { name: /^update$/i })).toBeInTheDocument()
  })

  it('opens a delete confirmation that names the target policy', async () => {
    const user = userEvent.setup()
    render(<ApprovalPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Role grant — manager + security')

    // lucide-react names the Trash2 icon's class `lucide-trash2` (no
    // hyphen between trash and 2) — Pencil is `lucide-pencil`.
    const deleteButtons = document.querySelectorAll('button > svg.lucide-trash2')
    expect(deleteButtons.length).toBeGreaterThan(0)
    await user.click(deleteButtons[0]!.parentElement as HTMLElement)

    // AlertDialog title
    expect(await screen.findByText('Delete Policy')).toBeInTheDocument()
    // Body should reference the policy by name
    await waitFor(() => {
      expect(
        screen.getByText((_, node) => node?.textContent === 'Delete "Role grant — manager + security"? This cannot be undone.'),
      ).toBeInTheDocument()
    })
  })
})
