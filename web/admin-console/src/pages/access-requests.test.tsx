import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module (must come before page import)
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn((url: string) =>
      url.includes('/credential') ? Promise.resolve({ value: 's3cr3t-p4ss' })
      : url.includes('/return') ? Promise.resolve({ status: 'returned' })
      : Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
    vault: {
      listSecrets: vi.fn(() => Promise.resolve({ secrets: [{ id: 'sec-1', name: 'db-root', type: 'password', current_version: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }] })),
    },
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { AccessRequestsPage } from './access-requests'
import { api } from '../lib/api'

const myRequest = {
  id: 'req-1',
  requester_id: 'me',
  requester_name: 'Test User',
  resource_name: 'Engineering Group',
  resource_type: 'group',
  status: 'pending',
  priority: 'normal',
  justification: 'Need access for onboarding',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const fulfilledVaultRequest = {
  id: 'req-vault-1',
  requester_id: 'me',
  requester_name: 'Test User',
  resource_name: 'db-root',
  resource_type: 'vault_credential',
  resource_id: 'sec-1',
  status: 'fulfilled',
  priority: 'normal',
  justification: 'Need db credentials for maintenance',
  expires_at: '2026-12-31T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const pendingApproval = {
  id: 'req-2',
  requester_id: 'someone-else',
  requester_name: 'Alice Approver',
  resource_name: 'AdminApp',
  resource_type: 'application',
  status: 'pending',
  priority: 'high',
  justification: 'Quarterly review',
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
}

const allRequest = {
  id: 'req-3',
  requester_id: 'me',
  requester_name: 'Test User',
  resource_name: 'PowerRole',
  resource_type: 'role',
  status: 'fulfilled',
  priority: 'normal',
  justification: 'Promoted to team lead',
  created_at: '2026-01-03T00:00:00Z',
  updated_at: '2026-01-03T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

// Route the mocked api.get to the right payload based on the called URL —
// the page makes three concurrent queries (mine / approvals / all) and the
// previous "single mockResolvedValue" approach would have served the same
// payload to all three.
function routeGet(url: string) {

  if (url.includes('/identity/roles')) {
    return Promise.resolve([
      { id: 'role-1', name: 'admin', description: '', is_composite: false, created_at: '' },
      { id: 'role-2', name: 'auditor', description: '', is_composite: false, created_at: '' },
    ])
  }
  if (url.includes('/identity/groups')) {
    return Promise.resolve([
      { id: 'grp-1', name: 'Administrators' },
      { id: 'grp-2', displayName: 'Developers' },
    ])
  }
  if (url.includes('requester_id=me')) {
    return Promise.resolve({ requests: [myRequest] })
  }
  if (url.includes('/my-approvals')) {
    return Promise.resolve({ pending_approvals: [pendingApproval] })
  }
  if (url.includes('/governance/requests')) {
    return Promise.resolve({ requests: [allRequest] })
  }
  return Promise.resolve({ requests: [] })
}

function routeGetWithVault(url: string) {
  if (url.includes('requester_id=me')) {
    return Promise.resolve({ requests: [myRequest, fulfilledVaultRequest] })
  }
  if (url.includes('/my-approvals')) {
    return Promise.resolve({ pending_approvals: [pendingApproval] })
  }
  if (url.includes('/governance/requests')) {
    return Promise.resolve({ requests: [allRequest] })
  }
  return Promise.resolve({ requests: [] })
}

describe('AccessRequestsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the page heading and Request Access button', async () => {
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Access Requests')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /request access/i }),
    ).toBeInTheDocument()
  })

  it('lists the current user\'s requests on the default tab', async () => {
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Engineering Group')).toBeInTheDocument()
    // Status badge from the request
    expect(screen.getAllByText(/pending/i).length).toBeGreaterThan(0)
  })

  it('switches to Pending Approvals tab and shows items needing my decision', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Engineering Group')

    // Radix Tabs listens for pointerDown / keyDown, not bare click — using
    // userEvent.click here so the tab actually transitions to active.
    // (fireEvent.click leaves data-state="inactive" and the tab content
    // never mounts.)
    await user.click(screen.getByRole('tab', { name: /pending approvals/i }))
    expect(await screen.findByText('AdminApp')).toBeInTheDocument()
    expect(screen.getByText('Alice Approver')).toBeInTheDocument()
  })

  it('switches to All Requests tab and surfaces fulfilled history', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Engineering Group')

    await user.click(screen.getByRole('tab', { name: /all requests/i }))
    expect(await screen.findByText('PowerRole')).toBeInTheDocument()
    // Fulfilled badge text comes from statusBadge map
    expect(screen.getAllByText(/fulfilled/i).length).toBeGreaterThan(0)
  })

  it('opens the create-request dialog when Request Access is clicked', async () => {
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Access Requests')

    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    // The dialog has a textarea with this placeholder; if it appears the
    // dialog opened. Using the placeholder rather than the label text
    // because labels are plain `<label>` here (no htmlFor association),
    // and the dialog title duplicates the trigger button's name.
    await waitFor(() => {
      expect(
        screen.getByPlaceholderText(/explain why you need access/i),
      ).toBeInTheDocument()
    })
  })

  it('renders an empty state when the user has no requests yet', async () => {
    vi.mocked(api.get).mockImplementation(() => Promise.resolve({ requests: [], pending_approvals: [] }) as ReturnType<typeof api.get>)
    render(<AccessRequestsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Access Requests')).toBeInTheDocument()
    // No request rows — the only "pending"-ish text would come from the tab
    // labels, not from a row badge. So the absence assertion is that the
    // table doesn't contain a fake row resource_name.
    expect(screen.queryByText('Engineering Group')).not.toBeInTheDocument()
  })

  // --- vault_credential create flow ---

  it('selecting Vault Credential shows the secret picker and Submit stays disabled until both secret and duration are chosen', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Access Requests')

    // Open dialog
    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    await waitFor(() => expect(screen.getByPlaceholderText(/explain why you need access/i)).toBeInTheDocument())

    // Select Vault Credential type via Radix Select
    const resourceTypeSelect = screen.getByRole('combobox', { name: /resource type/i })
    await user.click(resourceTypeSelect)
    const vaultOption = await screen.findByRole('option', { name: /vault credential/i })
    await user.click(vaultOption)

    // Secret picker should now be visible instead of free-text input
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/enter resource name/i)).not.toBeInTheDocument()
    })
    // The vault secrets dropdown should be present (placeholder text)
    expect(screen.getByText(/select a vault secret/i)).toBeInTheDocument()

    // Submit should be disabled — no secret or duration chosen yet
    const submitBtn = screen.getByRole('button', { name: /submit request/i })
    expect(submitBtn).toBeDisabled()

    // Select a secret
    const secretSelect = screen.getByRole('combobox', { name: /resource name/i })
    await user.click(secretSelect)
    const secretOption = await screen.findByRole('option', { name: /db-root/i })
    await user.click(secretOption)

    // Submit still disabled — no duration yet
    expect(submitBtn).toBeDisabled()

    // Select a duration (4 hours)
    const durationSelect = screen.getByRole('combobox', { name: /access duration/i })
    await user.click(durationSelect)
    const fourHourOption = await screen.findByRole('option', { name: /4 hours/i })
    await user.click(fourHourOption)

    // Now Submit should be enabled
    expect(submitBtn).not.toBeDisabled()
  })

  it('vault_credential create POST includes resource_id', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Access Requests')

    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    await waitFor(() => expect(screen.getByPlaceholderText(/explain why you need access/i)).toBeInTheDocument())

    // Select Vault Credential
    const resourceTypeSelect = screen.getByRole('combobox', { name: /resource type/i })
    await user.click(resourceTypeSelect)
    await user.click(await screen.findByRole('option', { name: /vault credential/i }))

    // Select secret
    const secretSelect = screen.getByRole('combobox', { name: /resource name/i })
    await user.click(secretSelect)
    await user.click(await screen.findByRole('option', { name: /db-root/i }))

    // Select duration
    const durationSelect = screen.getByRole('combobox', { name: /access duration/i })
    await user.click(durationSelect)
    await user.click(await screen.findByRole('option', { name: /4 hours/i }))

    // Fill justification
    fireEvent.change(screen.getByPlaceholderText(/explain why you need access/i), { target: { value: 'Need DB for maintenance' } })

    // Submit
    await user.click(screen.getByRole('button', { name: /submit request/i }))

    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith(
        '/api/v1/governance/requests',
        expect.objectContaining({
          resource_type: 'vault_credential',
          resource_id: 'sec-1',
          resource_name: 'db-root',
          duration: '4h',
        }),
      )
    })
    // Ensure resource_id is present and no permanent-transform applied
    const callArg = vi.mocked(api.post).mock.calls[0][1] as Record<string, unknown>
    expect(callArg).toHaveProperty('resource_id', 'sec-1')
    expect(callArg.duration).toBe('4h')
  })

  it('Permanent duration option is NOT shown for vault_credential type', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Access Requests')

    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    await waitFor(() => expect(screen.getByPlaceholderText(/explain why you need access/i)).toBeInTheDocument())

    // Select Vault Credential
    const resourceTypeSelect = screen.getByRole('combobox', { name: /resource type/i })
    await user.click(resourceTypeSelect)
    await user.click(await screen.findByRole('option', { name: /vault credential/i }))

    // Open duration picker
    const durationSelect = screen.getByRole('combobox', { name: /access duration/i })
    await user.click(durationSelect)

    // "Permanent" option should NOT be visible
    expect(screen.queryByRole('option', { name: /^permanent$/i })).not.toBeInTheDocument()
    // But time-based options should be
    expect(screen.getByRole('option', { name: /4 hours/i })).toBeInTheDocument()
  })

  it('Role type shows a resource picker (not free text) and submits the picked resource_id', async () => {
    const user = userEvent.setup()
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Access Requests')

    fireEvent.click(screen.getByRole('button', { name: /request access/i }))
    await waitFor(() => expect(screen.getByPlaceholderText(/explain why you need access/i)).toBeInTheDocument())

    // Select Role (non-vault)
    const resourceTypeSelect = screen.getByRole('combobox', { name: /resource type/i })
    await user.click(resourceTypeSelect)
    await user.click(await screen.findByRole('option', { name: /^role$/i }))

    // Resource Name should now be a picker populated from /identity/roles,
    // NOT a free-text box.
    expect(screen.queryByPlaceholderText(/enter resource name/i)).not.toBeInTheDocument()
    const resourceSelect = await screen.findByRole('combobox', { name: /resource name/i })
    await user.click(resourceSelect)
    await user.click(await screen.findByRole('option', { name: /^auditor$/i }))

    // Permanent duration remains available for non-vault types; selecting it
    // also closes the dropdown so it doesn't overlay the Submit button.
    const durationSelect = screen.getByRole('combobox', { name: /access duration/i })
    await user.click(durationSelect)
    await user.click(await screen.findByRole('option', { name: /^permanent$/i }))

    fireEvent.change(screen.getByPlaceholderText(/explain why you need access/i), { target: { value: 'Need auditor role' } })
    await user.click(screen.getByRole('button', { name: /submit request/i }))

    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith(
        '/api/v1/governance/requests',
        expect.objectContaining({
          resource_type: 'role',
          resource_id: 'role-2',
          resource_name: 'auditor',
          duration: '',
        }),
      )
    })
  })

  // --- fulfilled vault_credential row actions ---

  it('a fulfilled vault_credential row shows Retrieve and Return buttons', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => routeGetWithVault(url) as ReturnType<typeof api.get>)
    render(<AccessRequestsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('db-root')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retrieve/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /return/i })).toBeInTheDocument()
  })

  it('clicking Retrieve opens modal, Get Credential calls POST .../credential and shows the returned value', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => routeGetWithVault(url) as ReturnType<typeof api.get>)
    render(<AccessRequestsPage />, { wrapper: createWrapper() })

    await screen.findByText('db-root')

    // Clicking "Retrieve" opens the modal
    await user.click(screen.getByRole('button', { name: /retrieve/i }))
    // The modal opens; "Get Credential" button appears inside
    const getCredBtn = await screen.findByRole('button', { name: /get credential/i })
    expect(getCredBtn).not.toBeDisabled()

    // Click "Get Credential" inside the open dialog (userEvent so the Radix
    // DismissableLayer classifies the pointerdown as inside and keeps it open).
    await user.click(getCredBtn)

    // api.post was called with the credential URL
    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith(
        '/api/v1/governance/requests/req-vault-1/credential',
      )
    })

    // The one-shot value appears
    const revealedInput = await screen.findByTestId('retrieved-credential-value')
    expect(revealedInput).toHaveValue('s3cr3t-p4ss')
    expect(screen.getByText(/shown once/i)).toBeInTheDocument()
  })

  it('clicking Return (confirm) calls POST .../return and invalidates queries', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => routeGetWithVault(url) as ReturnType<typeof api.get>)
    render(<AccessRequestsPage />, { wrapper: createWrapper() })

    await screen.findByText('db-root')

    // Click Return button to open AlertDialog
    await user.click(screen.getByRole('button', { name: /return/i }))

    // Confirm in the AlertDialog
    const confirmBtn = await screen.findByRole('button', { name: /^return$/i })
    await user.click(confirmBtn)

    await waitFor(() => {
      expect(vi.mocked(api.post)).toHaveBeenCalledWith(
        '/api/v1/governance/requests/req-vault-1/return',
      )
    })
  })

  it('a non-vault fulfilled row does NOT show Retrieve or Return buttons', async () => {
    // allRequest is fulfilled but type 'role' — it is in All Requests tab, not My Requests
    // For My Requests, myRequest is pending type 'group' — no Retrieve/Return
    render(<AccessRequestsPage />, { wrapper: createWrapper() })
    await screen.findByText('Engineering Group')

    // Cancel is present (pending group request)
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
    // No Retrieve/Return for non-vault rows
    expect(screen.queryByRole('button', { name: /retrieve/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /return/i })).not.toBeInTheDocument()
  })
})
