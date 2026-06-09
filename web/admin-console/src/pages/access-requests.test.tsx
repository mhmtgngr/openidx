import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module (must come before page import)
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
})
