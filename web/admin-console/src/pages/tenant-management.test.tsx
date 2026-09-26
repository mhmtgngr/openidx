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

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }))
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast }),
}))

import { TenantManagementPage } from './tenant-management'
import { api } from '../lib/api'

const acmeOrg = { id: 'org-1', name: 'Acme Inc' }
let domains: unknown[] = []
const widgetsOrg = { id: 'org-2', name: 'Widgets Co' }

function routeGet(url: string) {
  if (url.includes('/organizations')) {
    // Backend returns a bare array (with X-Total-Count), not { data: [...] }.
    return Promise.resolve([acmeOrg, widgetsOrg])
  }
  if (url.includes('/branding')) return Promise.resolve({})
  if (url.includes('/settings')) return Promise.resolve({})
  if (url.includes('/domains')) return Promise.resolve({ data: domains })
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('TenantManagementPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    domains = []
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Organization select trigger', async () => {
    render(<TenantManagementPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Tenant Management')).toBeInTheDocument()
    expect(
      screen.getByText(/configure branding, settings, and domains per organization/i),
    ).toBeInTheDocument()
    // The Select trigger renders its placeholder copy.
    expect(screen.getByText(/select organization/i)).toBeInTheDocument()
  })

  it('shows the "Select an organization to manage" prompt before one is picked', async () => {
    render(<TenantManagementPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/select an organization to manage/i),
    ).toBeInTheDocument()
  })

  it('renders the Organization label above the select', async () => {
    render(<TenantManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('Tenant Management')

    expect(screen.getByText('Organization')).toBeInTheDocument()
  })

  // A domain is verified by its DNS record, so the page shows the record to
  // publish and asks the server to look it up -- it sends no token, since
  // nothing it could send stands in for the record.
  it('shows a pending domain\'s TXT record and verifies it by DNS alone', async () => {
    domains = [
      {
        id: 'd-pending', domain: 'login.acme.test', domain_type: 'custom', verified: false, primary_domain: false,
        verification_token: 'abc123',
        verification_record: {
          type: 'TXT', name: '_openidx-challenge.login.acme.test', value: 'openidx-domain-verification=abc123',
        },
      },
      { id: 'd-done', domain: 'portal.acme.test', domain_type: 'custom', verified: true, primary_domain: true },
    ]
    vi.mocked(api.post).mockRejectedValueOnce({ response: { status: 400 } })
    const user = userEvent.setup()
    render(<TenantManagementPage />, { wrapper: createWrapper() })

    await user.click(await screen.findByRole('button', { name: 'Domains' }))
    expect(await screen.findByText('_openidx-challenge.login.acme.test')).toBeInTheDocument()
    expect(screen.getByText('openidx-domain-verification=abc123')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Verify portal.acme.test' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Verify login.acme.test' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.post).mock.calls[0]).toEqual(['/api/v1/tenants/org-1/domains/d-pending/verify'])
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({
        title: 'Verification failed',
        description: expect.stringMatching(/did not find the TXT record/),
      })),
    )
  })
})
