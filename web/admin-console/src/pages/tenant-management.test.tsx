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

import { TenantManagementPage } from './tenant-management'
import { api } from '../lib/api'

const acmeOrg = { id: 'org-1', name: 'Acme Inc' }
const widgetsOrg = { id: 'org-2', name: 'Widgets Co' }

function routeGet(url: string) {
  if (url.includes('/organizations')) {
    return Promise.resolve({ data: [acmeOrg, widgetsOrg] })
  }
  if (url.includes('/branding')) return Promise.resolve({})
  if (url.includes('/settings')) return Promise.resolve({})
  if (url.includes('/domains')) return Promise.resolve({ data: [] })
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
})
