import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { DirectoriesPage } from './directories'
import { api } from '../lib/api'

const azureDir = {
  id: 'dir-1',
  name: 'Azure AD — Corporate',
  type: 'azure_ad',
  config: {},
  enabled: true,
  last_sync_at: '2026-06-09T12:00:00Z',
  sync_status: 'success',
  created_at: '2026-06-01T00:00:00Z',
  updated_at: '2026-06-09T12:00:00Z',
}

const ldapDir = {
  id: 'dir-2',
  name: 'On-prem LDAP',
  type: 'ldap',
  config: {},
  enabled: false,
  last_sync_at: null,
  sync_status: 'pending',
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

describe('DirectoriesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue([azureDir, ldapDir])
  })

  it('renders the heading', async () => {
    render(<DirectoriesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Directory Integrations')).toBeInTheDocument()
  })

  it('lists each directory with its name, type label, and never-synced fallback', async () => {
    render(<DirectoriesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Azure AD — Corporate')).toBeInTheDocument()
    expect(screen.getByText('On-prem LDAP')).toBeInTheDocument()

    // Type-label mapping: azure_ad -> "Azure AD", ldap -> "LDAP"
    expect(screen.getByText('Azure AD')).toBeInTheDocument()
    expect(screen.getByText('LDAP')).toBeInTheDocument()

    // "Never" appears in both the sync_status badge (for unknown
    // statuses) and the last_sync_at fallback, so assert it's
    // present at least once.
    expect(screen.getAllByText('Never').length).toBeGreaterThan(0)
  })

  it('shows the search input for filtering directories', async () => {
    render(<DirectoriesPage />, { wrapper: createWrapper() })
    await screen.findByText('Directory Integrations')
    expect(
      screen.getByPlaceholderText(/search directories/i),
    ).toBeInTheDocument()
  })

  it('shows the integration count line in the card description', async () => {
    render(<DirectoriesPage />, { wrapper: createWrapper() })
    await screen.findByText('Directory Integrations')
    // The CardDescription reads "N directory integration(s)" — 2 with
    // the default fixture.
    expect(screen.getByText('2 directory integration(s)')).toBeInTheDocument()
  })

  it('renders the empty state when no directories are configured', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    render(<DirectoriesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no directory integrations configured/i),
    ).toBeInTheDocument()
  })
})
