import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

// The auth mock is swapped per test: platform admin (super_admin in the
// default org) vs an organization admin (super_admin elsewhere).
const authUser = {
  current: {
    id: 'u1', email: 'a@example.com', name: 'A',
    roles: ['super_admin'], groups: [], permissions: [],
    orgId: '00000000-0000-0000-0000-000000000010',
  },
}
vi.mock('../lib/auth', () => ({
  useAuth: () => ({ user: authUser.current, isAuthenticated: true, isLoading: false }),
}))

import { ConnectorsPage, ConnectorWizardDialog, connectorState, routerSiteSlug } from './connectors'
import { api } from '../lib/api'

const sites = [
  { id: 's1', slug: 'default', name: 'Default', description: '', hop_addr: '', is_default: true },
  { id: 's2', slug: 'azure', name: 'Azure', description: '', hop_addr: '', is_default: false },
]

const routers = [
  { id: 'r1', name: 'hq-connector', isOnline: true, isVerified: true, hostname: 'hq.local', roleAttributes: ['ziti-routers'] },
  { id: 'r2', name: 'azure-connector', isOnline: false, isVerified: false, hostname: '', roleAttributes: ['site-azure', 'ziti-routers'] },
]

const routerStatus: { isOnline: boolean; isVerified: boolean } = { isOnline: false, isVerified: false }

function routeGet(url: string) {
  if (url.includes('/access/sites')) return Promise.resolve({ sites })
  if (/\/ziti\/fabric\/routers\/[^/]+$/.test(url)) return Promise.resolve({ id: 'new-router', ...routerStatus })
  if (url.includes('/ziti/fabric/routers')) return Promise.resolve(routers)
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

beforeEach(() => {
  vi.clearAllMocks()
  document.body.innerHTML = ''
  routerStatus.isOnline = false
  routerStatus.isVerified = false
  authUser.current = { ...authUser.current, orgId: '00000000-0000-0000-0000-000000000010', roles: ['super_admin'] }
  vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  vi.mocked(api.post).mockResolvedValue({
    router_id: 'new-router',
    name: 'office-connector-1',
    site_slug: 'azure',
    install_command: 'curl -fsSL https://example.org/install.sh | bash',
    onboard_command: 'docker run legacy',
  } as never)
})

describe('helpers', () => {
  it('derives connector state', () => {
    expect(connectorState({ isOnline: true })).toBe('online')
    expect(connectorState({ isVerified: true })).toBe('enrolled')
    expect(connectorState({})).toBe('waiting')
  })
  it('reads the site slug off roleAttributes', () => {
    expect(routerSiteSlug(routers[1] as never)).toBe('azure')
    expect(routerSiteSlug(routers[0] as never)).toBe('')
  })
})

describe('ConnectorsPage', () => {
  it('lists connectors grouped by site with state badges', async () => {
    render(<ConnectorsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('hq-connector')).toBeInTheDocument()
    expect(screen.getByText('azure-connector')).toBeInTheDocument()
    expect(screen.getByTestId('connector-state-online')).toBeInTheDocument()
    expect(screen.getByTestId('connector-state-waiting')).toBeInTheDocument()
  })

  it('shows the add button to a platform admin', async () => {
    render(<ConnectorsPage />, { wrapper: createWrapper() })
    expect(await screen.findByTestId('add-connector')).toBeInTheDocument()
    expect(screen.queryByTestId('read-only-note')).not.toBeInTheDocument()
  })

  it('is read-only for an organization admin', async () => {
    authUser.current = { ...authUser.current, orgId: '11111111-1111-1111-1111-111111111111' }
    render(<ConnectorsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('hq-connector')).toBeInTheDocument()
    expect(screen.queryByTestId('add-connector')).not.toBeInTheDocument()
    expect(screen.getByTestId('read-only-note')).toBeInTheDocument()
  })
})

describe('ConnectorWizardDialog', () => {
  it('walks the three steps and prefers install_command', async () => {
    render(<ConnectorWizardDialog open onOpenChange={() => {}} />, { wrapper: createWrapper() })
    // Step 1: requirements checklist.
    expect(screen.getByTestId('wizard-step-1')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('wizard-next'))
    // Step 2: name + site + private-by-default toggle.
    expect(screen.getByTestId('wizard-step-2')).toBeInTheDocument()
    expect(screen.queryByLabelText(/advertised/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('wizard-create'))
    // Step 3: install command.
    expect(await screen.findByTestId('wizard-step-3')).toBeInTheDocument()
    expect(screen.getByTestId('install-command').textContent).toContain('install.sh')
    const body = vi.mocked(api.post).mock.calls[0][1] as Record<string, unknown>
    expect(body.advertised_address).toBeUndefined()
  })

  it('sends advertised_address only when the public toggle is on', async () => {
    render(<ConnectorWizardDialog open onOpenChange={() => {}} />, { wrapper: createWrapper() })
    fireEvent.click(screen.getByTestId('wizard-next'))
    fireEvent.click(screen.getByRole('switch'))
    const addr = await screen.findByPlaceholderText('connector.example.org')
    fireEvent.change(addr, { target: { value: 'conn.example.org' } })
    fireEvent.click(screen.getByTestId('wizard-create'))
    await screen.findByTestId('wizard-step-3')
    const body = vi.mocked(api.post).mock.calls[0][1] as Record<string, unknown>
    expect(body.advertised_address).toBe('conn.example.org')
  })

  it('falls back to onboard_command when install_command is absent', async () => {
    vi.mocked(api.post).mockResolvedValue({
      router_id: 'new-router', name: 'n', site_slug: 'azure',
      onboard_command: 'docker run legacy',
    } as never)
    render(<ConnectorWizardDialog open onOpenChange={() => {}} />, { wrapper: createWrapper() })
    fireEvent.click(screen.getByTestId('wizard-next'))
    fireEvent.click(screen.getByTestId('wizard-create'))
    expect(await screen.findByTestId('wizard-step-3')).toBeInTheDocument()
    expect(screen.getByTestId('install-command').textContent).toContain('docker run legacy')
  })

  it('polls the router and flips waiting to online, then shows the publish link', async () => {
    vi.useFakeTimers()
    try {
      render(<ConnectorWizardDialog open onOpenChange={() => {}} />, { wrapper: createWrapper() })
      fireEvent.click(screen.getByTestId('wizard-next'))
      fireEvent.click(screen.getByTestId('wizard-create'))
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      expect(screen.getByTestId('wizard-step-3')).toBeInTheDocument()
      expect(screen.getByTestId('connector-state-waiting')).toBeInTheDocument()
      expect(screen.queryByTestId('next-step-publish')).not.toBeInTheDocument()
      // The router comes online; the 5s poll picks it up.
      routerStatus.isOnline = true
      routerStatus.isVerified = true
      await act(async () => { await vi.advanceTimersByTimeAsync(5100) })
      expect(screen.getByTestId('connector-state-online')).toBeInTheDocument()
      const link = screen.getByTestId('next-step-publish')
      expect(link.getAttribute('href')).toBe('/app-publish?site=azure')
    } finally {
      vi.useRealTimers()
    }
  })
})
