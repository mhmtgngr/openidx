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

import { ZitiDiscoveryPage } from './ziti-discovery'
import { api } from '../lib/api'

const discoveredService = {
  ziti_id: 'zs-1',
  name: 'prod-postgres',
  protocol: 'tcp',
  host: 'pg.internal',
  port: 5432,
  managed: false,
}

const managedService = {
  ziti_id: 'zs-2',
  name: 'prod-redis',
  protocol: 'tcp',
  host: 'redis.internal',
  port: 6379,
  managed: true,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ZitiDiscoveryPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      discovered_services: [discoveredService, managedService],
      already_managed: 1,
      available_for_import: 1,
    })
  })

  it('renders the heading + subtitle + Refresh button', async () => {
    render(<ZitiDiscoveryPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Ziti Service Discovery'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/discover and import existing ziti services into openidx/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /refresh/i }),
    ).toBeInTheDocument()
  })

  it('shows the three summary cards', async () => {
    render(<ZitiDiscoveryPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Total Services')).toBeInTheDocument()
    expect(screen.getByText('Already Managed')).toBeInTheDocument()
    expect(screen.getByText('Available to Import')).toBeInTheDocument()
  })

  it('lists discovered service rows by name', async () => {
    render(<ZitiDiscoveryPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('prod-postgres')).toBeInTheDocument()
    expect(screen.getByText('prod-redis')).toBeInTheDocument()
  })

  it('exposes the services search input', async () => {
    render(<ZitiDiscoveryPage />, { wrapper: createWrapper() })
    await screen.findByText('prod-postgres')

    expect(
      screen.getByPlaceholderText(/search services/i),
    ).toBeInTheDocument()
  })

  it('renders the Import Selected button with the current selection count', async () => {
    render(<ZitiDiscoveryPage />, { wrapper: createWrapper() })

    // Initial selection is zero → "Import Selected (0)".
    expect(
      await screen.findByRole('button', { name: /import selected \(0\)/i }),
    ).toBeInTheDocument()
  })
})
