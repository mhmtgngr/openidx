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

import { DevicesPage } from './devices'
import { api } from '../lib/api'

const trustedDevice = {
  id: 'dev-1',
  fingerprint: 'fp-aaaa',
  name: 'Alice MacBook',
  ip_address: '203.0.113.10',
  user_agent: 'Mozilla/5.0 (Macintosh) Chrome/120',
  location: 'San Francisco, US',
  trusted: true,
  last_seen_at: '2026-06-09T12:00:00Z',
  created_at: '2026-05-01T00:00:00Z',
  user_id: 'u-1',
  username: 'alice',
  email: 'alice@example.com',
  first_name: 'Alice',
  last_name: 'Anderson',
  ziti_id: 'ziti-1',
}

const untrustedDevice = {
  ...trustedDevice,
  id: 'dev-2',
  fingerprint: 'fp-bbbb',
  name: 'Bob iPhone',
  ip_address: '198.51.100.45',
  user_agent: 'Mozilla/5.0 (iPhone) Safari/17',
  trusted: false,
  user_id: 'u-2',
  username: 'bob',
  email: 'bob@example.com',
  first_name: 'Bob',
  last_name: 'Baxter',
  ziti_id: '',
}

const riskStats = {
  total_devices: 42,
  trusted_devices: 30,
  new_devices_today: 4,
  high_risk_logins_today: 2,
}

function routeGet(url: string) {
  if (url.includes('/risk/stats')) return Promise.resolve(riskStats)
  if (url.includes('/access/devices/enriched')) {
    return Promise.resolve({ devices: [trustedDevice, untrustedDevice], total: 2 })
  }
  return Promise.resolve({ devices: [], total: 0 })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DevicesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<DevicesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Devices')).toBeInTheDocument()
    expect(
      screen.getByText(/unified device management — trust status controls network access automatically/i),
    ).toBeInTheDocument()
  })

  it('shows the four risk stat cards (total / trusted / new today / high-risk)', async () => {
    render(<DevicesPage />, { wrapper: createWrapper() })
    // findByText polls until the riskStats query resolves (the heading
    // renders before the query, so awaiting the heading isn't enough).
    expect(await screen.findByText('Total Devices')).toBeInTheDocument()
    expect(screen.getByText('Trusted Devices')).toBeInTheDocument()
    expect(screen.getByText('New Devices Today')).toBeInTheDocument()
    expect(screen.getByText('High-Risk Logins Today')).toBeInTheDocument()

    // Card values from the fixture
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('30')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('lists each device with name, user, IP, and trust badge', async () => {
    render(<DevicesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Alice MacBook')).toBeInTheDocument()
    expect(screen.getByText('Bob iPhone')).toBeInTheDocument()

    // User columns: first+last name when present
    expect(screen.getByText('Alice Anderson')).toBeInTheDocument()
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('Bob Baxter')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()

    // IP columns
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.45')).toBeInTheDocument()

    // Trust badges (one of each)
    expect(screen.getByText('Trusted')).toBeInTheDocument()
    expect(screen.getByText('Untrusted')).toBeInTheDocument()
  })

  it('shows the empty state when no devices exist', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/risk/stats')) return Promise.resolve(riskStats) as ReturnType<typeof api.get>
      return Promise.resolve({ devices: [], total: 0 }) as ReturnType<typeof api.get>
    })
    render(<DevicesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('No devices found')).toBeInTheDocument()
  })

  it('exposes a device search input', async () => {
    render(<DevicesPage />, { wrapper: createWrapper() })
    await screen.findByText('Devices')
    expect(
      screen.getByPlaceholderText(/search by name, ip, user, or fingerprint/i),
    ).toBeInTheDocument()
  })
})
