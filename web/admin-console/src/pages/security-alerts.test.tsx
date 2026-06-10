import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
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

import { SecurityAlertsPage } from './security-alerts'
import { api } from '../lib/api'

const openAlert = {
  id: 'a-1',
  alert_type: 'brute_force',
  severity: 'critical',
  status: 'open',
  title: 'Multiple failed logins from 203.0.113.10',
  description: 'Detected 12 failed login attempts within 1 minute',
  source_ip: '203.0.113.10',
  created_at: '2026-06-09T10:00:00Z',
}

const resolvedAlert = {
  ...openAlert,
  id: 'a-2',
  alert_type: 'impossible_travel',
  severity: 'high',
  status: 'resolved',
  title: 'Impossible travel: NYC -> Tokyo',
  description: 'Two logins within 1h from cities 11k km apart',
  source_ip: '198.51.100.5',
}

const blockedIP = {
  id: 'ip-1',
  ip_address: '203.0.113.10',
  threat_type: 'brute_force',
  reason: 'Sustained credential stuffing',
  permanent: true,
  created_at: '2026-06-09T10:30:00Z',
}

function routeGet(url: string) {
  if (url.includes('/security-alerts')) {
    return Promise.resolve({ alerts: [openAlert, resolvedAlert], total: 2 })
  }
  if (url.includes('/ip-threats')) {
    return Promise.resolve({ threats: [blockedIP], total: 1 })
  }
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

describe('SecurityAlertsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<SecurityAlertsPage />, { wrapper: createWrapper() })
    // "Security Alerts" collides between the page heading and the tab
    // label — pick the h1 explicitly.
    expect(
      await screen.findByRole('heading', { name: /security alerts/i, level: 1 }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/monitor security threats and manage ip blocklists/i),
    ).toBeInTheDocument()
  })

  it('shows the three summary cards (Open / Critical / Blocked IPs)', async () => {
    render(<SecurityAlertsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Open Alerts')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('Blocked IPs')).toBeInTheDocument()
  })

  it('lists alert rows on the default Security Alerts tab', async () => {
    render(<SecurityAlertsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/multiple failed logins from 203.0.113.10/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/impossible travel: nyc -> tokyo/i),
    ).toBeInTheDocument()

    expect(screen.getByText('brute_force')).toBeInTheDocument()
    expect(screen.getByText('impossible_travel')).toBeInTheDocument()
  })

  it('switches to the IP Threat List tab and shows the blocked IP row', async () => {
    const user = userEvent.setup()
    render(<SecurityAlertsPage />, { wrapper: createWrapper() })
    await screen.findByRole('heading', { name: /security alerts/i, level: 1 })

    await user.click(screen.getByRole('tab', { name: /ip threat list/i }))

    expect(await screen.findByText('203.0.113.10')).toBeInTheDocument()
    expect(
      screen.getByText(/sustained credential stuffing/i),
    ).toBeInTheDocument()
  })

  it('shows the empty alerts state when no alerts match the filters', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/security-alerts')) {
        return Promise.resolve({ alerts: [], total: 0 }) as ReturnType<typeof api.get>
      }
      if (url.includes('/ip-threats')) {
        return Promise.resolve({ threats: [], total: 0 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<SecurityAlertsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no alerts found/i)).toBeInTheDocument()
    expect(
      screen.getByText(/security alerts will appear here when threats are detected/i),
    ).toBeInTheDocument()
  })
})
