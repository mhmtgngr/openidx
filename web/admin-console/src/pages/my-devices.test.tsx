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

import { MyDevicesPage } from './my-devices'
import { api } from '../lib/api'

const trustedDevice = {
  id: 'd-1',
  name: 'Work Laptop',
  description: 'Daily driver',
  device_type: 'laptop',
  os: 'macOS 14',
  browser: 'Chrome 120',
  trusted: true,
  trust_justification: 'Issued by IT',
  last_seen_at: '2026-06-09T10:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
}

const personalPhone = {
  id: 'd-2',
  name: 'Personal Phone',
  description: 'Pixel 8',
  device_type: 'mobile',
  os: 'Android 14',
  browser: 'Chrome 120',
  trusted: false,
  last_seen_at: '2026-06-08T15:00:00Z',
  created_at: '2026-04-01T00:00:00Z',
}

const zitiIdentity = {
  linked: true,
  enrolled: true,
  name: 'alice-laptop',
  attributes: ['engineering', 'on-call'],
}

// The person's agents as /api/v1/access/my-devices correlates them. `live` is
// the server's liveness verdict; `last_report_at` is what the badge counts
// from.
const silentAgent = {
  source: 'linked',
  iam: { name: 'Field Laptop', trusted: true, device_type: 'laptop' },
  ziti: {
    agent_id: 'agent-1',
    status: 'active',
    platform: 'windows',
    compliance_status: 'compliant',
    compliance_score: 100,
    posture: [],
    last_report_at: new Date(Date.now() - 42 * 60_000).toISOString(),
    live: false,
  },
}
const liveAgent = {
  source: 'ziti',
  ziti: {
    agent_id: 'agent-2',
    status: 'active',
    platform: 'android',
    compliance_status: 'compliant',
    compliance_score: 100,
    posture: [],
    last_report_at: new Date().toISOString(),
    live: true,
  },
}

// The agents card renders only when the correlation answers; the older
// cases below were written without it and count texts it would repeat.
let correlatedAgents: unknown[] = []

function routeGet(url: string) {
  if (url.includes('/ziti/sync/my-identity')) return Promise.resolve(zitiIdentity)
  if (url.includes('/access/my-devices')) return Promise.resolve({ devices: correlatedAgents })
  if (url.includes('/portal/devices')) {
    return Promise.resolve({ devices: [trustedDevice, personalPhone] })
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

describe('MyDevicesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    correlatedAgents = []
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Register button', async () => {
    render(<MyDevicesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('My Devices')).toBeInTheDocument()
    expect(
      screen.getByText(/manage your devices and how they connect/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /register this device/i }),
    ).toBeInTheDocument()
  })

  it('describes direct network access in plain language for a linked identity', async () => {
    render(<MyDevicesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/direct network access/i)).toBeInTheDocument()
    expect(
      screen.getByText(/this device can reach internal systems directly/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/active on this device/i)).toBeInTheDocument()

    // The overlay's internals (identity name, role attributes) are deliberately
    // NOT shown to end users — they carry no meaning for someone who just wants
    // to reach a machine.
    const text = document.body.textContent?.toLowerCase() || ''
    expect(text).not.toContain('ziti')
    expect(text).not.toContain('enrollment token')
  })

  it('lists the user devices with their name + Trusted/Untrusted badge', async () => {
    render(<MyDevicesPage />, { wrapper: createWrapper() })

    // Page renders device.name but not the description field.
    expect(await screen.findByText('Work Laptop')).toBeInTheDocument()
    expect(screen.getByText('Personal Phone')).toBeInTheDocument()
    // "Trusted" may appear in the row badge AND in the summary card
    // label ("Trusted Devices") — allow multiple.
    expect(screen.getAllByText('Trusted').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Untrusted').length).toBeGreaterThan(0)
  })

  // A compliant device whose agent has gone quiet is not trusted
  // (AGENT_LIVENESS_TIMEOUT). The fleet page told the administrator; the
  // person whose laptop it is saw "compliant" and a closed door.
  it('marks an agent that stopped reporting as offline, and a live one not', async () => {
    correlatedAgents = [silentAgent, liveAgent]
    render(<MyDevicesPage />, { wrapper: createWrapper() })

    const offline = await screen.findByText(/offline · 42 min/i)
    expect(offline.closest('[title]')).toHaveAttribute('title', expect.stringMatching(/not trusted until it reports again/i))
    expect(screen.getAllByText(/offline ·/i)).toHaveLength(1)
    expect(screen.getByText('agent-2')).toBeInTheDocument()
  })
})
