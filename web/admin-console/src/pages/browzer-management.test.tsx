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

import { BrowZerManagementPage } from './browzer-management'
import { api } from '../lib/api'

const healthyStatus = {
  browzer_enabled: true,
  domain: 'ztna.example.com',
  bootstrapper_url: 'https://ztna.example.com:1408',
  cert_type: 'custom',
  cert_subject: 'CN=ztna.example.com',
  cert_issuer: 'CN=Internal CA',
  cert_not_before: '2026-01-01T00:00:00Z',
  cert_not_after: '2027-01-01T00:00:00Z',
  cert_days_left: 200,
  cert_fingerprint: 'aa:bb:cc:dd',
  cert_san: ['ztna.example.com'],
  targets: [] as Array<unknown>,
}

const expiringStatus = {
  ...healthyStatus,
  cert_type: 'self_signed',
  cert_days_left: 14,
  cert_issuer: 'CN=Self-Signed',
}

const disabledStatus = {
  ...healthyStatus,
  browzer_enabled: false,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('BrowZerManagementPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(healthyStatus)
  })

  it('renders the heading + subtitle + an Enabled badge when browzer is on', async () => {
    render(<BrowZerManagementPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('BrowZer Bootstrapper Management')).toBeInTheDocument()
    expect(
      screen.getByText(/manage tls certificates, domain, and bootstrapper lifecycle/i),
    ).toBeInTheDocument()
    // Top-right status badge shows "Enabled"
    expect(screen.getAllByText('Enabled').length).toBeGreaterThan(0)
  })

  it('shows a Disabled badge and disabled status row when browzer is off', async () => {
    vi.mocked(api.get).mockResolvedValue(disabledStatus)
    render(<BrowZerManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('BrowZer Bootstrapper Management')
    expect(screen.getAllByText('Disabled').length).toBeGreaterThan(0)
  })

  it('exposes the three tabs (Overview / Certificates / Domain)', async () => {
    render(<BrowZerManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('BrowZer Bootstrapper Management')
    expect(screen.getByRole('tab', { name: /overview/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /certificates/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /domain/i })).toBeInTheDocument()
  })

  it('shows the certificate-expiring banner when cert_days_left ≤ 30', async () => {
    vi.mocked(api.get).mockResolvedValue(expiringStatus)
    render(<BrowZerManagementPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/consider uploading a ca-signed certificate/i),
    ).toBeInTheDocument()
    expect(screen.getByText('14 days')).toBeInTheDocument()
  })

  it('surfaces the bootstrapper URL on the Overview tab as a link', async () => {
    render(<BrowZerManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('BrowZer Bootstrapper Management')
    expect(screen.getByText('https://ztna.example.com:1408')).toBeInTheDocument()
    expect(screen.getByText('ztna.example.com')).toBeInTheDocument()
  })
})
