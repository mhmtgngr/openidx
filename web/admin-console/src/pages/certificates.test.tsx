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
    postFormData: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { CertificatesPage } from './certificates'
import { api } from '../lib/api'

const healthyPlatform = {
  cert_type: 'custom',
  subject: 'CN=auth.example.com',
  issuer: 'CN=Internal CA',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-01-01T00:00:00Z',
  days_left: 200,
  sans: ['auth.example.com'],
  fingerprint: 'aa:bb:cc',
}

const apisix = {
  enabled: true,
  cert_uploaded: true,
}

const status = {
  platform: healthyPlatform,
  apisix,
  expiry_alerts: [] as Array<{ name: string; days_left: number; severity: string }>,
}

const statusWithAlert = {
  platform: { ...healthyPlatform, days_left: 14 },
  apisix,
  expiry_alerts: [
    { name: 'Platform TLS', days_left: 14, severity: 'warning' },
  ],
}

const zitiCert = {
  id: 'ziti-1',
  name: 'ziti-controller-cert',
  cert_type: 'controller',
  subject: 'CN=ziti.example.com',
  issuer: 'CN=Ziti Root CA',
  fingerprint: 'dd:ee:ff',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-01-01T00:00:00Z',
  auto_renew: true,
  status: 'active',
  days_until_expiry: 200,
}

function routeGet(url: string) {
  if (url.includes('/access/certificates/status')) return Promise.resolve(status)
  if (url.includes('/access/ziti/certificates')) return Promise.resolve([zitiCert])
  return Promise.resolve(null)
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('CertificatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<CertificatesPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText('Certificate Management'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/manage tls certificates across the openidx platform/i),
    ).toBeInTheDocument()
  })

  it('shows the three tabs (Platform TLS / API Gateway / Ziti Certificates)', async () => {
    render(<CertificatesPage />, { wrapper: createWrapper() })
    await screen.findByText('Certificate Management')
    expect(screen.getByRole('tab', { name: /platform tls/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /api gateway/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /ziti certificates/i })).toBeInTheDocument()
  })

  it('displays the certificate type badge on the default Platform TLS tab', async () => {
    render(<CertificatesPage />, { wrapper: createWrapper() })
    await screen.findByText('Certificate Management')
    // CA-signed badge (rendered for cert_type === 'custom')
    expect(screen.getByText('CA-Signed')).toBeInTheDocument()
    // Platform TLS card title
    expect(screen.getByText(/platform tls certificate/i)).toBeInTheDocument()
  })

  it('surfaces the expiry-alert banner when expiry_alerts has entries', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/access/certificates/status')) {
        return Promise.resolve(statusWithAlert) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<CertificatesPage />, { wrapper: createWrapper() })
    await screen.findByText('Certificate Management')
    // "Platform TLS" appears both in the alert banner (as <strong>name</strong>)
    // and the Platform TLS Certificate card title — disambiguate.
    expect(screen.getAllByText('Platform TLS').length).toBeGreaterThan(0)
    // The alert renders "<name> expires in <days> days" — inline bold
    // copy split into multiple text nodes. Multiple ancestor nodes
    // satisfy the descendant-text check, so assert at-least-one match.
    expect(
      screen.getAllByText((_, node) => {
        const txt = node?.textContent || ''
        return /expires in/i.test(txt) && txt.includes('14')
      }).length,
    ).toBeGreaterThan(0)
  })

  it('renders the loading spinner branch while certStatus is pending', async () => {
    // Make the status query stay pending so we hit the loading return
    vi.mocked(api.get).mockReturnValue(new Promise(() => undefined) as ReturnType<typeof api.get>)
    const { container } = render(<CertificatesPage />, { wrapper: createWrapper() })
    // The page returns an h-64 container with the spinning RefreshCw —
    // verify the container exists in the DOM.
    expect(container.querySelector('.h-64')).not.toBeNull()
  })
})
