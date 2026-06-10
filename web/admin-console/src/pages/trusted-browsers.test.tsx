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

import { TrustedBrowsersPage } from './trusted-browsers'
import { api } from '../lib/api'

const trustedBrowser = {
  id: 'tb-1',
  name: 'Personal MacBook',
  ip_address: '203.0.113.50',
  expires_at: '2026-07-09T00:00:00Z',
  last_used_at: '2026-06-09T00:00:00Z',
  // Page filters with `b.active`, not is_active.
  active: true,
  fingerprint: 'fp-abc123',
}

function routeGet(url: string) {
  if (url.includes('/trusted-browsers/check')) {
    return Promise.resolve({ trusted: false })
  }
  if (url.includes('/trusted-browsers')) {
    return Promise.resolve([trustedBrowser])
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

describe('TrustedBrowsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<TrustedBrowsersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Trusted Browsers')).toBeInTheDocument()
    expect(
      screen.getByText(/manage browsers that can skip mfa verification/i),
    ).toBeInTheDocument()
  })

  it('shows the not-trusted banner when the current browser is unknown', async () => {
    render(<TrustedBrowsersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/this browser is not trusted/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /trust this browser/i }),
    ).toBeInTheDocument()
  })

  it('renders the How Trusted Browsers Work info card', async () => {
    render(<TrustedBrowsersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/how trusted browsers work/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/you won't need to verify mfa for 30 days/i),
    ).toBeInTheDocument()
  })

  it('lists active trusted browser rows', async () => {
    render(<TrustedBrowsersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Personal MacBook')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.50')).toBeInTheDocument()
  })

  it('shows the "No active trusted browsers" empty state', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/trusted-browsers/check')) {
        return Promise.resolve({ trusted: false }) as ReturnType<typeof api.get>
      }
      return Promise.resolve([]) as ReturnType<typeof api.get>
    })

    render(<TrustedBrowsersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no active trusted browsers/i),
    ).toBeInTheDocument()
  })
})
