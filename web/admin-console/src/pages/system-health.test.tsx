import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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
  // The page reads baseURL at module-import time and concatenates it
  // into the /health URL — supply a sentinel so the resulting URL is
  // well-formed even though our fetch stub ignores the input.
  baseURL: 'http://test',
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { SystemHealthPage } from './system-health'

const healthyResponse = {
  status: 'healthy',
  uptime_seconds: 7325, // 2h 2m 5s
  version: '1.1.0',
  dependencies: [
    // DEP_STATUS_CONFIG keys are 'up' / 'degraded' / 'down'; use those.
    {
      name: 'postgres',
      status: 'up',
      latency_ms: 3,
      last_checked: new Date().toISOString(),
      details: 'Connected to primary',
    },
    {
      name: 'redis',
      status: 'up',
      latency_ms: 1,
      last_checked: new Date().toISOString(),
    },
    {
      name: 'elasticsearch',
      status: 'degraded',
      latency_ms: 250,
      last_checked: new Date().toISOString(),
      details: 'High response time observed',
    },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

const originalFetch = globalThis.fetch

function setFetchMock(impl: (...args: unknown[]) => Promise<unknown>) {
  // System health calls fetch() directly against `${baseURL}/health`.
  // Assign on both globalThis and window so happy-dom + node-style code
  // pick up the mock regardless of resolution path.
  ;(globalThis as unknown as { fetch: typeof impl }).fetch = impl
}

describe('SystemHealthPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    setFetchMock(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(healthyResponse),
      } as unknown as Response),
    )
  })

  afterEach(() => {
    ;(globalThis as unknown as { fetch: typeof originalFetch }).fetch = originalFetch
  })

  it('renders the heading + subtitle once health resolves', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/monitor openidx platform dependencies and uptime/i),
    ).toBeInTheDocument()
    // Heading appears in both the loading branch and post-load branch — pick
    // by role to disambiguate.
    expect(
      screen.getByRole('heading', { name: /system health/i, level: 1 }),
    ).toBeInTheDocument()
  })

  it('shows the overall status banner with version badge + Check Now button', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/system healthy/i)).toBeInTheDocument()
    expect(screen.getByText('1.1.0')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /check now/i }),
    ).toBeInTheDocument()
  })

  it('renders each dependency card with its name + latency', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('postgres')).toBeInTheDocument()
    expect(screen.getByText('redis')).toBeInTheDocument()
    expect(screen.getByText('elasticsearch')).toBeInTheDocument()

    expect(screen.getByText('3ms')).toBeInTheDocument()
    expect(screen.getByText('1ms')).toBeInTheDocument()
    expect(screen.getByText('250ms')).toBeInTheDocument()

    // Connected to primary detail line.
    expect(screen.getByText(/connected to primary/i)).toBeInTheDocument()
    expect(
      screen.getByText(/high response time observed/i),
    ).toBeInTheDocument()
  })

  it('renders the loading branch before fetch resolves', async () => {
    setFetchMock(() => new Promise(() => undefined))
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/loading health status/i),
    ).toBeInTheDocument()
  })

  it('renders the empty / failed-fetch fallback when fetch errors', async () => {
    setFetchMock(() =>
      Promise.resolve({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      } as unknown as Response),
    )

    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/unable to retrieve health status/i),
    ).toBeInTheDocument()
  })
})
