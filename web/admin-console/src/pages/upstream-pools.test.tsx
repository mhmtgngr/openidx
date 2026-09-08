import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

const toast = vi.fn()
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast }),
}))

import { UpstreamPoolsPage } from './upstream-pools'
import { api } from '../lib/api'

// A pool doing its job: two live backends, a route on it.
const servingPool = {
  id: 'pool-1',
  name: 'payroll-backends',
  description: 'Payroll app instances',
  algorithm: 'roundrobin',
  hash_on: 'vars',
  hash_key: 'remote_addr',
  health_check_enabled: true,
  health_check_path: '/',
  healthy_threshold: 2,
  unhealthy_threshold: 3,
  health_check_interval: 5,
  health_check_timeout: 3,
  retries: null,
  members: [
    { id: 'm-1', host: '203.0.113.1', port: 8080, weight: 1, enabled: true },
    { id: 'm-2', host: '203.0.113.2', port: 8080, weight: 3, enabled: true },
  ],
  routes_using: 1,
  in_effect: true,
}

// The case the page exists to make visible: configured, linked to two routes,
// and serving nothing, because every backend is disabled. Those two routes are
// still up — they have fallen back to their single target.
const drainedPool = {
  ...servingPool,
  id: 'pool-2',
  name: 'billing-backends',
  description: 'Billing app instances',
  members: [{ id: 'm-3', host: '203.0.113.21', port: 9090, weight: 1, enabled: false }],
  routes_using: 2,
  in_effect: false,
  not_in_effect_reason:
    'no usable member: every member is disabled, drained to an unreachable address, or the pool is empty — routes on this pool fall back to their single target',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('UpstreamPoolsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ pools: [servingPool, drainedPool], total: 2 })
  })

  it('renders the heading, subtitle and Add Pool button', async () => {
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Upstream Pools')).toBeInTheDocument()
    expect(screen.getByText(/several backends with weights and active health checking/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add pool/i })).toBeInTheDocument()
  })

  it('lists each pool with its backends and weights', async () => {
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('payroll-backends')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.1:8080')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.2:8080')).toBeInTheDocument()
    expect(screen.getByText('weight 3')).toBeInTheDocument()
  })

  // The assertion this page is for. A pool that is configured and not serving
  // looks identical to a working one in any table of names and members, and the
  // operator's routes are silently on a single backend.
  it('marks a pool that is not serving, and says why, and says how many routes have fallen back', async () => {
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('billing-backends')).toBeInTheDocument()
    expect(screen.getByText('Not in effect')).toBeInTheDocument()
    expect(screen.getByText(/no usable member/i)).toBeInTheDocument()
    expect(screen.getByText('2 routes use this pool')).toBeInTheDocument()

    // And the working one is not flagged.
    expect(screen.getByText('In effect')).toBeInTheDocument()
    expect(screen.getByText('1 route uses this pool')).toBeInTheDocument()
  })

  it('shows a disabled backend as disabled rather than listing it like a live one', async () => {
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('203.0.113.21:9090')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  // A 409 from the delete is not an error to shrug at: it names the routes that
  // would have been moved back to a single backend, and the operator needs them.
  it('names the routes when a delete is refused because they still use the pool', async () => {
    vi.mocked(api.delete).mockRejectedValueOnce({
      response: { status: 409, data: { routes: ['payroll', 'payroll-admin'] } },
    })
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    await screen.findByText('payroll-backends')
    await userEvent.click(screen.getByRole('button', { name: /delete pool payroll-backends/i }))
    // Deleting a pool moves traffic, so it is confirmed first — and the
    // confirmation already warns that a route points at this one.
    expect(await screen.findByText(/1 route still points at this pool/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^delete$/i }))

    await waitFor(() => {
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Pool is still in use',
          description: expect.stringContaining('payroll, payroll-admin'),
          variant: 'destructive',
        }),
      )
    })
  })

  // Disabling the last backend answers 200. Reporting that as a plain success
  // would tell an operator draining a pool for maintenance that traffic had
  // stopped, when it has moved to the single to_url instead.
  it('warns that the pool has stopped serving when a member change empties it', async () => {
    vi.mocked(api.put).mockResolvedValueOnce({
      message: 'member updated',
      pool: { ...drainedPool, routes_using: 2, in_effect: false },
    })
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    await screen.findByText('payroll-backends')
    await userEvent.click(screen.getAllByRole('button', { name: /backends/i })[0])
    await userEvent.click(await screen.findByRole('switch', { name: /enabled for 203\.0\.113\.1:8080/i }))

    await waitFor(() => {
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'This pool is no longer serving',
          description: expect.stringContaining('fallen back'),
          variant: 'destructive',
        }),
      )
    })
  })

  it('tells the operator a new pool is not in effect until a route points at it', async () => {
    render(<UpstreamPoolsPage />, { wrapper: createWrapper() })

    await screen.findByText('payroll-backends')
    await userEvent.click(screen.getByRole('button', { name: /add pool/i }))

    expect(await screen.findByText(/serves nothing until a route points at it/i)).toBeInTheDocument()
  })
})
