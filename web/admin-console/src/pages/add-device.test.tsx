import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

// The QR canvas needs a 2D context jsdom does not provide, and nothing here
// asserts on the pixels.
vi.mock('qrcode.react', () => ({
  QRCodeCanvas: ({ value }: { value: string }) => <div data-testid="qr">{value}</div>,
}))

import { AddDevicePage } from './add-device'
import { api } from '../lib/api'

// The end-user device-enrolment wizard: the one page in the console a
// non-administrator is sent to, and the one that used to offer five platform
// downloads when two were built. It had no test.

// The server's code is 12 characters from an unambiguous alphabet with no
// separators (internal/access/enroll_session.go); the page groups it in fours
// for reading, which only works on that shape.
const SESSION = {
  id: 'sess-1',
  code: 'ABCDEFGHJKMN',
  deep_link: 'openidx://enroll?code=ABCDEFGHJKMN',
  server: 'https://openidx.example',
  expires_at: new Date(Date.now() + 600_000).toISOString(),
}

function wrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

function mockApi({
  manifest = {},
  status,
  statusFails = false,
}: {
  manifest?: Record<string, { url: string }>
  status?: { status: string; agent_id: string; device_trusted: boolean }
  statusFails?: boolean
} = {}) {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.includes('agent-manifest.json')) return Promise.resolve(manifest)
    if (url.includes('/enroll/session/')) {
      if (statusFails) return Promise.reject(new Error('status unavailable'))
      return Promise.resolve(status ?? { status: 'pending', agent_id: '', device_trusted: false })
    }
    return Promise.resolve({})
  })
  vi.mocked(api.post).mockResolvedValue(SESSION)
}

describe('AddDevicePage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // detectOS() reads the user agent, and jsdom's default says "linux", so
    // every test picks its platform explicitly rather than inheriting one.
    mockApi()
  })

  it('offers a download only for a platform the manifest actually lists', async () => {
    mockApi({ manifest: { windows: { url: '/downloads/openidx-agent.msi' } } })
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    await user.click(await screen.findByRole('button', { name: /^windows$/i }))
    const link = await screen.findByRole('link', { name: /download for windows/i })
    expect(link).toHaveAttribute('href', '/downloads/openidx-agent.msi')

    // Linux is built and released, but this deployment has not staged it.
    await user.click(screen.getByRole('button', { name: /^linux$/i }))
    expect(screen.queryByRole('link', { name: /download for/i })).not.toBeInTheDocument()
    expect(screen.getByText(/installer for linux is provided by your administrator/i)).toBeInTheDocument()
  })

  it('says outright that iOS and macOS have no client, rather than sending the user to an administrator', async () => {
    // The defect this page existed to demonstrate: five platforms offered, two
    // published. "Ask your administrator" for a build nobody has is the lie.
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    for (const [button, label] of [
      [/iphone \/ ipad/i, 'iPhone / iPad'],
      [/^macos$/i, 'macOS'],
    ] as const) {
      await user.click(await screen.findByRole('button', { name: button }))
      expect(
        screen.getByText(new RegExp(`openidx does not publish an ${label} client yet`, 'i')),
      ).toBeInTheDocument()
      expect(screen.queryByText(/provided by your administrator/i)).not.toBeInTheDocument()
    }
  })

  it('generates a connect code and shows it', async () => {
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    await user.click(await screen.findByRole('button', { name: /generate connect code/i }))

    expect(await screen.findByText('ABCD-EFGH-JKMN')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('/api/v1/access/agent/enroll/session', {})
    expect(screen.getByTestId('qr')).toHaveTextContent(SESSION.deep_link)
  })

  it('reports the trust state the server returned once the device connects', async () => {
    mockApi({ status: { status: 'enrolled', agent_id: 'agt-1', device_trusted: false } })
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    await user.click(await screen.findByRole('button', { name: /generate connect code/i }))

    expect(await screen.findByText(/device connected/i)).toBeInTheDocument()
    // Enrolled is not the same as trusted, and the badge has to say which.
    expect(screen.getByText(/pending trust approval/i)).toBeInTheDocument()
    expect(screen.queryByText(/trusted — full access/i)).not.toBeInTheDocument()
  })

  it('says "trusted" only when the server says so', async () => {
    mockApi({ status: { status: 'enrolled', agent_id: 'agt-1', device_trusted: true } })
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    await user.click(await screen.findByRole('button', { name: /generate connect code/i }))
    expect(await screen.findByText(/trusted — full access/i)).toBeInTheDocument()
  })

  it('surfaces a failing status poll instead of leaving the code on screen forever', async () => {
    mockApi({ statusFails: true })
    render(<AddDevicePage />, { wrapper: wrapper() })
    const user = userEvent.setup({ pointerEventsCheck: 0 })

    await user.click(await screen.findByRole('button', { name: /generate connect code/i }))

    expect(await screen.findByText(/enrollment status/i)).toBeInTheDocument()
  })
})
