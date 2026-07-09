import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
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

import { GuacamoleSessionsPage } from './guacamole-sessions'
import { api } from '../lib/api'

// ──────────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────────

const pendingRequest = {
  id: 'req-aabbccdd',
  org_id: 'org-1',
  connection_id: 'conn-db-prod',
  requester_id: 'user-alice',
  reason: 'routine maintenance',
  status: 'pending',
  created_at: '2026-07-01T10:00:00Z',
  expires_at: '2026-07-01T12:00:00Z',
}

const activeSession = {
  identifier: 'active-uuid-1234',
  connectionIdentifier: 'conn-web-01',
  username: 'bob',
  remoteHost: '10.0.0.5',
  startDate: 1751371200000,
}

const sessionRowWithTranscript = {
  id: 'hist-row-1',
  connection_id: 'conn-db-prod',
  user_id: 'user-charlie',
  started_at: '2026-06-30T08:00:00Z',
  ended_at: '2026-06-30T09:00:00Z',
  status: 'completed',
  transcript_available: true,
  recording_available: true,
  on_legal_hold: false,
}

const sessionRowNoTranscript = {
  id: 'hist-row-2',
  connection_id: 'conn-web-01',
  user_id: 'user-dave',
  started_at: '2026-06-29T08:00:00Z',
  status: 'active',
  transcript_available: false,
  recording_available: false,
  on_legal_hold: false,
}

const sessionRowOnHold = {
  id: 'hist-row-3',
  connection_id: 'conn-app-02',
  user_id: 'user-erin',
  started_at: '2026-06-28T08:00:00Z',
  ended_at: '2026-06-28T09:00:00Z',
  status: 'completed',
  transcript_available: true,
  recording_available: true,
  on_legal_hold: true,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function routeGet(url: string) {
  if (url.includes('/session-requests')) {
    return Promise.resolve({ requests: [pendingRequest] })
  }
  if (url.includes('/session-history')) {
    return Promise.resolve({
      sessions: [sessionRowWithTranscript, sessionRowNoTranscript, sessionRowOnHold],
    })
  }
  if (url.includes('/sessions') && !url.includes('/transcript')) {
    return Promise.resolve({ sessions: [activeSession] })
  }
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

describe('GuacamoleSessionsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    window.prompt = vi.fn()
    vi.mocked(api.get).mockImplementation(
      (url: string) => routeGet(url) as ReturnType<typeof api.get>,
    )
  })

  // ── Pending Requests tab ────────────────────────────────────────────────────

  it('renders the page heading', async () => {
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Privileged Sessions')).toBeInTheDocument()
  })

  it('renders the Pending Requests tab content', async () => {
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('user-alice')).toBeInTheDocument()
    expect(screen.getByText('conn-db-prod')).toBeInTheDocument()
    expect(screen.getByText('routine maintenance')).toBeInTheDocument()
  })

  it('Approve button calls the approve endpoint', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ request_id: 'req-aabbccdd', status: 'approved' })

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })

    const approveBtn = await screen.findByRole('button', { name: /approve/i })
    fireEvent.click(approveBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/session-requests/req-aabbccdd/approve',
      )
    })
  })

  it('Deny button calls the deny endpoint', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ request_id: 'req-aabbccdd', status: 'denied' })

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })

    const denyBtn = await screen.findByRole('button', { name: /deny/i })
    fireEvent.click(denyBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/session-requests/req-aabbccdd/deny',
      )
    })
  })

  // ── Active Sessions tab ─────────────────────────────────────────────────────

  it('renders active sessions after switching to the Active tab', async () => {
    // Radix Tabs requires userEvent (pointer events), not fireEvent.click
    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /active sessions/i }))

    expect(await screen.findByText('bob')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument()
    expect(screen.getByText('conn-web-01')).toBeInTheDocument()
  })

  it('Monitor button calls the share endpoint and opens share_url', async () => {
    const user = userEvent.setup()
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
    vi.mocked(api.post).mockResolvedValueOnce({ share_url: 'https://guac.example.com/share/abc' })

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /active sessions/i }))
    const monitorBtn = await screen.findByRole('button', { name: /monitor/i })
    fireEvent.click(monitorBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/active-uuid-1234/share',
      )
    })
    await waitFor(() => {
      expect(openSpy).toHaveBeenCalledWith('https://guac.example.com/share/abc', '_blank')
    })

    openSpy.mockRestore()
  })

  it('Terminate button opens the confirm dialog, then calls terminate endpoint', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({ message: 'ok', active_conn_id: 'active-uuid-1234' })

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /active sessions/i }))
    const terminateBtn = await screen.findByRole('button', { name: /terminate/i })
    fireEvent.click(terminateBtn)

    // Confirm dialog should appear
    expect(await screen.findByText(/terminate session/i)).toBeInTheDocument()

    // Click the confirm action inside the AlertDialog
    const confirmBtn = screen.getByRole('button', { name: /^terminate$/i })
    fireEvent.click(confirmBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/active-uuid-1234/terminate',
        { reason: undefined },
      )
    })
  })

  // ── Session History tab ─────────────────────────────────────────────────────

  it('renders session history after switching to the History tab', async () => {
    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /session history/i }))

    expect(await screen.findByText('user-charlie')).toBeInTheDocument()
    expect(screen.getByText('user-dave')).toBeInTheDocument()
  })

  it('Download transcript button is disabled when transcript_available is false', async () => {
    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-dave')

    // First row (hist-row-1) has transcript available → enabled
    // Second row (hist-row-2) has no transcript → disabled
    const transcriptBtns = screen.getAllByRole('button', { name: /transcript/i })
    expect(transcriptBtns[0]).not.toBeDisabled()
    expect(transcriptBtns[1]).toBeDisabled()
  })

  it('Download transcript calls api.get with responseType blob', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockReturnValue(undefined)

    const fakeBlob = new Blob(['keystroke data'], { type: 'text/plain' })
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/transcript')) {
        return Promise.resolve(fakeBlob) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })

    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')

    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-charlie')

    const transcriptBtns = screen.getAllByRole('button', { name: /transcript/i })
    fireEvent.click(transcriptBtns[0])

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/hist-row-1/transcript',
        { responseType: 'blob' },
      )
    })
  })

  it('recorded, un-held row shows "Place hold" and calls POST /legal-hold with a reason', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({})

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-charlie')

    const placeBtns = await screen.findAllByRole('button', { name: /place hold/i })
    fireEvent.click(placeBtns[0]) // hist-row-1

    // Reason dialog appears; confirm is disabled until a reason is entered
    expect(await screen.findByText('Place legal hold?')).toBeInTheDocument()
    const dialog = screen.getByRole('alertdialog')
    const confirmBtn = within(dialog).getByRole('button', { name: /^place hold$/i })
    expect(confirmBtn).toBeDisabled()

    fireEvent.change(within(dialog).getByPlaceholderText(/litigation case/i), {
      target: { value: 'litigation case #1234' },
    })
    fireEvent.click(confirmBtn)

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/hist-row-1/legal-hold',
        { reason: 'litigation case #1234' },
      )
    })
  })

  it('held row shows "Release hold" + an On hold badge and calls DELETE /legal-hold', async () => {
    const user = userEvent.setup()
    vi.mocked(api.delete).mockResolvedValueOnce({})

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-erin')

    expect(screen.getByText(/on hold/i)).toBeInTheDocument()

    const releaseBtn = await screen.findByRole('button', { name: /release hold/i })
    fireEvent.click(releaseBtn)

    // Reason dialog appears; the reason is optional for a release
    expect(await screen.findByText('Release legal hold?')).toBeInTheDocument()
    const dialog = screen.getByRole('alertdialog')
    fireEvent.change(within(dialog).getByPlaceholderText(/litigation case/i), {
      target: { value: 'case closed' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^release hold$/i }))

    await waitFor(() => {
      expect(api.delete).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/hist-row-3/legal-hold',
        { data: { reason: 'case closed' } },
      )
    })
  })

  it('row without a recording shows no legal-hold button', async () => {
    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    const daveCell = await screen.findByText('user-dave')
    const daveRow = daveCell.closest('tr') as HTMLElement
    expect(daveRow).toBeTruthy()
    const { queryByRole } = within(daveRow)
    expect(queryByRole('button', { name: /place hold/i })).toBeNull()
    expect(queryByRole('button', { name: /release hold/i })).toBeNull()
  })
})
