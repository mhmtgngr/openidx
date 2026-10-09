import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn() },
}))
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))
const hasRole = vi.fn(() => true)
vi.mock('../lib/auth', () => ({
  useAuth: () => ({ hasRole, user: { username: 'admin' } }),
}))

import { EnforcementPage } from './enforcement'
import { EnforcementBanner } from '../components/enforcement-banner'
import type { EnforcementPosture } from '../lib/enforcement'
import { api } from '../lib/api'

// GET /api/v1/security-posture as admin-api answers it mid-rollout: two
// controls open, one of them with observe events, a window with six days left.
const POSTURE: EnforcementPosture = {
  environment: 'production',
  fully_enforcing: false,
  observe_until: '2026-10-16',
  observe_days_left: 6,
  window_status: 'observe window until 2026-10-16 (6 day(s) left)',
  gates: [
    { name: 'ACCESS_ASSIGNMENT_ENFORCE', mode: 'off', enforcing: false, meaning: 'application assignment is a catalogue, not a grant', observe_action: 'access.assignment.would_deny', would_deny_7d: 14 },
    { name: 'STEPUP_GATE', mode: 'observe', enforcing: false, meaning: 'a PAM launch never asks for a fresh second factor', would_deny_7d: 0 },
    { name: 'BOT_GATE', mode: 'enforce', enforcing: true, would_deny_7d: 0 },
  ],
  env_lines: ['ACCESS_ASSIGNMENT_ENFORCE=true', 'STEPUP_GATE=enforce'],
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.get).mockReset()
  hasRole.mockReturnValue(true)
})

describe('EnforcementPage', () => {
  it('lists every control with its mode, what it leaves open and its would-deny count', async () => {
    vi.mocked(api.get).mockResolvedValue(POSTURE)
    wrap(<EnforcementPage />)
    expect(await screen.findByText('ACCESS_ASSIGNMENT_ENFORCE')).toBeInTheDocument()
    expect(screen.getByTestId('mode-ACCESS_ASSIGNMENT_ENFORCE')).toHaveTextContent('off')
    expect(screen.getByTestId('mode-STEPUP_GATE')).toHaveTextContent('observe')
    expect(screen.getByTestId('mode-BOT_GATE')).toHaveTextContent('enforce')
    expect(screen.getByText('application assignment is a catalogue, not a grant')).toBeInTheDocument()
    expect(screen.getByText('14')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/security-posture')
  })

  it('shows the exact settings that close the open controls', async () => {
    vi.mocked(api.get).mockResolvedValue(POSTURE)
    wrap(<EnforcementPage />)
    const pre = await screen.findByTestId('env-lines')
    expect(pre).toHaveTextContent('ACCESS_ASSIGNMENT_ENFORCE=true')
    expect(pre).toHaveTextContent('STEPUP_GATE=enforce')
  })

  it('hides the settings card once everything enforces', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...POSTURE, fully_enforcing: true, env_lines: [], gates: [POSTURE.gates[2]] })
    wrap(<EnforcementPage />)
    expect(await screen.findByText('BOT_GATE')).toBeInTheDocument()
    expect(screen.queryByTestId('env-lines')).not.toBeInTheDocument()
  })

  it('reports a failed read instead of an empty table', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('boom'))
    wrap(<EnforcementPage />)
    expect(await screen.findByText(/enforcement posture/i)).toBeInTheDocument()
  })
})

describe('EnforcementBanner', () => {
  it('tells an administrator how many controls are open and how long the window has left', async () => {
    vi.mocked(api.get).mockResolvedValue(POSTURE)
    wrap(<EnforcementBanner />)
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('2')
    expect(banner).toHaveTextContent('2026-10-16')
    expect(banner).toHaveTextContent('14')
    expect(screen.getByRole('link')).toHaveAttribute('href', '/enforcement')
  })

  it('renders nothing when every control enforces', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...POSTURE, fully_enforcing: true })
    wrap(<EnforcementBanner />)
    await vi.waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('does not even ask for a reader who could not act on it', () => {
    hasRole.mockReturnValue(false)
    wrap(<EnforcementBanner />)
    expect(api.get).not.toHaveBeenCalled()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
