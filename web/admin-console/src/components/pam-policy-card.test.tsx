import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), put: vi.fn() },
}))
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { PamPolicyCard, type PamPolicy } from './pam-policy-card'
import { api } from '../lib/api'

// GET /api/v1/access/pam/policy for an organization that existed before the
// migration: its row carries the old behaviour (nothing recorded, no cap).
const LEGACY: PamPolicy = {
  org_id: 'org-1',
  max_session_hours: 0,
  idle_timeout_minutes: 0,
  require_approval_internal: false,
  record_internal: false,
  launch_approval_window_minutes: 60,
  source: 'policy',
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

beforeEach(() => {
  vi.mocked(api.get).mockReset()
  vi.mocked(api.put).mockReset()
})

describe('PamPolicyCard', () => {
  it('shows the stored policy and warns when internal sessions are not recorded', async () => {
    vi.mocked(api.get).mockResolvedValue(LEGACY)
    wrap(<PamPolicyCard />)
    // The header renders before the answer arrives; the form only after it.
    expect(await screen.findByLabelText(/maximum session length/i)).toHaveValue(0)
    expect(screen.getByTestId('pam-policy-source')).toHaveTextContent(/set for this organization/i)
    expect(screen.getByRole('note')).toHaveTextContent(/not recorded/i)
    expect(api.get).toHaveBeenCalledWith('/api/v1/access/pam/policy')
  })

  it('labels the defaults and shows no warning when sessions are recorded', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...LEGACY, source: 'default', record_internal: true, max_session_hours: 8 })
    wrap(<PamPolicyCard />)
    await screen.findByLabelText(/maximum session length/i)
    expect(screen.getByTestId('pam-policy-source')).toHaveTextContent(/defaults/i)
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })

  it('saves the whole policy with what the administrator changed', async () => {
    vi.mocked(api.get).mockResolvedValue(LEGACY)
    vi.mocked(api.put).mockResolvedValue({ ...LEGACY, record_internal: true, max_session_hours: 12 })
    wrap(<PamPolicyCard />)
    await screen.findByLabelText(/maximum session length/i)
    fireEvent.click(screen.getByLabelText(/record internal/i))
    fireEvent.change(screen.getByLabelText(/maximum session length/i), { target: { value: '12' } })
    fireEvent.click(screen.getByRole('button', { name: /save policy/i }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/access/pam/policy', {
        max_session_hours: 12,
        idle_timeout_minutes: 0,
        require_approval_internal: false,
        record_internal: true,
        launch_approval_window_minutes: 60,
      }),
    )
  })

  it('survives an answer that is not a policy (the dashboard test mocks every GET alike)', async () => {
    vi.mocked(api.get).mockResolvedValue({ unrelated: true })
    wrap(<PamPolicyCard />)
    expect(await screen.findByLabelText(/maximum session length/i)).toHaveValue(8)
    expect(screen.getByTestId('pam-policy-source')).toHaveTextContent(/defaults/i)
  })
})
