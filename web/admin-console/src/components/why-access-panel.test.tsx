import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn() },
}))

import { WhyAccessPanel, type ExplainResponse } from './why-access-panel'
import { api } from '../lib/api'

const APPS = [
  { id: 'app-pay', name: 'Payroll' },
  { id: 'app-crm', name: 'CRM' },
]

// GET /api/v1/access/decisions/explain for an assigned person on a resource
// whose device-trust condition cannot be judged here.
const ALLOWED: ExplainResponse = {
  decision: {
    application_id: 'app-pay', application_name: 'Payroll', kind: 'web', enforced: true, allowed: true, would_deny: false,
    grant: 'group:Finance',
    conditions: [{ name: 'device_trust', required: 'trusted', observed: 'unknown', satisfied: false, judged: false }],
    reasons: [], step_up_required: false,
  },
  explain: 'Payroll: assigned through group Finance; device_trust ? (trusted, observed unknown) → allowed',
}

const DENIED: ExplainResponse = {
  decision: {
    application_id: 'app-crm', application_name: 'CRM', kind: 'web', enforced: true, allowed: false, would_deny: true,
    grant: '',
    conditions: [{ name: 'risk_ceiling', required: '<= 50', observed: '72', satisfied: false, judged: true }],
    reasons: ['not_assigned', 'risk_above_max'], step_up_required: true,
  },
  explain: 'CRM: not assigned; risk_ceiling ✗ (<= 50, observed 72) → denied: not_assigned, risk_above_max',
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

beforeEach(() => {
  vi.mocked(api.get).mockReset()
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.includes('/api/v1/applications')) return Promise.resolve(APPS) as ReturnType<typeof api.get>
    if (url.includes('app=app-pay')) return Promise.resolve(ALLOWED) as ReturnType<typeof api.get>
    if (url.includes('app=app-crm')) return Promise.resolve(DENIED) as ReturnType<typeof api.get>
    return Promise.resolve({}) as ReturnType<typeof api.get>
  })
})

describe('WhyAccessPanel', () => {
  it('loads the applications to pick from and asks nothing until one is chosen', async () => {
    wrap(<WhyAccessPanel userId="u-1" />)
    expect(await screen.findByTestId('why-app-picker')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/applications')
    expect(api.get).not.toHaveBeenCalledWith(expect.stringContaining('/decisions/explain'))
    expect(screen.getByText(/pick an application/i)).toBeInTheDocument()
  })

  it('shows an allowed decision with its grant and an unjudged condition', async () => {
    wrap(<WhyAccessPanel userId="u-1" initialAppId="app-pay" />)
    expect(await screen.findByTestId('why-verdict')).toHaveTextContent(/allowed/i)
    expect(screen.getByTestId('why-grant')).toHaveTextContent('group:Finance')
    expect(screen.getByTestId('why-cond-device_trust')).toHaveTextContent(/not known here/i)
    expect(screen.getByTestId('why-explain')).toHaveTextContent('assigned through group Finance')
    expect(api.get).toHaveBeenCalledWith('/api/v1/access/decisions/explain?user=u-1&app=app-pay')
  })

  it('shows a denied decision with the failing condition and the reasons', async () => {
    wrap(<WhyAccessPanel userId="u-1" initialAppId="app-crm" />)
    expect(await screen.findByTestId('why-verdict')).toHaveTextContent(/denied/i)
    expect(screen.getByTestId('why-grant')).toHaveTextContent(/none/i)
    expect(screen.getByTestId('why-cond-risk_ceiling')).toHaveTextContent(/not met/i)
    expect(screen.getByTestId('why-reasons')).toHaveTextContent('not_assigned, risk_above_max')
    expect(screen.getByText(/step-up required/i)).toBeInTheDocument()
  })
})
