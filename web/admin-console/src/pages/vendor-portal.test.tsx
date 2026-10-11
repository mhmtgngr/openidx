import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const { authState } = vi.hoisted(() => ({ authState: { roles: ['user'] as string[] } }))

vi.mock('../lib/api', () => ({ api: { get: vi.fn() } }))
vi.mock('../lib/auth', () => ({ useAuth: () => ({ user: { id: 'u-1', roles: authState.roles } }) }))

import { VendorPortalPage } from './vendor-portal'
import { VendorAwareHome } from '../components/vendor-aware-home'
import { api } from '../lib/api'

const external = {
  external: true,
  vendor: { id: 'v-1', name: 'Acme Field Service', require_engagement: true, closed_list: false },
  account_status: 'active',
  account_expires_at: '2099-01-01T00:00:00Z',
  sponsor: { name: 'Selin Sponsor', email: 'selin@example.test' },
  engagements: [
    { id: 'e-1', title: 'Firmware upgrade', purpose: '', ticket_ref: 'CHG-1', sponsor_name: 'Selin Sponsor', starts_at: '2026-10-11T08:00:00Z',
      ends_at: '2099-10-11T18:00:00Z', state: 'running', targets: [{ target_type: 'pam_entry', target_id: 'p-1', name: 'core-db' }] },
    { id: 'e-2', title: 'Next visit', purpose: '', ticket_ref: '', sponsor_name: '', starts_at: '2099-10-12T08:00:00Z',
      ends_at: '2099-10-12T18:00:00Z', state: 'scheduled', targets: [{ target_type: 'application', target_id: 'a-1', name: 'Plant HMI' }] },
  ],
}

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/vendor" element={<VendorPortalPage />} />
          <Route path="/dashboard" element={<VendorAwareHome><p>employee dashboard</p></VendorAwareHome>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('VendorPortalPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authState.roles = ['user']
  })

  it('shows a vendor user their running and coming engagements and their sponsor', async () => {
    vi.mocked(api.get).mockResolvedValue(external)
    renderAt('/vendor')
    expect(await screen.findByText('Firmware upgrade')).toBeInTheDocument()
    expect(screen.getByText('core-db')).toBeInTheDocument()
    expect(screen.getByText('Next visit')).toBeInTheDocument()
    expect(screen.getByText('Coming up')).toBeInTheDocument()
    expect(screen.getAllByText('Selin Sponsor').length).toBeGreaterThan(0)
    expect(screen.getByText('Engagements only')).toBeInTheDocument()
  })

  it('tells a vendor user with no running engagement who to ask', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...external, engagements: [] })
    renderAt('/vendor')
    expect(await screen.findByText('No engagement is running for you')).toBeInTheDocument()
    expect(screen.getByText(/Ask Selin Sponsor/)).toBeInTheDocument()
  })

  it('sends a vendor user from the dashboard to the portal', async () => {
    vi.mocked(api.get).mockResolvedValue(external)
    renderAt('/dashboard')
    expect(await screen.findByText('Firmware upgrade')).toBeInTheDocument()
    expect(screen.queryByText('employee dashboard')).toBeNull()
  })

  it('leaves an internal user on the dashboard, and staff never ask', async () => {
    vi.mocked(api.get).mockResolvedValue({ external: false })
    renderAt('/dashboard')
    expect(await screen.findByText('employee dashboard')).toBeInTheDocument()
    authState.roles = ['admin']
    vi.mocked(api.get).mockClear()
    renderAt('/dashboard')
    expect(screen.getAllByText('employee dashboard').length).toBeGreaterThan(0)
    expect(api.get).not.toHaveBeenCalled()
  })
})
