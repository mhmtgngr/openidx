import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(() => Promise.resolve({})) },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { EntraEAMCard, keyStates, type EAMStatus } from './entra-eam-card'
import { api } from '../lib/api'

const day = 86400000
const now = Date.now()
const status: EAMStatus = {
  enabled: true,
  issuer: 'https://idp.example.test/eam',
  discovery_url: 'https://idp.example.test/eam/.well-known/openid-configuration',
  jwks_url: 'https://idp.example.test/eam/jwks',
  authorize_url: 'https://idp.example.test/eam/authorize',
  client_id: 'app-1',
  tenant_ids: ['t-1', 't-2'],
  require_strong_factors: true,
  keys: [
    { kid: 'k-new', not_before: new Date(now + 2 * day).toISOString(), not_after: new Date(now + 400 * day).toISOString(), active: false, created_at: '' },
    { kid: 'k-cur', not_before: new Date(now - 10 * day).toISOString(), not_after: new Date(now + 300 * day).toISOString(), active: true, created_at: '' },
  ],
  verifications_24h: 7,
  verifications_failed_24h: 2,
}

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}><EntraEAMCard /></QueryClientProvider>)
}

describe('EntraEAMCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows what to register in Entra, tenants and the 24h count', async () => {
    vi.mocked(api.get).mockResolvedValue(status)
    renderCard()
    expect(await screen.findByText(status.discovery_url)).toBeInTheDocument()
    expect(screen.getByText(status.jwks_url)).toBeInTheDocument()
    expect(screen.getByText(status.authorize_url)).toBeInTheDocument()
    expect(screen.getByText('t-1, t-2')).toBeInTheDocument()
    expect(screen.getByTestId('eam-count')).toHaveTextContent('7')
    expect(screen.getByTestId('eam-count')).toHaveTextContent('2')
    expect(api.get).toHaveBeenCalledWith('/api/v1/oauth/eam/status')
  })

  it('rotates the key', async () => {
    vi.mocked(api.get).mockResolvedValue(status)
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: /rotate/i }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/oauth/eam/keys/rotate'))
  })

  it('cannot rotate while EAM is off', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...status, enabled: false, keys: [] })
    renderCard()
    expect(await screen.findByRole('button', { name: /rotate/i })).toBeDisabled()
  })

  it('says when only platform administrators may look', async () => {
    vi.mocked(api.get).mockRejectedValue({ response: { status: 403, data: { error: 'platform administrator required' } } })
    renderCard()
    expect(await screen.findByText(/platform administrators/i)).toBeInTheDocument()
  })
})

describe('keyStates', () => {
  it('the newest key in effect signs, a rotated-in one waits, older ones retire', () => {
    const old = { kid: 'k-old', not_before: new Date(now - 100 * day).toISOString(), not_after: new Date(now + day).toISOString(), active: true, created_at: '' }
    expect(keyStates([old, ...status.keys], now)).toEqual({ 'k-new': 'pending', 'k-cur': 'signing', 'k-old': 'retired' })
  })
})
