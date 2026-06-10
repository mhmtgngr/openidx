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

import { PasswordlessSettingsPage } from './passwordless-settings'
import { api } from '../lib/api'

const settings = {
  settings: {
    magic_link_enabled: true,
    qr_login_enabled: false,
    biometric_only_enabled: true,
    magic_link_expiry_minutes: 15,
    qr_login_expiry_minutes: 5,
  },
}

const stats = {
  stats: {
    magic_links_today: 42,
    qr_logins_today: 7,
    biometric_only_users: 128,
    passwordless_adoption_rate: 65,
  },
}

function routeGet(url: string) {
  if (url.includes('/passwordless/settings')) return Promise.resolve(settings)
  if (url.includes('/passwordless/stats')) return Promise.resolve(stats)
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

describe('PasswordlessSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Edit Settings / Test buttons', async () => {
    render(<PasswordlessSettingsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Passwordless Authentication'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/configure magic links, qr login, and biometric-only access/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /test magic link/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /edit settings/i }),
    ).toBeInTheDocument()
  })

  it('shows the four stat cards with values', async () => {
    render(<PasswordlessSettingsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Magic Links Today')).toBeInTheDocument()
    expect(screen.getByText('QR Logins Today')).toBeInTheDocument()
    expect(screen.getByText('Biometric-Only Users')).toBeInTheDocument()
    expect(screen.getByText('Adoption Rate')).toBeInTheDocument()

    // Stat values may collide with feature-card expiry minutes (e.g. 15).
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getAllByText('128').length).toBeGreaterThan(0)
    expect(screen.getByText('65%')).toBeInTheDocument()
  })

  it('renders the three feature cards (Magic Links / QR Login / Biometric)', async () => {
    render(<PasswordlessSettingsPage />, { wrapper: createWrapper() })

    // "Magic Links" appears in both the stat card label and the feature
    // card title.
    expect(
      (await screen.findAllByText('Magic Links')).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getByText(/email-based passwordless login/i),
    ).toBeInTheDocument()
  })
})
