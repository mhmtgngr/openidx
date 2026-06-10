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

import { SocialProvidersPage } from './social-providers'
import { api } from '../lib/api'

const googleProvider = {
  id: 'sp-1',
  provider_key: 'google',
  display_name: 'Google',
  button_color: '#4285F4',
  enabled: true,
  sort_order: 1,
  allowed_domains: ['example.com', 'corp.example.com'],
  auto_create_users: true,
  auto_link_by_email: true,
}

const githubProvider = {
  id: 'sp-2',
  provider_key: 'github',
  display_name: 'GitHub',
  button_color: '#24292e',
  enabled: false,
  sort_order: 2,
  allowed_domains: [],
  auto_create_users: false,
  auto_link_by_email: false,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SocialProvidersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ data: [googleProvider, githubProvider] })
  })

  it('renders the heading + subtitle + Add Provider button', async () => {
    render(<SocialProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Social Login Providers'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/configure social identity providers for sso/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add provider/i }),
    ).toBeInTheDocument()
  })

  it('renders each provider card with display name + Enabled/Disabled badge', async () => {
    render(<SocialProvidersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Google')).toBeInTheDocument()
    expect(screen.getByText('GitHub')).toBeInTheDocument()
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('shows the provider_key badges + allowed domain badges', async () => {
    render(<SocialProvidersPage />, { wrapper: createWrapper() })
    await screen.findByText('Google')

    expect(screen.getByText('google')).toBeInTheDocument()
    expect(screen.getByText('github')).toBeInTheDocument()

    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('corp.example.com')).toBeInTheDocument()
  })

  it('shows the empty state when no providers are configured', async () => {
    vi.mocked(api.get).mockResolvedValue({ data: [] })

    render(<SocialProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no social providers configured/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/add a social login provider to enable sso/i),
    ).toBeInTheDocument()
  })
})
