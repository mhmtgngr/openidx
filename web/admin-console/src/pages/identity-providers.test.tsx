import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
    createIdentityProvider: vi.fn(() => Promise.resolve({})),
    updateIdentityProvider: vi.fn(() => Promise.resolve({})),
    deleteIdentityProvider: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { IdentityProvidersPage } from './identity-providers'
import { api } from '../lib/api'

const oidcProvider = {
  id: 'idp-1',
  name: 'Google Workspace',
  provider_type: 'oidc',
  issuer_url: 'https://accounts.google.com',
  client_id: 'client-abc',
  client_secret: 'secret-xyz',
  scopes: ['openid', 'profile', 'email'],
  enabled: true,
}

const samlProvider = {
  id: 'idp-2',
  name: 'Okta SAML',
  provider_type: 'saml',
  issuer_url: 'https://example.okta.com',
  client_id: '',
  client_secret: '',
  scopes: [],
  enabled: false,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('IdentityProvidersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [oidcProvider, samlProvider] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: { 'x-total-count': '2' },
    })
  })

  it('renders the heading + Add Provider button', async () => {
    render(<IdentityProvidersPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Identity Providers')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add provider/i }),
    ).toBeInTheDocument()
  })

  it('shows the Quick Setup card and the Configured Providers card', async () => {
    render(<IdentityProvidersPage />, { wrapper: createWrapper() })
    await screen.findByText('Identity Providers')

    expect(screen.getByText('Quick Setup')).toBeInTheDocument()
    expect(screen.getByText('Configured Providers')).toBeInTheDocument()
    expect(
      screen.getByText(/manage external identity providers for single sign-on/i),
    ).toBeInTheDocument()
  })

  it('renders the Custom OIDC + Custom SAML quick-setup buttons', async () => {
    render(<IdentityProvidersPage />, { wrapper: createWrapper() })
    await screen.findByText('Identity Providers')

    expect(screen.getByText('Custom OIDC')).toBeInTheDocument()
    expect(screen.getByText('Custom SAML')).toBeInTheDocument()
  })

  it('lists configured providers with their name + issuer URL', async () => {
    render(<IdentityProvidersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Google Workspace')).toBeInTheDocument()
    expect(screen.getByText('Okta SAML')).toBeInTheDocument()

    expect(screen.getByText('https://accounts.google.com')).toBeInTheDocument()
    expect(screen.getByText('https://example.okta.com')).toBeInTheDocument()
  })

  it('opens the Add Provider modal when the Add Provider button is clicked', async () => {
    const user = userEvent.setup()
    render(<IdentityProvidersPage />, { wrapper: createWrapper() })
    await screen.findByText('Identity Providers')

    await user.click(screen.getByRole('button', { name: /add provider/i }))

    // The modal exposes form fields whose placeholders are unique copy.
    expect(
      await screen.findByPlaceholderText(/provider name/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/https:\/\/accounts.google.com/i),
    ).toBeInTheDocument()
  })

  it('shows the "No identity providers found." empty row when the list is empty', async () => {
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [] as unknown as ReturnType<typeof api.getWithHeaders>['data'],
      headers: { 'x-total-count': '0' },
    })

    render(<IdentityProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no identity providers found\./i),
    ).toBeInTheDocument()
  })
})
