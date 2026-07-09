import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
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

import { FederationConfigPage } from './federation-config'
import { api } from '../lib/api'

const corpRule = {
  id: 'rule-1',
  name: 'Corporate Azure AD',
  email_domain: 'example.com',
  provider_id: 'prov-azure',
  provider_name: 'Azure AD — Corporate',
  priority: 100,
  auto_redirect: true,
  enabled: true,
}

const partnerRule = {
  id: 'rule-2',
  name: 'Partner OIDC',
  email_domain: 'partner.io',
  provider_id: 'prov-partner',
  provider_name: 'Partner OIDC',
  priority: 50,
  auto_redirect: false,
  enabled: false,
}

const providers = [
  { id: 'prov-azure', name: 'Azure AD — Corporate' },
  { id: 'prov-partner', name: 'Partner OIDC' },
]

function routeGet(url: string) {
  if (url.includes('/federation/rules')) return Promise.resolve({ data: [corpRule, partnerRule] })
  if (url.includes('/identity/providers')) return Promise.resolve(providers)
  return Promise.resolve({ data: [] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('FederationConfigPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + the three top-level tabs', async () => {
    render(<FederationConfigPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Federation Configuration')).toBeInTheDocument()
    expect(
      screen.getByText(/manage federation rules, identity links, and custom claims mapping/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /federation rules/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /identity links/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /claims mapping/i })).toBeInTheDocument()
  })

  it('lists the rules on the default Federation Rules tab with email domain, provider, and status', async () => {
    render(<FederationConfigPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Corporate Azure AD')).toBeInTheDocument()
    // "Partner OIDC" appears as both the rule name AND the provider
    // name on the same row, so disambiguate.
    expect(screen.getAllByText('Partner OIDC').length).toBeGreaterThan(0)

    // Email-domain badges (rendered as inline mono badges)
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('partner.io')).toBeInTheDocument()

    // Status badges (Enabled / Disabled) — also appear elsewhere
    // (form Switch labels), so allow multiple matches.
    expect(screen.getAllByText('Enabled').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Disabled').length).toBeGreaterThan(0)

    // Auto-redirect Yes/No
    expect(screen.getByText('Yes')).toBeInTheDocument()
    expect(screen.getByText('No')).toBeInTheDocument()
  })

  it('exposes the Add Rule button + the rules count line', async () => {
    render(<FederationConfigPage />, { wrapper: createWrapper() })
    await screen.findByText('Corporate Azure AD')

    expect(screen.getByRole('button', { name: /add rule/i })).toBeInTheDocument()
    expect(screen.getByText(/federation rules \(2\)/i)).toBeInTheDocument()
  })

  it('switches to the Identity Links tab when its button is clicked', async () => {
    const user = userEvent.setup()
    render(<FederationConfigPage />, { wrapper: createWrapper() })
    await screen.findByText('Corporate Azure AD')

    // The tab buttons share their accessible name with the heading copy
    // ("identity links" appears in subtitle too), so the click target
    // must be the actual tab button. The tab labels include lucide
    // icons; using getAllByRole + index is more stable than a name
    // regex.
    const tabButtons = screen.getAllByRole('button', { name: /identity links/i })
    expect(tabButtons.length).toBeGreaterThan(0)
    await user.click(tabButtons[0])

    // Once the Identity Links tab is active, the FederationRules
    // table content is gone — "Corporate Azure AD" is no longer in
    // the DOM. Use that as the negative assertion.
    expect(screen.queryByText('Corporate Azure AD')).not.toBeInTheDocument()
  })

  it('renders the empty rules state when no rules are configured', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/federation/rules')) {
        return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<FederationConfigPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no federation rules configured/i),
    ).toBeInTheDocument()
  })
})
