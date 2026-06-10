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

import { AppLauncherPage } from './app-launcher'
import { api } from '../lib/api'

const slackApp = {
  id: 'app-slack',
  name: 'Slack Workspace',
  description: 'Team chat and collaboration',
  base_url: 'https://example.slack.com',
  protocol: 'SAML',
  logo_url: '',
  sso_enabled: true,
}

const githubApp = {
  id: 'app-github',
  name: 'GitHub Enterprise',
  description: 'Source code repositories',
  base_url: 'https://github.example.com',
  protocol: 'OIDC',
  logo_url: 'https://example.com/gh.png',
  sso_enabled: false,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AppLauncherPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ applications: [slackApp, githubApp] })
  })

  it('renders the heading + subtitle + search input', async () => {
    render(<AppLauncherPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('My Applications')).toBeInTheDocument()
    expect(
      screen.getByText(/launch your assigned applications with single sign-on/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/search applications/i),
    ).toBeInTheDocument()
  })

  it('lists each assigned application with name + protocol + Launch button', async () => {
    render(<AppLauncherPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Slack Workspace')).toBeInTheDocument()
    expect(screen.getByText('GitHub Enterprise')).toBeInTheDocument()

    expect(screen.getByText('SAML')).toBeInTheDocument()
    expect(screen.getByText('OIDC')).toBeInTheDocument()
    // Each card has a Launch button.
    expect(screen.getAllByRole('button', { name: /launch/i }).length).toBe(2)
    // SSO badge only renders for sso_enabled apps.
    expect(screen.getByText('SSO')).toBeInTheDocument()
  })

  it('filters the app list by the search input (case-insensitive)', async () => {
    const user = userEvent.setup()
    render(<AppLauncherPage />, { wrapper: createWrapper() })
    await screen.findByText('Slack Workspace')

    await user.type(screen.getByPlaceholderText(/search applications/i), 'github')

    // Only the matching card stays.
    expect(screen.getByText('GitHub Enterprise')).toBeInTheDocument()
    expect(screen.queryByText('Slack Workspace')).not.toBeInTheDocument()
  })

  it('renders the empty state when no applications are assigned', async () => {
    vi.mocked(api.get).mockResolvedValue({ applications: [] })
    render(<AppLauncherPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no applications assigned/i)).toBeInTheDocument()
    expect(
      screen.getByText(/contact your administrator/i),
    ).toBeInTheDocument()
  })
})
