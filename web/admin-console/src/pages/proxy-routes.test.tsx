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

import { ProxyRoutesPage } from './proxy-routes'
import { api } from '../lib/api'

const activeRoute = {
  id: 'rt-1',
  name: 'jira',
  from_url: 'jira.example.com',
  to_url: 'http://jira-internal:8080',
  route_type: 'http',
  enabled: true,
  require_auth: true,
  description: 'Atlassian Jira',
}

const sshRoute = {
  id: 'rt-2',
  name: 'bastion',
  from_url: 'bastion.example.com',
  to_url: 'ssh://bastion-internal:22',
  route_type: 'ssh',
  enabled: false,
  require_auth: false,
  description: 'SSH bastion',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ProxyRoutesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      routes: [activeRoute, sshRoute],
      total: 2,
    })
  })

  it('renders the heading + subtitle + Add Route / Quick Create buttons', async () => {
    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Proxy Routes')).toBeInTheDocument()
    expect(
      screen.getByText(/manage zero trust access proxy routes for internal applications/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add route/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /quick create/i }),
    ).toBeInTheDocument()
  })

  it('shows the routes-count badge derived from the total', async () => {
    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/2 routes/i)).toBeInTheDocument()
  })

  it('lists route rows with their name + Active/Disabled badge', async () => {
    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('jira')).toBeInTheDocument()
    expect(screen.getByText('bastion')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('renders the SSH protocol badge (uppercase) for ssh routes', async () => {
    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('SSH')).toBeInTheDocument()
  })

  it('shows the empty state when no routes exist', async () => {
    vi.mocked(api.get).mockResolvedValue({ routes: [], total: 0 })

    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no proxy routes found/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/create a proxy route to get started/i),
    ).toBeInTheDocument()
  })
})
