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

const appBackedRoute = {
  id: 'rt-3',
  name: 'confluence',
  from_url: 'confluence.example.com',
  to_url: 'http://confluence-internal:8090',
  route_type: 'http',
  enabled: true,
  require_auth: true,
  description: 'Atlassian Confluence',
  application_id: 'app-1',
  application_name: 'Confluence',
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

  it('shows the application-backed annotation and keeps roles/groups editable when application_id is set', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockResolvedValue({ routes: [appBackedRoute], total: 1 })

    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('confluence')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '' }))
    await user.click(await screen.findByText(/^edit$/i))

    expect(
      await screen.findByText(/this route is backed by the application/i),
    ).toBeInTheDocument()
    expect(screen.getByText('Confluence')).toBeInTheDocument()
    expect(
      screen.getByText(/once assignment enforcement is enabled/i),
    ).toBeInTheDocument()

    const rolesInput = screen.getByPlaceholderText('admin, developer')
    const groupsInput = screen.getByPlaceholderText('engineering, devops')
    expect(rolesInput).not.toBeDisabled()
    expect(groupsInput).not.toBeDisabled()
    expect(rolesInput).not.toHaveAttribute('readonly')
    expect(groupsInput).not.toHaveAttribute('readonly')
  })

  it('does not render the annotation, and keeps roles/groups editable, when application_id is absent', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockResolvedValue({ routes: [activeRoute], total: 1 })

    render(<ProxyRoutesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('jira')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '' }))
    await user.click(await screen.findByText(/^edit$/i))

    expect(await screen.findByPlaceholderText('admin, developer')).toBeInTheDocument()
    expect(
      screen.queryByText(/this route is backed by the application/i),
    ).not.toBeInTheDocument()

    const rolesInput = screen.getByPlaceholderText('admin, developer')
    const groupsInput = screen.getByPlaceholderText('engineering, devops')
    expect(rolesInput).not.toBeDisabled()
    expect(groupsInput).not.toBeDisabled()
    expect(rolesInput).not.toHaveAttribute('readonly')
    expect(groupsInput).not.toHaveAttribute('readonly')
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
