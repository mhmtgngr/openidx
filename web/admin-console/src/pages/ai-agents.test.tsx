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

import { AIAgentsPage } from './ai-agents'
import { api } from '../lib/api'

const assistantAgent = {
  id: 'agent-1',
  name: 'CI Pipeline Bot',
  description: 'Builds and deploys main branch',
  agent_type: 'assistant',
  owner_id: null,
  owner_email: 'platform@example.com',
  status: 'active',
  capabilities: ['build', 'deploy'],
  trust_level: 'low',
  rate_limits: { requests_per_minute: 60, requests_per_hour: 1000 },
  allowed_scopes: ['repo:read'],
  ip_allowlist: [],
  metadata: {},
  last_active_at: '2026-06-09T11:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-06-01T00:00:00Z',
}

const workflowAgent = {
  ...assistantAgent,
  id: 'agent-2',
  name: 'Nightly Report Generator',
  description: 'Compiles compliance reports',
  agent_type: 'workflow',
  status: 'suspended',
  trust_level: 'medium',
}

const analytics = {
  total_agents: 7,
  active_agents: 4,
  suspended_agents: 1,
  by_type: [{ type: 'assistant', count: 3 }, { type: 'workflow', count: 2 }],
  top_agents_24h: [
    { id: 'agent-1', name: 'CI Pipeline Bot', type: 'assistant', activity_count: 150 },
    { id: 'agent-2', name: 'Nightly Report Generator', type: 'workflow', activity_count: 75 },
  ],
  expiring_credentials_30d: 2,
  recent_failures_24h: 3,
}

function routeGet(url: string) {
  if (url.includes('/ai-agents/analytics')) return Promise.resolve(analytics)
  if (url.match(/\/ai-agents\/agent-/)) {
    return Promise.resolve({ data: assistantAgent, credentials: [] })
  }
  if (url.includes('/ai-agents')) {
    return Promise.resolve({ data: [assistantAgent, workflowAgent], total: 2 })
  }
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

describe('AIAgentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Create Agent button', async () => {
    render(<AIAgentsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('AI Agent Management')).toBeInTheDocument()
    expect(
      screen.getByText(/manage ai agent identities, credentials, and permissions/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create agent/i }),
    ).toBeInTheDocument()
  })

  it('shows the analytics cards (total / active / suspended / expiring / actions / failures)', async () => {
    render(<AIAgentsPage />, { wrapper: createWrapper() })

    // Wait for the analytics query to resolve via a label that's unique.
    expect(await screen.findByText('Total Agents')).toBeInTheDocument()
    // "Active" collides with the row badge so allow multiple.
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Suspended').length).toBeGreaterThan(0)
    expect(screen.getByText('Expiring Keys')).toBeInTheDocument()
    expect(screen.getByText('Actions (24h)')).toBeInTheDocument()
    expect(screen.getByText('Failures (24h)')).toBeInTheDocument()

    expect(screen.getByText('7')).toBeInTheDocument() // total_agents
    expect(screen.getByText('4')).toBeInTheDocument() // active_agents
    expect(screen.getByText('2')).toBeInTheDocument() // expiring_credentials_30d
    expect(screen.getByText('225')).toBeInTheDocument() // 150 + 75
    expect(screen.getByText('3')).toBeInTheDocument() // recent_failures_24h
  })

  it('lists the agent rows with name + description + type badge', async () => {
    render(<AIAgentsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('CI Pipeline Bot')).toBeInTheDocument()
    expect(screen.getByText('Nightly Report Generator')).toBeInTheDocument()

    expect(screen.getByText('Builds and deploys main branch')).toBeInTheDocument()
    expect(screen.getByText('Compiles compliance reports')).toBeInTheDocument()

    expect(screen.getByText('assistant')).toBeInTheDocument()
    expect(screen.getByText('workflow')).toBeInTheDocument()
  })

  it('renders the agents count label "Agents (2)" matching the fixture', async () => {
    render(<AIAgentsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText(/agents \(2\)/i)).toBeInTheDocument()
  })

  it('renders the empty list message when no agents are configured', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/ai-agents/analytics')) {
        return Promise.resolve({
          ...analytics, total_agents: 0, active_agents: 0, suspended_agents: 0, top_agents_24h: [],
        }) as ReturnType<typeof api.get>
      }
      if (url.includes('/ai-agents')) {
        return Promise.resolve({ data: [], total: 0 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<AIAgentsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no ai agents configured/i)).toBeInTheDocument()
  })
})
