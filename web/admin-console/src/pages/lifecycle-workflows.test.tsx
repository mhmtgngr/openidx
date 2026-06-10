import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { LifecycleWorkflowsPage } from './lifecycle-workflows'
import { api } from '../lib/api'

const onboardWorkflow = {
  id: 'wf-1',
  name: 'Engineer onboarding',
  description: 'Adds engineers to default groups',
  event_type: 'onboard',
  enabled: true,
  steps: [],
  created_at: '2026-01-01T00:00:00Z',
}

const offboardWorkflow = {
  id: 'wf-2',
  name: 'Standard offboarding',
  description: 'Disables accounts on departure',
  event_type: 'offboard',
  enabled: false,
  steps: [],
  created_at: '2026-02-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('LifecycleWorkflowsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [onboardWorkflow, offboardWorkflow] as unknown as Awaited<ReturnType<typeof api.getWithHeaders>>['data'],
      headers: { 'x-total-count': '2' },
    })
    vi.mocked(api.get).mockResolvedValue([])
  })

  it('renders the heading + subtitle + Create Workflow button', async () => {
    render(<LifecycleWorkflowsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Lifecycle Workflows'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/joiner\/mover\/leaver workflow automation/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create workflow/i }),
    ).toBeInTheDocument()
  })

  it('shows the five event-type stat cards', async () => {
    render(<LifecycleWorkflowsPage />, { wrapper: createWrapper() })
    await screen.findByText('Lifecycle Workflows')

    // Each event label appears in BOTH the stat card AND the
    // event-filter Select (the page also has a hidden SelectContent that
    // happy-dom renders).
    expect(screen.getAllByText('Onboard').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Transfer').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Offboard').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Leave').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Return').length).toBeGreaterThan(0)
  })

  it('renders the search + event-filter controls', async () => {
    render(<LifecycleWorkflowsPage />, { wrapper: createWrapper() })
    await screen.findByText('Lifecycle Workflows')

    expect(
      screen.getByPlaceholderText(/search workflows/i),
    ).toBeInTheDocument()
    // The event-filter Select trigger renders its placeholder copy.
    expect(screen.getByText('All Events')).toBeInTheDocument()
  })

  it('lists workflow rows with their name', async () => {
    render(<LifecycleWorkflowsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Engineer onboarding')).toBeInTheDocument()
    expect(screen.getByText('Standard offboarding')).toBeInTheDocument()
  })
})
