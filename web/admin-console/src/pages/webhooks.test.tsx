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

import { WebhooksPage } from './webhooks'
import { api } from '../lib/api'

const slackWebhook = {
  id: 'wh-1',
  name: 'Slack Alerts',
  url: 'https://hooks.slack.com/services/T00000/B00000/example',
  status: 'active',
  events: ['user.created', 'user.deleted', 'login.failed'],
  created_at: '2026-01-01T00:00:00Z',
}

const pagerDuty = {
  id: 'wh-2',
  name: 'PagerDuty Critical',
  url: 'https://events.pagerduty.com/v2/enqueue',
  status: 'disabled',
  events: ['security.alert'],
  created_at: '2026-02-01T00:00:00Z',
}

function routeGet(url: string) {
  if (url.includes('/deliveries')) return Promise.resolve({ deliveries: [] })
  if (url.includes('/webhooks/subscriptions')) {
    return Promise.resolve({ subscriptions: [slackWebhook, pagerDuty] })
  }
  return Promise.resolve({ subscriptions: [slackWebhook, pagerDuty] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('WebhooksPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Create Webhook button', async () => {
    render(<WebhooksPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Webhooks')).toBeInTheDocument()
    expect(
      screen.getByText(/manage webhook subscriptions and delivery history/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /create webhook/i }),
    ).toBeInTheDocument()
  })

  it('lists each webhook row with name + status badge', async () => {
    render(<WebhooksPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Slack Alerts')).toBeInTheDocument()
    expect(screen.getByText('PagerDuty Critical')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('disabled')).toBeInTheDocument()
  })

  it('shows the event-type badges per row (truncated to first 3 + count)', async () => {
    render(<WebhooksPage />, { wrapper: createWrapper() })
    await screen.findByText('Slack Alerts')

    expect(screen.getByText('user.created')).toBeInTheDocument()
    expect(screen.getByText('user.deleted')).toBeInTheDocument()
    expect(screen.getByText('login.failed')).toBeInTheDocument()
    expect(screen.getByText('security.alert')).toBeInTheDocument()
  })

  it('opens the Create Webhook dialog when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<WebhooksPage />, { wrapper: createWrapper() })
    await screen.findByText('Slack Alerts')

    await user.click(screen.getByRole('button', { name: /create webhook/i }))

    expect(
      await screen.findByPlaceholderText(/my webhook/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/https:\/\/example.com\/webhook/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no webhooks are configured', async () => {
    vi.mocked(api.get).mockResolvedValue({ subscriptions: [] })

    render(<WebhooksPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no webhooks configured/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/create a webhook to receive event notifications/i),
    ).toBeInTheDocument()
  })
})
