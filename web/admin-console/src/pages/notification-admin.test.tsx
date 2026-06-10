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

import { NotificationAdminPage } from './notification-admin'
import { api } from '../lib/api'

const routingRule = {
  id: 'rr-1',
  name: 'Security to Slack',
  event_type: 'security_alert',
  // The page reads rule.channels (array) in the row render.
  channels: ['slack'],
  target: '#security-alerts',
  priority: 'high',
  enabled: true,
}

const broadcast = {
  id: 'b-1',
  title: 'Maintenance window',
  body: 'Planned maintenance Saturday 2am-4am UTC',
  status: 'draft',
  created_at: '2026-06-01T00:00:00Z',
}

const stats = {
  total_sent: 5000,
  total_read: 3500,
  by_channel: { in_app: 2500, email: 2000, slack: 500 },
}

function routeGet(url: string) {
  if (url.includes('/notifications/routing-rules')) {
    return Promise.resolve({ data: [routingRule] })
  }
  if (url.includes('/notifications/broadcasts')) {
    return Promise.resolve({ data: [broadcast] })
  }
  if (url.includes('/notifications/stats')) return Promise.resolve(stats)
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

describe('NotificationAdminPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<NotificationAdminPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Notification Administration'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/manage routing rules, broadcasts, and delivery statistics/i),
    ).toBeInTheDocument()
  })

  it('shows the three tab buttons (Routing / Broadcasts / Stats)', async () => {
    render(<NotificationAdminPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Administration')

    expect(
      screen.getByRole('button', { name: /routing rules/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /broadcasts/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /delivery stats/i }),
    ).toBeInTheDocument()
  })

  it('lists routing rules on the default tab', async () => {
    render(<NotificationAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Security to Slack')).toBeInTheDocument()
  })

  it('switches to the Broadcasts tab and shows the broadcast row', async () => {
    const user = userEvent.setup()
    render(<NotificationAdminPage />, { wrapper: createWrapper() })
    await screen.findByText('Security to Slack')

    await user.click(screen.getByRole('button', { name: /^broadcasts$/i }))

    expect(await screen.findByText('Maintenance window')).toBeInTheDocument()
  })
})
