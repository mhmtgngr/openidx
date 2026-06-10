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

import { NotificationCenterPage } from './notification-center'
import { api } from '../lib/api'

const accessRequestNotif = {
  id: 'n-1',
  type: 'access_request',
  title: 'Access request approved',
  body: 'Your request for the Engineering group was approved.',
  read: false,
  created_at: '2026-06-09T10:00:00Z',
}

const securityNotif = {
  id: 'n-2',
  type: 'security_alert',
  title: 'New login from Berlin',
  body: 'A login was detected from a new location.',
  read: true,
  created_at: '2026-06-08T22:00:00Z',
}

const digestRecords = [
  { digest_type: 'daily', channel: 'email', enabled: true },
  { digest_type: 'weekly', channel: 'email', enabled: false },
]

function routeGet(url: string) {
  if (url.includes('/notifications/history')) {
    return Promise.resolve({ data: [accessRequestNotif, securityNotif] })
  }
  if (url.includes('/notifications/digest')) {
    return Promise.resolve({ data: digestRecords })
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

describe('NotificationCenterPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<NotificationCenterPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Notification Center')).toBeInTheDocument()
    expect(
      screen.getByText(/view and manage your notifications/i),
    ).toBeInTheDocument()
  })

  it('lists notification rows with their title + body', async () => {
    render(<NotificationCenterPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Access request approved'),
    ).toBeInTheDocument()
    expect(screen.getByText('New login from Berlin')).toBeInTheDocument()
    expect(
      screen.getByText(/your request for the engineering group was approved/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/a login was detected from a new location/i),
    ).toBeInTheDocument()
  })

  it('shows the Mark All Read button when there are unread notifications', async () => {
    render(<NotificationCenterPage />, { wrapper: createWrapper() })

    // 1 unread → "(1)" appended to label.
    expect(
      await screen.findByRole('button', { name: /mark all read \(1\)/i }),
    ).toBeInTheDocument()
  })

  it('renders the empty state when there are no notifications', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/notifications/digest')) {
        return Promise.resolve({ data: digestRecords }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
    })

    render(<NotificationCenterPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no notifications$/i),
    ).toBeInTheDocument()
  })
})
