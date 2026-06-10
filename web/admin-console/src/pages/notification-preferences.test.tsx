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

import { NotificationPreferencesPage } from './notification-preferences'
import { api } from '../lib/api'

const preferences = {
  preferences: [
    { channel: 'in_app', event_type: 'access_request', enabled: true },
    { channel: 'email', event_type: 'access_request', enabled: false },
    { channel: 'in_app', event_type: 'security_alert', enabled: true },
    { channel: 'email', event_type: 'security_alert', enabled: true },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('NotificationPreferencesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(preferences)
  })

  it('renders the heading + subtitle + Save Preferences button', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('Notification Preferences'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/choose how you want to be notified/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /save preferences/i }),
    ).toBeInTheDocument()
  })

  it('exposes the In-App + Email channel column headers', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Preferences')

    expect(screen.getByText('In-App')).toBeInTheDocument()
    expect(screen.getByText('Email')).toBeInTheDocument()
  })

  it('lists each notification event-type row', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Preferences')

    for (const label of [
      'Access Requests',
      'Security Alerts',
      'Session Revoked',
      'Review Assigned',
      'Group Requests',
      'Password Expiry',
      'MFA Changes',
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it('Save Preferences button starts disabled (no pending changes)', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Preferences')

    expect(
      screen.getByRole('button', { name: /save preferences/i }),
    ).toBeDisabled()
  })
})
