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

// The switchable types come from the deployment now. This file used to assert
// seven labels — Access Requests, Security Alerts, Session Revoked, Review
// Assigned, Group Requests, Password Expiry, MFA Changes — and this product has
// never sent a notification of any of them: the page was hard-coded and the
// test agreed with the page rather than with the product. The mock below is the
// shape GET /notifications/preference-types serves, which
// internal/notifications/catalogue_test.go holds against every sender in the
// tree.
const preferenceTypes = {
  types: [
    {
      type: 'access_granted',
      title: 'Access granted',
      description: 'You were granted an application or a privileged credential.',
      channels: ['in_app', 'push'],
    },
    {
      type: 'device_trust',
      title: 'Device trust',
      description: 'A device is awaiting approval, or your request was decided.',
      channels: ['in_app', 'push'],
    },
    {
      type: 'security',
      title: 'Security reminders',
      description: 'Something about your account needs attention.',
      channels: ['in_app', 'push'],
    },
    {
      type: 'broadcast',
      title: 'Announcements',
      description: 'Messages an administrator sent to everyone.',
      channels: ['in_app', 'push'],
    },
  ],
}

const preferences = {
  preferences: [
    { channel: 'in_app', event_type: 'access_granted', enabled: true },
    { channel: 'push', event_type: 'access_granted', enabled: false },
    { channel: 'in_app', event_type: 'security', enabled: true },
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
    vi.mocked(api.get).mockImplementation((url: string) =>
      Promise.resolve(url.includes('preference-types') ? preferenceTypes : preferences),
    )
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

  it('takes its channel columns from the served catalogue', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Preferences')

    expect(await screen.findByText('In-App')).toBeInTheDocument()
    expect(screen.getByText('Push')).toBeInTheDocument()
    // Email was a column for a channel nothing has ever delivered on.
    expect(screen.queryByText('Email')).not.toBeInTheDocument()
  })

  it('lists one row per served type and nothing the product does not send', async () => {
    render(<NotificationPreferencesPage />, { wrapper: createWrapper() })
    await screen.findByText('Notification Preferences')

    for (const label of ['Access Granted', 'Device Trust', 'Security Reminders', 'Announcements']) {
      expect(await screen.findByText(label)).toBeInTheDocument()
    }
    for (const gone of ['Access Requests', 'Security Alerts', 'Session Revoked', 'MFA Changes']) {
      expect(screen.queryByText(gone)).not.toBeInTheDocument()
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
