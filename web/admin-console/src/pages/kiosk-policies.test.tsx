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

import { KioskPoliciesPage } from './kiosk-policies'
import { api } from '../lib/api'

const policy = {
  id: 'kp-1',
  name: 'Front Desk Kiosk',
  description: 'Lobby check-in kiosk',
  mode: 'single_app',
  allowed_packages: ['com.example.checkin'],
  lock_task_features: ['HOME', 'NOTIFICATIONS'],
  enabled: true,
  updated_at: '2026-06-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('KioskPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue([policy])
  })

  it('renders the heading + subtitle + New policy button', async () => {
    render(<KioskPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Kiosk policies')).toBeInTheDocument()
    expect(
      screen.getByText(/lockdown configurations distributed to android agents/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /new policy/i }),
    ).toBeInTheDocument()
  })

  it('renders policy rows with their name + description + features count', async () => {
    render(<KioskPoliciesPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Front Desk Kiosk')).toBeInTheDocument()
    expect(screen.getByText('Lobby check-in kiosk')).toBeInTheDocument()
    expect(screen.getByText('2 features')).toBeInTheDocument()
  })

  it('opens the editor when New policy is clicked', async () => {
    const user = userEvent.setup()
    render(<KioskPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Front Desk Kiosk')

    await user.click(screen.getByRole('button', { name: /new policy/i }))

    expect(
      await screen.findByPlaceholderText(/front desk kiosk/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no policies exist', async () => {
    vi.mocked(api.get).mockResolvedValue([])

    render(<KioskPoliciesPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no policies yet\./i),
    ).toBeInTheDocument()
  })
})
