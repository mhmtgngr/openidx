import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({})),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Mock toast hook
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

// Import after mocks
import { SettingsPage } from '../pages/settings'
import { api } from '../lib/api'

const mockSettings = {
  general: {
    organization_name: 'Acme Corp',
    support_email: 'support@acme.com',
  },
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockSettings)
    vi.mocked(api.post).mockResolvedValue({ success: true })
  })

  it('renders the settings page heading', async () => {
    const wrapper = createWrapper()

    render(<SettingsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
  })

  // SMS delivery is configured once for the whole install. The backend answers
  // an organization's own admin with 403 "platform administrator required",
  // and the tab must say so instead of waiting for settings that never come.
  it('explains why the SMS tab is closed to an organization admin', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      url === '/api/v1/settings/sms'
        ? Promise.reject({ response: { status: 403, data: { error: 'platform administrator required' } } })
        : Promise.resolve(mockSettings),
    )
    const wrapper = createWrapper()

    render(<SettingsPage />, { wrapper })

    fireEvent.click(await screen.findByRole('button', { name: /SMS \/ OTP/ }))
    expect(await screen.findByText(/applies to every organization on this installation/i)).toBeInTheDocument()
    expect(screen.queryByText(/Loading SMS settings/i)).toBeNull()
    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled()
  })

  it('has save button', async () => {
    const wrapper = createWrapper()

    render(<SettingsPage />, { wrapper })

    await waitFor(() => {
      const saveButton = screen.queryByRole('button', { name: /save/i })
      expect(saveButton).toBeInTheDocument()
    })
  })
})
