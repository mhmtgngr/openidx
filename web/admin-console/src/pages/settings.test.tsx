import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

  it('has save button', async () => {
    const wrapper = createWrapper()

    render(<SettingsPage />, { wrapper })

    await waitFor(() => {
      const saveButton = screen.queryByRole('button', { name: /save/i })
      expect(saveButton).toBeInTheDocument()
    })
  })
})
