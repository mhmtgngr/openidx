import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({ methods: {}, enabled_count: 0, mfa_enabled: false })),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Mock toast hook
vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

// Mock QRCode component
vi.mock('qrcode.react', () => ({
  QRCodeSVG: () => <div data-testid="qrcode">QR Code</div>,
}))

// Import after mocks
import { MFASetupWizard } from '../components/mfa-setup-wizard'
import { api } from '../lib/api'

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('MFASetupWizard', () => {
  const mockOnClose = vi.fn()
  const mockOnComplete = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue({
      methods: { totp: false, sms: false, email: false, webauthn: false },
      enabled_count: 0,
      mfa_enabled: false,
    })
    vi.mocked(api.post).mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      qr_code_url: 'otpauth://totp/test',
    })
  })

  it('does not render when closed', () => {
    const wrapper = createWrapper()

    render(<MFASetupWizard open={false} onClose={mockOnClose} onComplete={mockOnComplete} />, { wrapper })

    expect(screen.queryByText('Add Authentication Method')).not.toBeInTheDocument()
  })

  it('renders wizard dialog when open', () => {
    const wrapper = createWrapper()

    render(<MFASetupWizard open={true} onClose={mockOnClose} onComplete={mockOnComplete} />, { wrapper })

    expect(screen.getByText('Add Authentication Method')).toBeInTheDocument()
  })

  it('renders method selection step', () => {
    const wrapper = createWrapper()

    render(<MFASetupWizard open={true} onClose={mockOnClose} onComplete={mockOnComplete} />, { wrapper })

    expect(screen.getByText('Authenticator App')).toBeInTheDocument()
    expect(screen.getByText('SMS')).toBeInTheDocument()
    expect(screen.getByText('Email')).toBeInTheDocument()
    expect(screen.getByText('Passkey')).toBeInTheDocument()
  })

  it('shows description for each MFA method', () => {
    const wrapper = createWrapper()

    render(<MFASetupWizard open={true} onClose={mockOnClose} onComplete={mockOnComplete} />, { wrapper })

    expect(screen.getByText(/Use an app like Google Authenticator/i)).toBeInTheDocument()
    expect(screen.getByText(/Receive verification codes via text message/i)).toBeInTheDocument()
  })
})
