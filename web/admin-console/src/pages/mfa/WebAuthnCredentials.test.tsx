import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { WebAuthnCredentialsPage } from './WebAuthnCredentials'

const mockCredentials = [
  {
    id: 'cred1',
    friendly_name: 'YubiKey 5C',
    authenticator: 'FIDO2 Security Key',
    is_passkey: false,
    created_at: '2024-01-01T00:00:00Z',
    last_used_at: '2024-03-01T00:00:00Z',
  },
  {
    id: 'cred2',
    friendly_name: 'MacBook Pro',
    authenticator: 'Passkey',
    is_passkey: true,
    created_at: '2024-02-01T00:00:00Z',
    last_used_at: null,
  },
]

// Mock the WebAuthn credentials hooks
const mockUseWebAuthnCredentials = {
  data: mockCredentials,
  isLoading: false,
  error: null,
  refetch: vi.fn(),
}
const mockUseRegisterWebAuthnCredential = {
  mutateAsync: vi.fn().mockResolvedValue({}),
  isPending: false,
}
const mockUseDeleteWebAuthnCredential = {
  mutateAsync: vi.fn().mockResolvedValue({}),
  isPending: false,
}
const mockUseRenameWebAuthnCredential = {
  mutateAsync: vi.fn().mockResolvedValue({}),
  isPending: false,
}

vi.mock('../../hooks/useWebAuthnCredentials', () => ({
  useWebAuthnCredentials: () => mockUseWebAuthnCredentials,
  useRegisterWebAuthnCredential: () => mockUseRegisterWebAuthnCredential,
  useDeleteWebAuthnCredential: () => mockUseDeleteWebAuthnCredential,
  useRenameWebAuthnCredential: () => mockUseRenameWebAuthnCredential,
}))

// Mock toast hook
vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('WebAuthnCredentialsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    localStorage.setItem('user', JSON.stringify({
      username: 'testuser',
      displayName: 'Test User',
    }))
  })

  it('renders the security keys page heading', () => {
    const wrapper = createWrapper()

    // Mock WebAuthn support
    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    expect(screen.getByText('Security Keys')).toBeInTheDocument()
  })

  it('renders register security key button when passkey is available', () => {
    const wrapper = createWrapper()

    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    expect(screen.getByText('Register Security Key')).toBeInTheDocument()
  })

  it('displays registered security keys', () => {
    const wrapper = createWrapper()

    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    expect(screen.getByText('YubiKey 5C')).toBeInTheDocument()
    expect(screen.getByText('MacBook Pro')).toBeInTheDocument()
  })

  it('shows passkey badge for passkey credentials', () => {
    const wrapper = createWrapper()

    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    // The passkey badge should be in the document
    expect(document.body.textContent).toContain('Passkey')
  })

  it('shows credential count in description', () => {
    const wrapper = createWrapper()

    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    expect(document.body.textContent).toContain('2 security keys registered')
  })

  it('shows about security keys section', () => {
    const wrapper = createWrapper()

    Object.defineProperty(window, 'PublicKeyCredential', {
      value: {},
      writable: true,
    })
    Object.defineProperty(window, 'location', {
      value: { protocol: 'https:', hostname: 'example.com' },
      writable: true,
    })

    render(<WebAuthnCredentialsPage />, { wrapper })

    expect(document.body.textContent).toContain('About Security Keys')
  })
})
