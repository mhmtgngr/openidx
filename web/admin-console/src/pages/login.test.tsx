import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LoginPage } from './login'

// Mock the auth library - use the same path as the component
vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    login: vi.fn(),
    isAuthenticated: false,
    isLoading: false,
  }),
}))

// Mock the API library - use factory to avoid hoisting issues
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getIdentityProviders: vi.fn(() => Promise.resolve([])),
  },
  baseURL: 'http://localhost:8001',
  IdentityProvider: {},
  getOAuthURL: vi.fn(() => 'http://localhost:8001'),
}))

// Mock WebAuthn functions - use the same path as the component
vi.mock('../lib/webauthn', () => ({
  decodeCredentialRequestOptions: vi.fn((x) => x),
  serializeAssertionResponse: vi.fn(() => '{}'),
}))

// Mock QRCode component
vi.mock('qrcode.react', () => ({
  QRCodeSVG: () => <div data-testid="qrcode">QR Code</div>,
}))

// Mock social provider icons - use the same path as the component
vi.mock('../components/icons/social-providers', () => ({
  getProviderIcon: () => null,
}))

// Mock window.location
const mockLocation = {
  hostname: 'localhost',
  search: '',
  href: 'http://localhost:5173/login',
}

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
})

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // Reset location search
    window.location.search = ''
  })

  const renderWithRouter = (component: React.ReactNode) => {
    return render(<MemoryRouter>{component}</MemoryRouter>)
  }

  it('renders the login card', () => {
    renderWithRouter(<LoginPage />)
    // Use getAllByText since OpenIDX appears multiple times
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
    expect(screen.getByText('Identity & Access Management Platform')).toBeInTheDocument()
  })

  it('renders footer links', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText('Privacy')).toBeInTheDocument()
    expect(screen.getByText('Terms')).toBeInTheDocument()
    expect(screen.getByText('Help')).toBeInTheDocument()
  })

  it('renders powered by footer', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText(/powered by/i)).toBeInTheDocument()
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
  })

  it('renders the shield icon container in the card header', () => {
    renderWithRouter(<LoginPage />)
    // The shield icon should be present (class from lucide)
    const cardHeader = document.querySelector('.bg-gradient-to-br')
    expect(cardHeader).toBeInTheDocument()
  })

  it('displays sign-in text', () => {
    renderWithRouter(<LoginPage />)
    expect(screen.getByText(/Sign in to access your OpenIDX admin console/i)).toBeInTheDocument()
  })
})
