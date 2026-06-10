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

import { OAuthPlaygroundPage } from './oauth-playground'

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('OAuthPlaygroundPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  it('renders the heading + subtitle + Reset Flow button', () => {
    render(<OAuthPlaygroundPage />, { wrapper: createWrapper() })

    expect(screen.getByText('OAuth Playground')).toBeInTheDocument()
    expect(
      screen.getByText(/step through the oauth 2.0 authorization code \+ pkce flow interactively/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /reset flow/i }),
    ).toBeInTheDocument()
  })

  it('renders the Step 1 card "Create Session"', () => {
    render(<OAuthPlaygroundPage />, { wrapper: createWrapper() })

    // "Create Session" appears in both the step-header title and the
    // flow-progress sidebar — getAllByText to disambiguate.
    expect(screen.getAllByText('Create Session').length).toBeGreaterThan(0)
    expect(
      screen.getByText(/generate pkce code_verifier, code_challenge, and state parameters/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /^create session$/i }),
    ).toBeInTheDocument()
  })

  it('renders the Step 2 "Authorize" step header', () => {
    render(<OAuthPlaygroundPage />, { wrapper: createWrapper() })

    expect(
      screen.getByText(/open the authorization url, sign in, and paste back the authorization code/i),
    ).toBeInTheDocument()
  })

  it('exposes the JWT decoder paste box', () => {
    render(<OAuthPlaygroundPage />, { wrapper: createWrapper() })

    expect(
      screen.getByPlaceholderText(/paste a jwt token here/i),
    ).toBeInTheDocument()
  })
})
