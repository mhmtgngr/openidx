import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
  baseURL: 'http://test',
}))

// LandingPage calls useAuth(); stub the module so we don't need a
// real AuthProvider wrapping the test.
vi.mock('../lib/auth', () => ({
  useAuth: () => ({
    isAuthenticated: false,
    login: vi.fn(),
    logout: vi.fn(),
    user: null,
  }),
}))

import { LandingPage } from './landing'

describe('LandingPage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('renders the marketing hero copy and headline', () => {
    render(
      <MemoryRouter>
        <LandingPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByText(/enterprise-grade security at 70% less cost/i),
    ).toBeInTheDocument()
    // Hero headline + responsive duplicates may render the same line
    // multiple times depending on breakpoint variants.
    expect(
      screen.getAllByText(/zero trust access platform for/i).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getAllByText(/modern enterprises/i).length,
    ).toBeGreaterThan(0)
  })

  it('renders the Start Free Trial + Live Demo CTAs', () => {
    render(
      <MemoryRouter>
        <LandingPage />
      </MemoryRouter>,
    )

    // CTAs appear in BOTH the desktop nav AND the hero — allow multiple.
    expect(
      screen.getAllByRole('button', { name: /start free trial/i }).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getByRole('button', { name: /live demo/i }),
    ).toBeInTheDocument()
  })

  it('renders the trust copy and the features section title', () => {
    render(
      <MemoryRouter>
        <LandingPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByText(/no credit card required/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/14-day free trial/i)).toBeInTheDocument()
    expect(screen.getByText(/setup in minutes/i)).toBeInTheDocument()
    expect(screen.getByText(/complete security platform/i)).toBeInTheDocument()
  })
})
