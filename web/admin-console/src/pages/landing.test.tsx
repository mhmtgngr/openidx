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

const renderLanding = () =>
  render(
    <MemoryRouter>
      <LandingPage />
    </MemoryRouter>,
  )

describe('LandingPage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('renders the hero badge and headline', () => {
    renderLanding()

    expect(
      screen.getByText(/open source · self-hosted · apache-2\.0/i),
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

  it('renders the Sign In CTA and the documentation/GitHub links', () => {
    renderLanding()

    // Sign In appears in the nav, the hero, and the CTA card — allow multiple.
    expect(
      screen.getAllByRole('button', { name: /sign in/i }).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getByRole('link', { name: /view documentation/i }),
    ).toHaveAttribute('href', expect.stringContaining('mhmtgngr.github.io/openidx'))
    expect(
      screen.getByRole('link', { name: /view on github/i }),
    ).toHaveAttribute('href', expect.stringContaining('github.com/mhmtgngr/openidx'))
  })

  it('renders the trust copy and the features section title', () => {
    renderLanding()

    expect(screen.getByText(/100% open source/i)).toBeInTheDocument()
    expect(
      screen.getByText(/your data stays on your infrastructure/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/docker compose quick start/i)).toBeInTheDocument()
    expect(screen.getByText(/complete security platform/i)).toBeInTheDocument()
  })

  it('makes no claims a self-hosted OSS project cannot keep', () => {
    const { container } = renderLanding()

    // Pins the truthfulness rewrite: no invented trials, pricing, savings,
    // or adoption numbers — and no dead href="#" links.
    expect(screen.queryByText(/free trial/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/credit card/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/70%/)).not.toBeInTheDocument()
    expect(screen.queryByText(/thousands of organizations/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/pricing/i)).not.toBeInTheDocument()
    expect(container.querySelectorAll('a[href="#"]').length).toBe(0)
  })
})
