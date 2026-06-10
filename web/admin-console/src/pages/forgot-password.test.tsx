import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  baseURL: 'http://test',
}))

import { ForgotPasswordPage } from './forgot-password'

const originalFetch = globalThis.fetch

function setFetchMock(impl: (...args: unknown[]) => Promise<unknown>) {
  ;(globalThis as unknown as { fetch: typeof impl }).fetch = impl
}

describe('ForgotPasswordPage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  afterEach(() => {
    ;(globalThis as unknown as { fetch: typeof originalFetch }).fetch = originalFetch
  })

  it('renders the OpenIDX header + email input + Send Reset Link button', () => {
    render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    )

    // "OpenIDX" appears in both the brand CardTitle and the footer
    // "Powered by OpenIDX" line — allow multiple.
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
    expect(screen.getByText('Reset your password')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/enter your email address/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /send reset link/i }),
    ).toBeInTheDocument()
  })

  it('renders the Back-to-login link', () => {
    render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('button', { name: /back to login/i }),
    ).toBeInTheDocument()
  })

  it('shows the success message after a successful submit', async () => {
    setFetchMock(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as unknown as Response),
    )

    const user = userEvent.setup()
    render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByPlaceholderText(/enter your email address/i),
      'alice@example.com',
    )
    await user.click(screen.getByRole('button', { name: /send reset link/i }))

    expect(
      await screen.findByText(/if an account with that email exists/i),
    ).toBeInTheDocument()
  })

  it('shows the error message when the API responds with an error', async () => {
    setFetchMock(() =>
      Promise.resolve({
        ok: false,
        json: () => Promise.resolve({ error: 'Rate limit exceeded' }),
      } as unknown as Response),
    )

    const user = userEvent.setup()
    render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    )

    await user.type(
      screen.getByPlaceholderText(/enter your email address/i),
      'alice@example.com',
    )
    await user.click(screen.getByRole('button', { name: /send reset link/i }))

    expect(
      await screen.findByText(/rate limit exceeded/i),
    ).toBeInTheDocument()
  })
})
