import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  baseURL: 'http://test',
}))

import { ResetPasswordPage } from './reset-password'

const originalFetch = globalThis.fetch

function setFetchMock(impl: (...args: unknown[]) => Promise<unknown>) {
  ;(globalThis as unknown as { fetch: typeof impl }).fetch = impl
}

describe('ResetPasswordPage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  afterEach(() => {
    ;(globalThis as unknown as { fetch: typeof originalFetch }).fetch = originalFetch
  })

  it('renders the invalid-token banner when ?token is missing', () => {
    render(
      <MemoryRouter initialEntries={['/reset-password']}>
        <ResetPasswordPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByText(/invalid or missing reset token\./i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /back to login/i }),
    ).toBeInTheDocument()
  })

  it('renders the reset form when ?token=... is present', () => {
    render(
      <MemoryRouter initialEntries={['/reset-password?token=tok-abc']}>
        <ResetPasswordPage />
      </MemoryRouter>,
    )

    // "OpenIDX" appears in both the brand CardTitle and the footer
    // "Powered by OpenIDX" line — allow multiple.
    expect(screen.getAllByText('OpenIDX').length).toBeGreaterThan(0)
    expect(screen.getByText('Set a new password')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/enter new password/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/confirm new password/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /reset password/i }),
    ).toBeInTheDocument()
  })

  it('shows a "Passwords do not match" error when the confirmation differs', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/reset-password?token=tok-abc']}>
        <ResetPasswordPage />
      </MemoryRouter>,
    )

    await user.type(screen.getByPlaceholderText(/enter new password/i), 'abcd1234')
    await user.type(screen.getByPlaceholderText(/confirm new password/i), 'abcd9999')
    await user.click(screen.getByRole('button', { name: /reset password/i }))

    expect(
      await screen.findByText(/passwords do not match/i),
    ).toBeInTheDocument()
  })

  it('shows the success message after a successful reset', async () => {
    setFetchMock(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as unknown as Response),
    )

    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/reset-password?token=tok-abc']}>
        <ResetPasswordPage />
      </MemoryRouter>,
    )

    await user.type(screen.getByPlaceholderText(/enter new password/i), 'newPass12')
    await user.type(screen.getByPlaceholderText(/confirm new password/i), 'newPass12')
    await user.click(screen.getByRole('button', { name: /reset password/i }))

    expect(
      await screen.findByText(/your password has been reset successfully/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /go to login/i }),
    ).toBeInTheDocument()
  })

  it('renders the policy-violations list when the server returns violations', async () => {
    setFetchMock(() =>
      Promise.resolve({
        ok: false,
        json: () => Promise.resolve({
          violations: ['Must contain a number', 'Must contain a symbol'],
        }),
      } as unknown as Response),
    )

    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/reset-password?token=tok-abc']}>
        <ResetPasswordPage />
      </MemoryRouter>,
    )

    await user.type(screen.getByPlaceholderText(/enter new password/i), 'aaaaaaaa')
    await user.type(screen.getByPlaceholderText(/confirm new password/i), 'aaaaaaaa')
    await user.click(screen.getByRole('button', { name: /reset password/i }))

    expect(
      await screen.findByText(/password does not meet the requirements/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/must contain a number/i)).toBeInTheDocument()
    expect(screen.getByText(/must contain a symbol/i)).toBeInTheDocument()
  })
})
