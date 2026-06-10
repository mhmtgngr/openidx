import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/api', () => ({
  baseURL: 'http://test',
}))

import { MagicLinkVerifyPage } from './magic-link-verify'

describe('MagicLinkVerifyPage', () => {
  // The page redirects via window.location.href on mount; stub `location`
  // so the navigation doesn't blow up jsdom-style hosts.
  const originalLocation = window.location

  beforeEach(() => {
    document.body.innerHTML = ''
  })

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: originalLocation,
    })
  })

  function stubLocation(search: string) {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: {
        search,
        href: '',
      } as unknown as Location,
    })
  }

  it('renders the "Verifying your sign-in link..." copy', () => {
    stubLocation('?token=abc&login_session=xyz')

    render(
      <MemoryRouter>
        <MagicLinkVerifyPage />
      </MemoryRouter>,
    )

    expect(
      screen.getByText(/verifying your sign-in link/i),
    ).toBeInTheDocument()
  })

  it('redirects to the OAuth verify URL when token + login_session are present', () => {
    stubLocation('?token=t-123&login_session=ls-456')

    render(
      <MemoryRouter>
        <MagicLinkVerifyPage />
      </MemoryRouter>,
    )

    expect(window.location.href).toBe(
      'http://test/oauth/magic-link-verify?token=t-123&login_session=ls-456',
    )
  })

  it('redirects to /login with invalid_magic_link when query params are missing', () => {
    stubLocation('')

    render(
      <MemoryRouter>
        <MagicLinkVerifyPage />
      </MemoryRouter>,
    )

    expect(window.location.href).toBe('/login?error=invalid_magic_link')
  })
})
