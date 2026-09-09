import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { PamSessionWindow } from './pam-session-window'

describe('PamSessionWindow', () => {
  // Drive what the polled iframe reports as its hash (same technique as the
  // GuacSessionViewer test) so we control the "navigation" without a real frame.
  let currentHash = '#/client/abc'

  beforeEach(() => {
    vi.useFakeTimers()
    currentHash = '#/client/abc'
    localStorage.clear()
    Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
      configurable: true,
      get() {
        return { location: { get hash() { return currentHash } } }
      },
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    delete (HTMLIFrameElement.prototype as unknown as Record<string, unknown>).contentWindow
    localStorage.clear()
  })

  function renderAt(search: string) {
    return render(
      <MemoryRouter initialEntries={[`/pam-session${search}`]}>
        <PamSessionWindow />
      </MemoryRouter>,
    )
  }

  it('frames the guac url from a valid single-use handoff, then consumes it', () => {
    localStorage.setItem('pam-session:k1', JSON.stringify({ url: 'https://guac/x', title: 'DC01' }))
    renderAt('?k=k1')

    // Handoff is consumed (removed) immediately on mount — single use.
    expect(localStorage.getItem('pam-session:k1')).toBeNull()

    act(() => { vi.advanceTimersByTime(1100) })
    const iframe = document.querySelector('iframe') as HTMLIFrameElement
    expect(iframe).toBeInTheDocument()
    expect(iframe.getAttribute('src')).toBe('https://guac/x')
    expect(screen.queryByText('Session ended')).not.toBeInTheDocument()
  })

  it('shows the OpenIDX "Session ended" overlay (not guac chrome) when the session leaves the client route', () => {
    localStorage.setItem('pam-session:k2', JSON.stringify({ url: 'https://guac/x', title: 'DC01' }))
    renderAt('?k=k2')

    // Reach an active client session first.
    act(() => { vi.advanceTimersByTime(1100) })
    expect(document.querySelector('iframe')).toBeInTheDocument()

    // Guac navigates back to its home/manager → the monitor takes over.
    currentHash = '#/'
    act(() => { vi.advanceTimersByTime(1100) })

    expect(screen.getByText('Session ended')).toBeInTheDocument()
    // The guac frame is unmounted — the user can never see guac's chrome.
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })

  it('shows the expired card when the handoff is missing / already consumed', () => {
    renderAt('?k=missing')
    expect(screen.getByText(/this session link has expired/i)).toBeInTheDocument()
    // No frame is ever mounted without a handoff.
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })

  // A launch that never reaches a client route inside the 20s grace window is
  // 'failed'. Which body that card shows is the whole point of the overlay
  // flag: on an overlay launch the broker has no address off the overlay, so a
  // machine without a running client cannot reach it — and the generic card's
  // two guesses ("may be temporary", "may not have access") are both wrong
  // while its Try again would fail identically forever.
  function failASession(key: string, handoff: Record<string, unknown>) {
    localStorage.setItem('pam-session:' + key, JSON.stringify(handoff))
    currentHash = '#/' // never a client route
    renderAt('?k=' + key)
    act(() => { vi.advanceTimersByTime(21_000) })
  }

  it('names the client as the cause when an OVERLAY session never connects', () => {
    failASession('k3', { url: 'https://ziti-guac/x', title: 'DC01', overlay: true })

    expect(screen.getByText(/couldn't connect to DC01/i)).toBeInTheDocument()
    expect(screen.getByText(/only from a device running the OpenIDX client/i)).toBeInTheDocument()
    // The generic guesses must not be what this user reads.
    expect(screen.queryByText(/may be temporary/i)).not.toBeInTheDocument()
    // The action that actually fixes it is offered, alongside a retry.
    expect(screen.getByRole('button', { name: /set up the client/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
  })

  it('keeps the generic body for a DIRECT session, where the client is not the cause', () => {
    failASession('k4', { url: 'https://guac/x', title: 'DC01', overlay: false })

    expect(screen.getByText(/may be temporary/i)).toBeInTheDocument()
    expect(screen.queryByText(/OpenIDX client/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /set up the client/i })).not.toBeInTheDocument()
  })

  it('treats a handoff with no overlay field as not-overlay', () => {
    // An opener that predates the field — the message this window always
    // showed is the one it keeps. Guessing "overlay" here would tell a user
    // on a direct session to go install a client they do not need.
    failASession('k5', { url: 'https://guac/x', title: 'DC01' })

    expect(screen.getByText(/may be temporary/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /set up the client/i })).not.toBeInTheDocument()
  })

  it('does not blame the client when an overlay session ENDED rather than failed', () => {
    // Reaching a client route and then leaving it is a session that worked.
    localStorage.setItem(
      'pam-session:k6',
      JSON.stringify({ url: 'https://ziti-guac/x', title: 'DC01', overlay: true }),
    )
    renderAt('?k=k6')
    act(() => { vi.advanceTimersByTime(1100) }) // reaches '#/client/abc' → active
    currentHash = '#/'
    act(() => { vi.advanceTimersByTime(1100) }) // → ended

    expect(screen.getByText('Session ended')).toBeInTheDocument()
    expect(screen.queryByText(/OpenIDX client/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /set up the client/i })).not.toBeInTheDocument()
  })
})
