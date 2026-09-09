import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { openPamSessionWindow } from './pam-session-handoff'
import type { PamConnectResult } from './api'

function result(extra: Partial<PamConnectResult> = {}): PamConnectResult {
  return { launch_type: 'guacamole', connect_url: 'https://guac/x?token=t', entry_id: 'e1', ...extra }
}

function handoffFor(openArg: string) {
  const key = new URLSearchParams(openArg.split('?')[1]).get('k')!
  return { key, value: JSON.parse(localStorage.getItem('pam-session:' + key)!) }
}

describe('openPamSessionWindow', () => {
  beforeEach(() => {
    localStorage.clear()
    window.open = vi.fn()
  })
  afterEach(() => localStorage.clear())

  const opened = () => (window.open as ReturnType<typeof vi.fn>).mock.calls[0][0] as string

  // The whole point of the wrapper: the connect URL carries a bearer token, so
  // it must never reach the address bar or the browser's history. Both
  // launchers used to make this decision separately and one of them made it
  // the other way.
  it('opens the wrapper, never the token-bearing URL', () => {
    expect(openPamSessionWindow(result(), 'DC01')).toBe(true)
    expect(opened()).toMatch(/^\/pam-session\?k=/)
    expect(opened()).not.toContain('token')
    expect(opened()).not.toContain('guac')
  })

  it('hands the URL and title off through a single-use localStorage entry', () => {
    openPamSessionWindow(result(), 'DC01')
    expect(handoffFor(opened()).value).toMatchObject({
      url: 'https://guac/x?token=t',
      title: 'DC01',
    })
  })

  it('gives each launch its own unguessable key', () => {
    openPamSessionWindow(result(), 'DC01')
    openPamSessionWindow(result(), 'DC02')
    const calls = (window.open as ReturnType<typeof vi.fn>).mock.calls
    const keys = calls.map((c) => new URLSearchParams((c[0] as string).split('?')[1]).get('k'))
    expect(new Set(keys).size).toBe(2)
    expect(keys[0]!.length).toBeGreaterThanOrEqual(32)
  })

  // Which failure card the window shows hangs on this one field.
  it.each([
    ['ziti', true],
    ['direct', false],
    ['', false],
    [undefined, false],
  ])('marks reach_mode=%s as overlay=%s', (reachMode, overlay) => {
    openPamSessionWindow(result(reachMode === undefined ? {} : { reach_mode: reachMode }), 'DC01')
    expect(handoffFor(opened()).value.overlay).toBe(overlay)
  })

  it('falls back to `url` when the result has no connect_url', () => {
    openPamSessionWindow({ launch_type: 'url', url: 'https://site/', entry_id: 'e1' }, 'Portal')
    expect(handoffFor(opened()).value.url).toBe('https://site/')
  })

  it('reports there was nothing to launch rather than opening a blank window', () => {
    expect(openPamSessionWindow({ launch_type: 'guacamole', entry_id: 'e1' }, 'DC01')).toBe(false)
    expect(window.open).not.toHaveBeenCalled()
  })

  // Private mode and a full quota both throw on setItem. Opening the raw URL
  // as a fallback would put the token in history for exactly the users whose
  // browser is configured to keep less of it; the window's "expired" card is
  // the better outcome.
  it('still opens the wrapper — never the raw URL — when storage throws', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError')
    })
    expect(openPamSessionWindow(result(), 'DC01')).toBe(true)
    expect(opened()).toMatch(/^\/pam-session\?k=/)
    expect(opened()).not.toContain('token')
    setItem.mockRestore()
  })
})
