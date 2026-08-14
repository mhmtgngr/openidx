import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  isTokenExpired,
  parseJwtPayload,
  ensureFreshToken,
  TOKEN_FRESHNESS_MARGIN_SECONDS,
} from './session-token'

/**
 * Regression cover for the Live Audit Stream field report: the page failed with
 * close code 1006, which was read as "the audit service is down". It was not.
 * The server answered 401 "token is expired" and the browser collapsed that
 * into 1006, because the HTTP status of a failed WebSocket handshake is never
 * visible to JavaScript. These tests hold the line that a token is proven fresh
 * BEFORE a socket is opened, since a handshake gets no second attempt.
 */

/** Build a JWT whose exp sits `secondsFromNow` away. Only exp is read. */
function makeToken(secondsFromNow: number): string {
  const payload = { exp: Math.floor(Date.now() / 1000) + secondsFromNow }
  const encode = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, '')
  return `${encode({ alg: 'RS256' })}.${encode(payload)}.sig`
}

function storageOf(values: Record<string, string | undefined>) {
  return {
    getItem: (key: string) => values[key] ?? null,
  }
}

describe('parseJwtPayload', () => {
  it('reads the exp claim from a well-formed token', () => {
    const payload = parseJwtPayload(makeToken(120))
    expect(payload?.exp).toBeGreaterThan(Date.now() / 1000)
  })

  it.each([
    ['empty string', ''],
    ['no payload segment', 'header-only'],
    ['payload that is not base64', 'a.!!!!.c'],
    ['payload that is not JSON', `a.${btoa('plain text')}.c`],
  ])('returns null for %s rather than throwing', (_label, token) => {
    expect(parseJwtPayload(token)).toBeNull()
  })
})

describe('isTokenExpired', () => {
  it('accepts a token with plenty of life left', () => {
    expect(isTokenExpired(makeToken(3600))).toBe(false)
  })

  it('rejects a token that has already expired', () => {
    expect(isTokenExpired(makeToken(-1))).toBe(true)
  })

  it('rejects a token expiring inside the freshness margin', () => {
    // The exact failure the margin exists for: this token passes a naive
    // exp > now check, then dies during the handshake and returns as 1006.
    expect(isTokenExpired(makeToken(TOKEN_FRESHNESS_MARGIN_SECONDS - 5))).toBe(true)
  })

  it('accepts a token expiring just outside the margin', () => {
    expect(isTokenExpired(makeToken(TOKEN_FRESHNESS_MARGIN_SECONDS + 5))).toBe(false)
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty', ''],
  ])('treats a %s token as expired', (_label, token) => {
    expect(isTokenExpired(token)).toBe(true)
  })

  it('treats a token with no exp claim as expired rather than trusting it', () => {
    const encode = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, '')
    const noExp = `${encode({ alg: 'RS256' })}.${encode({ sub: 'u1' })}.sig`
    expect(isTokenExpired(noExp)).toBe(true)
  })

  it('honours a caller-supplied margin', () => {
    const token = makeToken(60)
    expect(isTokenExpired(token, 10)).toBe(false)
    expect(isTokenExpired(token, 120)).toBe(true)
  })
})

describe('ensureFreshToken', () => {
  let refresh: ReturnType<typeof vi.fn>

  beforeEach(() => {
    refresh = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('uses the stored token without refreshing when it is still fresh', async () => {
    const token = makeToken(3600)
    const result = await ensureFreshToken(refresh, storageOf({ token }))

    expect(result).toEqual({ ok: true, token })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('refreshes an expired token and returns the new one', async () => {
    const fresh = makeToken(3600)
    const values: Record<string, string> = {
      token: makeToken(-60),
      refresh_token: 'refresh-abc',
    }
    refresh.mockImplementation(async () => {
      values.token = fresh
      return true
    })

    const result = await ensureFreshToken(refresh, storageOf(values))

    expect(refresh).toHaveBeenCalledWith('refresh-abc')
    expect(result).toEqual({ ok: true, token: fresh })
  })

  it('reports no_session when there is nothing to refresh with', async () => {
    const result = await ensureFreshToken(refresh, storageOf({ token: makeToken(-60) }))

    expect(result).toEqual({ ok: false, reason: 'no_session' })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('reports refresh_failed when the refresh call is rejected', async () => {
    refresh.mockResolvedValue(false)

    const result = await ensureFreshToken(
      refresh,
      storageOf({ token: makeToken(-60), refresh_token: 'refresh-abc' })
    )

    expect(result).toEqual({ ok: false, reason: 'refresh_failed' })
  })

  it('reports refresh_failed when refresh claims success but the token is still stale', async () => {
    // Guards against handing back a dead token on the strength of a boolean,
    // which would open a socket that immediately closes with 1006.
    refresh.mockResolvedValue(true)

    const result = await ensureFreshToken(
      refresh,
      storageOf({ token: makeToken(-60), refresh_token: 'refresh-abc' })
    )

    expect(result).toEqual({ ok: false, reason: 'refresh_failed' })
  })

  it('refreshes when no token is stored at all but a refresh token exists', async () => {
    const fresh = makeToken(3600)
    const values: Record<string, string | undefined> = {
      token: undefined,
      refresh_token: 'refresh-abc',
    }
    refresh.mockImplementation(async () => {
      values.token = fresh
      return true
    })

    const result = await ensureFreshToken(refresh, storageOf(values))

    expect(result).toEqual({ ok: true, token: fresh })
  })
})
