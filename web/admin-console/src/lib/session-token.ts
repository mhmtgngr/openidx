/**
 * Session token freshness, shared by anything that must present a token itself
 * instead of letting the axios layer attach it.
 *
 * This exists because of a field report against the Live Audit Stream: the page
 * failed on load with WS_CONNECTION_ERROR and close code 1006, and 1006 was
 * read as "the audit service is down". It was not. Measured against production
 * on 2026-08-14:
 *
 *   valid token   -> WebSocket opened and stayed open (readyState 1)
 *   expired token -> onerror, then close code 1006
 *   server log    -> 401 "token has invalid claims: token is expired"
 *
 * A browser cannot expose the HTTP status of a failed WebSocket handshake to
 * JavaScript, so every authentication failure surfaces as 1006. The close code
 * is a symptom; the cause is an expired access token.
 *
 * REST calls survived this because axios refreshes on 401 and retries. A
 * WebSocket gets one handshake and no retry, so it needs the token to be valid
 * before it is offered.
 */

/** Decoded JWT payload fields this module relies on. */
interface JwtPayload {
  exp?: number
}

/**
 * Decode a JWT payload. Returns null for anything unreadable; a malformed token
 * is treated as unusable rather than trusted.
 */
export function parseJwtPayload(token: string): JwtPayload | null {
  try {
    const base64Url = token.split('.')[1]
    if (!base64Url) return null
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const json = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(json) as JwtPayload
  } catch {
    return null
  }
}

/**
 * Seconds of headroom required before a token is considered usable for a new
 * connection. A token expiring in two seconds passes a naive exp > now check
 * and then dies mid-handshake, which is the same 1006 with extra steps.
 */
export const TOKEN_FRESHNESS_MARGIN_SECONDS = 30

/**
 * True when the token is missing, unreadable, already expired, or about to
 * expire within the margin. A token with no exp claim cannot be shown to be
 * fresh, so it is treated as stale rather than assumed good.
 */
export function isTokenExpired(
  token: string | null | undefined,
  marginSeconds: number = TOKEN_FRESHNESS_MARGIN_SECONDS
): boolean {
  if (!token) return true
  const payload = parseJwtPayload(token)
  if (!payload || typeof payload.exp !== 'number') return true
  return payload.exp * 1000 - Date.now() <= marginSeconds * 1000
}

/** Outcome of a freshness check, so callers can tell "no token" from "refused". */
export type FreshTokenResult =
  | { ok: true; token: string }
  | { ok: false; reason: 'no_session' | 'refresh_failed' }

/**
 * Return a token that is safe to open a WebSocket with, refreshing first if the
 * current one is stale.
 *
 * The background refresh in AuthProvider runs on a 30-second interval, which
 * browsers throttle heavily in backgrounded tabs. Returning to a tab left open
 * over lunch is exactly the state the field report hit, so freshness is checked
 * at connect time instead of being assumed from the interval.
 */
export async function ensureFreshToken(
  refresh: (refreshToken: string) => Promise<boolean>,
  storage: Pick<Storage, 'getItem'> = localStorage
): Promise<FreshTokenResult> {
  const token = storage.getItem('token')
  if (!isTokenExpired(token)) {
    return { ok: true, token: token as string }
  }

  const refreshToken = storage.getItem('refresh_token')
  if (!refreshToken) {
    return { ok: false, reason: 'no_session' }
  }

  const refreshed = await refresh(refreshToken)
  if (!refreshed) {
    return { ok: false, reason: 'refresh_failed' }
  }

  const fresh = storage.getItem('token')
  if (isTokenExpired(fresh)) {
    // The refresh reported success but the stored token is still stale. Report
    // it rather than opening a connection that is going to close with 1006.
    return { ok: false, reason: 'refresh_failed' }
  }
  return { ok: true, token: fresh as string }
}
