/**
 * The claims of a JWT, read without verifying it. The console only decides
 * what to show from them; every API verifies the token itself. Null when the
 * token is not a JWT.
 *
 * Its own module because lib/auth.tsx and the request interceptor in
 * lib/api.ts both read the token, and auth.tsx already imports api.ts.
 */
export function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return null
  }
}
