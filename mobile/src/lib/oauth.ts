/**
 * Pure OAuth token operations against the OpenIDX OAuth service.
 *
 * Uses `fetch` (not the axios client) so the axios 401-refresh interceptor can
 * call `refreshTokens` without recursing through itself. PKCE authorize is
 * driven by expo-auth-session in auth.tsx; token exchange/refresh/logout live
 * here so both the auth provider and the api interceptor can share them.
 */
import { OAUTH_BASE_URL, OAUTH_CLIENT_ID, OAUTH_REDIRECT_URI } from '@/config';
import type { Tokens } from '@/lib/secureStore';

type TokenResponse = {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  id_token?: string;
};

function toTokens(r: TokenResponse): Tokens {
  return {
    accessToken: r.access_token,
    refreshToken: r.refresh_token,
    expiresAt: Math.floor(Date.now() / 1000) + (r.expires_in ?? 3600),
  };
}

async function tokenRequest(body: Record<string, string>): Promise<Tokens> {
  const res = await fetch(`${OAUTH_BASE_URL}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`token endpoint ${res.status}: ${text}`);
  }
  return toTokens((await res.json()) as TokenResponse);
}

/**
 * Exchange an authorization code (PKCE) for tokens. `redirectUri` must be the
 * exact value used in the authorize request; defaults to the app's scheme URI.
 */
export function exchangeCode(
  code: string,
  codeVerifier: string,
  redirectUri: string = OAUTH_REDIRECT_URI,
): Promise<Tokens> {
  return tokenRequest({
    grant_type: 'authorization_code',
    client_id: OAUTH_CLIENT_ID,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
}

/** Refresh the access token using a refresh token (public client, no secret). */
export function refreshTokens(refreshToken: string): Promise<Tokens> {
  return tokenRequest({
    grant_type: 'refresh_token',
    client_id: OAUTH_CLIENT_ID,
    refresh_token: refreshToken,
  });
}

/** Server-side session + refresh-token revocation. Best-effort. */
export async function revokeSession(accessToken: string): Promise<void> {
  try {
    await fetch(`${OAUTH_BASE_URL}/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ${accessToken}`,
      },
      body: new URLSearchParams({ id_token_hint: accessToken }).toString(),
    });
  } catch {
    // ignore — local tokens are cleared regardless
  }
}
