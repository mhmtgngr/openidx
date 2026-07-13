/**
 * Passkey (WebAuthn) support.
 *
 * ENROLLMENT is fully native: an authenticated user registers a platform
 * passkey via the bearer-authenticated /mfa/webauthn/register/{begin,finish}
 * endpoints and react-native-passkeys `create()` (Face ID / fingerprint /
 * Credential Manager). Requires associated-domains (iOS) / assetlinks.json
 * (Android) for the WebAuthn RP ID so the OS binds the passkey to the domain.
 *
 * LOGIN is fully native and usernameless: /oauth/native/login-init mints a
 * login_session from our PKCE params, then passkey-begin/finish run against it
 * and passkey-finish returns the auth code (in redirect_url) which we exchange
 * with the PKCE verifier. Falls back to the browser PKCE flow (auth.tsx) when
 * passkeys aren't available on the device.
 */
import { create, get, isSupported } from 'react-native-passkeys';

import {
  OAUTH_BASE_URL,
  OAUTH_CLIENT_ID,
  OAUTH_REDIRECT_URI,
  OAUTH_SCOPES,
} from '@/config';
import { api } from '@/lib/api';
import { exchangeCode } from '@/lib/oauth';
import { createPkce } from '@/lib/pkce';
import type { Tokens } from '@/lib/secureStore';

const REGISTER_BEGIN = '/api/v1/identity/mfa/webauthn/register/begin';
const REGISTER_FINISH = '/api/v1/identity/mfa/webauthn/register/finish';
const CREDENTIALS = '/api/v1/identity/mfa/webauthn/credentials';

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${OAUTH_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} ${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}

export type PasskeyCredential = {
  id: string;
  transports?: string[];
  created_at?: string;
};

export function passkeysSupported(): boolean {
  return isSupported();
}

/**
 * Register a new platform passkey for the signed-in user.
 * Server `register/begin` returns WebAuthn creation options ({ publicKey });
 * we hand `publicKey` to the OS, then post the attestation to `register/finish`.
 */
export async function enrollPasskey(): Promise<void> {
  const options = await api.post<{ publicKey: Record<string, unknown> }>(
    REGISTER_BEGIN,
  );
  const credential = await create(
    options.publicKey as Parameters<typeof create>[0],
  );
  if (!credential) throw new Error('passkey creation cancelled');
  await api.post(REGISTER_FINISH, credential);
}

/**
 * Fully-native usernameless passkey login. Returns tokens for the auth provider
 * to persist. Throws if the OS has no discoverable credential or the user cancels.
 */
export async function passkeyLogin(): Promise<Tokens> {
  const { verifier, challenge } = await createPkce();

  // 1. Mint a login_session bound to our PKCE params.
  const { login_session } = await postJson<{ login_session: string }>(
    '/native/login-init',
    {
      client_id: OAUTH_CLIENT_ID,
      redirect_uri: OAUTH_REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      scope: OAUTH_SCOPES.join(' '),
    },
  );

  // 2. Begin discoverable WebAuthn; 3. satisfy it with the platform authenticator.
  const options = await postJson<{ publicKey: Record<string, unknown> }>(
    '/passkey-begin',
    { login_session },
  );
  const assertion = await get(options.publicKey as Parameters<typeof get>[0]);
  if (!assertion) throw new Error('passkey sign-in cancelled');

  // 4. Finish → { redirect_url: openidx://oauth-callback?code=…&state=… }.
  const { redirect_url } = await postJson<{ redirect_url: string }>(
    '/passkey-finish',
    { login_session, credential: assertion },
  );
  // RN's URL.searchParams is unreliable — parse the code param directly.
  const code = /[?&]code=([^&]+)/.exec(redirect_url)?.[1];
  if (!code) throw new Error('no authorization code returned');

  // 5. Exchange the code with our PKCE verifier.
  return exchangeCode(code, verifier, OAUTH_REDIRECT_URI);
}

export function listPasskeys(): Promise<PasskeyCredential[]> {
  return api.get<PasskeyCredential[]>(CREDENTIALS);
}

export function deletePasskey(id: string): Promise<void> {
  return api.delete<void>(`${CREDENTIALS}/${encodeURIComponent(id)}`);
}
