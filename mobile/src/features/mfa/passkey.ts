/**
 * Passkey (WebAuthn) support.
 *
 * ENROLLMENT is fully native: an authenticated user registers a platform
 * passkey via the bearer-authenticated /mfa/webauthn/register/{begin,finish}
 * endpoints and react-native-passkeys `create()` (Face ID / fingerprint /
 * Credential Manager). Requires associated-domains (iOS) / assetlinks.json
 * (Android) for the WebAuthn RP ID so the OS binds the passkey to the domain.
 *
 * LOGIN with a passkey is driven by the browser PKCE flow (see auth.tsx) — the
 * server login page offers WebAuthn, which the system browser satisfies with
 * the platform authenticator. Fully-native usernameless login (react-native
 * `get()`) additionally needs a JSON `login_session`-init endpoint on the OAuth
 * service; tracked as a backend follow-up.
 */
import { create, isSupported } from 'react-native-passkeys';

import { api } from '@/lib/api';

const REGISTER_BEGIN = '/api/v1/identity/mfa/webauthn/register/begin';
const REGISTER_FINISH = '/api/v1/identity/mfa/webauthn/register/finish';
const CREDENTIALS = '/api/v1/identity/mfa/webauthn/credentials';

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

export function listPasskeys(): Promise<PasskeyCredential[]> {
  return api.get<PasskeyCredential[]>(CREDENTIALS);
}

export function deletePasskey(id: string): Promise<void> {
  return api.delete<void>(`${CREDENTIALS}/${encodeURIComponent(id)}`);
}
