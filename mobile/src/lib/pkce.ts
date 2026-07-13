/**
 * PKCE helper (S256) for the native passkey login flow, which drives the OAuth
 * authorize params itself (via /oauth/native/login-init) rather than through
 * expo-auth-session's browser AuthRequest.
 */
import * as Crypto from 'expo-crypto';

function toBase64Url(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export type Pkce = { verifier: string; challenge: string };

export async function createPkce(): Promise<Pkce> {
  // 32 random bytes → base64url verifier (43 chars, RFC 7636 compliant).
  const bytes = Crypto.getRandomBytes(32);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const verifier = toBase64Url(globalThis.btoa(bin));

  const challengeB64 = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    verifier,
    { encoding: Crypto.CryptoEncoding.BASE64 },
  );
  return { verifier, challenge: toBase64Url(challengeB64) };
}
