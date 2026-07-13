/**
 * Minimal, verification-free JWT payload decode. The server validates the
 * signature; the client only reads claims for UI (sub/email/name/roles/…).
 */
export type Claims = {
  sub?: string;
  email?: string;
  name?: string;
  preferred_username?: string;
  exp?: number;
  roles?: string[];
  groups?: string[];
  permissions?: string[];
};

function base64UrlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  // atob is available in the RN Hermes runtime.
  const bin = globalThis.atob(b64);
  try {
    // decode UTF-8 bytes
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return bin;
  }
}

export function decodeClaims(token: string | null | undefined): Claims | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64UrlDecode(parts[1])) as Claims;
  } catch {
    return null;
  }
}
