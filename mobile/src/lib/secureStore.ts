/**
 * Token storage backed by the OS keystore (iOS Keychain / Android Keystore) via
 * expo-secure-store. Replaces the web console's localStorage token handling.
 */
import * as SecureStore from 'expo-secure-store';

const ACCESS = 'oidx.access_token';
const REFRESH = 'oidx.refresh_token';
const EXP = 'oidx.token_exp'; // unix seconds
const ORG_SLUG = 'oidx.org_slug';

export type Tokens = {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // unix seconds
};

export async function getAccessToken(): Promise<string | null> {
  return SecureStore.getItemAsync(ACCESS);
}

export async function getRefreshToken(): Promise<string | null> {
  return SecureStore.getItemAsync(REFRESH);
}

export async function getExpiresAt(): Promise<number> {
  const v = await SecureStore.getItemAsync(EXP);
  return v ? Number(v) : 0;
}

export async function setTokens(t: Tokens): Promise<void> {
  await SecureStore.setItemAsync(ACCESS, t.accessToken);
  await SecureStore.setItemAsync(EXP, String(t.expiresAt));
  if (t.refreshToken) {
    await SecureStore.setItemAsync(REFRESH, t.refreshToken);
  }
}

export async function clearTokens(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(ACCESS),
    SecureStore.deleteItemAsync(REFRESH),
    SecureStore.deleteItemAsync(EXP),
  ]);
}

export async function getOrgSlug(): Promise<string | null> {
  return SecureStore.getItemAsync(ORG_SLUG);
}

export async function setOrgSlug(slug: string | null): Promise<void> {
  if (slug) await SecureStore.setItemAsync(ORG_SLUG, slug);
  else await SecureStore.deleteItemAsync(ORG_SLUG);
}
