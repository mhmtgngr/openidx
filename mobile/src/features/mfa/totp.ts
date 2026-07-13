/**
 * TOTP (authenticator-app) enrollment. Backend: internal/identity (mfa/totp/*).
 */
import { api } from '@/lib/api';

const BASE = '/api/v1/identity/mfa/totp';

export type TotpSetup = {
  secret: string;
  qr_code_url?: string;
  provisioning_uri?: string;
};

export type TotpStatus = {
  enrolled: boolean;
  backup_codes_count?: number;
};

/** Begin enrollment — returns the shared secret + otpauth:// provisioning URI. */
export function setupTotp(): Promise<TotpSetup> {
  return api.post<TotpSetup>(`${BASE}/setup`);
}

/** Confirm enrollment with a code from the authenticator app. */
export function enrollTotp(code: string): Promise<unknown> {
  return api.post(`${BASE}/enroll`, { code });
}

export function totpStatus(): Promise<TotpStatus> {
  return api.get<TotpStatus>(`${BASE}/status`);
}

export function disableTotp(): Promise<unknown> {
  return api.delete(`${BASE}`);
}
