/**
 * Push MFA — this device as an approval authenticator (number-matching).
 * Backend: internal/identity/pushmfa.go.
 *
 * MVP delivery is poll-based: real FCM/APNs delivery is a fast-follow, so until
 * then the device registers with a stable per-install id as the token
 * placeholder and challenges are opened by challenge_id (deep link
 * `openidx://approve/<id>` — the shape a future push notification will use).
 * The number-matching status endpoint redacts the code, so the user enters the
 * number shown on the other device; we submit it with the approve/deny verdict.
 */
import * as Crypto from 'expo-crypto';
import * as Device from 'expo-device';
import { Platform } from 'react-native';

import { api } from '@/lib/api';
import * as SecureStore from 'expo-secure-store';

const BASE = '/api/v1/identity/mfa/push';
const INSTALL_ID = 'oidx.install_id';

export type PushDevice = {
  id: string;
  platform: string;
  device_name: string;
  enabled: boolean;
  trusted: boolean;
  created_at: string;
};

export type PushChallengeStatus = {
  id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  expires_at: string;
};

async function installId(): Promise<string> {
  let id = await SecureStore.getItemAsync(INSTALL_ID);
  if (!id) {
    id = Crypto.randomUUID();
    await SecureStore.setItemAsync(INSTALL_ID, id);
  }
  return id;
}

/** Register this device as a push authenticator (idempotent by install id). */
export async function registerDevice(): Promise<PushDevice> {
  return api.post<PushDevice>(`${BASE}/register`, {
    device_token: await installId(), // FCM/APNs token replaces this (fast-follow)
    platform: Platform.OS,
    device_name: Device.deviceName ?? `${Platform.OS} device`,
    device_model: Device.modelName ?? undefined,
    os_version: Device.osVersion ?? undefined,
  });
}

export function listDevices(): Promise<PushDevice[]> {
  return api.get<PushDevice[]>(`${BASE}/devices`);
}

export function deleteDevice(id: string): Promise<void> {
  return api.delete<void>(`${BASE}/devices/${encodeURIComponent(id)}`);
}

export function getChallengeStatus(id: string): Promise<PushChallengeStatus> {
  return api.get<PushChallengeStatus>(
    `${BASE}/challenge/${encodeURIComponent(id)}`,
  );
}

/** Submit the number the user read off the other device, with the verdict. */
export function verifyChallenge(
  challengeId: string,
  challengeCode: string,
  approved: boolean,
): Promise<{ verified: boolean }> {
  return api.post<{ verified: boolean }>(`${BASE}/verify`, {
    challenge_id: challengeId,
    challenge_code: challengeCode,
    approved,
  });
}
