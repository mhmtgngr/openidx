/**
 * Phase 3 — the phone as a managed, posture-reporting OpenIDX device.
 *
 * Because the app is already OAuth-authenticated, it enrolls straight through
 * the existing OAuth agent path (no separate token): POST /agent/enroll/oauth
 * creates the agent, auto-provisions a Ziti identity (returns `ziti_jwt` for the
 * native Ziti module to enroll), and files a device-trust entry. Posture is
 * reported via POST /agent/report. Agent creds live in the keystore.
 */
import * as Device from 'expo-device';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

import { api } from '@/lib/api';
import type { PostureResult } from '@/features/ziti/posture';

const BASE = '/api/v1/access';
const AGENT_ID = 'oidx.agent_id';
const DEVICE_ID = 'oidx.agent_device_id';
const AUTH_TOKEN = 'oidx.agent_auth_token';
const ZITI_JWT = 'oidx.ziti_jwt';

export type EnrollResult = {
  agent_id: string;
  device_id: string;
  auth_token: string;
  status: string;
  ziti_jwt?: string;
};

export type AgentIdentity = { agentId: string; deviceId: string } | null;

export async function getAgentIdentity(): Promise<AgentIdentity> {
  const agentId = await SecureStore.getItemAsync(AGENT_ID);
  const deviceId = await SecureStore.getItemAsync(DEVICE_ID);
  return agentId && deviceId ? { agentId, deviceId } : null;
}

/** Enroll this device (OAuth path — uses the signed-in session). Idempotent-ish:
 *  the backend reconciles by physical device fingerprint. */
export async function enrollDevice(): Promise<EnrollResult> {
  const res = await api.post<EnrollResult>(`${BASE}/agent/enroll/oauth`, {
    hostname: Device.deviceName ?? `${Platform.OS}-device`,
    os: Platform.OS,
    arch: Device.modelName ?? 'unknown',
    platform: 'mobile',
    form_factor: Device.deviceType === Device.DeviceType.TABLET ? 'tablet' : 'phone',
    management_mode: 'byod',
  });
  await SecureStore.setItemAsync(AGENT_ID, res.agent_id);
  await SecureStore.setItemAsync(DEVICE_ID, res.device_id);
  if (res.auth_token) await SecureStore.setItemAsync(AUTH_TOKEN, res.auth_token);
  if (res.ziti_jwt) await SecureStore.setItemAsync(ZITI_JWT, res.ziti_jwt);
  return res;
}

/** The Ziti enrollment JWT (for the native Ziti module to enroll an identity). */
export function getZitiJwt(): Promise<string | null> {
  return SecureStore.getItemAsync(ZITI_JWT);
}

/** Report a device-posture snapshot. No-op (returns false) if not enrolled. */
export async function reportPosture(results: PostureResult[]): Promise<boolean> {
  const id = await getAgentIdentity();
  if (!id) return false;
  await api.post(
    `${BASE}/agent/report`,
    { agent_id: id.agentId, device_id: id.deviceId, results },
    { headers: { 'X-Agent-ID': id.agentId } },
  );
  return true;
}
