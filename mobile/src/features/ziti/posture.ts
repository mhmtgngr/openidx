/**
 * Device-posture collection for the agent/report contract. Uses the signals
 * available to an Expo app; jailbreak/root is best-effort (Android only, and
 * experimental). Each result maps to the backend's posture-check shape.
 */
import * as Device from 'expo-device';
import * as LocalAuthentication from 'expo-local-authentication';
import { Platform } from 'react-native';

export type PostureResult = {
  check_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  result: {
    status: 'pass' | 'fail' | 'unknown';
    score: number; // 0..100
    details: Record<string, unknown>;
    message: string;
  };
  ran_at: string;
};

export async function collectPosture(): Promise<PostureResult[]> {
  const now = new Date().toISOString();
  const results: PostureResult[] = [];

  // Screen lock / biometric enrolled — a strong proxy for a locked device.
  const hasHw = await LocalAuthentication.hasHardwareAsync();
  const enrolled = hasHw && (await LocalAuthentication.isEnrolledAsync());
  results.push({
    check_type: 'screen_lock',
    severity: 'high',
    result: {
      status: enrolled ? 'pass' : 'fail',
      score: enrolled ? 100 : 0,
      details: { hardware: hasHw },
      message: enrolled ? 'Device lock/biometric enrolled' : 'No device lock enrolled',
    },
    ran_at: now,
  });

  // Jailbreak / root (best-effort; Android experimental, iOS unknown here).
  let rooted: boolean | null = null;
  try {
    rooted = await Device.isRootedExperimentalAsync();
  } catch {
    rooted = null;
  }
  results.push({
    check_type: 'jailbreak_root',
    severity: 'critical',
    result: {
      status: rooted === null ? 'unknown' : rooted ? 'fail' : 'pass',
      score: rooted ? 0 : 100,
      details: { platform: Platform.OS },
      message:
        rooted === null
          ? 'Root/jailbreak status unknown'
          : rooted
            ? 'Device appears rooted/jailbroken'
            : 'No root/jailbreak detected',
    },
    ran_at: now,
  });

  // OS version (informational — policy can gate on minimums server-side).
  results.push({
    check_type: 'os_version',
    severity: 'info',
    result: {
      status: 'pass',
      score: 100,
      details: {
        os: Platform.OS,
        os_version: Device.osVersion ?? 'unknown',
        model: Device.modelName ?? 'unknown',
        is_physical: Device.isDevice,
      },
      message: `${Platform.OS} ${Device.osVersion ?? '?'}`,
    },
    ran_at: now,
  });

  return results;
}
