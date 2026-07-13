/**
 * Step-up (re-authentication) MFA. Backend: internal/oauth/stepup.go.
 *
 * Guards a high-value operation (e.g. launching a privileged PAM session in
 * Phase 2). Flow: request a challenge → satisfy one available factor → receive
 * a short-lived `step_up_token` to attach to the guarded call.
 */
import { api } from '@/lib/api';

export type StepUpChallenge = {
  challenge_id: string;
  available_methods: string[]; // e.g. ['totp','push','webauthn','sms','email']
  expires_at: string;
  reason?: string;
};

export type StepUpResult = {
  step_up_token: string;
};

export function requestStepUp(reason?: string): Promise<StepUpChallenge> {
  return api.post<StepUpChallenge>('/oauth/stepup-challenge', { reason });
}

/** Verify a factor (`method` + `code`) against a challenge → step_up_token. */
export function verifyStepUp(
  challengeId: string,
  method: string,
  code: string,
): Promise<StepUpResult> {
  return api.post<StepUpResult>('/oauth/stepup-verify', {
    challenge_id: challengeId,
    method,
    code,
  });
}
