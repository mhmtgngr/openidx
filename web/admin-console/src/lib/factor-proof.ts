import type { AxiosError } from 'axios'

// A self-service change to your second factors -- removing one, replacing one,
// adding one to an account that already has one, changing the account's
// address -- carries proof that the account holder is making it: the account's
// password, or, where the change removes or replaces the TOTP credential, a
// current code from it. The server says which it needs by refusing the change
// with 403 and the proofs it accepts (internal/identity/factor_proof.go).

export interface FactorProof {
  current_password?: string
  totp_code?: string
}

export type ProofField = 'current_password' | 'totp_code'

export type ProofRefusalCode =
  | 'reauthentication_required'
  | 'reauthentication_failed'
  | 'reauthentication_locked'
  | 'reauthentication_unavailable'

export interface ProofRefusal {
  code: ProofRefusalCode
  accepts: ProofField[]
}

const refusalCodes: ProofRefusalCode[] = [
  'reauthentication_required',
  'reauthentication_failed',
  'reauthentication_locked',
  'reauthentication_unavailable',
]

// proofRefusal reads the server's refusal out of a failed request, or answers
// null when the failure is something else.
export function proofRefusal(err: unknown): ProofRefusal | null {
  const response = (err as AxiosError<{ error?: string; accepts?: unknown }> | undefined)?.response
  if (response?.status !== 403) return null
  const code = response.data?.error as ProofRefusalCode | undefined
  if (!code || !refusalCodes.includes(code)) return null
  const accepts = Array.isArray(response.data?.accepts)
    ? (response.data.accepts as unknown[]).filter(
        (f): f is ProofField => f === 'current_password' || f === 'totp_code',
      )
    : []
  return { code, accepts }
}

// ProofCancelled is what a change fails with when the user closes the prompt
// instead of giving the proof. It needs no error message of its own.
export class ProofCancelled extends Error {
  constructor() {
    super('The change was cancelled.')
    this.name = 'ProofCancelled'
  }
}

// proofRefusalMessageKey is the catalog key that explains a refusal the user
// cannot answer from the prompt -- a lockout, or an account with no password
// here -- or null when the error is not one.
export function proofRefusalMessageKey(err: unknown): string | null {
  switch (proofRefusal(err)?.code) {
    case 'reauthentication_locked':
      return 'components.factorProof.locked'
    case 'reauthentication_unavailable':
      return 'components.factorProof.unavailable'
    default:
      return null
  }
}
