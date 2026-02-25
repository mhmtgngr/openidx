// WebAuthn helper functions for base64url encoding/decoding

/**
 * Encode an ArrayBuffer to a base64url string
 */
export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Decode a base64url string to an ArrayBuffer
 */
export function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

/**
 * Convert WebAuthn PublicKeyCredentialRequestOptions from server JSON format
 * (base64url encoded fields) to the format expected by navigator.credentials.get()
 */
export function decodeCredentialRequestOptions(
  options: PublicKeyCredentialRequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64urlToBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type as PublicKeyCredentialType,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
    userVerification: options.userVerification as UserVerificationRequirement | undefined,
  }
}

/**
 * Convert WebAuthn PublicKeyCredentialCreationOptions from server JSON format
 * to the format expected by navigator.credentials.create()
 */
export function decodeCredentialCreationOptions(
  options: PublicKeyCredentialCreationOptionsJSON
): PublicKeyCredentialCreationOptions {
  return {
    rp: options.rp,
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    challenge: base64urlToBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: base64urlToBuffer(cred.id),
      type: cred.type as PublicKeyCredentialType,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
    authenticatorSelection: options.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
    attestation: options.attestation as AttestationConveyancePreference | undefined,
  }
}

/**
 * Serialize a PublicKeyCredential (authentication response) to JSON for sending to server
 */
export function serializeAssertionResponse(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAssertionResponse
  return JSON.stringify({
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
  })
}

/**
 * Serialize a PublicKeyCredential (registration response) to JSON for sending to server
 */
export function serializeAttestationResponse(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAttestationResponse
  return JSON.stringify({
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  })
}

// JSON types for server responses (base64url-encoded fields)
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string
  timeout?: number
  rpId?: string
  allowCredentials?: {
    id: string
    type: string
    transports?: string[]
  }[]
  userVerification?: string
}

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: { name: string; id?: string }
  user: { id: string; name: string; displayName: string }
  challenge: string
  pubKeyCredParams: { type: string; alg: number }[]
  timeout?: number
  excludeCredentials?: {
    id: string
    type: string
    transports?: string[]
  }[]
  authenticatorSelection?: AuthenticatorSelectionCriteria
  attestation?: string
}
