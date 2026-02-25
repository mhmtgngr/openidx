// React Query hook for WebAuthn credential management with automatic error handling
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { mfaApi } from '../api/mfa'
import {
  decodeCredentialCreationOptions,
  serializeAttestationResponse,
} from '../lib/webauthn'

// Query keys
export const webAuthnKeys = {
  all: ['webauthn'] as const,
  credentials: () => [...webAuthnKeys.all, 'credentials'] as const,
}

/**
 * Hook to fetch WebAuthn credentials for the authenticated user
 */
export function useWebAuthnCredentials() {
  return useQuery({
    queryKey: webAuthnKeys.credentials(),
    queryFn: mfaApi.listWebAuthnCredentials,
    staleTime: 1000 * 60 * 5, // 5 minutes
    retry: (failureCount, error) => {
      // Don't retry on 403 Forbidden (ownership/permission errors)
      if (error instanceof Error && error.message.includes('permission')) {
        return false
      }
      return failureCount < 2
    },
  })
}

/**
 * Hook to register a new WebAuthn credential
 */
export function useRegisterWebAuthnCredential() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (params: { username: string; displayName: string; friendlyName?: string }) => {
      // Step 1: Begin registration
      const beginResponse = await mfaApi.beginWebAuthnRegistration({
        username: params.username,
        display_name: params.displayName,
        friendly_name: params.friendlyName,
      })

      // Step 2: Create credential via browser API
      const options = decodeCredentialCreationOptions(beginResponse.options.publicKey)
      const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential

      if (!credential) {
        throw new Error('Registration was cancelled')
      }

      // Step 3: Finish registration
      const attestationJSON = serializeAttestationResponse(credential)
      return await mfaApi.finishWebAuthnRegistration({ response: attestationJSON })
    },
    onSuccess: () => {
      // Invalidate credentials query to refresh the list
      queryClient.invalidateQueries({ queryKey: webAuthnKeys.credentials() })
    },
  })
}

/**
 * Hook to delete a WebAuthn credential
 */
export function useDeleteWebAuthnCredential() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (credentialId: string) => {
      await mfaApi.deleteWebAuthnCredential(credentialId)
    },
    onSuccess: () => {
      // Invalidate credentials query to refresh the list
      queryClient.invalidateQueries({ queryKey: webAuthnKeys.credentials() })
    },
  })
}

/**
 * Hook to rename a WebAuthn credential
 */
export function useRenameWebAuthnCredential() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (params: { credentialId: string; friendlyName: string }) => {
      await mfaApi.renameWebAuthnCredential(params.credentialId, {
        friendly_name: params.friendlyName,
      })
    },
    onSuccess: () => {
      // Invalidate credentials query to refresh the list
      queryClient.invalidateQueries({ queryKey: webAuthnKeys.credentials() })
    },
  })
}

/**
 * Hook for WebAuthn authentication (login flow)
 */
export function useWebAuthnAuthentication() {
  return useMutation({
    mutationFn: async (params: {
      userId: string
      onBegin?: (options: PublicKeyCredentialRequestOptions) => void
    }) => {
      // Step 1: Begin authentication
      const beginResponse = await mfaApi.beginWebAuthnLogin({ user_id: params.userId })

      // Step 2: Convert options and call optional callback
      // We need to parse the options first for the browser API
      // The server sends base64url encoded options
      const optionsJson = beginResponse.options.publicKey

      // Decode challenge and credentials from base64url
      const challenge = base64urlToBuffer(optionsJson.challenge)
      const allowCredentials = optionsJson.allowCredentials?.map((cred: any) => ({
        id: base64urlToBuffer(cred.id),
        type: cred.type as PublicKeyCredentialType,
      }))

      const options: PublicKeyCredentialRequestOptions = {
        challenge,
        timeout: optionsJson.timeout,
        rpId: optionsJson.rpId,
        allowCredentials,
        userVerification: optionsJson.userVerification as UserVerificationRequirement | undefined,
      }

      // Call callback if provided (e.g., to show UI)
      params.onBegin?.(options)

      // Step 3: Get credential via browser API
      const credential = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential

      if (!credential) {
        throw new Error('Authentication was cancelled')
      }

      // Step 4: Serialize and finish authentication
      const response = serializeAssertionResponse(credential)
      return await mfaApi.finishWebAuthnLogin({
        user_id: params.userId,
        response,
      })
    },
  })
}

// Helper function for base64url decoding (duplicate from webauthn.ts to avoid circular deps)
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

// Helper function for serializing assertion response
function serializeAssertionResponse(credential: PublicKeyCredential): string {
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

function bufferToBase64url(buffer: ArrayBuffer): string {
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
