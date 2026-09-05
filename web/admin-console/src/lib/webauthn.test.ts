import { describe, it, expect } from 'vitest'
import {
  base64urlToBuffer,
  bufferToBase64url,
  decodeCredentialCreationOptions,
  decodeCredentialRequestOptions,
  serializeAssertionResponse,
  serializeAttestationResponse,
} from './webauthn'

// The passkey wire format is base64url, and the browser API speaks
// ArrayBuffer. This module is the only place the two meet, on the enrolment
// and the sign-in path, and a single wrong byte reads as "your security key
// did not work" with nothing to look at. It had no test.

const bytes = (...v: number[]) => new Uint8Array(v).buffer
const toArray = (b: ArrayBuffer) => Array.from(new Uint8Array(b))

describe('base64url', () => {
  it('encodes without +, / or padding', () => {
    // 0xFB 0xFF encodes to "+/8=" in standard base64.
    expect(bufferToBase64url(bytes(0xfb, 0xff, 0xbf))).toBe('-_-_')
    expect(bufferToBase64url(bytes(1))).toBe('AQ')
    expect(bufferToBase64url(bytes(1, 2))).toBe('AQI')
    expect(bufferToBase64url(bytes())).toBe('')
  })

  it('round-trips every byte value', () => {
    const all = new Uint8Array(256)
    for (let i = 0; i < 256; i++) all[i] = i
    const encoded = bufferToBase64url(all.buffer)
    expect(encoded).not.toMatch(/[+/=]/)
    expect(toArray(base64urlToBuffer(encoded))).toEqual(Array.from(all))
  })

  it('decodes each unpadded length', () => {
    // A base64url string can be 2, 3 or 4 chars into the final quantum; the
    // padding has to be re-added or atob throws.
    expect(toArray(base64urlToBuffer('AQ'))).toEqual([1])
    expect(toArray(base64urlToBuffer('AQI'))).toEqual([1, 2])
    expect(toArray(base64urlToBuffer('AQID'))).toEqual([1, 2, 3])
    expect(toArray(base64urlToBuffer(''))).toEqual([])
  })

  it('accepts the padded, standard-alphabet form too', () => {
    expect(toArray(base64urlToBuffer('-_-_'))).toEqual([0xfb, 0xff, 0xbf])
    expect(toArray(base64urlToBuffer('+/+/'))).toEqual([0xfb, 0xff, 0xbf])
  })
})

describe('decodeCredentialRequestOptions', () => {
  it('turns the server JSON into what navigator.credentials.get() wants', () => {
    const decoded = decodeCredentialRequestOptions({
      challenge: 'AQID',
      timeout: 60000,
      rpId: 'openidx.example',
      allowCredentials: [{ id: 'BAUG', type: 'public-key', transports: ['usb', 'nfc'] }],
      userVerification: 'required',
    })

    expect(toArray(decoded.challenge as ArrayBuffer)).toEqual([1, 2, 3])
    expect(decoded.timeout).toBe(60000)
    expect(decoded.rpId).toBe('openidx.example')
    expect(decoded.userVerification).toBe('required')
    expect(decoded.allowCredentials).toHaveLength(1)
    expect(toArray(decoded.allowCredentials![0].id as ArrayBuffer)).toEqual([4, 5, 6])
    expect(decoded.allowCredentials![0].transports).toEqual(['usb', 'nfc'])
  })

  it('leaves allowCredentials undefined when the server omits it', () => {
    // Usernameless sign-in sends no allow list; an empty ARRAY is not the same
    // thing to the platform authenticator, so the absence has to survive.
    const decoded = decodeCredentialRequestOptions({ challenge: 'AQID' })
    expect(decoded.allowCredentials).toBeUndefined()
  })
})

describe('decodeCredentialCreationOptions', () => {
  it('decodes the challenge and the user handle, and keeps the rest', () => {
    const decoded = decodeCredentialCreationOptions({
      rp: { name: 'OpenIDX', id: 'openidx.example' },
      user: { id: 'AQID', name: 'admin', displayName: 'Admin' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 30000,
      excludeCredentials: [{ id: 'BwgJ', type: 'public-key' }],
      attestation: 'none',
    })

    expect(toArray(decoded.challenge as ArrayBuffer)).toEqual([4, 5, 6])
    expect(toArray(decoded.user.id as ArrayBuffer)).toEqual([1, 2, 3])
    expect(decoded.user.name).toBe('admin')
    expect(decoded.user.displayName).toBe('Admin')
    expect(decoded.rp).toEqual({ name: 'OpenIDX', id: 'openidx.example' })
    expect(decoded.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }])
    expect(toArray(decoded.excludeCredentials![0].id as ArrayBuffer)).toEqual([7, 8, 9])
    expect(decoded.attestation).toBe('none')
  })
})

describe('serialize', () => {
  it('encodes an assertion, and null userHandle stays null', () => {
    const json = JSON.parse(
      serializeAssertionResponse({
        id: 'cred-1',
        rawId: bytes(1, 2, 3),
        type: 'public-key',
        response: {
          authenticatorData: bytes(4, 5, 6),
          clientDataJSON: bytes(7, 8, 9),
          signature: bytes(10, 11, 12),
          userHandle: null,
        },
      } as unknown as PublicKeyCredential),
    )

    expect(json).toEqual({
      id: 'cred-1',
      rawId: 'AQID',
      type: 'public-key',
      response: {
        authenticatorData: 'BAUG',
        clientDataJSON: 'BwgJ',
        signature: 'CgsM',
        userHandle: null,
      },
    })
  })

  it('encodes a userHandle when the authenticator returns one', () => {
    const json = JSON.parse(
      serializeAssertionResponse({
        id: 'cred-1',
        rawId: bytes(1),
        type: 'public-key',
        response: {
          authenticatorData: bytes(1),
          clientDataJSON: bytes(1),
          signature: bytes(1),
          userHandle: bytes(1, 2, 3),
        },
      } as unknown as PublicKeyCredential),
    )
    expect(json.response.userHandle).toBe('AQID')
  })

  it('encodes an attestation', () => {
    const json = JSON.parse(
      serializeAttestationResponse({
        id: 'cred-2',
        rawId: bytes(1, 2, 3),
        type: 'public-key',
        response: {
          attestationObject: bytes(4, 5, 6),
          clientDataJSON: bytes(7, 8, 9),
        },
      } as unknown as PublicKeyCredential),
    )

    expect(json).toEqual({
      id: 'cred-2',
      rawId: 'AQID',
      type: 'public-key',
      response: { attestationObject: 'BAUG', clientDataJSON: 'BwgJ' },
    })
  })

  it('survives a round trip through the decoder', () => {
    // What the server sends is what the browser gets back, byte for byte.
    const challenge = bufferToBase64url(new Uint8Array([0, 127, 128, 255, 0xfb]).buffer)
    const decoded = decodeCredentialRequestOptions({ challenge })
    expect(bufferToBase64url(decoded.challenge as ArrayBuffer)).toBe(challenge)
  })
})
