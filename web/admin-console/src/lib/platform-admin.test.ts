import { describe, it, expect } from 'vitest'
import { DEFAULT_ORG_ID, isPlatformAdmin, tokenIsPlatformAdmin } from './platform-admin'

// Mirrors middleware.IsPlatformAdmin (internal/common/middleware/tokenorg.go):
// super_admin held in the default organization, and nothing less.
const OTHER_ORG = '11111111-1111-1111-1111-111111111111'

function token(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${b64({ alg: 'RS256', typ: 'at+jwt' })}.${b64(claims)}.sig`
}

describe('isPlatformAdmin', () => {
  it('is super_admin held in the default organization', () => {
    expect(DEFAULT_ORG_ID).toBe('00000000-0000-0000-0000-000000000010')
    expect(isPlatformAdmin({ roles: ['super_admin'], orgId: DEFAULT_ORG_ID })).toBe(true)
    expect(isPlatformAdmin({ roles: ['admin', 'super_admin'], orgId: DEFAULT_ORG_ID })).toBe(true)
  })

  it('is not super_admin held anywhere else, or with no organization', () => {
    expect(isPlatformAdmin({ roles: ['super_admin'], orgId: OTHER_ORG })).toBe(false)
    expect(isPlatformAdmin({ roles: ['super_admin'], orgId: '' })).toBe(false)
    expect(isPlatformAdmin({ roles: ['super_admin'] })).toBe(false)
  })

  it('is not any other role of the default organization', () => {
    expect(isPlatformAdmin({ roles: ['admin'], orgId: DEFAULT_ORG_ID })).toBe(false)
    expect(isPlatformAdmin({ roles: [], orgId: DEFAULT_ORG_ID })).toBe(false)
    expect(isPlatformAdmin(null)).toBe(false)
    expect(isPlatformAdmin(undefined)).toBe(false)
  })
})

describe('tokenIsPlatformAdmin', () => {
  it('reads the roles and org_id the token carries', () => {
    expect(tokenIsPlatformAdmin(token({ roles: ['super_admin'], org_id: DEFAULT_ORG_ID }))).toBe(true)
    expect(tokenIsPlatformAdmin(token({ roles: ['super_admin'], org_id: OTHER_ORG }))).toBe(false)
    expect(tokenIsPlatformAdmin(token({ roles: ['super_admin'] }))).toBe(false)
    expect(tokenIsPlatformAdmin(token({ roles: ['admin'], org_id: DEFAULT_ORG_ID }))).toBe(false)
    expect(tokenIsPlatformAdmin(token({ roles: 'super_admin', org_id: DEFAULT_ORG_ID }))).toBe(false)
  })

  it('is false for no token and for one that is not a JWT', () => {
    expect(tokenIsPlatformAdmin(null)).toBe(false)
    expect(tokenIsPlatformAdmin('')).toBe(false)
    expect(tokenIsPlatformAdmin('not-a-jwt')).toBe(false)
  })
})
