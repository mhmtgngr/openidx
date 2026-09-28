import { parseJwt } from './jwt'

/**
 * The install's default organization: the one the installer seeds, whatever
 * DEFAULT_ORG_ID names (middleware.DefaultOrgID, internal/common/middleware/
 * tenant_resolver.go).
 */
export const DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000010'

/**
 * Whether the signed-in user is a platform admin: super_admin held in the
 * default organization, read from the token's org_id. The same rule as
 * middleware.IsPlatformAdmin (internal/common/middleware/tokenorg.go).
 *
 * The role name alone decides nothing: super_admin can be held in any
 * organization, and only the default organization's makes its holder the
 * install's. Only a platform admin may act in another organization, so only
 * a platform admin gets the organization selector, and only a platform
 * admin's requests carry the selection.
 */
export function isPlatformAdmin(user: { roles?: string[]; orgId?: string } | null | undefined): boolean {
  return !!user && user.orgId === DEFAULT_ORG_ID && (user.roles ?? []).includes('super_admin')
}

/** isPlatformAdmin for a raw access token, as the request interceptor holds it. */
export function tokenIsPlatformAdmin(token: string | null): boolean {
  const claims = token ? parseJwt(token) : null
  if (!claims) return false
  return isPlatformAdmin({
    roles: Array.isArray(claims.roles) ? (claims.roles as string[]) : [],
    orgId: typeof claims.org_id === 'string' ? claims.org_id : '',
  })
}

/**
 * True when the backend refused because the setting applies to every
 * organization on the install and the caller is not a platform administrator
 * (internal/common/middleware/platform_admin.go). An organization's admin can
 * open these pages, so the refusal has to say why rather than surface as a
 * bare 403.
 */
export function isPlatformAdminRequired(error: unknown): boolean {
  const res = (error as { response?: { status?: number; data?: { error?: unknown } } } | null)?.response
  return res?.status === 403 && res.data?.error === 'platform administrator required'
}
