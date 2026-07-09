// Frontend mirror of the backend RBAC hierarchy (internal/auth/roles.go).
// Keep the levels in sync with RoleLevel there:
//   super_admin (4) > admin (3) > operator (2) > auditor (1) > user (0)
// compliance_reader is a standalone read-only tier: it grants audit visibility
// only and must NOT unlock anything outside the audit domain.

export type MinRole = 'user' | 'auditor' | 'operator' | 'admin' | 'super_admin'

export const ROLE_LEVELS: Record<MinRole, number> = {
  user: 0,
  auditor: 1,
  operator: 2,
  admin: 3,
  super_admin: 4,
}

const COMPLIANCE_READER = 'compliance_reader'
const COMPLIANCE_READER_LEVEL = ROLE_LEVELS.auditor

/**
 * Highest hierarchy level granted by the user's roles.
 * compliance_reader only counts when `forAuditDomain` is true — it is an
 * audit-trail-only role and must not surface identity/config navigation.
 */
export function roleLevel(roles: string[] | undefined, forAuditDomain = false): number {
  if (!roles || roles.length === 0) return ROLE_LEVELS.user
  let level = ROLE_LEVELS.user
  for (const role of roles) {
    if (role === COMPLIANCE_READER) {
      if (forAuditDomain) level = Math.max(level, COMPLIANCE_READER_LEVEL)
      continue
    }
    const known = ROLE_LEVELS[role as MinRole]
    if (known !== undefined) level = Math.max(level, known)
  }
  return level
}

/** True when the user's roles satisfy the required minimum role. */
export function hasMinRole(
  roles: string[] | undefined,
  min: MinRole,
  forAuditDomain = false
): boolean {
  return roleLevel(roles, forAuditDomain) >= ROLE_LEVELS[min]
}
