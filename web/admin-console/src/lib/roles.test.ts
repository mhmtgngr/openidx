import { describe, it, expect } from 'vitest'
import { roleLevel, hasMinRole, ROLE_LEVELS } from './roles'

describe('roleLevel', () => {
  it('mirrors the backend hierarchy (internal/auth/roles.go)', () => {
    expect(roleLevel(['super_admin'])).toBe(4)
    expect(roleLevel(['admin'])).toBe(3)
    expect(roleLevel(['operator'])).toBe(2)
    expect(roleLevel(['auditor'])).toBe(1)
    expect(roleLevel(['user'])).toBe(0)
  })

  it('returns the highest level when a user has multiple roles', () => {
    expect(roleLevel(['user', 'auditor', 'admin'])).toBe(ROLE_LEVELS.admin)
  })

  it('treats empty, undefined, and unknown roles as base user', () => {
    expect(roleLevel([])).toBe(0)
    expect(roleLevel(undefined)).toBe(0)
    expect(roleLevel(['something-custom'])).toBe(0)
  })

  it('only counts compliance_reader inside the audit domain', () => {
    expect(roleLevel(['compliance_reader'])).toBe(0)
    expect(roleLevel(['compliance_reader'], true)).toBe(ROLE_LEVELS.auditor)
  })
})

describe('hasMinRole', () => {
  it('grants access hierarchically', () => {
    expect(hasMinRole(['super_admin'], 'admin')).toBe(true)
    expect(hasMinRole(['admin'], 'operator')).toBe(true)
    expect(hasMinRole(['operator'], 'auditor')).toBe(true)
    expect(hasMinRole(['auditor'], 'operator')).toBe(false)
    expect(hasMinRole(['user'], 'auditor')).toBe(false)
  })

  it('lets a pure super_admin token satisfy admin checks', () => {
    // Regression: the old sidebar literal-matched hasRole('admin'), hiding all
    // admin menus from tokens that only carried super_admin.
    expect(hasMinRole(['super_admin'], 'admin')).toBe(true)
  })

  it('scopes compliance_reader to audit-domain checks', () => {
    expect(hasMinRole(['compliance_reader'], 'auditor', true)).toBe(true)
    expect(hasMinRole(['compliance_reader'], 'auditor', false)).toBe(false)
  })
})
