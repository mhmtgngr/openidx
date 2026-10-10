import { describe, it, expect } from 'vitest'
import appSource from '../App.tsx?raw'
import { navigation, filterNavigation, allNavHrefs, topLevelNavItems, findNavPath, NAV_TOP_LEVEL_LIMIT } from './navigation'

// Routes declared in App.tsx, e.g. path="users" or path="audit/dashboard".
// Parsing the source keeps this test a pure consistency check — no rendering,
// no lazy-loading — so menu/route drift fails fast with a readable diff.
function appRoutePaths(): Set<string> {
  const paths = new Set<string>()
  for (const match of appSource.matchAll(/<Route\s+[^>]*path="([^"*:]+)"/g)) {
    paths.add('/' + match[1].replace(/^\//, ''))
  }
  return paths
}

describe('navigation config integrity', () => {
  it('every menu item points at a route defined in App.tsx', () => {
    const routes = appRoutePaths()
    const missing = allNavHrefs().filter((href) => !routes.has(href))
    expect(missing).toEqual([])
  })

  it('has no duplicate hrefs', () => {
    // A handful of destinations intentionally appear twice: once as a
    // self-service entry for regular users and once in an admin/operator
    // section, because the page itself is role-aware (e.g. Sessions renders
    // "My Sessions" for a user and full "Session Management" for an operator).
    // Those are allowed; every other duplicate is a config mistake.
    const intentionalDuplicates = new Set(['/sessions'])
    const hrefs = allNavHrefs()
    const dupes = hrefs.filter(
      (href, i) => hrefs.indexOf(href) !== i && !intentionalDuplicates.has(href),
    )
    expect(dupes).toEqual([])
  })

  it('keeps every page reachable that used to be in the menu, plus the audit gaps', () => {
    const hrefs = new Set(allNavHrefs())
    // Branding was consolidated into Tenant Management: the /branding route
    // still exists in App.tsx purely as a redirect (old links resolve), so it
    // is intentionally NOT a nav item anymore.
    expect(hrefs.has('/branding')).toBe(false)
    expect(hrefs.has('/tenant-management')).toBe(true)
    expect(hrefs.has('/audit/dashboard')).toBe(true)
  })

  it('reads as seven groups, what people reach first', () => {
    expect(navigation.map((g) => g.id)).toEqual([
      'home', 'access', 'identity', 'devices', 'security', 'audit', 'settings',
    ])
  })

  it(`shows at most ${NAV_TOP_LEVEL_LIMIT} top-level entries`, () => {
    // Everything else is a child page. The limit is the point of the
    // grouping: a new page goes under a parent unless it is a daily stop.
    expect(topLevelNavItems().length).toBeLessThanOrEqual(NAV_TOP_LEVEL_LIMIT)
  })

  it('nests one level only', () => {
    for (const item of topLevelNavItems()) {
      for (const child of item.children ?? []) expect(child.children, child.href).toBeUndefined()
    }
  })

  it('locates a child page under its parent and group', () => {
    const vault = findNavPath('/vault-secrets')!
    expect(vault.group.id).toBe('access')
    expect(vault.parent?.href).toBe('/pam-dashboard')
    expect(vault.item.href).toBe('/vault-secrets')
    const users = findNavPath('/users')!
    expect(users.group.id).toBe('identity')
    expect(users.parent).toBeUndefined()
    expect(findNavPath('/users/123')).toBeNull()
  })
})

describe('filterNavigation role visibility', () => {
  it('shows a plain user only the personal workspace', () => {
    const groups = filterNavigation({ roles: ['user'], viewMode: 'admin' })
    expect(groups.map((g) => g.id)).toEqual(['home'])
  })

  it('gives auditors (reporters) the audit & reporting domain', () => {
    const groups = filterNavigation({ roles: ['auditor'], viewMode: 'admin' })
    const ids = groups.map((g) => g.id)
    expect(ids).toContain('audit')
    expect(ids).not.toContain('identity')
    expect(ids).not.toContain('access')
    const auditHrefs = allNavHrefs(groups.filter((g) => g.id === 'audit'))
    expect(auditHrefs).toContain('/audit-logs')
    expect(auditHrefs).toContain('/reports')
    // admin-gated audit config stays hidden from auditors
    expect(auditHrefs).not.toContain('/audit-archival')
  })

  it('limits compliance_reader strictly to the audit domain', () => {
    const groups = filterNavigation({ roles: ['compliance_reader'], viewMode: 'admin' })
    expect(groups.map((g) => g.id)).toEqual(['home', 'audit'])
  })

  it('gives operators (management) day-to-day items but no admin config', () => {
    const groups = filterNavigation({ roles: ['operator'], viewMode: 'admin' })
    const hrefs = allNavHrefs(groups)
    expect(hrefs).toContain('/users')
    expect(hrefs).toContain('/devices')
    expect(hrefs).toContain('/guacamole-sessions')
    expect(hrefs).not.toContain('/settings')
    expect(hrefs).not.toContain('/vault-secrets')
    expect(hrefs).not.toContain('/tenant-management')
  })

  it('lifts a child the caller may see out from under a parent they may not', () => {
    // Network Topology (operator) sits under Overlay Network (admin).
    const operator = filterNavigation({ roles: ['operator'], viewMode: 'admin' })
    const access = operator.find((g) => g.id === 'access')!
    const top = access.sections.flatMap((s) => s.items)
    expect(top.map((i) => i.href)).toContain('/network-topology')
    expect(top.map((i) => i.href)).not.toContain('/ziti-network')
    // An admin sees it where it belongs.
    const admin = filterNavigation({ roles: ['admin'], viewMode: 'admin' })
    const overlay = admin.find((g) => g.id === 'access')!.sections[0].items.find((i) => i.href === '/ziti-network')!
    expect(overlay.children?.map((c) => c.href)).toContain('/network-topology')
  })

  it('gives admins everything except super_admin-only entries', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin' })
    const hrefs = allNavHrefs(groups)
    expect(hrefs).toContain('/vault-secrets')
    expect(hrefs).toContain('/ziti-network')
    // Branding was folded into Tenant Management; it is no longer its own item.
    expect(hrefs).not.toContain('/branding')
    // Backend: tenant-management endpoints are gated by RequireAdmin
    // (admin/super_admin), so admins legitimately get this entry.
    expect(hrefs).toContain('/tenant-management')
  })

  it('reserves tenant management for super_admin', () => {
    const groups = filterNavigation({ roles: ['super_admin'], viewMode: 'admin' })
    const hrefs = allNavHrefs(groups)
    expect(hrefs).toContain('/tenant-management')
  })
})

describe('filterNavigation view modes', () => {
  it('management view caps an admin to the operator slice', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'management' })
    const hrefs = allNavHrefs(groups)
    expect(hrefs).toContain('/users')
    expect(hrefs).toContain('/audit-logs')
    expect(hrefs).not.toContain('/settings')
    expect(hrefs).not.toContain('/vault-secrets')
  })

  it('reporting view narrows the console to personal + audit content', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'reporting' })
    expect(groups.map((g) => g.id).sort()).toEqual(['audit', 'home'])
  })
})

describe('filterNavigation search', () => {
  it('matches by name and answers with a flat list of pages', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'vault' })
    expect(allNavHrefs(groups)).toEqual(['/vault-secrets'])
    // The match was a child; the result holds the page itself, not its parent.
    expect(groups[0].sections[0].items[0].children).toBeUndefined()
  })

  it('finds a child by its parent name', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'overlay' })
    expect(allNavHrefs(groups)).toContain('/network-topology')
  })

  it('matches by keyword aliases (pam, ziti, reporter)', () => {
    const pam = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'pam' })
    expect(allNavHrefs(pam)).toContain('/vault-secrets')

    const ziti = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'ziti' })
    expect(allNavHrefs(ziti)).toContain('/ziti-network')

    const reporter = filterNavigation({ roles: ['auditor'], viewMode: 'admin', query: 'reporter' })
    expect(allNavHrefs(reporter)).toContain('/audit-logs')
  })

  it('never surfaces items above the caller role', () => {
    const groups = filterNavigation({ roles: ['user'], viewMode: 'admin', query: 'vault' })
    expect(allNavHrefs(groups)).toEqual([])
  })

  it('returns nothing for gibberish', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'zzzz-no-match' })
    expect(groups).toEqual([])
  })
})
