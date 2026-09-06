import { describe, it, expect, afterEach } from 'vitest'
import i18n, { ensureLanguage, setLanguage, supportedLanguages } from '../i18n'
import { navigation, filterNavigation, flattenNavItems, scoreNavItem } from './navigation'

// The typeof-en typing keeps en/tr catalogs in lockstep with each other; this
// test pins the third edge — that every key the navigation config references
// actually exists in every catalog. A typo'd nameKey would otherwise render
// as the raw key string.

afterEach(async () => {
  await setLanguage('en')
})

function resolve(lng: string, key: string): unknown {
  return i18n.getResource(lng, 'translation', key)
}

describe('navigation i18n', () => {
  const allKeys: string[] = ['nav.domains.home', 'palette.ariaLabel', 'palette.placeholder', 'breadcrumb.ariaLabel']
  for (const group of navigation) {
    if (group.labelKey) allKeys.push(group.labelKey)
    for (const section of group.sections) {
      if (section.labelKey) allKeys.push(section.labelKey)
      for (const item of section.items) allKeys.push(item.nameKey)
    }
  }

  it('every referenced key resolves to a non-empty string in every language', async () => {
    for (const lang of supportedLanguages) {
      // Only English ships with the entry chunk; the rest arrive on demand.
      await ensureLanguage(lang.code)
      for (const key of allKeys) {
        const value = resolve(lang.code, key)
        expect(value, `${lang.code}: ${key}`).toBeTypeOf('string')
        expect((value as string).length, `${lang.code}: ${key} is empty`).toBeGreaterThan(0)
      }
    }
  })

  it('labels with text carry a key; empty labels carry none', () => {
    for (const group of navigation) {
      expect(!!group.labelKey, `group ${group.id}`).toBe(group.label !== '')
      for (const section of group.sections) {
        expect(!!section.labelKey, `section "${section.label}" in ${group.id}`).toBe(section.label !== '')
      }
    }
  })

  it('sidebar search matches Turkish names too', async () => {
    await setLanguage('tr')
    const groups = filterNavigation({
      roles: ['super_admin'],
      viewMode: 'admin',
      query: 'kullanıcılar',
    })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toContain('/users')
  })

  it('command-palette scoring matches Turkish names too', async () => {
    await setLanguage('tr')
    const users = flattenNavItems().find((i) => i.href === '/users')!
    expect(scoreNavItem(users, 'kullanıcılar')).toBeGreaterThan(0)
    // English stays a synonym in the Turkish UI.
    expect(scoreNavItem(users, 'users')).toBeGreaterThan(0)
  })
})
