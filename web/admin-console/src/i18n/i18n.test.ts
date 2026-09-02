import { describe, it, expect, afterEach } from 'vitest'
import i18n, { supportedLanguages } from './index'

// The singleton is initialized by the test setup file (same module as
// main.tsx). Restore English so other test files see the default language.
afterEach(async () => {
  await i18n.changeLanguage('en')
})

describe('i18n', () => {
  it('initializes with English as the fallback', () => {
    expect(i18n.isInitialized).toBe(true)
    expect(i18n.t('landing.nav.signIn')).toBe('Sign In')
  })

  it('switches to Turkish and back', async () => {
    await i18n.changeLanguage('tr')
    expect(i18n.t('landing.nav.signIn')).toBe('Oturum Aç')
    expect(i18n.t('landing.hero.point1')).toBe('%100 açık kaynak (Apache-2.0)')
    expect(i18n.t('login.form.signIn')).toBe('Oturum Aç')
    expect(i18n.t('chrome.account.logout')).toBe('Oturumu Kapat')

    await i18n.changeLanguage('en')
    expect(i18n.t('landing.nav.signIn')).toBe('Sign In')
  })

  it('interpolates values', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('landing.footer.copyright', { year: 2026 })).toContain('2026')
  })

  it('declares every supported language in the resource bundle', () => {
    for (const lang of supportedLanguages) {
      expect(i18n.hasResourceBundle(lang.code, 'translation')).toBe(true)
    }
  })
})
