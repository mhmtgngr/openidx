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

  // Keys referenced through runtime maps (frictionKey, KIND_META, STATUS_META)
  // are plain string literals the typeof-en typing cannot check, so pin them
  // here: a typo'd key would otherwise render as the raw key string.
  it('resolves every map-driven page key in every language', () => {
    const mapKeys = [
      'pages.mySecurity.friction.low',
      'pages.mySecurity.friction.normal',
      'pages.mySecurity.friction.strict',
      'pages.myNetwork.kinds.web',
      'pages.myNetwork.kinds.remoteDesktop',
      'pages.myNetwork.kinds.ssh',
      'pages.myNetwork.kinds.database',
      'pages.myNetwork.statuses.ready',
      'pages.myNetwork.statuses.requestAccess',
      'pages.myNetwork.statuses.needsSetup',
      'pages.dashboard.activity.eventFallback',
      'queryError.defaultResource',
      // notification-center: FILTER_TABS labelKeys + the template-literal list titles
      'pages.notifications.tabs.all',
      'pages.notifications.tabs.unread',
      'pages.notifications.tabs.security',
      'pages.notifications.tabs.access',
      'pages.notifications.tabs.system',
      'pages.notifications.listTitles.all',
      'pages.notifications.listTitles.unread',
      'pages.notifications.listTitles.security',
      'pages.notifications.listTitles.access',
      'pages.notifications.listTitles.system',
      // access-requests: DURATION_OPTIONS labelKeys + the per-type picker placeholders
      'pages.accessRequests.durations.permanent',
      'pages.accessRequests.durations.h4',
      'pages.accessRequests.durations.h8',
      'pages.accessRequests.durations.d1',
      'pages.accessRequests.durations.d3',
      'pages.accessRequests.durations.d7',
      'pages.accessRequests.durations.d30',
      'pages.accessRequests.durations.d90',
      'pages.accessRequests.create.pickerPlaceholder.role',
      'pages.accessRequests.create.pickerPlaceholder.group',
      'pages.accessRequests.create.pickerPlaceholder.application',
      // lib/compliance tooltip sentences
      'compliance.neverReported',
    ]
    for (const lang of supportedLanguages) {
      for (const key of mapKeys) {
        const value = i18n.getResource(lang.code, 'translation', key)
        expect(value, `${lang.code}: ${key}`).toBeTypeOf('string')
        expect((value as string).length, `${lang.code}: ${key} is empty`).toBeGreaterThan(0)
      }
    }
  })

  it('pluralizes the dashboard relative times in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.dashboard.time.hourAgo', { count: 1 })).toBe('1 hour ago')
    expect(i18n.t('pages.dashboard.time.hourAgo', { count: 3 })).toBe('3 hours ago')
    expect(i18n.t('pages.dashboard.time.dayAgo', { count: 2 })).toBe('2 days ago')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.dashboard.time.hourAgo', { count: 1 })).toBe('1 saat önce')
    expect(i18n.t('pages.dashboard.time.hourAgo', { count: 3 })).toBe('3 saat önce')
  })

  it('pluralizes the notification-center times and browser expiry in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.notifications.time.minuteAgo', { count: 1 })).toBe('1 minute ago')
    expect(i18n.t('pages.notifications.time.minuteAgo', { count: 5 })).toBe('5 minutes ago')
    expect(i18n.t('pages.trustedBrowsers.active.expiresIn', { count: 1 })).toBe('Expires in 1 day')
    expect(i18n.t('pages.trustedBrowsers.active.expiresIn', { count: 30 })).toBe('Expires in 30 days')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.notifications.time.minuteAgo', { count: 5 })).toBe('5 dakika önce')
    expect(i18n.t('pages.trustedBrowsers.active.expiresIn', { count: 30 })).toBe('30 gün içinde doluyor')
  })

  it('interpolates the page strings that carry values', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.sessions.revoke.description', { username: 'alice', ip: '10.0.0.5' }),
    ).toBe('Revoke the session for alice from 10.0.0.5? The session will be signed out immediately.')
    expect(i18n.t('queryError.loadFailed', { resource: 'sessions' })).toBe(
      'Failed to load sessions. Please try again.',
    )

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.sessions.revoke.description', { username: 'alice', ip: '10.0.0.5' }),
    ).toContain('alice')
    expect(i18n.t('pages.myNetwork.readyCount', { n: 2 })).toBe('2 kullanıma hazır')
  })
})
