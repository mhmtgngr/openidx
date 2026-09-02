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
      // bulk-operations: operationTypes labelKey/descKey pairs
      ...[
        'enableUsers',
        'disableUsers',
        'deleteUsers',
        'assignRole',
        'removeRole',
        'addToGroup',
        'removeFromGroup',
        'resetPasswords',
      ].flatMap((k) => [`pages.bulkOps.types.${k}.label`, `pages.bulkOps.types.${k}.desc`]),
      // ops-cockpit: BrokerRow badge label via template-literal key
      'pages.opsCockpit.brokers.health.healthy',
      'pages.opsCockpit.brokers.health.degraded',
      'pages.opsCockpit.brokers.health.down',
      // directories: dialog tab labels + attribute-mapping rows via template-literal keys
      ...['connection', 'search', 'mapping', 'sync'].map((k) => `pages.directories.tabs.${k}`),
      ...['username', 'email', 'first_name', 'last_name', 'display_name', 'group_name'].map(
        (k) => `pages.directories.mapping.${k}`,
      ),
      // identity-providers: PROVIDER_TEMPLATES descriptionKeys
      'pages.identityProviders.templates.google',
      'pages.identityProviders.templates.github',
      'pages.identityProviders.templates.microsoft',
      // saml-service-providers: NAME_ID_FORMATS labelKeys
      ...['email', 'unspecified', 'persistent', 'transient'].map(
        (k) => `pages.samlProviders.formats.${k}`,
      ),
      // provisioning-rules: the trigger/operator/action option lists render
      // their labels through template-literal keys built from the option value.
      ...[
        'user_created',
        'user_updated',
        'user_deleted',
        'group_membership',
        'attribute_change',
        'scheduled',
      ].map((k) => `pages.provisioningRules.triggers.${k}`),
      ...[
        'equals',
        'not_equals',
        'contains',
        'not_contains',
        'starts_with',
        'ends_with',
        'regex',
        'greater_than',
        'less_than',
      ].map((k) => `pages.provisioningRules.operators.${k}`),
      ...[
        'add_to_group',
        'remove_from_group',
        'assign_role',
        'remove_role',
        'set_attribute',
        'send_email',
        'notify_admin',
        'disable_account',
        'enable_account',
      ].map((k) => `pages.provisioningRules.actionTypes.${k}`),
      // governance: review/campaign type, schedule and entitlement-type labels
      // all resolve from runtime maps or template-literal keys.
      ...['user_access', 'role_assignment', 'application_access', 'privileged_access'].flatMap(
        (k) => [`pages.accessReviews.types.${k}`, `pages.certCampaigns.types.${k}`],
      ),
      ...['once', 'quarterly', 'semi_annual', 'annual'].map(
        (k) => `pages.certCampaigns.schedules.${k}`,
      ),
      ...[
        'manager_review',
        'application_access',
        'role_certification',
        'entitlement_review',
      ].map((k) => `pages.attestation.types.${k}`),
      ...['role', 'group', 'application'].map((k) => `pages.entitlements.types.${k}`),
      // review-detail: the batch-decision verb, keyed by the decision value
      ...['approved', 'revoked', 'flagged'].map(
        (k) => `pages.reviewDetail.batch.actions.${k}`,
      ),
      // directories: validateForm messages resolved through the i18n singleton
      ...[
        'nameRequired',
        'typeRequired',
        'hostRequired',
        'portRequired',
        'bindDnRequired',
        'bindPasswordRequired',
        'baseDnRequired',
        'userFilterRequired',
        'usernameMappingRequired',
        'emailMappingRequired',
        'tenantIdRequired',
        'clientIdRequired',
        'clientSecretRequired',
      ].map((k) => `pages.directories.validation.${k}`),
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
