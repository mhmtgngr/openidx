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
      // risk-dashboard: bucketLabelKey() picks the distribution label
      ...['critical', 'high', 'medium', 'mediumLow', 'low'].map(
        (k) => `pages.riskDashboard.buckets.${k}`,
      ),
      // login-anomalies: riskScoreBadge() picks the severity word
      ...['critical', 'high', 'medium', 'low'].map((k) => `pages.loginAnomalies.levels.${k}`),
      // auth/login analytics: the period selector maps its value to a common key
      ...['h24', 'd7', 'd30', 'd90'].map((k) => `common.periods.${k}`),
      // rotation-policies: connector vocabulary, the schema-driven field labels
      // and the generation-policy charset boxes all resolve template keys.
      ...[
        'directory',
        'generate_only',
        'ssh',
        'ssh_key',
        'postgres',
        'mysql',
        'aws_iam',
        'gcp_sa',
      ].map((k) => `pages.rotationPolicies.connectors.${k}`),
      ...[
        'host',
        'port',
        'username',
        'adminSecret',
        'adminUsername',
        'adminAuth',
        'adminAuthPassword',
        'adminAuthPrivateKey',
        'hostKey',
        'iamUser',
        'adminSecretAws',
        'region',
        'dbname',
        'dbnameOptional',
        'sslmode',
        'targetRole',
        'tls',
        'targetUser',
        'targetHost',
        'serviceAccountEmail',
        'adminSecretGcp',
        'selectSecret',
      ].map((k) => `pages.rotationPolicies.fields.${k}`),
      ...['upper', 'lower', 'digits', 'symbols'].map(
        (k) => `pages.rotationPolicies.dialog.charsets.${k}`,
      ),
      // app-publish: the classification vocabulary is keyed by the path's own value
      ...['critical', 'sensitive', 'protected', 'public'].map(
        (k) => `pages.appPublish.classes.${k}`,
      ),
      // windows-apps: the pool placement label is keyed by the pool's strategy
      ...['least_loaded', 'round_robin'].map((k) => `pages.windowsApps.placements.${k}`),
      // remote-support: the viewer badge keys off the session's own mode value
      ...['interactive', 'view'].map((k) => `pages.remoteSupport.modes.${k}`),
      // audit-logs: filter list, stats chart and detail dialog all resolve the
      // event type and outcome by the backend's own enum value
      ...[
        'authentication',
        'authorization',
        'user_management',
        'group_management',
        'role_management',
        'configuration',
        'data_access',
        'system',
      ].map((k) => `pages.auditLogs.eventTypes.${k}`),
      ...['success', 'failure', 'pending'].map((k) => `pages.auditLogs.outcomes.${k}`),
      // admin-audit-log: ACTION_TYPES / TARGET_TYPES carry labelKey, not a label
      ...[
        'all',
        'create',
        'update',
        'delete',
        'enable',
        'disable',
        'assign',
        'revoke',
        'login',
        'logout',
      ].map((k) => `pages.adminAuditLog.actions.${k}`),
      ...[
        'all',
        'user',
        'group',
        'application',
        'policy',
        'role',
        'settings',
        'apiKey',
        'webhook',
      ].map((k) => `pages.adminAuditLog.targets.${k}`),
      // compliance-reports: the framework label is keyed by the report's type
      ...['soc2', 'iso27001', 'gdpr', 'hipaa', 'pci_dss', 'custom'].map(
        (k) => `pages.complianceReports.frameworks.${k}`,
      ),
      // reports: both dialogs render the report-type list from the enum
      ...['user_access', 'compliance', 'entitlement', 'activity'].map(
        (k) => `pages.reports.reportTypes.${k}`,
      ),
      // policies: the badge keys off the policy's own type; the form Select and
      // the rule builder read their own lists
      ...[
        'separation_of_duty',
        'risk_based',
        'timebound',
        'location',
        'conditional_access',
      ].map((k) => `pages.policies.types.${k}`),
      ...['separation_of_duty', 'risk_based', 'timebound', 'location'].map(
        (k) => `pages.policies.formTypes.${k}`,
      ),
      ...['allow', 'deny', 'require_approval', 'step_up_mfa'].map(
        (k) => `pages.policies.effects.${k}`,
      ),
      // conditionTemplates carries only the field name; both the label and the
      // example resolve from it, so every field needs both halves present
      ...[
        'conflicting_roles',
        'min_risk_score',
        'max_risk_score',
        'start_hour',
        'end_hour',
        'days',
        'allowed_ips',
        'blocked_ips',
        'require_mfa',
        'device_trust_required',
        'allowed_locations',
        'blocked_locations',
      ].flatMap((k) => [`pages.policies.conditions.${k}`, `pages.policies.placeholders.${k}`]),
      'pages.policies.placeholders.conditional_max_risk_score',
      // abac-policies: resourceTypes/attributeOptions/operatorOptions are
      // module-level value lists resolved at render
      ...['application', 'route', 'service', 'all'].map(
        (k) => `pages.abacPolicies.resourceTypes.${k}`,
      ),
      ...[
        'department',
        'location',
        'device_trust_level',
        'time_of_day',
        'risk_score',
        'group_membership',
        'ip_range',
      ].map((k) => `pages.abacPolicies.attributes.${k}`),
      ...[
        'eq',
        'neq',
        'in',
        'not_in',
        'gt',
        'gte',
        'lt',
        'lte',
        'between',
        'contains',
      ].map((k) => `pages.abacPolicies.operators.${k}`),
      // zero-trust: the access-method chip keys off the route's own transport
      ...['proxy', 'ziti', 'browzer', 'guacamole'].map((k) => `pages.zeroTrust.methods.${k}`),
      ...['notConfigured', 'reachable', 'unreachable'].map(
        (k) => `pages.zeroTrust.zitiStatus.${k}`,
      ),
      // ziti-setup: STATUS_META carries the key; the status icon's aria-label
      // and the checklist badge both resolve through it
      ...[
        'complete',
        'warning',
        'action_needed',
        'error',
        'blocked',
        'optional',
      ].map((k) => `pages.zitiSetup.statuses.${k}`),
      // lib/connection-path + lib/remote-app resolve through the i18n singleton
      'pam.remoteAppSecretHint',
      ...[
        'approvalGate',
        'youConnect',
        'linkedCredential',
        'vaultedSecret',
        'noCredential',
        'browserTerminal',
        'remoteApp',
        'guacSession',
        'recording',
        'ziti',
        'direct',
      ].flatMap((k) => [`pam.path.${k}.title`, `pam.path.${k}.desc`]),
      ...['title', 'signedInAs', 'signedInAsDomain', 'desc'].map((k) => `pam.path.target.${k}`),
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
      // proxy-routes: HOSTING_MODES / ROUTE_TYPES render through the catalog,
      // and ConnectionTestButton names each backend probe the same way.
      ...['identity', 'hop', 'direct'].flatMap((k) => [
        `pages.proxyRoutes.hostingModes.${k}`,
        `pages.proxyRoutes.hostingModeHints.${k}`,
      ]),
      ...['http', 'ssh', 'rdp', 'vnc', 'telnet'].map((k) => `pages.proxyRoutes.routeTypes.${k}`),
      ...['upstream', 'ziti', 'guacamole', 'tcp'].map(
        (k) => `pages.proxyRoutes.connectionTest.tests.${k}`,
      ),
      // settings: the tab strip, the SMS provider registry and the credential
      // field labels every provider draws from.
      ...['general', 'security', 'authentication', 'sms', 'branding'].map(
        (k) => `pages.settings.tabs.${k}`,
      ),
      ...[
        'mock',
        'twilio',
        'aws_sns',
        'netgsm',
        'ileti_merkezi',
        'verimor',
        'turkcell',
        'vodafone',
        'turk_telekom',
        'mutlucell',
        'webhook',
      ].map((k) => `pages.settings.sms.providers.${k}`),
      ...[
        'accountSid',
        'authToken',
        'fromNumber',
        'region',
        'accessKey',
        'secretKey',
        'userCode',
        'password',
        'senderHeader',
        'apiKey',
        'apiSecret',
        'senderName',
        'username',
        'senderId',
        'senderAddress',
        'webhookUrl',
      ].map((k) => `pages.settings.sms.fields.${k}`),
      // consent-management: tabs plus the three backend vocabularies its
      // badges and request-type column resolve through.
      ...['consents', 'dsars', 'retention', 'assessments'].map(
        (k) => `pages.consentManagement.tabs.${k}`,
      ),
      ...[
        'pending',
        'in_progress',
        'completed',
        'rejected',
        'draft',
        'in_review',
        'approved',
      ].map((k) => `pages.consentManagement.statuses.${k}`),
      ...['low', 'medium', 'high', 'critical'].map(
        (k) => `pages.consentManagement.risks.${k}`,
      ),
      ...['export', 'delete', 'restrict', 'access', 'rectify', 'portability'].map(
        (k) => `pages.consentManagement.requestTypes.${k}`,
      ),
      // ziti-network: the posture-check vocabularies the controller returns,
      // resolved by key in both the table and the create/edit dialog.
      ...['OS', 'Domain', 'MFA', 'Process', 'MAC'].map(
        (k) => `pages.zitiNetwork.posture.checkTypes.${k}`,
      ),
      ...['low', 'medium', 'high', 'critical'].map(
        (k) => `pages.zitiNetwork.posture.severities.${k}`,
      ),
      // notification-admin: the delivery channels and broadcast vocabularies
      // the notification service uses, plus the two client-side option lists.
      ...['in_app', 'email', 'sms', 'push'].map(
        (k) => `pages.notificationAdmin.channels.${k}`,
      ),
      ...['draft', 'scheduled', 'sent'].map(
        (k) => `pages.notificationAdmin.statuses.${k}`,
      ),
      ...['all', 'role', 'group'].map(
        (k) => `pages.notificationAdmin.targetTypes.${k}`,
      ),
      ...['low', 'normal', 'high', 'urgent'].map(
        (k) => `pages.notificationAdmin.priorities.${k}`,
      ),
      // user-access-360: the device-source labels `deviceSourceLabel` returns
      // as keys, and the agent's compliance vocabulary.
      ...['linked', 'iam', 'ziti'].map((k) => `pages.userAccess360.devices.sources.${k}`),
      ...['compliant', 'non_compliant', 'grace_period', 'unknown'].map(
        (k) => `pages.userAccess360.devices.complianceStatuses.${k}`,
      ),
      // lifecycle-workflows: the four vocabularies the lifecycle service owns,
      // each driving a filter, a badge and a form select off one list.
      ...['onboard', 'transfer', 'offboard', 'leave', 'return'].map(
        (k) => `pages.lifecycleWorkflows.events.${k}`,
      ),
      ...['manual', 'scheduled', 'webhook'].map(
        (k) => `pages.lifecycleWorkflows.triggers.${k}`,
      ),
      ...[
        'assign_role',
        'remove_role',
        'assign_group',
        'remove_group',
        'enable_user',
        'disable_user',
        'revoke_sessions',
      ].map((k) => `pages.lifecycleWorkflows.actionTypes.${k}`),
      ...['pending', 'in_progress', 'completed', 'failed', 'rejected'].map(
        (k) => `pages.lifecycleWorkflows.executionStatuses.${k}`,
      ),
      // delegations: the delegation API's scope kinds, plus the per-kind hint
      // that tells the operator where to find that scope's UUID.
      ...['group', 'role', 'application', 'organization'].map(
        (k) => `pages.delegations.scopeTypes.${k}`,
      ),
      ...['group', 'role', 'application', 'organization', 'fallback'].map(
        (k) => `pages.delegations.scopeIdHints.${k}`,
      ),
      // api-explorer: the services the catalog endpoint groups endpoints by.
      ...['identity', 'oauth', 'governance', 'audit', 'admin', 'provisioning'].map(
        (k) => `pages.apiExplorer.services.${k}`,
      ),
      // system-health: the overall and per-dependency status vocabularies,
      // whose config maps no longer carry English labels.
      ...['healthy', 'degraded', 'unhealthy'].map(
        (k) => `pages.systemHealth.statuses.${k}`,
      ),
      ...['up', 'degraded', 'down'].map((k) => `pages.systemHealth.depStatuses.${k}`),
      // developer-settings: the tab strip and the API-key expiry presets, both
      // driven off `id`/`key` lists that no longer carry English labels.
      ...['api_keys', 'webhooks', 'cors', 'rate_limits'].map(
        (k) => `pages.developerSettings.tabs.${k}`,
      ),
      ...['d30', 'd60', 'd90', 'd180', 'd365', 'never'].map(
        (k) => `pages.developerSettings.apiKeys.expiry.${k}`,
      ),
      // device-trust-approval: the request lifecycle, shared by the tab strip
      // and the row badge.
      ...['pending', 'approved', 'rejected', 'expired'].map(
        (k) => `pages.deviceTrustApproval.statuses.${k}`,
      ),
      // agent-fleet: the agent lifecycle and the posture-compliance vocabulary.
      ...['active', 'pending', 'revoked'].map((k) => `pages.agentFleet.statuses.${k}`),
      ...['compliant', 'grace_period', 'non_compliant', 'unknown'].map(
        (k) => `pages.agentFleet.complianceStatuses.${k}`,
      ),
      // ziti-ai-insights: detector output, the shared severity scale used by
      // anomalies/risk/recommendations alike, and the resolved subject kinds.
      ...[
        'new_service_access',
        'off_hours_access',
        'dormant_identity_active',
        'session_spike',
      ].map((k) => `pages.zitiAiInsights.anomalyTypes.${k}`),
      ...['low', 'medium', 'high', 'critical'].map(
        (k) => `pages.zitiAiInsights.severities.${k}`,
      ),
      ...['user', 'agent', 'service', 'unresolved', 'unknown'].map(
        (k) => `pages.zitiAiInsights.subjectKinds.${k}`,
      ),
      // usage-analytics: the adoption endpoint's feature names, in both of the
      // shapes it has shipped.
      ...[
        'mfa_totp',
        'mfa_webauthn',
        'passkey_login',
        'magic_link',
        'api_keys',
        'social_login',
        'totp',
        'webauthn',
        'passkey',
        'sms',
        'mfa',
        'sso',
      ].map((k) => `pages.usageAnalytics.features.${k}`),
      // webhooks: the subscription lifecycle and the delivery lifecycle.
      ...['active', 'disabled'].map((k) => `pages.webhooks.statuses.${k}`),
      ...['delivered', 'failed', 'pending'].map(
        (k) => `pages.webhooks.deliveryStatuses.${k}`,
      ),
      // tenant-management: the tab strip, the three colour fields keyed by the
      // branding field name, the JSON settings groups and the domain kinds.
      ...['branding', 'settings', 'domains'].map(
        (k) => `pages.tenantManagement.tabs.${k}`,
      ),
      ...['primary_color', 'secondary_color', 'background_color'].map(
        (k) => `pages.tenantManagement.branding.colors.${k}`,
      ),
      ...['security', 'authentication', 'session'].map(
        (k) => `pages.tenantManagement.settings.categories.${k}`,
      ),
      ...['subdomain', 'custom'].map((k) => `pages.tenantManagement.domains.types.${k}`),
      // devices: the type derived from the user agent, and the overlay
      // enrolment state derived from the device's Ziti identity.
      ...['mobile', 'tablet', 'desktop'].map((k) => `pages.devices.deviceTypes.${k}`),
      ...['enrolled', 'pending', 'none'].map((k) => `pages.devices.zitiStatuses.${k}`),
      // ai-agents: the agent lifecycle vocabularies, each rendered twice —
      // lowercase on the row badge, title case in the create form.
      ...['assistant', 'autonomous', 'workflow', 'integration'].flatMap((k) => [
        `pages.aiAgents.agentTypes.${k}`,
        `pages.aiAgents.form.typeOptions.${k}`,
      ]),
      ...['low', 'medium', 'high'].flatMap((k) => [
        `pages.aiAgents.trustLevels.${k}`,
        `pages.aiAgents.form.trustOptions.${k}`,
      ]),
      ...['active', 'suspended', 'inactive'].map((k) => `pages.aiAgents.statuses.${k}`),
      ...['active', 'revoked', 'expired'].map(
        (k) => `pages.aiAgents.credentialStatuses.${k}`,
      ),
      // network-topology: the node kinds, plural for the filter buttons and the
      // summary rows, singular for the selected node's badge, plus the node
      // health the topology model computes and the per-kind empty sentence.
      ...['all', 'identity', 'router', 'service'].map(
        (k) => `pages.networkTopology.kinds.${k}`,
      ),
      ...['identity', 'router', 'service'].map(
        (k) => `pages.networkTopology.nodeKinds.${k}`,
      ),
      ...['up', 'down', 'degraded', 'unknown'].map(
        (k) => `pages.networkTopology.statuses.${k}`,
      ),
      ...['identity', 'service'].map(
        (k) => `pages.networkTopology.detail.noPolicies.${k}`,
      ),
      // predictive-analytics: the forecaster's trend directions.
      ...['increasing', 'decreasing', 'stable', 'insufficient_data'].map(
        (k) => `pages.predictiveAnalytics.trends.${k}`,
      ),
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

  it('pluralizes the MFA factor counts in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.securityKeys.count', { count: 1 })).toBe('1 security key registered')
    expect(i18n.t('pages.securityKeys.count', { count: 3 })).toBe('3 security keys registered')
    expect(i18n.t('pages.pushDevices.count', { count: 1 })).toBe('1 device enrolled')
    expect(i18n.t('pages.pushDevices.count', { count: 2 })).toBe('2 devices enrolled')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.securityKeys.count', { count: 3 })).toBe('3 güvenlik anahtarı kayıtlı')
    expect(i18n.t('pages.pushDevices.count', { count: 2 })).toBe('2 cihaz kayıtlı')
  })

  it('pluralizes the audit counts in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.auditLogs.dayEvents', { date: '2026-01-01', count: 1 })).toBe(
      '2026-01-01: 1 event',
    )
    expect(i18n.t('pages.auditLogs.dayEvents', { date: '2026-01-01', count: 7 })).toBe(
      '2026-01-01: 7 events',
    )
    expect(i18n.t('pages.adminAuditLog.toast.exportedDesc', { count: 1 })).toBe(
      'Exported 1 record to CSV.',
    )
    expect(i18n.t('pages.adminAuditLog.toast.exportedDesc', { count: 4 })).toBe(
      'Exported 4 records to CSV.',
    )

    // Turkish does not inflect the noun after a numeral, so both plural forms
    // carry the same wording -- but both must still resolve, not fall back.
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.auditLogs.dayEvents', { date: '2026-01-01', count: 7 })).toBe(
      '2026-01-01: 7 olay',
    )
    expect(i18n.t('pages.adminAuditLog.toast.exportedDesc', { count: 4 })).toBe(
      '4 kayıt CSV olarak dışa aktarıldı.',
    )
  })

  it('pluralizes the ABAC counts in both languages', async () => {
    await i18n.changeLanguage('en')
    // The list header and the per-row chip both read from these, and the page
    // tests assert the exact strings ("0 policies", "1 condition").
    expect(i18n.t('pages.abacPolicies.policyCount', { count: 0 })).toBe('0 policies')
    expect(i18n.t('pages.abacPolicies.policyCount', { count: 1 })).toBe('1 policy')
    expect(i18n.t('pages.abacPolicies.policyCount', { count: 2 })).toBe('2 policies')
    expect(i18n.t('pages.abacPolicies.conditionCount', { count: 1 })).toBe('1 condition')
    expect(i18n.t('pages.abacPolicies.conditionCount', { count: 2 })).toBe('2 conditions')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.abacPolicies.policyCount', { count: 2 })).toBe('2 politika')
    expect(i18n.t('pages.abacPolicies.conditionCount', { count: 2 })).toBe('2 koşul')
  })

  it('pluralizes the proxy-route count in both languages', async () => {
    await i18n.changeLanguage('en')
    // The page test asserts the exact badge text ("2 routes").
    expect(i18n.t('pages.proxyRoutes.routeCount', { count: 0 })).toBe('0 routes')
    expect(i18n.t('pages.proxyRoutes.routeCount', { count: 1 })).toBe('1 route')
    expect(i18n.t('pages.proxyRoutes.routeCount', { count: 2 })).toBe('2 routes')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.proxyRoutes.routeCount', { count: 2 })).toBe('2 rota')
  })

  it('pluralizes the OTP code length in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.settings.sms.digits', { count: 4 })).toBe('4 digits')
    expect(i18n.t('pages.settings.sms.digits', { count: 1 })).toBe('1 digit')

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.settings.sms.digits', { count: 6 })).toBe('6 hane')
  })

  it('resolves an unknown consent status or risk level to its raw value', async () => {
    // Both badges fall back rather than rendering a bare key, so a value the
    // privacy service adds later is still readable.
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.consentManagement.statuses.in_review')).toBe('In Review')
    expect(
      i18n.t('pages.consentManagement.statuses.escalated', { defaultValue: 'escalated' }),
    ).toBe('escalated')
    expect(
      i18n.t('pages.consentManagement.risks.severe', { defaultValue: 'Severe' }),
    ).toBe('Severe')
  })

  it('keeps the notification channel breakdown invariant, not pluralized', async () => {
    // The count is interpolated as {{n}} so i18next does not try to resolve a
    // plural form the catalog deliberately does not carry, and Turkish keeps
    // its percent sign in front of the number.
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.notificationAdmin.stats.channelCount', { n: 12, percentage: 40 }),
    ).toBe('12 (40%)')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.notificationAdmin.stats.channelCount', { n: 1, percentage: 3 }),
    ).toBe('1 (%3)')
  })

  it('falls back to the capitalized scope type and the generic scope hint', async () => {
    // A scope kind the delegation API adds later reads as itself in the filter,
    // the badge and both forms, and its Scope ID field still gets a hint.
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.delegations.scopeTypes.tenant', { defaultValue: 'Tenant' }),
    ).toBe('Tenant')
    expect(
      i18n.t('pages.delegations.scopeIdHints.tenant', {
        defaultValue: i18n.t('pages.delegations.scopeIdHints.fallback'),
      }),
    ).toBe('UUID of the scoped resource.')
  })

  it('pluralizes the relations-doctor scan result in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.systemHealth.relations.scanResult', { count: 1, remaining: 2 }),
    ).toBe('1 safe fix applied, 2 remaining.')
    expect(
      i18n.t('pages.systemHealth.relations.scanResult', { count: 3, remaining: 0 }),
    ).toBe('3 safe fixes applied, 0 remaining.')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.systemHealth.relations.scanResult', { count: 1, remaining: 2 }),
    ).toBe('1 güvenli düzeltme uygulandı, 2 tane kaldı.')
  })

  it('resolves an unknown lifecycle action type to its raw value', async () => {
    // The workflow's action list comes back from the server; an action the
    // lifecycle service adds later still reads as itself in the row badge,
    // the builder and the execute dialog.
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.lifecycleWorkflows.actionTypes.assign_role')).toBe('Rol Ata')
    expect(
      i18n.t('pages.lifecycleWorkflows.actionTypes.reset_password', {
        defaultValue: 'reset_password',
      }),
    ).toBe('reset_password')
  })

  it('keeps the OAuth playground protocol parameter names untranslated', async () => {
    // code_verifier and friends are the wire identifiers a developer types;
    // only the prose around them localizes.
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.oauthPlayground.jwt.useAccessToken')).toContain('access_token')
    expect(i18n.t('pages.oauthPlayground.step1.desc')).toContain('code_verifier')
    expect(i18n.t('pages.oauthPlayground.step4.call')).toContain('/oauth/userinfo')
  })

  it('pluralizes the Access 360 dial-policy line in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.userAccess360.ziti.via', { count: 1, names: 'a' })).toBe(
      'Via 1 dial policy: a',
    )
    expect(i18n.t('pages.userAccess360.ziti.via', { count: 2, names: 'a, b' })).toBe(
      'Via 2 dial policies: a, b',
    )

    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.userAccess360.ziti.via', { count: 2, names: 'a, b' })).toBe(
      '2 çevirme politikası üzerinden: a, b',
    )
  })

  it('resolves an unknown agent compliance status to its prettified raw value', async () => {
    // The agent reports the status; an unknown one still reads as itself rather
    // than surfacing a bare key in the badge.
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.userAccess360.devices.complianceStatuses.non_compliant')).toBe(
      'non compliant',
    )
    expect(
      i18n.t('pages.userAccess360.devices.complianceStatuses.pending_scan', {
        defaultValue: 'pending scan',
      }),
    ).toBe('pending scan')
  })

  it('resolves an unknown notification channel to its raw value', async () => {
    // A channel the notification service adds later must still read as itself
    // in the rule table, the broadcast row and the delivery breakdown alike.
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.notificationAdmin.channels.in_app')).toBe('Uygulama içi')
    expect(
      i18n.t('pages.notificationAdmin.channels.webhook', { defaultValue: 'webhook' }),
    ).toBe('webhook')
  })

  it('resolves an unknown Ziti posture check type to its raw value', async () => {
    // The controller's own typeId is the wire value, so a check type a newer
    // controller reports still renders instead of leaking a bare key.
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.zitiNetwork.posture.checkTypes.Domain')).toBe('Etki alanı')
    expect(
      i18n.t('pages.zitiNetwork.posture.checkTypes.Windows', { defaultValue: 'Windows' }),
    ).toBe('Windows')
  })

  it('resolves an unknown connection-test probe to its prettified raw value', async () => {
    // ConnectionTestButton names probes from the backend's own map, so one
    // added later must still read as itself.
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.proxyRoutes.connectionTest.tests.upstream')).toBe('Upstream')
    expect(
      i18n.t('pages.proxyRoutes.connectionTest.tests.dns_resolve', {
        defaultValue: 'dns_resolve'.replace('_', ' '),
      }),
    ).toBe('dns resolve')
  })

  it('leaves an unrecognised hosting mode without a hint', async () => {
    // The pre-i18n page rendered nothing when `.find()` missed; the catalog
    // lookup must not surface a bare key in its place.
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.proxyRoutes.hostingModeHints.tunnel', { defaultValue: '' }),
    ).toBe('')
  })

  it('resolves an unknown audit event type to its prettified raw value', async () => {
    // The page falls back rather than rendering a bare key, so a type the
    // backend adds later is still readable.
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.auditLogs.eventTypes.secret_rotation', {
        defaultValue: 'secret_rotation'.replace('_', ' '),
      }),
    ).toBe('secret rotation')
  })

  it('resolves an unknown agent status to its prettified raw value', async () => {
    // Both agent badges fall back rather than rendering a bare key, so a
    // lifecycle or compliance value the backend adds later is still readable.
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.agentFleet.statuses.quarantined', {
        defaultValue: 'quarantined'.replace(/_/g, ' '),
      }),
    ).toBe('quarantined')
    expect(
      i18n.t('pages.agentFleet.complianceStatuses.awaiting_report', {
        defaultValue: 'awaiting_report'.replace(/_/g, ' '),
      }),
    ).toBe('awaiting report')
    // The known values still resolve through the catalog in both languages.
    expect(i18n.t('pages.agentFleet.complianceStatuses.non_compliant')).toBe('non compliant')
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.agentFleet.complianceStatuses.non_compliant')).toBe('uyumsuz')
  })

  it('interpolates the agent enrolment checksum and the revoke confirmation', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.agentFleet.qr.downloadApk', { checksum: 'a1b2c3d4e5f6…' })).toBe(
      'Download APK (a1b2c3d4e5f6…)',
    )
    expect(i18n.t('pages.agentFleet.revokeDialog.desc', { agentId: 'agt-001' })).toContain(
      'agt-001',
    )
  })

  it('resolves an unknown Ziti anomaly type and severity to their raw values', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.zitiAiInsights.anomalyTypes.impossible_travel', {
        defaultValue: 'impossible_travel'.replace(/_/g, ' '),
      }),
    ).toBe('impossible travel')
    expect(
      i18n.t('pages.zitiAiInsights.severities.info', { defaultValue: 'info' }),
    ).toBe('info')
  })

  it('names the directory a resolved Ziti subject came from', async () => {
    // A UUID-named overlay identity says nothing on its own, so the row states
    // what kind of account it is — and, for a person, where they came from.
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.zitiAiInsights.subjectFromSource', { source: 'ldap' })).toBe(
      'person (ldap)',
    )
    expect(i18n.t('pages.zitiAiInsights.subjectKinds.unresolved')).toBe(
      'account not visible here',
    )
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.zitiAiInsights.subjectFromSource', { source: 'ldap' })).toBe(
      'kişi (ldap)',
    )
  })

  it('pluralizes both counts in the Ziti analysis summary', async () => {
    await i18n.changeLanguage('en')
    const one = i18n.t('pages.zitiAiInsights.toasts.analysisSummary', {
      observations: i18n.t('pages.zitiAiInsights.toasts.analysisObservations', { count: 1 }),
      anomalies: i18n.t('pages.zitiAiInsights.toasts.analysisAnomalies', { count: 1 }),
    })
    expect(one).toBe('1 observation analyzed, 1 new anomaly detected.')
    const many = i18n.t('pages.zitiAiInsights.toasts.analysisSummary', {
      observations: i18n.t('pages.zitiAiInsights.toasts.analysisObservations', { count: 12 }),
      anomalies: i18n.t('pages.zitiAiInsights.toasts.analysisAnomalies', { count: 3 }),
    })
    expect(many).toBe('12 observations analyzed, 3 new anomalies detected.')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.zitiAiInsights.toasts.analysisObservations', { count: 12 }),
    ).toBe('12 gözlem incelendi')
  })

  it('pluralizes the usage-analytics registration total in both languages', async () => {
    // The raw number picks the plural; the locale-formatted string fills the
    // sentence, so a five-figure total still reads as "12,345".
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.usageAnalytics.registrations.total', { count: 1, formatted: '1' }),
    ).toBe('Total: 1 new user')
    expect(
      i18n.t('pages.usageAnalytics.registrations.total', {
        count: 12345,
        formatted: (12345).toLocaleString('en-US'),
      }),
    ).toBe('Total: 12,345 new users')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.usageAnalytics.registrations.total', { count: 3, formatted: '3' }),
    ).toBe('Toplam: 3 yeni kullanıcı')
  })

  it('resolves an unknown webhook delivery status to its raw value', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.webhooks.deliveryStatuses.dropped', { defaultValue: 'dropped' }),
    ).toBe('dropped')
    expect(i18n.t('pages.webhooks.deliveryStatuses.delivered')).toBe('Delivered')
    // The subscription statuses stay lowercase, as the page has always shown.
    expect(i18n.t('pages.webhooks.statuses.active')).toBe('active')
  })

  it('names the tenant settings group inside its own sentence', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.tenantManagement.settings.desc', {
        category: i18n.t('pages.tenantManagement.settings.categories.session'),
      }),
    ).toBe('Edit Session settings as JSON')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.tenantManagement.settings.desc', {
        category: i18n.t('pages.tenantManagement.settings.categories.session'),
      }),
    ).toBe('Oturum ayarlarını JSON olarak düzenleyin')
  })

  it('pluralizes the device pagination line in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.devices.showing', { from: 1, to: 1, total: 1, count: 1 }),
    ).toBe('Showing 1 to 1 of 1 device')
    expect(
      i18n.t('pages.devices.showing', { from: 1, to: 20, total: 42, count: 42 }),
    ).toBe('Showing 1 to 20 of 42 devices')

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.devices.showing', { from: 1, to: 20, total: 42, count: 42 }),
    ).toBe('42 cihazdan 1-20 arası gösteriliyor')
  })

  it('renders the AI agent vocabularies in both the badge and the form casing', async () => {
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.aiAgents.agentTypes.assistant')).toBe('assistant')
    expect(i18n.t('pages.aiAgents.form.typeOptions.assistant')).toBe('Assistant')
    expect(
      i18n.t('pages.aiAgents.trustBadge', {
        level: i18n.t('pages.aiAgents.trustLevels.high'),
      }),
    ).toBe('Trust: high')
    // A lifecycle value the API adds later still reads as itself.
    expect(
      i18n.t('pages.aiAgents.statuses.quarantined', { defaultValue: 'quarantined' }),
    ).toBe('quarantined')
  })

  it('pluralizes the Ziti bulk-import summary in both languages', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.zitiDiscovery.toasts.bulkSummary', {
        imported: i18n.t('pages.zitiDiscovery.toasts.bulkImported', { count: 1 }),
        failed: i18n.t('pages.zitiDiscovery.toasts.bulkFailed', { n: 0 }),
      }),
    ).toBe('Imported 1 service. 0 failed.')
    expect(
      i18n.t('pages.zitiDiscovery.toasts.bulkSummary', {
        imported: i18n.t('pages.zitiDiscovery.toasts.bulkImported', { count: 7 }),
        failed: i18n.t('pages.zitiDiscovery.toasts.bulkFailed', { n: 2 }),
      }),
    ).toBe('Imported 7 services. 2 failed.')
    expect(i18n.t('pages.zitiDiscovery.bulk.submit', { count: 1 })).toBe(
      'Import 1 Service',
    )

    await i18n.changeLanguage('tr')
    expect(
      i18n.t('pages.zitiDiscovery.toasts.bulkImported', { count: 7 }),
    ).toBe('7 servis aktarıldı.')
  })

  it('inflects the topology empty sentence per node kind', async () => {
    // Keyed by the node kind rather than interpolating the word, so a locale
    // that inflects the noun can write each sentence out.
    await i18n.changeLanguage('en')
    expect(i18n.t('pages.networkTopology.detail.noPolicies.identity')).toBe(
      'No service policies reference this identity.',
    )
    expect(i18n.t('pages.networkTopology.detail.noPolicies.service')).toBe(
      'No service policies reference this service.',
    )
    await i18n.changeLanguage('tr')
    expect(i18n.t('pages.networkTopology.detail.noPolicies.identity')).toContain(
      'kimliğe',
    )
  })

  it('resolves an unknown forecast trend to its prettified raw value', async () => {
    await i18n.changeLanguage('en')
    expect(
      i18n.t('pages.predictiveAnalytics.trends.accelerating', {
        defaultValue: 'accelerating'.replace(/_/g, ' '),
      }),
    ).toBe('accelerating')
    expect(i18n.t('pages.predictiveAnalytics.trends.insufficient_data')).toBe(
      'Insufficient data',
    )
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
