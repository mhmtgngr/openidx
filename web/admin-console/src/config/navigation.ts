// Single source of truth for the admin-console navigation.
//
// To add a menu item: add one entry to the right section below (and make sure
// App.tsx has a matching <Route>). navigation.test.ts cross-checks every href
// against App.tsx routes, so a typo or a forgotten route fails CI instead of
// shipping an unreachable page.
//
// Visibility is role-driven and mirrors the backend hierarchy
// (internal/auth/roles.go): super_admin > admin > operator > auditor > user.
// compliance_reader unlocks only the audit domain (see lib/roles.ts).
import {
  LayoutDashboard,
  Users,
  Users2,
  AppWindow,
  ClipboardCheck,
  FileText,
  Settings,
  Shield,
  Scale,
  ShieldCheck,
  ClipboardList,
  Key as KeyIcon,
  User,
  Workflow,
  Network,
  FolderSync,
  Smartphone,
  Bell,
  GitPullRequest,
  ShieldAlert,
  Monitor,
  Building2,
  BarChart3,
  Eye,
  Fingerprint,
  KeyRound,
  ShieldOff,
  Link2,
  Activity,
  Search,
  Share2,
  Layers,
  Globe,
  FileKey,
  Upload,
  BookOpen,
  Target,
  Package,
  Gauge,
  UserCheck,
  Filter,
  Code2,
  Play,
  HeartPulse,
  AlertTriangle,
  ScrollText,
  TrendingUp,
  PieChart,
  Bot,
  Lightbulb,
  Mail,
  UserMinus,
  ClipboardSignature,
  ArchiveRestore,
  FileCheck,
  Send,
  Video,
  Lock,
  RefreshCw,
  MonitorPlay,
  Radio,
  Brain,
  Server,
  Home,
} from 'lucide-react'
import i18n from '@/i18n'
import { hasMinRole, type MinRole } from '@/lib/roles'

export type NavIcon = React.ComponentType<{ className?: string }>

// Top-level product domains. IAM, Ziti (zero-trust network) and PAM are the
// three pillars of the platform; audit feeds the reporter persona.
export type NavDomain = 'home' | 'iam' | 'ziti' | 'pam' | 'audit' | 'ai' | 'platform'

// Console lens: admins can narrow the console to the operator ("management")
// or auditor ("reporting") slice; lower roles are capped to their own level.
export type ViewMode = 'admin' | 'management' | 'reporting'

export interface NavItem {
  /** Canonical English name — also a search synonym in any UI language. */
  name: string
  /** Catalog key for the displayed (translated) name. */
  nameKey: string
  href: string
  icon: NavIcon
  /** Minimum role that should see this entry (hierarchical). */
  minRole: MinRole
  /** Extra terms the sidebar quick-search matches besides the name. */
  keywords?: string[]
}

export interface NavSection {
  /** Sub-heading inside a domain (canonical English). Empty label = no heading rendered. */
  label: string
  /** Catalog key for the displayed heading; absent when label is empty. */
  labelKey?: string
  items: NavItem[]
}

export interface NavDomainGroup {
  id: NavDomain
  /** Domain heading (canonical English). Empty for the personal (home) group. */
  label: string
  /** Catalog key for the displayed heading; absent when label is empty. */
  labelKey?: string
  icon: NavIcon
  sections: NavSection[]
}

// Display resolvers: components render these (they re-render on language
// change via useTranslation); the raw name/label stay canonical English and
// keep working as search synonyms.
export const navItemName = (item: NavItem): string => i18n.t(item.nameKey)
export const navSectionLabel = (s: NavSection): string => (s.labelKey ? i18n.t(s.labelKey) : '')
export const navDomainLabel = (g: NavDomainGroup): string => (g.labelKey ? i18n.t(g.labelKey) : '')

export const navigation: NavDomainGroup[] = [
  {
    id: 'home',
    label: '',
    icon: Home,
    sections: [
      {
        label: '',
        items: [
          { name: 'Dashboard', nameKey: 'nav.items.dashboard', href: '/dashboard', icon: LayoutDashboard, minRole: 'user', keywords: ['overview', 'home'] },
          { name: 'My Profile', nameKey: 'nav.items.myProfile', href: '/profile', icon: User, minRole: 'user', keywords: ['account', 'password'] },
          { name: 'My Apps & Network', nameKey: 'nav.items.myAppsNetwork', href: '/my-network', icon: Globe, minRole: 'user', keywords: ['what can i reach', 'connect', 'remote', 'servers', 'access', 'resources', 'apps', 'launcher', 'portal', 'sso', 'sign in', 'windows', 'remoteapp', 'ssms', 'rds', 'quick links', 'shortcuts', 'teams', 'zoom', 'support', 'privileged', 'pam', 'secrets', 'checkout', 'sessions'] },
          { name: 'My Access', nameKey: 'nav.items.myAccess', href: '/my-access', icon: Eye, minRole: 'user', keywords: ['entitlements', 'permissions'] },
          { name: 'My Devices', nameKey: 'nav.items.myDevices', href: '/my-devices', icon: Smartphone, minRole: 'user', keywords: ['phone', 'enrollment'] },
          { name: 'My Sessions', nameKey: 'nav.items.mySessions', href: '/sessions', icon: Monitor, minRole: 'user', keywords: ['active sessions', 'sign out', 'devices', 'logged in'] },
          { name: 'My Security', nameKey: 'nav.items.mySecurity', href: '/my-security', icon: ShieldCheck, minRole: 'user', keywords: ['security score', 'risk', 'insights', 'mfa'] },
          { name: 'Trusted Browsers', nameKey: 'nav.items.trustedBrowsers', href: '/trusted-browsers', icon: Monitor, minRole: 'user', keywords: ['remembered'] },
          { name: 'Access Requests', nameKey: 'nav.items.accessRequests', href: '/access-requests', icon: GitPullRequest, minRole: 'user', keywords: ['request access', 'approvals'] },
          { name: 'Notifications', nameKey: 'nav.items.notifications', href: '/notification-center', icon: Bell, minRole: 'user', keywords: ['inbox', 'alerts'] },
        ],
      },
      {
        label: 'Operations',
        labelKey: 'nav.sections.operations',
        items: [
          { name: 'Ops Cockpit', nameKey: 'nav.items.opsCockpit', href: '/ops-cockpit', icon: Gauge, minRole: 'operator', keywords: ['operations', 'situational', 'overview', 'command center', 'noc'] },
        ],
      },
    ],
  },
  {
    id: 'iam',
    label: 'Identity & Access (IAM)',
    labelKey: 'nav.domains.iam',
    icon: Fingerprint,
    sections: [
      {
        label: 'Identity',
        labelKey: 'nav.sections.identity',
        items: [
          { name: 'Users', nameKey: 'nav.items.users', href: '/users', icon: Users, minRole: 'operator', keywords: ['people', 'accounts', 'iam'] },
          { name: 'Groups', nameKey: 'nav.items.groups', href: '/groups', icon: Users2, minRole: 'operator', keywords: ['teams', 'membership'] },
          { name: 'Roles', nameKey: 'nav.items.roles', href: '/roles', icon: ShieldCheck, minRole: 'admin', keywords: ['rbac', 'permissions'] },
          { name: 'Directories', nameKey: 'nav.items.directories', href: '/directories', icon: FolderSync, minRole: 'admin', keywords: ['ldap', 'active directory', 'sync'] },
          { name: 'Service Accounts', nameKey: 'nav.items.serviceAccounts', href: '/service-accounts', icon: KeyIcon, minRole: 'admin', keywords: ['machine', 'api accounts'] },
          { name: 'Bulk Operations', nameKey: 'nav.items.bulkOperations', href: '/bulk-operations', icon: Layers, minRole: 'operator', keywords: ['import', 'export', 'csv'] },
        ],
      },
      {
        label: 'Applications & Federation',
        labelKey: 'nav.sections.appsFederation',
        items: [
          { name: 'Applications', nameKey: 'nav.items.applications', href: '/applications', icon: AppWindow, minRole: 'admin', keywords: ['oauth', 'clients', 'sso'] },
          { name: 'Identity Providers', nameKey: 'nav.items.identityProviders', href: '/identity-providers', icon: KeyIcon, minRole: 'admin', keywords: ['idp', 'oidc', 'saml'] },
          { name: 'SAML Providers', nameKey: 'nav.items.samlProviders', href: '/saml-service-providers', icon: Fingerprint, minRole: 'admin', keywords: ['saml', 'service provider', 'federation'] },
          { name: 'Social Providers', nameKey: 'nav.items.socialProviders', href: '/social-providers', icon: Globe, minRole: 'admin', keywords: ['google', 'github', 'social login'] },
          { name: 'Federation', nameKey: 'nav.items.federation', href: '/federation-config', icon: Link2, minRole: 'admin', keywords: ['trust', 'external idp'] },
          { name: 'Provisioning Rules', nameKey: 'nav.items.provisioningRules', href: '/provisioning-rules', icon: Workflow, minRole: 'admin', keywords: ['scim', 'sync rules'] },
          { name: 'Lifecycle Workflows', nameKey: 'nav.items.lifecycleWorkflows', href: '/lifecycle-workflows', icon: Workflow, minRole: 'admin', keywords: ['joiner', 'mover', 'leaver', 'onboarding'] },
        ],
      },
      {
        label: 'Governance',
        labelKey: 'nav.sections.governance',
        items: [
          { name: 'Policies', nameKey: 'nav.items.policies', href: '/policies', icon: Scale, minRole: 'operator', keywords: ['opa', 'rules'] },
          { name: 'Approval Policies', nameKey: 'nav.items.approvalPolicies', href: '/approval-policies', icon: ShieldCheck, minRole: 'admin', keywords: ['workflow', 'approvers'] },
          { name: 'Access Reviews', nameKey: 'nav.items.accessReviews', href: '/access-reviews', icon: ClipboardCheck, minRole: 'operator', keywords: ['recertification', 'review'] },
          { name: 'Cert Campaigns', nameKey: 'nav.items.certCampaigns', href: '/certification-campaigns', icon: Target, minRole: 'admin', keywords: ['certification', 'campaign'] },
          { name: 'Attestation', nameKey: 'nav.items.attestation', href: '/attestation-campaigns', icon: ClipboardSignature, minRole: 'admin', keywords: ['attest', 'campaign'] },
          { name: 'Entitlements', nameKey: 'nav.items.entitlements', href: '/entitlements', icon: Package, minRole: 'admin', keywords: ['grants', 'catalog'] },
          { name: 'Assignment Report', nameKey: 'nav.items.assignmentReport', href: '/assignment-report', icon: ClipboardList, minRole: 'admin', keywords: ['assignment', 'enforcement', 'who loses access'] },
          { name: 'ABAC Policies', nameKey: 'nav.items.abacPolicies', href: '/abac-policies', icon: Filter, minRole: 'admin', keywords: ['attribute', 'context'] },
          { name: 'Lifecycle Policies', nameKey: 'nav.items.lifecyclePolicies', href: '/lifecycle-policies', icon: UserMinus, minRole: 'admin', keywords: ['deprovision', 'dormant', 'offboarding'] },
          { name: 'Sessions', nameKey: 'nav.items.sessions', href: '/sessions', icon: Monitor, minRole: 'operator', keywords: ['active sessions', 'revoke'] },
          { name: 'Delegations', nameKey: 'nav.items.delegations', href: '/delegations', icon: UserCheck, minRole: 'admin', keywords: ['delegate', 'admin rights'] },
          { name: 'Privacy Dashboard', nameKey: 'nav.items.privacyDashboard', href: '/privacy-dashboard', icon: Shield, minRole: 'admin', keywords: ['gdpr', 'data subject'] },
          { name: 'Consent Mgmt', nameKey: 'nav.items.consentMgmt', href: '/consent-management', icon: FileCheck, minRole: 'admin', keywords: ['consent', 'gdpr'] },
        ],
      },
      {
        label: 'Security & MFA',
        labelKey: 'nav.sections.securityMfa',
        items: [
          { name: 'MFA Management', nameKey: 'nav.items.mfaManagement', href: '/mfa-management', icon: Shield, minRole: 'operator', keywords: ['totp', 'factors', 'reset mfa'] },
          { name: 'Risk Policies', nameKey: 'nav.items.riskPolicies', href: '/risk-policies', icon: Activity, minRole: 'admin', keywords: ['adaptive', 'conditional access'] },
          { name: 'Login Anomalies', nameKey: 'nav.items.loginAnomalies', href: '/login-anomalies', icon: AlertTriangle, minRole: 'operator', keywords: ['impossible travel', 'suspicious'] },
          { name: 'Security Alerts', nameKey: 'nav.items.securityAlerts', href: '/security-alerts', icon: ShieldAlert, minRole: 'operator', keywords: ['incidents', 'threats'] },
          { name: 'Hardware Tokens', nameKey: 'nav.items.hardwareTokens', href: '/hardware-tokens', icon: KeyRound, minRole: 'operator', keywords: ['yubikey', 'otp'] },
          { name: 'Device Trust Approval', nameKey: 'nav.items.deviceTrustApproval', href: '/device-trust-approval', icon: Fingerprint, minRole: 'operator', keywords: ['device approval'] },
          { name: 'MFA Bypass Codes', nameKey: 'nav.items.mfaBypassCodes', href: '/mfa-bypass-codes', icon: ShieldOff, minRole: 'admin', keywords: ['recovery', 'backup codes'] },
          { name: 'Passwordless', nameKey: 'nav.items.passwordless', href: '/passwordless-settings', icon: Link2, minRole: 'admin', keywords: ['magic link', 'webauthn'] },
          { name: 'Security Keys', nameKey: 'nav.items.securityKeys', href: '/security-keys', icon: KeyRound, minRole: 'admin', keywords: ['webauthn', 'fido2', 'passkey'] },
          { name: 'Push Devices', nameKey: 'nav.items.pushDevices', href: '/push-devices', icon: Bell, minRole: 'admin', keywords: ['push mfa', 'mobile'] },
        ],
      },
    ],
  },
  {
    id: 'ziti',
    label: 'Zero Trust Network (Ziti)',
    labelKey: 'nav.domains.ziti',
    icon: Network,
    sections: [
      {
        label: 'Network Access',
        labelKey: 'nav.sections.networkAccess',
        items: [
          { name: 'Zero Trust Access', nameKey: 'nav.items.zeroTrustAccess', href: '/zero-trust', icon: Shield, minRole: 'admin', keywords: ['ztna', 'ziti', 'services'] },
          { name: 'Proxy Routes', nameKey: 'nav.items.proxyRoutes', href: '/proxy-routes', icon: Network, minRole: 'admin', keywords: ['reverse proxy', 'gateway', 'vhost'] },
          { name: 'Network Setup', nameKey: 'nav.items.networkSetup', href: '/ziti-setup', icon: Server, minRole: 'admin', keywords: ['ziti setup', 'controller', 'router'] },
          { name: 'Ziti Network', nameKey: 'nav.items.zitiNetwork', href: '/ziti-network', icon: Globe, minRole: 'admin', keywords: ['openziti', 'identities', 'edge routers'] },
          { name: 'Network Topology', nameKey: 'nav.items.networkTopology', href: '/network-topology', icon: Share2, minRole: 'operator', keywords: ['map', 'overlay', 'graph', 'topology'] },
          { name: 'Ziti Discovery', nameKey: 'nav.items.zitiDiscovery', href: '/ziti-discovery', icon: Search, minRole: 'admin', keywords: ['scan', 'discover services'] },
          { name: 'AI Insights', nameKey: 'nav.items.aiInsights', href: '/ziti-ai-insights', icon: Brain, minRole: 'admin', keywords: ['anomaly', 'risk score', 'quarantine', 'ai'] },
          { name: 'BrowZer', nameKey: 'nav.items.browzer', href: '/browzer-management', icon: Play, minRole: 'admin', keywords: ['browser access', 'clientless'] },
          { name: 'App Publish', nameKey: 'nav.items.appPublish', href: '/app-publish', icon: Upload, minRole: 'admin', keywords: ['publish application', 'expose'] },
          { name: 'Certificates', nameKey: 'nav.items.certificates', href: '/certificates', icon: FileKey, minRole: 'admin', keywords: ['tls', 'pki', 'ca'] },
        ],
      },
      {
        label: 'Devices & Endpoints',
        labelKey: 'nav.sections.devicesEndpoints',
        items: [
          { name: 'Devices', nameKey: 'nav.items.devices', href: '/devices', icon: Smartphone, minRole: 'operator', keywords: ['endpoints', 'posture'] },
          { name: 'Agent Fleet', nameKey: 'nav.items.agentFleet', href: '/agent-fleet', icon: Radio, minRole: 'operator', keywords: ['agents', 'tunneler', 'fleet'] },
          { name: 'Kiosk Policies', nameKey: 'nav.items.kioskPolicies', href: '/kiosk-policies', icon: Lock, minRole: 'admin', keywords: ['kiosk', 'shared device'] },
          { name: 'Remote Support', nameKey: 'nav.items.remoteSupport', href: '/remote-support', icon: Video, minRole: 'operator', keywords: ['screen share', 'assist'] },
        ],
      },
    ],
  },
  {
    id: 'pam',
    label: 'Privileged Access (PAM)',
    labelKey: 'nav.domains.pam',
    icon: KeyRound,
    sections: [
      {
        label: '',
        items: [
          { name: 'PAM Dashboard', nameKey: 'nav.items.pamDashboard', href: '/pam-dashboard', icon: Gauge, minRole: 'admin', keywords: ['pam overview', 'privileged access', 'summary'] },
          { name: 'Connections', nameKey: 'nav.items.connections', href: '/pam-connections', icon: Server, minRole: 'operator', keywords: ['rdm', 'remote desktop manager', 'devolutions', 'rdp', 'ssh', 'vnc', 'connection manager', 'passwordless', 'launch'] },
          { name: 'Windows Apps', nameKey: 'nav.items.windowsApps', href: '/windows-apps', icon: AppWindow, minRole: 'operator', keywords: ['remoteapp', 'ssms', 'published applications', 'rds', 'app catalog', 'windows', 'single app', 'seamless'] },
          { name: 'Quick Links', nameKey: 'nav.items.quickLinks', href: '/quick-links-admin', icon: Link2, minRole: 'admin', keywords: ['support', 'shortcuts', 'launcher', 'teams', 'zoom', 'curate', 'links'] },
          { name: 'Vault Secrets', nameKey: 'nav.items.vaultSecrets', href: '/vault-secrets', icon: KeyRound, minRole: 'admin', keywords: ['pam', 'secrets', 'credentials', 'vault'] },
          { name: 'Rotation Policies', nameKey: 'nav.items.rotationPolicies', href: '/rotation-policies', icon: RefreshCw, minRole: 'admin', keywords: ['password rotation', 'rotate'] },
          { name: 'Privileged Sessions', nameKey: 'nav.items.privilegedSessions', href: '/guacamole-sessions', icon: MonitorPlay, minRole: 'operator', keywords: ['rdp', 'ssh', 'vnc', 'session recording', 'guacamole'] },
        ],
      },
    ],
  },
  {
    id: 'audit',
    label: 'Audit & Reporting',
    labelKey: 'nav.domains.audit',
    icon: FileText,
    sections: [
      {
        label: 'Audit Trail',
        labelKey: 'nav.sections.auditTrail',
        items: [
          { name: 'Audit Logs', nameKey: 'nav.items.auditLogs', href: '/audit-logs', icon: FileText, minRole: 'auditor', keywords: ['events', 'trail', 'reporter'] },
          { name: 'Live Audit Stream', nameKey: 'nav.items.liveAuditStream', href: '/audit/dashboard', icon: Radio, minRole: 'auditor', keywords: ['realtime', 'websocket', 'stream'] },
          { name: 'Unified Audit', nameKey: 'nav.items.unifiedAudit', href: '/unified-audit', icon: Layers, minRole: 'auditor', keywords: ['combined', 'all services'] },
          { name: 'Admin Audit Log', nameKey: 'nav.items.adminAuditLog', href: '/admin-audit-log', icon: ScrollText, minRole: 'auditor', keywords: ['admin actions', 'changes'] },
          { name: 'Audit Archival', nameKey: 'nav.items.auditArchival', href: '/audit-archival', icon: ArchiveRestore, minRole: 'admin', keywords: ['retention', 'archive', 'export'] },
        ],
      },
      {
        label: 'Analytics & Reports',
        labelKey: 'nav.sections.analyticsReports',
        items: [
          { name: 'Login Analytics', nameKey: 'nav.items.loginAnalytics', href: '/login-analytics', icon: Activity, minRole: 'auditor', keywords: ['sign-in', 'trends'] },
          { name: 'Auth Analytics', nameKey: 'nav.items.authAnalytics', href: '/auth-analytics', icon: TrendingUp, minRole: 'auditor', keywords: ['authentication', 'mfa usage'] },
          { name: 'Usage Analytics', nameKey: 'nav.items.usageAnalytics', href: '/usage-analytics', icon: PieChart, minRole: 'auditor', keywords: ['adoption', 'activity'] },
          { name: 'Risk Dashboard', nameKey: 'nav.items.riskDashboard', href: '/risk-dashboard', icon: AlertTriangle, minRole: 'auditor', keywords: ['risk score', 'threats'] },
          { name: 'Compliance', nameKey: 'nav.items.compliance', href: '/compliance-reports', icon: ClipboardList, minRole: 'auditor', keywords: ['soc2', 'iso', 'gdpr', 'reports'] },
          { name: 'Compliance Posture', nameKey: 'nav.items.compliancePosture', href: '/compliance-dashboard', icon: Gauge, minRole: 'auditor', keywords: ['posture', 'controls'] },
          { name: 'Reports', nameKey: 'nav.items.reports', href: '/reports', icon: BarChart3, minRole: 'auditor', keywords: ['scheduled', 'export', 'reporter'] },
        ],
      },
    ],
  },
  {
    id: 'ai',
    label: 'AI & Intelligence',
    labelKey: 'nav.domains.ai',
    icon: Brain,
    sections: [
      {
        label: '',
        items: [
          { name: 'AI Agents', nameKey: 'nav.items.aiAgents', href: '/ai-agents', icon: Bot, minRole: 'admin', keywords: ['assistant', 'automation'] },
          { name: 'Security Posture', nameKey: 'nav.items.securityPosture', href: '/ispm', icon: ShieldCheck, minRole: 'admin', keywords: ['ispm', 'posture management'] },
          { name: 'Identity Intelligence', nameKey: 'nav.items.identityIntelligence', href: '/ai-intelligence', icon: Brain, minRole: 'admin', keywords: ['fusion', 'copilot', 'briefing', 'local ai', 'llm'] },
          { name: 'Recommendations', nameKey: 'nav.items.recommendations', href: '/ai-recommendations', icon: Lightbulb, minRole: 'admin', keywords: ['suggestions', 'insights'] },
          { name: 'Predictions', nameKey: 'nav.items.predictions', href: '/predictive-analytics', icon: TrendingUp, minRole: 'admin', keywords: ['forecast', 'ml'] },
        ],
      },
    ],
  },
  {
    id: 'platform',
    label: 'Platform',
    labelKey: 'nav.domains.platform',
    icon: Settings,
    sections: [
      {
        label: 'System',
        labelKey: 'nav.sections.system',
        items: [
          { name: 'System Health', nameKey: 'nav.items.systemHealth', href: '/system-health', icon: HeartPulse, minRole: 'operator', keywords: ['status', 'services', 'uptime'] },
          { name: 'Organizations', nameKey: 'nav.items.organizations', href: '/organizations', icon: Building2, minRole: 'admin', keywords: ['orgs', 'multi-tenant'] },
          { name: 'Tenant Mgmt', nameKey: 'nav.items.tenantMgmt', href: '/tenant-management', icon: Building2, minRole: 'admin', keywords: ['tenants', 'platform admin', 'branding', 'logo', 'theme', 'colors', 'white label'] },
          { name: 'Email Templates', nameKey: 'nav.items.emailTemplates', href: '/email-templates', icon: Mail, minRole: 'admin', keywords: ['mail', 'templates'] },
          { name: 'Notification Mgmt', nameKey: 'nav.items.notificationMgmt', href: '/notification-admin', icon: Send, minRole: 'admin', keywords: ['broadcast', 'announcements'] },
          { name: 'Webhooks', nameKey: 'nav.items.webhooks', href: '/webhooks', icon: Bell, minRole: 'admin', keywords: ['events', 'integrations', 'callbacks'] },
          { name: 'Settings', nameKey: 'nav.items.settings', href: '/settings', icon: Settings, minRole: 'admin', keywords: ['configuration', 'system settings'] },
        ],
      },
      {
        label: 'Developer',
        labelKey: 'nav.sections.developer',
        items: [
          { name: 'API Explorer', nameKey: 'nav.items.apiExplorer', href: '/api-explorer', icon: Code2, minRole: 'admin', keywords: ['rest', 'try api'] },
          { name: 'OAuth Playground', nameKey: 'nav.items.oauthPlayground', href: '/oauth-playground', icon: Play, minRole: 'admin', keywords: ['token', 'flows', 'debug'] },
          { name: 'API Docs', nameKey: 'nav.items.apiDocs', href: '/api-docs', icon: BookOpen, minRole: 'admin', keywords: ['swagger', 'openapi', 'reference'] },
          { name: 'Developer Settings', nameKey: 'nav.items.developerSettings', href: '/developer-settings', icon: Settings, minRole: 'admin', keywords: ['api keys', 'sdk'] },
          { name: 'Error Catalog', nameKey: 'nav.items.errorCatalog', href: '/error-catalog', icon: AlertTriangle, minRole: 'admin', keywords: ['error codes', 'troubleshooting'] },
        ],
      },
    ],
  },
]

// View modes cap the effective role level so the same config powers the
// admin / management (operator) / reporting (auditor) lenses.
const VIEW_MODE_CAP: Record<ViewMode, MinRole> = {
  admin: 'super_admin',
  management: 'operator',
  reporting: 'auditor',
}

const LEVEL: Record<MinRole, number> = {
  user: 0,
  auditor: 1,
  operator: 2,
  admin: 3,
  super_admin: 4,
}

export interface NavFilter {
  roles: string[]
  viewMode: ViewMode
  query?: string
}

function itemVisible(item: NavItem, domain: NavDomain, filter: NavFilter): boolean {
  const cap = LEVEL[VIEW_MODE_CAP[filter.viewMode]]
  if (LEVEL[item.minRole] > cap) return false
  // Reporting lens focuses the console on personal + audit content.
  if (filter.viewMode === 'reporting' && domain !== 'audit' && domain !== 'home') return false
  return hasMinRole(filter.roles, item.minRole, domain === 'audit')
}

function itemMatches(item: NavItem, section: NavSection, group: NavDomainGroup, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  // Both the translated names/labels and the canonical English ones match, so
  // search works in either language (keywords stay English synonyms).
  const haystack = [
    navItemName(item),
    item.name,
    item.href,
    navSectionLabel(section),
    section.label,
    navDomainLabel(group),
    group.label,
    ...(item.keywords ?? []),
  ]
    .join(' ')
    .toLowerCase()
  return q.split(/\s+/).every((term) => haystack.includes(term))
}

/**
 * Applies role, view-mode and search filtering. Returns only domains/sections
 * that still contain at least one visible item.
 */
export function filterNavigation(filter: NavFilter, groups: NavDomainGroup[] = navigation): NavDomainGroup[] {
  return groups
    .map((group) => ({
      ...group,
      sections: group.sections
        .map((section) => ({
          ...section,
          items: section.items.filter(
            (item) =>
              itemVisible(item, group.id, filter) &&
              itemMatches(item, section, group, filter.query ?? '')
          ),
        }))
        .filter((section) => section.items.length > 0),
    }))
    .filter((group) => group.sections.length > 0)
}

/** All hrefs declared in the navigation config (used by consistency tests). */
export function allNavHrefs(groups: NavDomainGroup[] = navigation): string[] {
  return groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
}

/** A nav item flattened with its domain label — the row shape the command palette renders. */
export interface FlatNavItem extends NavItem {
  domainLabel: string
  domainLabelKey: string
}

/**
 * Flatten domain groups into a single ordered list, carrying each item's
 * domain label. Pass the already-role-filtered groups (from filterNavigation)
 * so the command palette only ever offers pages the user can actually open.
 */
export function flattenNavItems(groups: NavDomainGroup[] = navigation): FlatNavItem[] {
  const out: FlatNavItem[] = []
  for (const g of groups) {
    for (const s of g.sections) {
      for (const item of s.items) {
        out.push({
          ...item,
          domainLabel: g.label || 'Home',
          domainLabelKey: g.labelKey ?? 'nav.domains.home',
        })
      }
    }
  }
  return out
}

/**
 * Rank a flattened item against a lowercased query for the command palette.
 * Higher is better; <= 0 means "no match". Name matches beat keyword matches,
 * and a prefix/word-start match beats a mid-string one, so "use" surfaces
 * "Users" above a page that merely lists "users" as a keyword.
 */
export function scoreNavItem(item: FlatNavItem, q: string): number {
  if (!q) return 1
  // The displayed (translated) name scores exactly like the canonical English
  // one, so typing in either language surfaces the page.
  for (const name of [navItemName(item).toLowerCase(), item.name.toLowerCase()]) {
    if (name === q) return 100
    if (name.startsWith(q)) return 80
    if (new RegExp(`\\b${escapeRegExp(q)}`).test(name)) return 60
    if (name.includes(q)) return 40
  }
  if (i18n.t(item.domainLabelKey).toLowerCase().includes(q)) return 20
  if (item.domainLabel.toLowerCase().includes(q)) return 20
  for (const kw of item.keywords ?? []) {
    if (kw.toLowerCase().includes(q)) return 15
  }
  if (item.href.toLowerCase().includes(q)) return 10
  return 0
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
