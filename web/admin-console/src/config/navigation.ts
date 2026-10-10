// Single source of truth for the admin-console navigation.
//
// To add a menu item: add one entry under the right group below (and make sure
// App.tsx has a matching <Route>). navigation.test.ts cross-checks every href
// against App.tsx routes, so a typo or a forgotten route fails CI instead of
// shipping an unreachable page.
//
// The sidebar shows at most NAV_TOP_LEVEL_LIMIT top-level entries (seven
// groups, each a short list); every other page is a child of one of them and
// appears beneath its parent when that part of the console is open. A new
// page is a child unless it is one of the few things an administrator opens
// every day; navigation.test.ts holds the line.
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
  Handshake,
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

// Top-level groups, in the order an administrator thinks: what people reach,
// who they are, what they reach it from, how it is protected, what happened,
// how the platform is set up. Audit feeds the reporter persona
// (compliance_reader unlocks that group alone, see lib/roles.ts).
export type NavDomain = 'home' | 'access' | 'identity' | 'devices' | 'security' | 'audit' | 'settings'

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
  /**
   * Pages that belong under this one. They render indented beneath the parent
   * when it (or one of them) is the current page, and the command palette and
   * breadcrumbs know them. A child the caller may see while the parent is
   * hidden by role shows on its own, so no page is lost to a stricter parent.
   */
  children?: NavItem[]
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
          { name: 'Dashboard', nameKey: 'nav.items.dashboard', href: '/dashboard', icon: LayoutDashboard, minRole: 'user', keywords: ['overview', 'home'],
            children: [
              { name: 'Notifications', nameKey: 'nav.items.notifications', href: '/notification-center', icon: Bell, minRole: 'user', keywords: ['inbox', 'alerts'] },
            ],
          },
          { name: 'My Apps & Network', nameKey: 'nav.items.myAppsNetwork', href: '/my-network', icon: Globe, minRole: 'user', keywords: ['what can i reach', 'connect', 'remote', 'servers', 'access', 'resources', 'apps', 'launcher', 'portal', 'sso', 'sign in', 'windows', 'remoteapp', 'ssms', 'rds', 'quick links', 'shortcuts', 'teams', 'zoom', 'support', 'privileged', 'pam', 'secrets', 'checkout', 'sessions'],
            children: [
              { name: 'Access Requests', nameKey: 'nav.items.accessRequests', href: '/access-requests', icon: GitPullRequest, minRole: 'user', keywords: ['request access', 'approvals'] },
            ],
          },
          { name: 'My Access', nameKey: 'nav.items.myAccess', href: '/my-access', icon: Eye, minRole: 'user', keywords: ['entitlements', 'permissions'] },
          { name: 'My Devices', nameKey: 'nav.items.myDevices', href: '/my-devices', icon: Smartphone, minRole: 'user', keywords: ['phone', 'enrollment'],
            children: [
              { name: 'Trusted Browsers', nameKey: 'nav.items.trustedBrowsers', href: '/trusted-browsers', icon: Monitor, minRole: 'user', keywords: ['remembered'] },
            ],
          },
          { name: 'My Security', nameKey: 'nav.items.mySecurity', href: '/my-security', icon: ShieldCheck, minRole: 'user', keywords: ['security score', 'risk', 'insights', 'mfa'],
            children: [
              { name: 'My Sessions', nameKey: 'nav.items.mySessions', href: '/sessions', icon: Monitor, minRole: 'user', keywords: ['active sessions', 'sign out', 'devices', 'logged in'] },
            ],
          },
          { name: 'My Profile', nameKey: 'nav.items.myProfile', href: '/profile', icon: User, minRole: 'user', keywords: ['account', 'password'] },
        ],
      },
    ],
  },
  {
    id: 'access',
    label: 'Resources & Access',
    labelKey: 'nav.domains.access',
    icon: AppWindow,
    sections: [
      {
        label: '',
        items: [
          { name: 'Applications', nameKey: 'nav.items.applications', href: '/applications', icon: AppWindow, minRole: 'admin', keywords: ['oauth', 'clients', 'sso'],
            children: [
              { name: 'App Publish', nameKey: 'nav.items.appPublish', href: '/app-publish', icon: Upload, minRole: 'admin', keywords: ['publish application', 'expose'] },
              { name: 'SAML Providers', nameKey: 'nav.items.samlProviders', href: '/saml-service-providers', icon: Fingerprint, minRole: 'admin', keywords: ['saml', 'service provider', 'federation'] },
            ],
          },
          { name: 'Network Services', nameKey: 'nav.items.networkServices', href: '/zero-trust', icon: Network, minRole: 'admin', keywords: ['ztna', 'ziti', 'services'],
            children: [
              { name: 'Proxy Routes', nameKey: 'nav.items.proxyRoutes', href: '/proxy-routes', icon: Network, minRole: 'admin', keywords: ['reverse proxy', 'gateway', 'vhost'] },
              { name: 'Upstream Pools', nameKey: 'nav.items.upstreamPools', href: '/upstream-pools', icon: Server, minRole: 'admin', keywords: ['load balancer', 'backends', 'health check', 'weights', 'upstream'] },
              { name: 'BrowZer', nameKey: 'nav.items.browzer', href: '/browzer-management', icon: Play, minRole: 'admin', keywords: ['browser access', 'clientless'] },
              { name: 'Certificates', nameKey: 'nav.items.certificates', href: '/certificates', icon: FileKey, minRole: 'admin', keywords: ['tls', 'pki', 'ca'] },
            ],
          },
          { name: 'Privileged Connections', nameKey: 'nav.items.privilegedConnections', href: '/pam-connections', icon: MonitorPlay, minRole: 'operator', keywords: ['rdm', 'remote desktop manager', 'devolutions', 'rdp', 'ssh', 'vnc', 'connection manager', 'passwordless', 'launch'],
            children: [
              { name: 'Privileged Sessions', nameKey: 'nav.items.privilegedSessions', href: '/guacamole-sessions', icon: MonitorPlay, minRole: 'operator', keywords: ['rdp', 'ssh', 'vnc', 'session recording', 'guacamole'] },
              { name: 'Windows Apps', nameKey: 'nav.items.windowsApps', href: '/windows-apps', icon: AppWindow, minRole: 'operator', keywords: ['remoteapp', 'ssms', 'published applications', 'rds', 'app catalog', 'windows', 'single app', 'seamless'] },
              { name: 'Quick Links', nameKey: 'nav.items.quickLinks', href: '/quick-links-admin', icon: Link2, minRole: 'admin', keywords: ['support', 'shortcuts', 'launcher', 'teams', 'zoom', 'curate', 'links'] },
            ],
          },
          { name: 'PAM Overview', nameKey: 'nav.items.pamOverview', href: '/pam-dashboard', icon: KeyRound, minRole: 'admin', keywords: ['pam overview', 'privileged access', 'summary'],
            children: [
              { name: 'Vault Secrets', nameKey: 'nav.items.vaultSecrets', href: '/vault-secrets', icon: KeyRound, minRole: 'admin', keywords: ['pam', 'secrets', 'credentials', 'vault'] },
              { name: 'Rotation Policies', nameKey: 'nav.items.rotationPolicies', href: '/rotation-policies', icon: RefreshCw, minRole: 'admin', keywords: ['password rotation', 'rotate'] },
            ],
          },
          { name: 'Access Policies', nameKey: 'nav.items.accessPolicies', href: '/policies', icon: Scale, minRole: 'operator', keywords: ['opa', 'rules'],
            children: [
              { name: 'Approval Policies', nameKey: 'nav.items.approvalPolicies', href: '/approval-policies', icon: ShieldCheck, minRole: 'admin', keywords: ['workflow', 'approvers'] },
              { name: 'ABAC Policies', nameKey: 'nav.items.abacPolicies', href: '/abac-policies', icon: Filter, minRole: 'admin', keywords: ['attribute', 'context'] },
              { name: 'Entitlements', nameKey: 'nav.items.entitlements', href: '/entitlements', icon: Package, minRole: 'admin', keywords: ['grants', 'catalog'] },
              { name: 'Assignment Report', nameKey: 'nav.items.assignmentReport', href: '/assignment-report', icon: ClipboardList, minRole: 'admin', keywords: ['assignment', 'enforcement', 'who loses access'] },
            ],
          },
          { name: 'Access Reviews', nameKey: 'nav.items.accessReviews', href: '/access-reviews', icon: ClipboardCheck, minRole: 'operator', keywords: ['recertification', 'review'],
            children: [
              { name: 'Cert Campaigns', nameKey: 'nav.items.certCampaigns', href: '/certification-campaigns', icon: Target, minRole: 'admin', keywords: ['certification', 'campaign'] },
              { name: 'Attestation', nameKey: 'nav.items.attestation', href: '/attestation-campaigns', icon: ClipboardSignature, minRole: 'admin', keywords: ['attest', 'campaign'] },
            ],
          },
          { name: 'Overlay Network', nameKey: 'nav.items.overlayNetwork', href: '/ziti-network', icon: Globe, minRole: 'admin', keywords: ['openziti', 'identities', 'edge routers'],
            children: [
              { name: 'Network Topology', nameKey: 'nav.items.networkTopology', href: '/network-topology', icon: Share2, minRole: 'operator', keywords: ['map', 'overlay', 'graph', 'topology'] },
              { name: 'Network Setup', nameKey: 'nav.items.networkSetup', href: '/ziti-setup', icon: Server, minRole: 'admin', keywords: ['ziti setup', 'controller', 'router'] },
              { name: 'Ziti Discovery', nameKey: 'nav.items.zitiDiscovery', href: '/ziti-discovery', icon: Search, minRole: 'admin', keywords: ['scan', 'discover services'] },
              { name: 'AI Insights', nameKey: 'nav.items.aiInsights', href: '/ziti-ai-insights', icon: Brain, minRole: 'admin', keywords: ['anomaly', 'risk score', 'quarantine', 'ai'] },
            ],
          },
          { name: 'Remote Support', nameKey: 'nav.items.remoteSupport', href: '/remote-support', icon: Video, minRole: 'operator', keywords: ['screen share', 'assist'] },
        ],
      },
    ],
  },
  {
    id: 'identity',
    label: 'Identity',
    labelKey: 'nav.domains.identity',
    icon: Fingerprint,
    sections: [
      {
        label: '',
        items: [
          { name: 'Users', nameKey: 'nav.items.users', href: '/users', icon: Users, minRole: 'operator', keywords: ['people', 'accounts', 'iam'],
            children: [
              { name: 'External Users', nameKey: 'nav.items.externalUsers', href: '/external-users', icon: Handshake, minRole: 'admin', keywords: ['vendor', 'contractor', 'third party', 'sponsor', 'guest'] },
              { name: 'Service Accounts', nameKey: 'nav.items.serviceAccounts', href: '/service-accounts', icon: KeyIcon, minRole: 'admin', keywords: ['machine', 'api accounts'] },
              { name: 'Bulk Operations', nameKey: 'nav.items.bulkOperations', href: '/bulk-operations', icon: Layers, minRole: 'operator', keywords: ['import', 'export', 'csv'] },
            ],
          },
          { name: 'Groups', nameKey: 'nav.items.groups', href: '/groups', icon: Users2, minRole: 'operator', keywords: ['teams', 'membership'] },
          { name: 'Roles', nameKey: 'nav.items.roles', href: '/roles', icon: ShieldCheck, minRole: 'admin', keywords: ['rbac', 'permissions'],
            children: [
              { name: 'Delegations', nameKey: 'nav.items.delegations', href: '/delegations', icon: UserCheck, minRole: 'admin', keywords: ['delegate', 'admin rights'] },
            ],
          },
          { name: 'Organizations', nameKey: 'nav.items.organizations', href: '/organizations', icon: Building2, minRole: 'admin', keywords: ['orgs', 'multi-tenant'],
            children: [
              { name: 'Tenant Mgmt', nameKey: 'nav.items.tenantMgmt', href: '/tenant-management', icon: Building2, minRole: 'admin', keywords: ['tenants', 'platform admin', 'branding', 'logo', 'theme', 'colors', 'white label'] },
            ],
          },
          { name: 'Identity Providers', nameKey: 'nav.items.identityProviders', href: '/identity-providers', icon: KeyIcon, minRole: 'admin', keywords: ['idp', 'oidc', 'saml'],
            children: [
              { name: 'Directories', nameKey: 'nav.items.directories', href: '/directories', icon: FolderSync, minRole: 'admin', keywords: ['ldap', 'active directory', 'sync'] },
              { name: 'Social Providers', nameKey: 'nav.items.socialProviders', href: '/social-providers', icon: Globe, minRole: 'admin', keywords: ['google', 'github', 'social login'] },
              { name: 'Federation', nameKey: 'nav.items.federation', href: '/federation-config', icon: Link2, minRole: 'admin', keywords: ['trust', 'external idp'] },
            ],
          },
          { name: 'Lifecycle', nameKey: 'nav.items.lifecycle', href: '/lifecycle-workflows', icon: Workflow, minRole: 'admin', keywords: ['joiner', 'mover', 'leaver', 'onboarding'],
            children: [
              { name: 'Lifecycle Policies', nameKey: 'nav.items.lifecyclePolicies', href: '/lifecycle-policies', icon: UserMinus, minRole: 'admin', keywords: ['deprovision', 'dormant', 'offboarding'] },
              { name: 'Provisioning Rules', nameKey: 'nav.items.provisioningRules', href: '/provisioning-rules', icon: Workflow, minRole: 'admin', keywords: ['scim', 'sync rules'] },
            ],
          },
          { name: 'Privacy', nameKey: 'nav.items.privacy', href: '/privacy-dashboard', icon: Shield, minRole: 'admin', keywords: ['gdpr', 'data subject'],
            children: [
              { name: 'Consent Mgmt', nameKey: 'nav.items.consentMgmt', href: '/consent-management', icon: FileCheck, minRole: 'admin', keywords: ['consent', 'gdpr'] },
            ],
          },
        ],
      },
    ],
  },
  {
    id: 'devices',
    label: 'Devices',
    labelKey: 'nav.domains.devices',
    icon: Smartphone,
    sections: [
      {
        label: '',
        items: [
          { name: 'Devices', nameKey: 'nav.items.devices', href: '/devices', icon: Smartphone, minRole: 'operator', keywords: ['endpoints', 'posture'],
            children: [
              { name: 'Device Trust Approval', nameKey: 'nav.items.deviceTrustApproval', href: '/device-trust-approval', icon: Fingerprint, minRole: 'operator', keywords: ['device approval'] },
            ],
          },
          { name: 'Agent Fleet', nameKey: 'nav.items.agentFleet', href: '/agent-fleet', icon: Radio, minRole: 'operator', keywords: ['agents', 'tunneler', 'fleet'] },
          { name: 'Kiosk Policies', nameKey: 'nav.items.kioskPolicies', href: '/kiosk-policies', icon: Lock, minRole: 'admin', keywords: ['kiosk', 'shared device'] },
        ],
      },
    ],
  },
  {
    id: 'security',
    label: 'Security',
    labelKey: 'nav.domains.security',
    icon: Shield,
    sections: [
      {
        label: '',
        items: [
          { name: 'MFA', nameKey: 'nav.items.mfa', href: '/mfa-management', icon: Shield, minRole: 'operator', keywords: ['totp', 'factors', 'reset mfa'],
            children: [
              { name: 'Hardware Tokens', nameKey: 'nav.items.hardwareTokens', href: '/hardware-tokens', icon: KeyRound, minRole: 'operator', keywords: ['yubikey', 'otp'] },
              { name: 'Security Keys', nameKey: 'nav.items.securityKeys', href: '/security-keys', icon: KeyRound, minRole: 'admin', keywords: ['webauthn', 'fido2', 'passkey'] },
              { name: 'Push Devices', nameKey: 'nav.items.pushDevices', href: '/push-devices', icon: Bell, minRole: 'admin', keywords: ['push mfa', 'mobile'] },
              { name: 'Passwordless', nameKey: 'nav.items.passwordless', href: '/passwordless-settings', icon: Link2, minRole: 'admin', keywords: ['magic link', 'webauthn'] },
              { name: 'MFA Bypass Codes', nameKey: 'nav.items.mfaBypassCodes', href: '/mfa-bypass-codes', icon: ShieldOff, minRole: 'admin', keywords: ['recovery', 'backup codes'] },
            ],
          },
          { name: 'Sessions', nameKey: 'nav.items.sessions', href: '/sessions', icon: Monitor, minRole: 'operator', keywords: ['active sessions', 'revoke'] },
          { name: 'Risk & Alerts', nameKey: 'nav.items.riskAlerts', href: '/security-alerts', icon: ShieldAlert, minRole: 'operator', keywords: ['incidents', 'threats'],
            children: [
              { name: 'Login Anomalies', nameKey: 'nav.items.loginAnomalies', href: '/login-anomalies', icon: AlertTriangle, minRole: 'operator', keywords: ['impossible travel', 'suspicious'] },
              { name: 'Risk Policies', nameKey: 'nav.items.riskPolicies', href: '/risk-policies', icon: Activity, minRole: 'admin', keywords: ['adaptive', 'conditional access'] },
            ],
          },
          { name: 'Security Posture', nameKey: 'nav.items.securityPosture', href: '/ispm', icon: ShieldCheck, minRole: 'admin', keywords: ['ispm', 'posture management'],
            children: [
              { name: 'AI Agents', nameKey: 'nav.items.aiAgents', href: '/ai-agents', icon: Bot, minRole: 'admin', keywords: ['assistant', 'automation'] },
              { name: 'Identity Intelligence', nameKey: 'nav.items.identityIntelligence', href: '/ai-intelligence', icon: Brain, minRole: 'admin', keywords: ['fusion', 'copilot', 'briefing', 'local ai', 'llm'] },
              { name: 'Recommendations', nameKey: 'nav.items.recommendations', href: '/ai-recommendations', icon: Lightbulb, minRole: 'admin', keywords: ['suggestions', 'insights'] },
              { name: 'Predictions', nameKey: 'nav.items.predictions', href: '/predictive-analytics', icon: TrendingUp, minRole: 'admin', keywords: ['forecast', 'ml'] },
            ],
          },
          { name: 'Enforcement', nameKey: 'nav.items.enforcement', href: '/enforcement', icon: ShieldCheck, minRole: 'admin', keywords: ['observe', 'enforce', 'gates', 'would deny', 'production'] },
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
        label: '',
        items: [
          { name: 'Audit Logs', nameKey: 'nav.items.auditLogs', href: '/audit-logs', icon: FileText, minRole: 'auditor', keywords: ['events', 'trail', 'reporter'],
            children: [
              { name: 'Live Audit Stream', nameKey: 'nav.items.liveAuditStream', href: '/audit/dashboard', icon: Radio, minRole: 'auditor', keywords: ['realtime', 'websocket', 'stream'] },
              { name: 'Unified Audit', nameKey: 'nav.items.unifiedAudit', href: '/unified-audit', icon: Layers, minRole: 'auditor', keywords: ['combined', 'all services'] },
              { name: 'Admin Audit Log', nameKey: 'nav.items.adminAuditLog', href: '/admin-audit-log', icon: ScrollText, minRole: 'auditor', keywords: ['admin actions', 'changes'] },
              { name: 'Audit Archival', nameKey: 'nav.items.auditArchival', href: '/audit-archival', icon: ArchiveRestore, minRole: 'admin', keywords: ['retention', 'archive', 'export'] },
            ],
          },
          { name: 'Analytics', nameKey: 'nav.items.analytics', href: '/login-analytics', icon: TrendingUp, minRole: 'auditor', keywords: ['sign-in', 'trends'],
            children: [
              { name: 'Auth Analytics', nameKey: 'nav.items.authAnalytics', href: '/auth-analytics', icon: TrendingUp, minRole: 'auditor', keywords: ['authentication', 'mfa usage'] },
              { name: 'Usage Analytics', nameKey: 'nav.items.usageAnalytics', href: '/usage-analytics', icon: PieChart, minRole: 'auditor', keywords: ['adoption', 'activity'] },
            ],
          },
          { name: 'Risk Dashboard', nameKey: 'nav.items.riskDashboard', href: '/risk-dashboard', icon: AlertTriangle, minRole: 'auditor', keywords: ['risk score', 'threats'] },
          { name: 'Compliance', nameKey: 'nav.items.compliance', href: '/compliance-reports', icon: ClipboardList, minRole: 'auditor', keywords: ['soc2', 'iso', 'gdpr', 'reports'],
            children: [
              { name: 'Compliance Posture', nameKey: 'nav.items.compliancePosture', href: '/compliance-dashboard', icon: Gauge, minRole: 'auditor', keywords: ['posture', 'controls'] },
            ],
          },
          { name: 'Reports', nameKey: 'nav.items.reports', href: '/reports', icon: BarChart3, minRole: 'auditor', keywords: ['scheduled', 'export', 'reporter'] },
        ],
      },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    labelKey: 'nav.domains.settings',
    icon: Settings,
    sections: [
      {
        label: '',
        items: [
          { name: 'System Health', nameKey: 'nav.items.systemHealth', href: '/system-health', icon: HeartPulse, minRole: 'operator', keywords: ['status', 'services', 'uptime'],
            children: [
              { name: 'Ops Cockpit', nameKey: 'nav.items.opsCockpit', href: '/ops-cockpit', icon: Gauge, minRole: 'operator', keywords: ['operations', 'situational', 'overview', 'command center', 'noc'] },
            ],
          },
          { name: 'Settings', nameKey: 'nav.items.settings', href: '/settings', icon: Settings, minRole: 'admin', keywords: ['configuration', 'system settings'],
            children: [
              { name: 'Email Templates', nameKey: 'nav.items.emailTemplates', href: '/email-templates', icon: Mail, minRole: 'admin', keywords: ['mail', 'templates'] },
            ],
          },
          { name: 'Notification Mgmt', nameKey: 'nav.items.notificationMgmt', href: '/notification-admin', icon: Send, minRole: 'admin', keywords: ['broadcast', 'announcements'],
            children: [
              { name: 'Webhooks', nameKey: 'nav.items.webhooks', href: '/webhooks', icon: Bell, minRole: 'admin', keywords: ['events', 'integrations', 'callbacks'] },
            ],
          },
          { name: 'Developer', nameKey: 'nav.items.developer', href: '/api-explorer', icon: Code2, minRole: 'admin', keywords: ['rest', 'try api'],
            children: [
              { name: 'OAuth Playground', nameKey: 'nav.items.oauthPlayground', href: '/oauth-playground', icon: Play, minRole: 'admin', keywords: ['token', 'flows', 'debug'] },
              { name: 'API Docs', nameKey: 'nav.items.apiDocs', href: '/api-docs', icon: BookOpen, minRole: 'admin', keywords: ['swagger', 'openapi', 'reference'] },
              { name: 'Developer Settings', nameKey: 'nav.items.developerSettings', href: '/developer-settings', icon: Settings, minRole: 'admin', keywords: ['api keys', 'sdk'] },
              { name: 'Error Catalog', nameKey: 'nav.items.errorCatalog', href: '/error-catalog', icon: AlertTriangle, minRole: 'admin', keywords: ['error codes', 'troubleshooting'] },
            ],
          },
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

function itemMatches(item: NavItem, section: NavSection, group: NavDomainGroup, query: string, parent?: NavItem): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  // Both the translated names/labels and the canonical English ones match, so
  // search works in either language (keywords stay English synonyms). A child
  // also answers to its parent's name: "pam" finds the vault under PAM.
  const haystack = [
    navItemName(item),
    item.name,
    item.href,
    navSectionLabel(section),
    section.label,
    navDomainLabel(group),
    group.label,
    ...(item.keywords ?? []),
    ...(parent ? [navItemName(parent), parent.name] : []),
  ]
    .join(' ')
    .toLowerCase()
  return q.split(/\s+/).every((term) => haystack.includes(term))
}

/**
 * The items of one section after role, lens and search filtering. Children
 * stay beneath a visible parent. A child whose parent the caller may not see
 * is lifted to the section itself, and so is every match while searching, so
 * a search result is a flat list of pages rather than a tree with one leaf.
 */
function filterItems(section: NavSection, group: NavDomainGroup, filter: NavFilter): NavItem[] {
  const query = filter.query ?? ''
  const searching = query.trim().length > 0
  const out: NavItem[] = []
  for (const item of section.items) {
    const parentVisible = itemVisible(item, group.id, filter)
    const kids = (item.children ?? []).filter(
      (child) => itemVisible(child, group.id, filter) && itemMatches(child, section, group, query, item),
    )
    const parentMatches = parentVisible && itemMatches(item, section, group, query)
    if (parentVisible && !searching) {
      out.push(kids.length > 0 ? { ...item, children: kids } : { ...item, children: undefined })
      continue
    }
    if (parentMatches) out.push({ ...item, children: undefined })
    for (const child of kids) out.push({ ...child, children: undefined })
  }
  return out
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
        .map((section) => ({ ...section, items: filterItems(section, group, filter) }))
        .filter((section) => section.items.length > 0),
    }))
    .filter((group) => group.sections.length > 0)
}

/** Every item in document order, children right after their parent. */
function walkItems(groups: NavDomainGroup[]): NavItem[] {
  return groups.flatMap((g) =>
    g.sections.flatMap((s) => s.items.flatMap((i) => [i, ...(i.children ?? [])])),
  )
}

/** All hrefs declared in the navigation config, children included (used by consistency tests). */
export function allNavHrefs(groups: NavDomainGroup[] = navigation): string[] {
  return walkItems(groups).map((i) => i.href)
}

/** Top-level entries only: what the sidebar shows before anything is opened. */
export function topLevelNavItems(groups: NavDomainGroup[] = navigation): NavItem[] {
  return groups.flatMap((g) => g.sections.flatMap((s) => s.items))
}

/** The sidebar never shows more than this many top-level entries. */
export const NAV_TOP_LEVEL_LIMIT = 40

/** The trail to a page: its group, then its parent (if any), then itself. */
export interface NavPath {
  group: NavDomainGroup
  parent?: NavItem
  item: NavItem
}

/** Where a pathname sits in the navigation, or null for a page that is not in it. */
export function findNavPath(pathname: string, groups: NavDomainGroup[] = navigation): NavPath | null {
  for (const group of groups) {
    for (const section of group.sections) {
      for (const item of section.items) {
        if (item.href === pathname) return { group, item }
        for (const child of item.children ?? []) {
          if (child.href === pathname) return { group, parent: item, item: child }
        }
      }
    }
  }
  return null
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
        for (const page of [item, ...(item.children ?? [])]) {
          out.push({
            ...page,
            children: undefined,
            domainLabel: g.label || 'Home',
            domainLabelKey: g.labelKey ?? 'nav.domains.home',
          })
        }
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
