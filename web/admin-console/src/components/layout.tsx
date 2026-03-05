import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  Users2,
  AppWindow,
  ClipboardCheck,
  FileText,
  Settings,
  LogOut,
  Shield,
  Menu,
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
  Rocket,
  Eye,
  Fingerprint,
  KeyRound,
  ShieldOff,
  Link2,
  Activity,
  Search,
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
  Fingerprint as FingerprintIcon,
  Bot,
  Lightbulb,
  Mail,
  UserMinus,
  ClipboardSignature,
  ArchiveRestore,
  FileCheck,
  Send,
} from 'lucide-react'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth, type UserRole } from '../lib/auth'
import { api } from '../lib/api'
import { NotificationBell } from './notification-bell'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Avatar, AvatarFallback } from './ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'

interface NavItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  /** Minimum role required to see this item. 'user' = everyone */
  minRole: UserRole
}

interface NavSection {
  label: string
  /** Minimum role to see this entire section */
  minRole: UserRole
  items: NavItem[]
}

const navigationSections: NavSection[] = [
  // ── Everyone ──
  {
    label: '',
    minRole: 'user',
    items: [
      { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, minRole: 'user' },
      { name: 'My Profile', href: '/profile', icon: User, minRole: 'user' },
      { name: 'My Apps', href: '/app-launcher', icon: Rocket, minRole: 'user' },
      { name: 'My Access', href: '/my-access', icon: Eye, minRole: 'user' },
      { name: 'My Devices', href: '/my-devices', icon: Smartphone, minRole: 'user' },
      { name: 'Trusted Browsers', href: '/trusted-browsers', icon: Monitor, minRole: 'user' },
      { name: 'Access Requests', href: '/access-requests', icon: GitPullRequest, minRole: 'user' },
      { name: 'Client Setup', href: '/client-setup', icon: Smartphone, minRole: 'user' },
      { name: 'Notifications', href: '/notification-center', icon: Bell, minRole: 'user' },
    ],
  },
  // ── Identity (operator+) ──
  {
    label: 'Identity',
    minRole: 'operator',
    items: [
      { name: 'Users', href: '/users', icon: Users, minRole: 'operator' },
      { name: 'Groups', href: '/groups', icon: Users2, minRole: 'operator' },
      { name: 'Roles', href: '/roles', icon: ShieldCheck, minRole: 'admin' },
      { name: 'Directories', href: '/directories', icon: FolderSync, minRole: 'admin' },
      { name: 'Service Accounts', href: '/service-accounts', icon: KeyIcon, minRole: 'admin' },
    ],
  },
  // ── Applications (admin+) ──
  {
    label: 'Applications',
    minRole: 'admin',
    items: [
      { name: 'Applications', href: '/applications', icon: AppWindow, minRole: 'admin' },
      { name: 'Identity Providers', href: '/identity-providers', icon: KeyIcon, minRole: 'admin' },
      { name: 'Provisioning Rules', href: '/provisioning-rules', icon: Workflow, minRole: 'admin' },
      { name: 'Lifecycle Workflows', href: '/lifecycle-workflows', icon: Workflow, minRole: 'admin' },
      { name: 'Social Providers', href: '/social-providers', icon: Globe, minRole: 'admin' },
      { name: 'Federation', href: '/federation-config', icon: Link2, minRole: 'admin' },
    ],
  },
  // ── Network & Access (operator+ for monitoring, admin for config) ──
  {
    label: 'Network & Access',
    minRole: 'operator',
    items: [
      { name: 'Proxy Routes', href: '/proxy-routes', icon: Network, minRole: 'admin' },
      { name: 'Ziti Network', href: '/ziti-network', icon: Shield, minRole: 'operator' },
      { name: 'Ziti Discovery', href: '/ziti-discovery', icon: Search, minRole: 'operator' },
      { name: 'BrowZer', href: '/browzer-management', icon: Globe, minRole: 'admin' },
      { name: 'App Publish', href: '/app-publish', icon: Upload, minRole: 'admin' },
      { name: 'Certificates', href: '/certificates', icon: FileKey, minRole: 'admin' },
      { name: 'Devices', href: '/devices', icon: Smartphone, minRole: 'operator' },
    ],
  },
  // ── Governance (operator+) ──
  {
    label: 'Governance',
    minRole: 'operator',
    items: [
      { name: 'Policies', href: '/policies', icon: Scale, minRole: 'operator' },
      { name: 'Approval Policies', href: '/approval-policies', icon: ShieldCheck, minRole: 'admin' },
      { name: 'Access Reviews', href: '/access-reviews', icon: ClipboardCheck, minRole: 'operator' },
      { name: 'Cert Campaigns', href: '/certification-campaigns', icon: Target, minRole: 'admin' },
      { name: 'Entitlements', href: '/entitlements', icon: Package, minRole: 'operator' },
      { name: 'ABAC Policies', href: '/abac-policies', icon: Filter, minRole: 'admin' },
      { name: 'Sessions', href: '/sessions', icon: Monitor, minRole: 'operator' },
      { name: 'Security Alerts', href: '/security-alerts', icon: ShieldAlert, minRole: 'operator' },
      { name: 'Privacy Dashboard', href: '/privacy-dashboard', icon: Shield, minRole: 'admin' },
      { name: 'Consent Mgmt', href: '/consent-management', icon: FileCheck, minRole: 'admin' },
    ],
  },
  // ── Security & MFA (operator+) ──
  {
    label: 'Security & MFA',
    minRole: 'operator',
    items: [
      { name: 'MFA Management', href: '/mfa-management', icon: Shield, minRole: 'operator' },
      { name: 'Risk Policies', href: '/risk-policies', icon: Activity, minRole: 'admin' },
      { name: 'Login Anomalies', href: '/login-anomalies', icon: AlertTriangle, minRole: 'operator' },
      { name: 'Hardware Tokens', href: '/hardware-tokens', icon: KeyRound, minRole: 'operator' },
      { name: 'Device Trust Approval', href: '/device-trust-approval', icon: Fingerprint, minRole: 'operator' },
      { name: 'MFA Bypass Codes', href: '/mfa-bypass-codes', icon: ShieldOff, minRole: 'admin' },
      { name: 'Passwordless', href: '/passwordless-settings', icon: Link2, minRole: 'admin' },
      { name: 'Security Keys', href: '/security-keys', icon: KeyRound, minRole: 'operator' },
      { name: 'Push Devices', href: '/push-devices', icon: Bell, minRole: 'operator' },
    ],
  },
  // ── Audit & Reports (auditor+) ──
  {
    label: 'Audit & Reports',
    minRole: 'auditor',
    items: [
      { name: 'Audit Logs', href: '/audit-logs', icon: FileText, minRole: 'auditor' },
      { name: 'Unified Audit', href: '/unified-audit', icon: Layers, minRole: 'auditor' },
      { name: 'Admin Audit Log', href: '/admin-audit-log', icon: ScrollText, minRole: 'admin' },
      { name: 'Login Analytics', href: '/login-analytics', icon: Activity, minRole: 'auditor' },
      { name: 'Auth Analytics', href: '/auth-analytics', icon: TrendingUp, minRole: 'auditor' },
      { name: 'Usage Analytics', href: '/usage-analytics', icon: PieChart, minRole: 'auditor' },
      { name: 'Risk Dashboard', href: '/risk-dashboard', icon: AlertTriangle, minRole: 'auditor' },
      { name: 'Compliance', href: '/compliance-reports', icon: ClipboardList, minRole: 'auditor' },
      { name: 'Compliance Posture', href: '/compliance-dashboard', icon: Gauge, minRole: 'auditor' },
      { name: 'Reports', href: '/reports', icon: BarChart3, minRole: 'auditor' },
    ],
  },
  // ── AI & Intelligence (admin+) ──
  {
    label: 'AI & Intelligence',
    minRole: 'admin',
    items: [
      { name: 'AI Agents', href: '/ai-agents', icon: Bot, minRole: 'admin' },
      { name: 'Security Posture', href: '/ispm', icon: ShieldCheck, minRole: 'admin' },
      { name: 'Recommendations', href: '/ai-recommendations', icon: Lightbulb, minRole: 'admin' },
      { name: 'Predictions', href: '/predictive-analytics', icon: TrendingUp, minRole: 'admin' },
    ],
  },
  // ── Enterprise (admin+) ──
  {
    label: 'Enterprise',
    minRole: 'admin',
    items: [
      { name: 'SAML Providers', href: '/saml-service-providers', icon: FingerprintIcon, minRole: 'admin' },
      { name: 'Bulk Operations', href: '/bulk-operations', icon: Layers, minRole: 'admin' },
      { name: 'Email Templates', href: '/email-templates', icon: Mail, minRole: 'admin' },
      { name: 'Lifecycle Policies', href: '/lifecycle-policies', icon: UserMinus, minRole: 'admin' },
      { name: 'Attestation', href: '/attestation-campaigns', icon: ClipboardSignature, minRole: 'admin' },
      { name: 'Audit Archival', href: '/audit-archival', icon: ArchiveRestore, minRole: 'admin' },
    ],
  },
  // ── Developer (admin+) ──
  {
    label: 'Developer',
    minRole: 'admin',
    items: [
      { name: 'API Explorer', href: '/api-explorer', icon: Code2, minRole: 'admin' },
      { name: 'OAuth Playground', href: '/oauth-playground', icon: Play, minRole: 'admin' },
      { name: 'Developer Settings', href: '/developer-settings', icon: Settings, minRole: 'admin' },
      { name: 'Error Catalog', href: '/error-catalog', icon: AlertTriangle, minRole: 'admin' },
    ],
  },
  // ── System (admin+, tenant mgmt super_admin only) ──
  {
    label: 'System',
    minRole: 'admin',
    items: [
      { name: 'System Health', href: '/system-health', icon: HeartPulse, minRole: 'admin' },
      { name: 'Organizations', href: '/organizations', icon: Building2, minRole: 'admin' },
      { name: 'Delegations', href: '/delegations', icon: UserCheck, minRole: 'admin' },
      { name: 'Webhooks', href: '/webhooks', icon: Bell, minRole: 'admin' },
      { name: 'API Docs', href: '/api-docs', icon: BookOpen, minRole: 'admin' },
      { name: 'Settings', href: '/settings', icon: Settings, minRole: 'admin' },
      { name: 'Tenant Mgmt', href: '/tenant-management', icon: Building2, minRole: 'super_admin' },
      { name: 'Notification Mgmt', href: '/notification-admin', icon: Send, minRole: 'admin' },
    ],
  },
]

function ZitiStatusIndicator() {
  const navigate = useNavigate()
  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status-header'],
    queryFn: () => api.get<{ enabled: boolean; controller_reachable?: boolean; services_count: number; identities_count: number }>('/api/v1/access/ziti/status'),
    refetchInterval: 30000,
  })
  const { data: browzerStatus } = useQuery({
    queryKey: ['browzer-status-header'],
    queryFn: () => api.get<{ enabled: boolean; configured?: boolean }>('/api/v1/access/ziti/browzer/status'),
    refetchInterval: 30000,
    enabled: !!zitiStatus?.enabled,
  })

  if (!zitiStatus?.enabled) return null

  return (
    <button
      onClick={() => navigate('/ziti-network')}
      className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-gray-100 transition-colors text-sm"
      title="Ziti Network Status"
    >
      <Network className="h-4 w-4 text-blue-600" />
      {zitiStatus.controller_reachable ? (
        <span className="h-2 w-2 rounded-full bg-green-500" />
      ) : (
        <span className="h-2 w-2 rounded-full bg-red-500" />
      )}
      {browzerStatus?.enabled && browzerStatus?.configured && (
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 bg-blue-50 text-blue-700 border-blue-200">
          BrowZer
        </Badge>
      )}
    </button>
  )
}

export function Layout() {
  const { user, logout, hasRole, hasMinRole } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const navigate = useNavigate()

  const initials = user?.name
    ?.split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase() || 'U'

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? 'w-64' : 'w-16'
        } flex flex-col bg-white border-r transition-all duration-300`}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-4 border-b">
          {sidebarOpen && (
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="text-xl font-bold">OpenIDX</span>
            </div>
          )}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            <Menu className="h-5 w-5" />
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-4 space-y-1">
          {navigationSections
            .filter((section) => hasMinRole(section.minRole))
            .map((section, sIdx) => {
              const visibleItems = section.items.filter(
                (item) => hasMinRole(item.minRole)
              )
              if (visibleItems.length === 0) return null
              return (
                <div key={sIdx}>
                  {section.label && sidebarOpen && (
                    <div className="px-3 pt-4 pb-1 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                      {section.label}
                    </div>
                  )}
                  {!section.label && sIdx > 0 && <div className="my-2 border-t" />}
                  {visibleItems.map((item) => (
                    <NavLink
                      key={item.name}
                      to={item.href}
                      className={({ isActive }) =>
                        `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                          isActive
                            ? 'bg-blue-50 text-blue-700'
                            : 'text-gray-600 hover:bg-gray-100'
                        }`
                      }
                    >
                      <item.icon className="h-5 w-5 flex-shrink-0" />
                      {sidebarOpen && <span className="text-sm">{item.name}</span>}
                    </NavLink>
                  ))}
                </div>
              )
            })}
        </nav>

        {/* User menu */}
        <div className="p-4 border-t">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className={`w-full ${sidebarOpen ? 'justify-start' : 'justify-center'}`}
              >
                <Avatar className="h-8 w-8">
                  <AvatarFallback>{initials}</AvatarFallback>
                </Avatar>
                {sidebarOpen && (
                  <div className="ml-3 text-left">
                    <p className="text-sm font-medium">{user?.name}</p>
                    <p className="text-xs text-gray-500">{user?.email}</p>
                  </div>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <div>My Account</div>
                {user?.roles && user.roles.length > 0 && (
                  <div className="text-xs font-normal text-gray-500 mt-0.5">
                    {user.roles.join(', ')}
                  </div>
                )}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => navigate('/profile')}>
                <User className="mr-2 h-4 w-4" />
                My Profile
              </DropdownMenuItem>
              {hasMinRole('admin') && (
                <DropdownMenuItem onClick={() => navigate('/settings')}>
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={logout} className="text-red-600">
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar with status indicators and notification bell */}
        <header className="h-16 border-b bg-white flex items-center justify-end px-8 gap-4">
          {hasMinRole('operator') && <ZitiStatusIndicator />}
          <NotificationBell />
        </header>
        <main className="flex-1 overflow-auto">
          <div className="p-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
