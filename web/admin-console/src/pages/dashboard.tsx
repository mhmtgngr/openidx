import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Users,
  Shield,
  Key,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Settings,
  Network,
  RefreshCw,
  KeyRound,
  RotateCw,
  MonitorPlay,
} from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import {
  Rocket,
  Eye,
  ShieldCheck,
  Smartphone,
  GitPullRequest,
  Bell,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { api } from '../lib/api'
import i18n from '../i18n'
import { useAuth } from '../lib/auth'
import { roleLevel, ROLE_LEVELS } from '../lib/roles'
import { GettingStarted } from '../components/getting-started'
import { QueryError } from '../components/query-error'

// Matches the /api/v1/dashboard recent_events item.
interface RecentEvent {
  id: string
  type: string
  timestamp: string
  actor?: string
  action?: string
  outcome?: string
  // tolerated legacy shape
  message?: string
}

interface SystemMetrics {
  cpu_usage?: number
  memory_usage?: number
  disk_usage?: number
  uptime_seconds?: number
}

interface ZitiStatus {
  enabled: boolean
  sdk_ready: boolean
  controller_reachable?: boolean
  services_count: number
  identities_count: number
}

interface ZitiSyncStatus {
  unsynced_users: number
  total_users: number
  total_identities: number
}

interface DashboardStats {
  total_users: number
  active_users: number
  active_sessions: number
  pending_reviews: number
  recent_events?: RecentEvent[]
  system_metrics?: SystemMetrics
  // The backend returns security_alerts as an object; older builds returned a
  // bare count. Typed as unknown and normalized so neither shape can crash the
  // render (rendering an object as a React child throws — error #31).
  security_alerts?: unknown
  // Optional / not always present in the current backend response.
  total_applications?: number
  recent_activity?: RecentEvent[]
}

// normalizeAlerts accepts either the object form
// {failed_logins_24h, suspicious_ips, active_threats} or a bare number and
// returns a consistent breakdown + total.
function normalizeAlerts(sa: unknown): {
  failed: number
  suspicious: number
  threats: number
  total: number
} {
  if (typeof sa === 'number') {
    return { failed: sa, suspicious: 0, threats: 0, total: sa }
  }
  if (sa && typeof sa === 'object') {
    const o = sa as Record<string, unknown>
    const failed = Number(o.failed_logins_24h) || 0
    const suspicious = Number(o.suspicious_ips) || 0
    const threats = Number(o.active_threats) || 0
    return { failed, suspicious, threats, total: failed + suspicious + threats }
  }
  return { failed: 0, suspicious: 0, threats: 0, total: 0 }
}

// eventLabel renders a recent event regardless of which field carries the text.
function eventLabel(e: RecentEvent): string {
  if (e.message) return e.message
  const parts = [e.actor, e.action, e.outcome].filter(Boolean)
  return parts.length ? parts.join(' · ') : e.type || i18n.t('pages.dashboard.activity.eventFallback')
}

function relativeTime(timestamp: string): string {
  const now = Date.now()
  const then = new Date(timestamp).getTime()
  const seconds = Math.floor((now - then) / 1000)
  if (seconds < 60) return i18n.t('pages.dashboard.time.justNow')
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return i18n.t('pages.dashboard.time.minAgo', { n: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return i18n.t('pages.dashboard.time.hourAgo', { count: hours })
  const days = Math.floor(hours / 24)
  return i18n.t('pages.dashboard.time.dayAgo', { count: days })
}

function activityIcon(type: string) {
  switch (type) {
    case 'authentication': return Shield
    case 'user_management': return Users
    case 'configuration': return Settings
    default: return Activity
  }
}

// The end-user landing: friendly, task-oriented shortcuts into the personal
// self-service pages a regular user actually has access to — instead of the
// admin stat cards (which linked to /users, /applications, /audit-logs that a
// plain user cannot open) and org-wide analytics.
function PersonalDashboard({ name }: { name?: string }) {
  const { t } = useTranslation()
  const firstName = (name ?? '').trim().split(/\s+/)[0]
  const actions = [
    { titleKey: 'nav.items.myAppsNetwork', descKey: 'pages.dashboard.personal.myNetworkDesc', icon: Rocket, link: '/my-network', color: 'text-primary' },
    { titleKey: 'nav.items.myAccess', descKey: 'pages.dashboard.personal.myAccessDesc', icon: Eye, link: '/my-access', color: 'text-green-600' },
    { titleKey: 'nav.items.mySecurity', descKey: 'pages.dashboard.personal.mySecurityDesc', icon: ShieldCheck, link: '/my-security', color: 'text-purple-600' },
    { titleKey: 'nav.items.myDevices', descKey: 'pages.dashboard.personal.myDevicesDesc', icon: Smartphone, link: '/my-devices', color: 'text-orange-600' },
    { titleKey: 'nav.items.accessRequests', descKey: 'pages.dashboard.personal.accessRequestsDesc', icon: GitPullRequest, link: '/access-requests', color: 'text-sky-600' },
    { titleKey: 'nav.items.notifications', descKey: 'pages.dashboard.personal.notificationsDesc', icon: Bell, link: '/notification-center', color: 'text-rose-600' },
  ]
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          {firstName
            ? t('pages.dashboard.personal.welcome', { name: firstName })
            : t('pages.dashboard.personal.welcomeNoName')}
        </h1>
        <p className="text-muted-foreground">{t('pages.dashboard.personal.subtitle')}</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {actions.map((a) => (
          <Link key={a.link} to={a.link} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer h-full hover:shadow-md transition-shadow">
              <CardHeader className="flex flex-row items-center gap-3 pb-2">
                <a.icon className={`h-6 w-6 ${a.color}`} />
                <CardTitle className="text-base font-semibold">{t(a.titleKey)}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">{t(a.descKey)}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}

export function DashboardPage() {
  const { t } = useTranslation()
  const [period, setPeriod] = useState('30d')
  const { hasRole, user } = useAuth()

  // Persona split: operator+ get the administrative overview; a plain end user
  // gets a personal dashboard instead — and the org-wide admin queries below
  // are gated off for them, so a regular user's dashboard never calls the
  // org-scoped analytics endpoints.
  const isStaff = roleLevel(user?.roles ?? []) >= ROLE_LEVELS.operator

  const { data: stats, isLoading, isError, error } = useQuery({
    queryKey: ['dashboard'],
    // Normalize so every rendered field has a safe default at runtime — the
    // backend can omit numeric counts / arrays entirely, and rendering
    // undefined.toLocaleString() (or mapping over undefined) crashes the page.
    queryFn: async () => {
      const raw = (await api.get<DashboardStats>('/api/v1/dashboard')) ?? ({} as DashboardStats)
      return {
        ...raw,
        total_users: raw.total_users ?? 0,
        active_users: raw.active_users ?? 0,
        active_sessions: raw.active_sessions ?? 0,
        pending_reviews: raw.pending_reviews ?? 0,
        total_applications: raw.total_applications ?? 0,
        recent_events: raw.recent_events ?? [],
        recent_activity: raw.recent_activity ?? [],
      } as DashboardStats
    },
    enabled: isStaff,
  })

  const { data: loginAnalytics } = useQuery({
    queryKey: ['analytics-logins', period],
    queryFn: async () => {
      const raw = await api.get<{ data?: { date: string; successful: number; failed: number }[] }>(`/api/v1/analytics/logins?period=${period}`)
      return { data: raw?.data ?? [] }
    },
    enabled: isStaff,
  })

  const { data: riskAnalytics } = useQuery({
    queryKey: ['analytics-risk', period],
    queryFn: async () => {
      const raw = await api.get<{ data?: { level: string; count: number }[] }>(`/api/v1/analytics/risk?period=${period}`)
      return { data: raw?.data ?? [] }
    },
    enabled: isStaff,
  })

  const { data: eventAnalytics } = useQuery({
    queryKey: ['analytics-events', period],
    queryFn: async () => {
      const raw = await api.get<{ data?: { event_type: string; count: number }[] }>(`/api/v1/analytics/events?period=${period}`)
      return { data: raw?.data ?? [] }
    },
    enabled: isStaff,
  })

  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: async () => {
      const raw = await api.get<ZitiStatus>('/api/v1/access/ziti/status')
      if (!raw) return raw
      return {
        ...raw,
        services_count: raw.services_count ?? 0,
        identities_count: raw.identities_count ?? 0,
      }
    },
    refetchInterval: 15000,
    enabled: isStaff,
  })

  const { data: zitiSync } = useQuery({
    queryKey: ['ziti-sync-status'],
    queryFn: async () => {
      const raw = await api.get<ZitiSyncStatus>('/api/v1/access/ziti/sync/status')
      if (!raw) return raw
      return {
        ...raw,
        unsynced_users: raw.unsynced_users ?? 0,
        total_users: raw.total_users ?? 0,
        total_identities: raw.total_identities ?? 0,
      }
    },
    enabled: isStaff && !!zitiStatus?.enabled,
    refetchInterval: 15000,
  })

  // End users see a personal landing, not the org overview or its stat cards.
  if (!isStaff) {
    return <PersonalDashboard name={user?.name} />
  }

  if (isError) return <QueryError error={error} resource={t('pages.dashboard.resourceName')} />

  const statCards = [
    {
      title: t('pages.dashboard.stats.totalUsers'),
      value: stats?.total_users || 0,
      description: t('pages.dashboard.stats.activeCount', { n: stats?.active_users || 0 }),
      icon: Users,
      color: 'text-primary',
      link: '/users',
    },
    {
      title: t('pages.dashboard.stats.applications'),
      value: stats?.total_applications || 0,
      description: t('pages.dashboard.stats.registeredApps'),
      icon: Key,
      color: 'text-green-600',
      link: '/applications',
    },
    {
      title: t('pages.dashboard.stats.activeSessions'),
      value: stats?.active_sessions || 0,
      description: t('pages.dashboard.stats.currentSessions'),
      icon: Activity,
      color: 'text-purple-600',
      link: '/audit-logs',
    },
    {
      title: t('pages.dashboard.stats.pendingReviews'),
      value: stats?.pending_reviews || 0,
      description: t('pages.dashboard.stats.accessReviews'),
      icon: Clock,
      color: 'text-orange-600',
      link: '/access-reviews',
    },
  ]

  const recentActivity: RecentEvent[] = stats?.recent_events || stats?.recent_activity || []
  const alerts = normalizeAlerts(stats?.security_alerts)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.dashboard')}</h1>
        <p className="text-muted-foreground">
          {t('pages.dashboard.subtitle')}
        </p>
      </div>

      {/* First-run onboarding — self-hides once the required steps are done. */}
      {roleLevel(user?.roles ?? []) >= ROLE_LEVELS.admin && <GettingStarted />}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Link key={stat.title} to={stat.link} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {isLoading ? '...' : stat.value.toLocaleString()}
                </div>
                <p className="text-xs text-muted-foreground">{stat.description}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Alerts and Activity */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-orange-500" />
              {t('pages.dashboard.alerts.title')}
            </CardTitle>
            <CardDescription>{t('pages.dashboard.alerts.subtitle')}</CardDescription>
          </CardHeader>
          <CardContent>
            {alerts.total === 0 ? (
              <div className="flex items-center gap-2 text-green-600">
                <CheckCircle className="h-5 w-5" />
                <span>{t('pages.dashboard.alerts.none')}</span>
              </div>
            ) : (
              <div className="space-y-2">
                {alerts.failed > 0 && (
                  <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{t('pages.dashboard.alerts.failedLogins')}</span>
                    <span className="text-sm font-semibold text-orange-600">{alerts.failed}</span>
                  </div>
                )}
                {alerts.suspicious > 0 && (
                  <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{t('pages.dashboard.alerts.suspiciousIps')}</span>
                    <span className="text-sm font-semibold text-orange-600">{alerts.suspicious}</span>
                  </div>
                )}
                {alerts.threats > 0 && (
                  <div className="flex items-center justify-between p-2 bg-red-50 rounded-lg">
                    <span className="text-sm">{t('pages.dashboard.alerts.activeThreats')}</span>
                    <span className="text-sm font-semibold text-red-600">{alerts.threats}</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-blue-500" />
              {t('pages.dashboard.activity.title')}
            </CardTitle>
            <CardDescription>{t('pages.dashboard.activity.subtitle')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recentActivity.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('pages.dashboard.activity.none')}</p>
              ) : (
                recentActivity.map((item) => {
                  const Icon = activityIcon(item.type)
                  return (
                    <div key={item.id} className="flex items-center justify-between p-2 hover:bg-muted rounded-lg">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm">{eventLabel(item)}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{relativeTime(item.timestamp)}</span>
                    </div>
                  )
                })
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Ziti Network Status */}
      {zitiStatus && (
        <Link to="/ziti-network" className="block">
          <Card className="hover:shadow-md transition-shadow cursor-pointer border-blue-200 bg-blue-50/30">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <Network className="h-4 w-4 text-primary" />
                {t('pages.dashboard.ziti.title')}
                {zitiStatus.controller_reachable ? (
                  <span className="ml-auto flex items-center gap-1.5 text-xs text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                    {t('pages.dashboard.ziti.connected')}
                  </span>
                ) : (
                  <span className="ml-auto flex items-center gap-1.5 text-xs text-red-500">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    {t('pages.dashboard.ziti.disconnected')}
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-6 text-sm">
                <div>
                  <span className="text-2xl font-bold">{zitiStatus.services_count}</span>
                  <span className="text-muted-foreground ml-1.5">{t('pages.dashboard.ziti.services')}</span>
                </div>
                <div>
                  <span className="text-2xl font-bold">{zitiStatus.identities_count}</span>
                  <span className="text-muted-foreground ml-1.5">{t('pages.dashboard.ziti.identities')}</span>
                </div>
                {zitiSync && zitiSync.unsynced_users > 0 && (
                  <div className="flex items-center gap-1.5 text-orange-600">
                    <RefreshCw className="h-3.5 w-3.5" />
                    <span className="text-sm font-medium">{t('pages.dashboard.ziti.unsynced', { n: zitiSync.unsynced_users })}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </Link>
      )}

      {/* Privileged Access (PAM) entry point — admin only */}
      {hasRole('admin') && (
        <Card className="border-purple-200 bg-purple-50/30">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Shield className="h-4 w-4 text-purple-600" />
              {t('pages.dashboard.pam.title')}
            </CardTitle>
            <CardDescription>{t('pages.dashboard.pam.subtitle')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Link to="/pam-dashboard" className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md">
                <Shield className="h-4 w-4 text-purple-600" />
                {t('nav.items.pamDashboard')}
              </Link>
              <Link to="/vault-secrets" className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md">
                <KeyRound className="h-4 w-4 text-purple-600" />
                {t('nav.items.vaultSecrets')}
              </Link>
              <Link to="/rotation-policies" className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md">
                <RotateCw className="h-4 w-4 text-purple-600" />
                {t('nav.items.rotationPolicies')}
              </Link>
              <Link to="/guacamole-sessions" className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md">
                <MonitorPlay className="h-4 w-4 text-purple-600" />
                {t('nav.items.privilegedSessions')}
              </Link>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Analytics Section */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">{t('pages.dashboard.analytics.title')}</h2>
        <div className="flex gap-2">
          {['7d', '30d', '90d'].map((p) => (
            <Button key={p} variant={period === p ? 'default' : 'outline'} size="sm" onClick={() => setPeriod(p)}>
              {p}
            </Button>
          ))}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* Login Activity Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">{t('pages.dashboard.analytics.loginActivity')}</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={loginAnalytics?.data || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Area type="monotone" dataKey="successful" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.3} />
                <Area type="monotone" dataKey="failed" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Risk Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">{t('pages.dashboard.analytics.riskDistribution')}</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={riskAnalytics?.data || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="level" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Event Types */}
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-medium">{t('pages.dashboard.analytics.topEventTypes')}</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={eventAnalytics?.data || []} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fontSize: 12 }} />
                <YAxis type="category" dataKey="event_type" tick={{ fontSize: 11 }} width={150} />
                <Tooltip />
                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
