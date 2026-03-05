import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
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
  Laptop,
  AppWindow,
  UserCircle,
  Rocket,
  ArrowRight,
  Lock,
  Globe,
  Bell,
  Smartphone,
  FolderKey,
  FileText,
  ClipboardCheck,
  BarChart3,
  ShieldAlert,
  Eye,
  Scale,
} from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'

interface ActivityItem {
  id: string
  type: string
  message: string
  actor_id?: string
  actor_name?: string
  timestamp: string
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

interface AuthStatistics {
  total_logins: number
  successful_logins: number
  failed_logins: number
  mfa_usage: number
  logins_by_method: Record<string, number>
}

interface DashboardStats {
  total_users: number
  active_users: number
  total_groups: number
  total_applications: number
  active_sessions: number
  pending_reviews: number
  security_alerts: number
  recent_activity: ActivityItem[]
  auth_stats: AuthStatistics
  security_alert_details?: { message: string; count: number; timestamp: string }[]
}

function relativeTime(timestamp: string): string {
  const now = Date.now()
  const then = new Date(timestamp).getTime()
  const seconds = Math.floor((now - then) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`
  const days = Math.floor(hours / 24)
  return `${days} day${days > 1 ? 's' : ''} ago`
}

function activityIcon(type: string) {
  switch (type) {
    case 'authentication': return Shield
    case 'user_management': return Users
    case 'configuration': return Settings
    case 'audit': return FileText
    default: return Activity
  }
}

// ─── Shared: Activity List ────────────────────────────────────────

function ActivityList({ items, emptyText = 'No recent activity' }: { items: ActivityItem[]; emptyText?: string }) {
  return (
    <div className="space-y-2">
      {items.length === 0 ? (
        <p className="text-sm text-gray-500">{emptyText}</p>
      ) : (
        items.map((item) => {
          const Icon = activityIcon(item.type)
          return (
            <div key={item.id} className="flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg">
              <div className="flex items-center gap-2">
                <Icon className="h-4 w-4 text-gray-500" />
                <span className="text-sm">{item.message}</span>
              </div>
              <span className="text-xs text-gray-500 whitespace-nowrap ml-2">{relativeTime(item.timestamp)}</span>
            </div>
          )
        })
      )}
    </div>
  )
}

// ─── Shared: Ziti Network Card ────────────────────────────────────

function ZitiNetworkCard({ zitiStatus, zitiSync, linkTo }: { zitiStatus: ZitiStatus; zitiSync?: ZitiSyncStatus | null; linkTo: string }) {
  return (
    <Link to={linkTo} className="block">
      <Card className="hover:shadow-md transition-shadow cursor-pointer border-blue-200 bg-blue-50/30">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <Network className="h-4 w-4 text-blue-600" />
            Zero Trust Network
            {zitiStatus.controller_reachable ? (
              <span className="ml-auto flex items-center gap-1.5 text-xs text-green-600">
                <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                Connected
              </span>
            ) : (
              <span className="ml-auto flex items-center gap-1.5 text-xs text-red-500">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                Disconnected
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-2xl font-bold">{zitiStatus.services_count}</span>
              <span className="text-muted-foreground ml-1.5">services</span>
            </div>
            <div>
              <span className="text-2xl font-bold">{zitiStatus.identities_count}</span>
              <span className="text-muted-foreground ml-1.5">identities</span>
            </div>
            {zitiSync && zitiSync.unsynced_users > 0 && (
              <div className="flex items-center gap-1.5 text-orange-600">
                <RefreshCw className="h-3.5 w-3.5" />
                <span className="text-sm font-medium">{zitiSync.unsynced_users} users unsynced</span>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}

// ─── Shared: Analytics Charts ─────────────────────────────────────

function AnalyticsSection({ period, setPeriod }: { period: string; setPeriod: (p: string) => void }) {
  const { data: loginAnalytics } = useQuery({
    queryKey: ['analytics-logins', period],
    queryFn: () => api.get<{ data: { date: string; successful: number; failed: number }[] }>(`/api/v1/analytics/logins?period=${period}`),
  })
  const { data: riskAnalytics } = useQuery({
    queryKey: ['analytics-risk', period],
    queryFn: () => api.get<{ data: { level: string; count: number }[] }>(`/api/v1/analytics/risk?period=${period}`),
  })
  const { data: eventAnalytics } = useQuery({
    queryKey: ['analytics-events', period],
    queryFn: () => api.get<{ data: { event_type: string; count: number }[] }>(`/api/v1/analytics/events?period=${period}`),
  })

  return (
    <>
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Analytics</h2>
        <div className="flex gap-2">
          {['7d', '30d', '90d'].map((p) => (
            <Button key={p} variant={period === p ? 'default' : 'outline'} size="sm" onClick={() => setPeriod(p)}>
              {p}
            </Button>
          ))}
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Login Activity</CardTitle></CardHeader>
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
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Risk Distribution</CardTitle></CardHeader>
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
        <Card className="md:col-span-2">
          <CardHeader><CardTitle className="text-sm font-medium">Top Event Types</CardTitle></CardHeader>
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
    </>
  )
}

// ═══════════════════════════════════════════════════════════════════
// USER Dashboard — regular end-user view
// ═══════════════════════════════════════════════════════════════════

function UserDashboard() {
  const { user } = useAuth()
  const firstName = user?.name?.split(' ')[0] || 'there'

  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 15000,
  })

  const { data: stats } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

  const hasApps = (stats?.total_applications || 0) > 0
  const hasMfa = (stats?.auth_stats?.mfa_usage || 0) > 0
  const hasZiti = zitiStatus?.enabled && zitiStatus?.controller_reachable

  const checklist = [
    { label: 'Set up your profile', done: !!user?.name, href: '/profile', icon: UserCircle },
    { label: 'Enable multi-factor authentication', done: hasMfa, href: '/mfa-management', icon: Lock },
    { label: 'Browse available applications', done: hasApps, href: '/app-launcher', icon: AppWindow },
    { label: 'Register a trusted device', done: false, href: '/my-devices', icon: Smartphone },
  ]
  const completedCount = checklist.filter((c) => c.done).length
  const allDone = completedCount === checklist.length

  const quickActions = [
    { label: 'My Applications', description: 'Launch your apps', href: '/app-launcher', icon: AppWindow, color: 'text-blue-600 bg-blue-50' },
    { label: 'My Access', description: 'View permissions & roles', href: '/my-access', icon: FolderKey, color: 'text-green-600 bg-green-50' },
    { label: 'My Devices', description: 'Manage trusted devices', href: '/my-devices', icon: Laptop, color: 'text-purple-600 bg-purple-50' },
    { label: 'Notifications', description: 'Alerts & updates', href: '/notification-center', icon: Bell, color: 'text-orange-600 bg-orange-50' },
  ]

  const recentActivity = (stats?.recent_activity || [])
    .filter((a) => a.actor_id === user?.id || !a.actor_id)
    .slice(0, 5)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Welcome back, {firstName}</h1>
        <p className="text-muted-foreground">Here&apos;s what&apos;s happening with your account</p>
      </div>

      {/* Getting Started */}
      {!allDone && (
        <Card className="border-blue-200 bg-gradient-to-r from-blue-50 to-indigo-50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Rocket className="h-5 w-5 text-blue-600" />
              Getting Started
            </CardTitle>
            <CardDescription>Complete these steps to secure your account ({completedCount}/{checklist.length})</CardDescription>
            <div className="mt-2 h-2 w-full rounded-full bg-blue-100">
              <div className="h-2 rounded-full bg-blue-600 transition-all" style={{ width: `${(completedCount / checklist.length) * 100}%` }} />
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-2 sm:grid-cols-2">
              {checklist.map((item) => (
                <Link key={item.label} to={item.href} className={`flex items-center gap-3 rounded-lg p-3 transition-colors ${item.done ? 'bg-green-50 text-green-700' : 'bg-white hover:bg-blue-50'}`}>
                  {item.done ? <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" /> : <item.icon className="h-5 w-5 text-blue-500 flex-shrink-0" />}
                  <span className={`text-sm font-medium ${item.done ? 'line-through opacity-60' : ''}`}>{item.label}</span>
                  {!item.done && <ArrowRight className="h-4 w-4 ml-auto text-gray-400" />}
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick Actions */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {quickActions.map((action) => (
          <Link key={action.label} to={action.href} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow h-full">
              <CardContent className="flex items-center gap-4 p-5">
                <div className={`rounded-xl p-3 ${action.color}`}><action.icon className="h-6 w-6" /></div>
                <div>
                  <p className="font-semibold text-sm">{action.label}</p>
                  <p className="text-xs text-muted-foreground">{action.description}</p>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Ziti + Activity */}
      <div className="grid gap-4 md:grid-cols-2">
        {hasZiti && (
          <Link to="/client-setup" className="block">
            <Card className="hover:shadow-md transition-shadow cursor-pointer border-blue-200 bg-blue-50/30 h-full">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <Globe className="h-4 w-4 text-blue-600" />
                  Secure Network
                  <span className="ml-auto flex items-center gap-1.5 text-xs text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                    Protected
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-3">Your connection is secured with zero-trust networking.</p>
                <div className="flex items-center gap-4 text-sm">
                  <div><span className="text-xl font-bold">{zitiStatus?.services_count || 0}</span><span className="text-muted-foreground ml-1">apps available</span></div>
                </div>
                <p className="text-xs text-blue-600 mt-3 flex items-center gap-1">Set up your secure client <ArrowRight className="h-3 w-3" /></p>
              </CardContent>
            </Card>
          </Link>
        )}
        <Card className={hasZiti ? '' : 'md:col-span-2'}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-medium"><Activity className="h-4 w-4 text-blue-500" />My Recent Activity</CardTitle>
          </CardHeader>
          <CardContent><ActivityList items={recentActivity} /></CardContent>
        </Card>
      </div>

      {/* Account Security */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm font-medium"><Shield className="h-4 w-4 text-green-500" />Account Security</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Lock className={`h-5 w-5 ${hasMfa ? 'text-green-500' : 'text-orange-500'}`} />
              <div>
                <p className="text-sm font-medium">Multi-Factor Auth</p>
                <p className={`text-xs ${hasMfa ? 'text-green-600' : 'text-orange-600'}`}>{hasMfa ? 'Enabled' : 'Not set up'}</p>
              </div>
              {!hasMfa && <Link to="/mfa-management" className="ml-auto"><Button size="sm" variant="outline" className="text-xs">Enable</Button></Link>}
            </div>
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Smartphone className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-sm font-medium">Trusted Devices</p>
                <p className="text-xs text-muted-foreground"><Link to="/my-devices" className="text-blue-600 hover:underline">Manage</Link></p>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <Key className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-sm font-medium">Active Sessions</p>
                <p className="text-xs text-muted-foreground">{stats?.active_sessions || 0} active</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════
// AUDITOR Dashboard — compliance & audit focus
// ═══════════════════════════════════════════════════════════════════

function AuditorDashboard() {
  const { user } = useAuth()
  const firstName = user?.name?.split(' ')[0] || 'there'
  const [period, setPeriod] = useState('30d')

  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

  const recentActivity = stats?.recent_activity || []

  const statCards = [
    { title: 'Active Sessions', value: stats?.active_sessions || 0, description: 'Across all users', icon: Activity, color: 'text-blue-600', link: '/audit-logs' },
    { title: 'Security Alerts', value: stats?.security_alerts || 0, description: 'Requiring review', icon: ShieldAlert, color: 'text-red-600', link: '/security-alerts' },
    { title: 'Pending Reviews', value: stats?.pending_reviews || 0, description: 'Access reviews', icon: ClipboardCheck, color: 'text-orange-600', link: '/access-reviews' },
    { title: 'Total Users', value: stats?.total_users || 0, description: `${stats?.active_users || 0} active`, icon: Users, color: 'text-green-600', link: '/audit-logs' },
  ]

  const quickActions = [
    { label: 'Audit Logs', description: 'Review system events', href: '/audit-logs', icon: FileText, color: 'text-blue-600 bg-blue-50' },
    { label: 'Compliance Reports', description: 'View compliance status', href: '/compliance-reports', icon: ClipboardCheck, color: 'text-green-600 bg-green-50' },
    { label: 'Risk Dashboard', description: 'Monitor risk levels', href: '/risk-dashboard', icon: AlertTriangle, color: 'text-red-600 bg-red-50' },
    { label: 'Login Analytics', description: 'Authentication patterns', href: '/login-analytics', icon: BarChart3, color: 'text-purple-600 bg-purple-50' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Auditor Dashboard</h1>
        <p className="text-muted-foreground">Welcome back, {firstName} — compliance and security overview</p>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Link key={stat.title} to={stat.link} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{isLoading ? '...' : stat.value.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">{stat.description}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {quickActions.map((action) => (
          <Link key={action.label} to={action.href} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow h-full">
              <CardContent className="flex items-center gap-4 p-5">
                <div className={`rounded-xl p-3 ${action.color}`}><action.icon className="h-6 w-6" /></div>
                <div>
                  <p className="font-semibold text-sm">{action.label}</p>
                  <p className="text-xs text-muted-foreground">{action.description}</p>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Security Alerts + Activity */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-orange-500" />Security Alerts</CardTitle>
            <CardDescription>Events requiring your review</CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.security_alerts === 0 ? (
              <div className="flex items-center gap-2 text-green-600"><CheckCircle className="h-5 w-5" /><span>No active alerts</span></div>
            ) : (
              <div className="space-y-2">
                {stats?.security_alert_details?.map((alert, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{alert.message} ({alert.count}x)</span>
                    <span className="text-xs text-orange-600">{relativeTime(alert.timestamp)}</span>
                  </div>
                )) || (
                  <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{stats?.security_alerts} failed authentication attempts (24h)</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Activity className="h-5 w-5 text-blue-500" />System Activity</CardTitle>
            <CardDescription>Latest auditable events</CardDescription>
          </CardHeader>
          <CardContent><ActivityList items={recentActivity.slice(0, 8)} /></CardContent>
        </Card>
      </div>

      {/* Auth Stats Summary */}
      {stats?.auth_stats && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-medium"><Shield className="h-4 w-4 text-blue-500" />Authentication Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-4">
              <div className="text-center p-3 rounded-lg bg-green-50">
                <div className="text-2xl font-bold text-green-700">{stats.auth_stats.successful_logins}</div>
                <p className="text-xs text-green-600">Successful Logins</p>
              </div>
              <div className="text-center p-3 rounded-lg bg-red-50">
                <div className="text-2xl font-bold text-red-700">{stats.auth_stats.failed_logins}</div>
                <p className="text-xs text-red-600">Failed Logins</p>
              </div>
              <div className="text-center p-3 rounded-lg bg-blue-50">
                <div className="text-2xl font-bold text-blue-700">{stats.auth_stats.mfa_usage}%</div>
                <p className="text-xs text-blue-600">MFA Adoption</p>
              </div>
              <div className="text-center p-3 rounded-lg bg-purple-50">
                <div className="text-2xl font-bold text-purple-700">{stats.auth_stats.total_logins}</div>
                <p className="text-xs text-purple-600">Total Logins</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Analytics */}
      <AnalyticsSection period={period} setPeriod={setPeriod} />
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════
// OPERATOR Dashboard — day-to-day operations focus
// ═══════════════════════════════════════════════════════════════════

function OperatorDashboard() {
  const { user } = useAuth()
  const firstName = user?.name?.split(' ')[0] || 'there'
  const [period, setPeriod] = useState('30d')

  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 15000,
  })

  const { data: zitiSync } = useQuery({
    queryKey: ['ziti-sync-status'],
    queryFn: () => api.get<ZitiSyncStatus>('/api/v1/access/ziti/sync/status'),
    enabled: !!zitiStatus?.enabled,
    refetchInterval: 15000,
  })

  const recentActivity = stats?.recent_activity || []

  const statCards = [
    { title: 'Total Users', value: stats?.total_users || 0, description: `${stats?.active_users || 0} active`, icon: Users, color: 'text-blue-600', link: '/users' },
    { title: 'Active Sessions', value: stats?.active_sessions || 0, description: 'Current sessions', icon: Activity, color: 'text-purple-600', link: '/sessions' },
    { title: 'Security Alerts', value: stats?.security_alerts || 0, description: 'Needs attention', icon: ShieldAlert, color: 'text-red-600', link: '/security-alerts' },
    { title: 'Pending Reviews', value: stats?.pending_reviews || 0, description: 'Access reviews', icon: Clock, color: 'text-orange-600', link: '/access-reviews' },
  ]

  const quickActions = [
    { label: 'Manage Users', description: 'Create, edit, disable users', href: '/users', icon: Users, color: 'text-blue-600 bg-blue-50' },
    { label: 'Manage Groups', description: 'Group membership', href: '/groups', icon: Users, color: 'text-green-600 bg-green-50' },
    { label: 'Access Reviews', description: 'Review access requests', href: '/access-reviews', icon: ClipboardCheck, color: 'text-orange-600 bg-orange-50' },
    { label: 'Security Alerts', description: 'Investigate incidents', href: '/security-alerts', icon: ShieldAlert, color: 'text-red-600 bg-red-50' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Operations Dashboard</h1>
        <p className="text-muted-foreground">Welcome back, {firstName} — here&apos;s your operational overview</p>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Link key={stat.title} to={stat.link} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{isLoading ? '...' : stat.value.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">{stat.description}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {quickActions.map((action) => (
          <Link key={action.label} to={action.href} className="block transition-transform hover:scale-[1.02]">
            <Card className="cursor-pointer hover:shadow-md transition-shadow h-full">
              <CardContent className="flex items-center gap-4 p-5">
                <div className={`rounded-xl p-3 ${action.color}`}><action.icon className="h-6 w-6" /></div>
                <div>
                  <p className="font-semibold text-sm">{action.label}</p>
                  <p className="text-xs text-muted-foreground">{action.description}</p>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Alerts + Activity */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-orange-500" />Security Alerts</CardTitle>
            <CardDescription>Issues requiring operator action</CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.security_alerts === 0 ? (
              <div className="flex items-center gap-2 text-green-600"><CheckCircle className="h-5 w-5" /><span>No active alerts</span></div>
            ) : (
              <div className="space-y-2">
                {stats?.security_alert_details?.map((alert, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{alert.message} ({alert.count}x)</span>
                    <span className="text-xs text-orange-600">{relativeTime(alert.timestamp)}</span>
                  </div>
                )) || (
                  <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{stats?.security_alerts} failed authentication attempts (24h)</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Activity className="h-5 w-5 text-blue-500" />Recent Activity</CardTitle>
            <CardDescription>Latest system actions</CardDescription>
          </CardHeader>
          <CardContent><ActivityList items={recentActivity.slice(0, 8)} /></CardContent>
        </Card>
      </div>

      {/* Ziti Network */}
      {zitiStatus?.enabled && <ZitiNetworkCard zitiStatus={zitiStatus} zitiSync={zitiSync} linkTo="/ziti-network" />}

      {/* Analytics */}
      <AnalyticsSection period={period} setPeriod={setPeriod} />
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════
// ADMIN / SUPER_ADMIN Dashboard — full platform overview
// ═══════════════════════════════════════════════════════════════════

function AdminDashboard() {
  const { user, hasMinRole } = useAuth()
  const firstName = user?.name?.split(' ')[0] || 'Admin'
  const [period, setPeriod] = useState('30d')
  const isSuperAdmin = hasMinRole('super_admin')

  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

  const { data: zitiStatus } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 15000,
  })

  const { data: zitiSync } = useQuery({
    queryKey: ['ziti-sync-status'],
    queryFn: () => api.get<ZitiSyncStatus>('/api/v1/access/ziti/sync/status'),
    enabled: !!zitiStatus?.enabled,
    refetchInterval: 15000,
  })

  const statCards = [
    { title: 'Total Users', value: stats?.total_users || 0, description: `${stats?.active_users || 0} active`, icon: Users, color: 'text-blue-600', link: '/users' },
    { title: 'Applications', value: stats?.total_applications || 0, description: 'Registered apps', icon: Key, color: 'text-green-600', link: '/applications' },
    { title: 'Active Sessions', value: stats?.active_sessions || 0, description: 'Current sessions', icon: Activity, color: 'text-purple-600', link: '/audit-logs' },
    { title: 'Pending Reviews', value: stats?.pending_reviews || 0, description: 'Access reviews', icon: Clock, color: 'text-orange-600', link: '/access-reviews' },
  ]

  const recentActivity = stats?.recent_activity || []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          {isSuperAdmin ? 'Super Admin Dashboard' : 'Admin Dashboard'}
        </h1>
        <p className="text-muted-foreground">Welcome back, {firstName} — here&apos;s your platform overview</p>
      </div>

      {/* Super Admin: Tenant notice */}
      {isSuperAdmin && (
        <Card className="border-purple-200 bg-purple-50/30">
          <CardContent className="flex items-center gap-4 p-4">
            <Scale className="h-5 w-5 text-purple-600" />
            <div className="flex-1">
              <p className="text-sm font-medium">Super Admin Access</p>
              <p className="text-xs text-muted-foreground">You have cross-tenant management privileges</p>
            </div>
            <Link to="/tenant-management"><Button size="sm" variant="outline">Manage Tenants</Button></Link>
          </CardContent>
        </Card>
      )}

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
                <div className="text-2xl font-bold">{isLoading ? '...' : stat.value.toLocaleString()}</div>
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
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-orange-500" />Security Alerts</CardTitle>
            <CardDescription>Recent security events requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.security_alerts === 0 ? (
              <div className="flex items-center gap-2 text-green-600"><CheckCircle className="h-5 w-5" /><span>No active alerts</span></div>
            ) : (
              <div className="space-y-2">
                {stats?.security_alert_details?.map((alert, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{alert.message} ({alert.count}x)</span>
                    <span className="text-xs text-orange-600">{relativeTime(alert.timestamp)}</span>
                  </div>
                )) || (
                  <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                    <span className="text-sm">{stats?.security_alerts} failed authentication attempts (24h)</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Activity className="h-5 w-5 text-blue-500" />Recent Activity</CardTitle>
            <CardDescription>Latest actions in the system</CardDescription>
          </CardHeader>
          <CardContent><ActivityList items={recentActivity} /></CardContent>
        </Card>
      </div>

      {/* Ziti Network */}
      {zitiStatus?.enabled && <ZitiNetworkCard zitiStatus={zitiStatus} zitiSync={zitiSync} linkTo="/ziti-network" />}

      {/* Analytics */}
      <AnalyticsSection period={period} setPeriod={setPeriod} />
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════
// Main Dashboard — routes to role-specific view
// ═══════════════════════════════════════════════════════════════════

export function DashboardPage() {
  const { highestRole } = useAuth()

  switch (highestRole) {
    case 'super_admin':
    case 'admin':
      return <AdminDashboard />
    case 'operator':
      return <OperatorDashboard />
    case 'auditor':
      return <AuditorDashboard />
    default:
      return <UserDashboard />
  }
}
