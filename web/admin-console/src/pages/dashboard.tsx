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
} from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { api } from '../lib/api'

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
    default: return Activity
  }
}

export function DashboardPage() {
  const [period, setPeriod] = useState('30d')

  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

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
    {
      title: 'Total Users',
      value: stats?.total_users || 0,
      description: `${stats?.active_users || 0} active`,
      icon: Users,
      color: 'text-blue-600',
      link: '/users',
    },
    {
      title: 'Applications',
      value: stats?.total_applications || 0,
      description: 'Registered apps',
      icon: Key,
      color: 'text-green-600',
      link: '/applications',
    },
    {
      title: 'Active Sessions',
      value: stats?.active_sessions || 0,
      description: 'Current sessions',
      icon: Activity,
      color: 'text-purple-600',
      link: '/audit-logs',
    },
    {
      title: 'Pending Reviews',
      value: stats?.pending_reviews || 0,
      description: 'Access reviews',
      icon: Clock,
      color: 'text-orange-600',
      link: '/access-reviews',
    },
  ]

  const recentActivity = stats?.recent_activity || []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your identity platform
        </p>
      </div>

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
              Security Alerts
            </CardTitle>
            <CardDescription>Recent security events requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.security_alerts === 0 ? (
              <div className="flex items-center gap-2 text-green-600">
                <CheckCircle className="h-5 w-5" />
                <span>No active alerts</span>
              </div>
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
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-blue-500" />
              Recent Activity
            </CardTitle>
            <CardDescription>Latest actions in the system</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recentActivity.length === 0 ? (
                <p className="text-sm text-gray-500">No recent activity</p>
              ) : (
                recentActivity.map((item) => {
                  const Icon = activityIcon(item.type)
                  return (
                    <div key={item.id} className="flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-gray-500" />
                        <span className="text-sm">{item.message}</span>
                      </div>
                      <span className="text-xs text-gray-500">{relativeTime(item.timestamp)}</span>
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
      )}

      {/* Analytics Section */}
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
        {/* Login Activity Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Login Activity</CardTitle>
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
            <CardTitle className="text-sm font-medium">Risk Distribution</CardTitle>
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
            <CardTitle className="text-sm font-medium">Top Event Types</CardTitle>
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
