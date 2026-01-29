import { useQuery } from '@tanstack/react-query'
import {
  Users,
  Shield,
  Key,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Settings
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { api } from '../lib/api'

interface ActivityItem {
  id: string
  type: string
  message: string
  actor_id?: string
  actor_name?: string
  timestamp: string
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
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api.get<DashboardStats>('/api/v1/dashboard'),
  })

  const statCards = [
    {
      title: 'Total Users',
      value: stats?.total_users || 0,
      description: `${stats?.active_users || 0} active`,
      icon: Users,
      color: 'text-blue-600',
    },
    {
      title: 'Applications',
      value: stats?.total_applications || 0,
      description: 'Registered apps',
      icon: Key,
      color: 'text-green-600',
    },
    {
      title: 'Active Sessions',
      value: stats?.active_sessions || 0,
      description: 'Current sessions',
      icon: Activity,
      color: 'text-purple-600',
    },
    {
      title: 'Pending Reviews',
      value: stats?.pending_reviews || 0,
      description: 'Access reviews',
      icon: Clock,
      color: 'text-orange-600',
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
          <Card key={stat.title}>
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
                <div className="flex items-center justify-between p-2 bg-orange-50 rounded-lg">
                  <span className="text-sm">Multiple failed login attempts</span>
                  <span className="text-xs text-orange-600">2 hours ago</span>
                </div>
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
    </div>
  )
}
