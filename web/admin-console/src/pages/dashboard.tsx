import { useQuery } from '@tanstack/react-query'
import { 
  Users, 
  Shield, 
  Key, 
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { api } from '../lib/api'

interface DashboardStats {
  total_users: number
  active_users: number
  total_groups: number
  total_applications: number
  active_sessions: number
  pending_reviews: number
  security_alerts: number
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
              <div className="flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2">
                  <Users className="h-4 w-4 text-gray-500" />
                  <span className="text-sm">New user created</span>
                </div>
                <span className="text-xs text-gray-500">5 min ago</span>
              </div>
              <div className="flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-gray-500" />
                  <span className="text-sm">Policy updated</span>
                </div>
                <span className="text-xs text-gray-500">1 hour ago</span>
              </div>
              <div className="flex items-center justify-between p-2 hover:bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-gray-500" />
                  <span className="text-sm">App registered</span>
                </div>
                <span className="text-xs text-gray-500">2 hours ago</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
