import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Database,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DependencyHealth {
  name: string
  status: 'up' | 'degraded' | 'down'
  latency_ms: number
  last_checked: string
  details?: string
}

interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy'
  uptime_seconds: number
  version?: string
  dependencies: DependencyHealth[]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  parts.push(`${minutes}m`)
  return parts.join(' ')
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

const STATUS_CONFIG = {
  healthy: {
    label: 'Healthy',
    bgColor: 'bg-green-50 border-green-200',
    textColor: 'text-green-800',
    icon: CheckCircle2,
    iconColor: 'text-green-600',
  },
  degraded: {
    label: 'Degraded',
    bgColor: 'bg-yellow-50 border-yellow-200',
    textColor: 'text-yellow-800',
    icon: AlertTriangle,
    iconColor: 'text-yellow-600',
  },
  unhealthy: {
    label: 'Unhealthy',
    bgColor: 'bg-red-50 border-red-200',
    textColor: 'text-red-800',
    icon: XCircle,
    iconColor: 'text-red-600',
  },
} as const

const DEP_STATUS_CONFIG = {
  up: {
    dotColor: 'bg-green-500',
    label: 'Up',
    badgeClass: 'bg-green-100 text-green-800 border-green-200',
  },
  degraded: {
    dotColor: 'bg-yellow-500',
    label: 'Degraded',
    badgeClass: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  },
  down: {
    dotColor: 'bg-red-500',
    label: 'Down',
    badgeClass: 'bg-red-100 text-red-800 border-red-200',
  },
} as const

const DEP_ICONS: Record<string, React.ElementType> = {
  PostgreSQL: Database,
  Redis: Server,
  Elasticsearch: Activity,
  OPA: Server,
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SystemHealthPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const {
    data: health,
    isLoading,
    isFetching,
    dataUpdatedAt,
  } = useQuery({
    queryKey: ['system-health'],
    queryFn: () => api_get_health(),
    refetchInterval: 30_000,
  })

  // We use the api helper but the health endpoint might be at a different path
  async function api_get_health(): Promise<HealthResponse> {
    const token = localStorage.getItem('token')
    const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8080'
    const response = await fetch(`${baseURL}/health`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) {
      throw new Error(`Health check failed: ${response.status}`)
    }
    return response.json()
  }

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['system-health'] })
    toast({ title: 'Refreshing', description: 'Checking system health...' })
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">System Health</h1>
        <p className="text-center py-8">Loading health status...</p>
      </div>
    )
  }

  const overallStatus = health?.status || 'unhealthy'
  const config = STATUS_CONFIG[overallStatus]
  const StatusIcon = config.icon

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Health</h1>
          <p className="text-muted-foreground">
            Monitor OpenIDX platform dependencies and uptime
          </p>
        </div>
        <div className="flex items-center gap-3">
          {dataUpdatedAt > 0 && (
            <span className="text-xs text-muted-foreground">
              Last checked: {new Date(dataUpdatedAt).toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={isFetching}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`}
            />
            {isFetching ? 'Checking...' : 'Check Now'}
          </Button>
        </div>
      </div>

      {/* Overall status banner */}
      <div className={`rounded-lg border p-6 ${config.bgColor}`}>
        <div className="flex items-center gap-4">
          <StatusIcon className={`h-10 w-10 ${config.iconColor}`} />
          <div>
            <h2 className={`text-2xl font-bold ${config.textColor}`}>
              System {config.label}
            </h2>
            <div className="flex items-center gap-4 mt-1">
              {health && (
                <>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    Uptime: {formatUptime(health.uptime_seconds)}
                  </div>
                  {health.version && (
                    <Badge variant="outline">{health.version}</Badge>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Dependency cards */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Dependencies</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {(health?.dependencies || []).map((dep) => {
            const depConfig = DEP_STATUS_CONFIG[dep.status]
            const DepIcon = DEP_ICONS[dep.name] || Server

            return (
              <Card key={dep.name}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <DepIcon className="h-5 w-5 text-muted-foreground" />
                      <CardTitle className="text-base">{dep.name}</CardTitle>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`inline-block h-2.5 w-2.5 rounded-full ${depConfig.dotColor}`}
                      />
                      <span
                        className={`text-xs font-medium px-2 py-0.5 rounded-full border ${depConfig.badgeClass}`}
                      >
                        {depConfig.label}
                      </span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Latency</span>
                      <span className="font-mono font-medium">
                        {dep.latency_ms}ms
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Last Checked</span>
                      <span className="text-xs">
                        {formatTimestamp(dep.last_checked)}
                      </span>
                    </div>
                    {dep.details && (
                      <p className="text-xs text-muted-foreground border-t pt-2 mt-2">
                        {dep.details}
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>

      {/* Empty state if no health data */}
      {!health && (
        <Card>
          <CardContent className="py-12 text-center">
            <XCircle className="h-12 w-12 mx-auto text-red-400 mb-4" />
            <CardTitle className="mb-2">Unable to Retrieve Health Status</CardTitle>
            <CardDescription>
              The health endpoint did not respond. Verify that the platform services are running.
            </CardDescription>
            <Button variant="outline" className="mt-4" onClick={handleRefresh}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
