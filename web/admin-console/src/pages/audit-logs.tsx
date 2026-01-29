import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Search, Download, Shield, User, Settings, Database, AlertTriangle, CheckCircle, XCircle, Filter, Calendar, TrendingUp, BarChart3, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AuditEvent {
  id: string
  timestamp: string
  event_type: string
  category: string
  action: string
  outcome: string
  actor_id: string
  actor_type: string
  actor_ip: string
  target_id: string
  target_type: string
  resource_id: string
  details: Record<string, unknown>
  session_id: string
  request_id: string
}

interface AuditStatistics {
  total_events: number
  by_type: Record<string, number>
  by_outcome: Record<string, number>
  by_category: Record<string, number>
  events_per_day: Array<{ date: string; count: number }>
  failed_auth_count: number
  success_rate: number
}

const eventTypeIcons: Record<string, React.ReactNode> = {
  authentication: <Shield className="h-4 w-4" />,
  authorization: <Shield className="h-4 w-4" />,
  user_management: <User className="h-4 w-4" />,
  group_management: <User className="h-4 w-4" />,
  role_management: <User className="h-4 w-4" />,
  configuration: <Settings className="h-4 w-4" />,
  data_access: <Database className="h-4 w-4" />,
  system: <Settings className="h-4 w-4" />,
}

const eventTypeColors: Record<string, string> = {
  authentication: 'bg-blue-100 text-blue-800',
  authorization: 'bg-purple-100 text-purple-800',
  user_management: 'bg-green-100 text-green-800',
  group_management: 'bg-teal-100 text-teal-800',
  role_management: 'bg-cyan-100 text-cyan-800',
  configuration: 'bg-orange-100 text-orange-800',
  data_access: 'bg-yellow-100 text-yellow-800',
  system: 'bg-gray-100 text-gray-800',
}

const outcomeIcons: Record<string, React.ReactNode> = {
  success: <CheckCircle className="h-4 w-4 text-green-600" />,
  failure: <XCircle className="h-4 w-4 text-red-600" />,
  pending: <AlertTriangle className="h-4 w-4 text-yellow-600" />,
}

const PAGE_SIZE = 50

export function AuditLogsPage() {
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')
  const [outcomeFilter, setOutcomeFilter] = useState<string>('')
  const [showStats, setShowStats] = useState(true)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)

  // Date range defaults to last 30 days
  const defaultEndDate = new Date().toISOString().split('T')[0]
  const defaultStartDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  const [startDate, setStartDate] = useState(defaultStartDate)
  const [endDate, setEndDate] = useState(defaultEndDate)

  const { data: events, isLoading } = useQuery({
    queryKey: ['audit-events', page, eventTypeFilter, outcomeFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (eventTypeFilter) params.set('event_type', eventTypeFilter)
      if (outcomeFilter) params.set('outcome', outcomeFilter)
      const result = await api.getWithHeaders<AuditEvent[]>(`/api/v1/audit/events?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: statistics } = useQuery({
    queryKey: ['audit-statistics', startDate, endDate],
    queryFn: () => api.get<AuditStatistics>(`/api/v1/audit/statistics?start=${startDate}&end=${endDate}`),
  })

  const exportMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch('/api/v1/audit/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          start_time: new Date(startDate).toISOString(),
          end_time: new Date(endDate + 'T23:59:59').toISOString(),
          event_type: eventTypeFilter || undefined,
          outcome: outcomeFilter || undefined,
        }),
      })
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit_events_${startDate}_${endDate}.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    },
    onSuccess: () => {
      toast({
        title: 'Export Complete',
        description: 'Audit events have been exported to CSV.',
        variant: 'success',
      })
    },
    onError: () => {
      toast({
        title: 'Export Failed',
        description: 'Failed to export audit events.',
        variant: 'destructive',
      })
    },
  })

  // Client-side search filter (server handles event_type and outcome filtering)
  const filteredEvents = events?.filter(event => {
    if (search === '') return true
    return (
      event.action.toLowerCase().includes(search.toLowerCase()) ||
      event.actor_id?.toLowerCase().includes(search.toLowerCase()) ||
      event.actor_ip?.toLowerCase().includes(search.toLowerCase()) ||
      event.target_id?.toLowerCase().includes(search.toLowerCase())
    )
  })

  const totalPages = Math.ceil(totalCount / PAGE_SIZE)

  // Calculate max for chart scaling
  const maxDailyEvents = Math.max(...(statistics?.events_per_day?.map(d => d.count) || [1]))

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const eventTypes = [...new Set(events?.map(e => e.event_type) || [])]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Audit Logs</h1>
          <p className="text-muted-foreground">View and search audit events</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setShowStats(!showStats)}
          >
            <BarChart3 className="mr-2 h-4 w-4" />
            {showStats ? 'Hide' : 'Show'} Stats
          </Button>
          <Button
            variant="outline"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
          >
            <Download className="mr-2 h-4 w-4" />
            {exportMutation.isPending ? 'Exporting...' : 'Export CSV'}
          </Button>
        </div>
      </div>

      {/* Date Range Selector */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-gray-500" />
              <span className="text-sm font-medium">Date Range:</span>
            </div>
            <div className="flex items-center gap-2">
              <Input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-40"
              />
              <span className="text-gray-500">to</span>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-40"
              />
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setStartDate(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0])
                  setEndDate(new Date().toISOString().split('T')[0])
                }}
              >
                Last 7 Days
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setStartDate(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0])
                  setEndDate(new Date().toISOString().split('T')[0])
                }}
              >
                Last 30 Days
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setStartDate(new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0])
                  setEndDate(new Date().toISOString().split('T')[0])
                }}
              >
                Last 90 Days
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Statistics Section */}
      {showStats && statistics && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-lg bg-blue-100 flex items-center justify-center">
                    <TrendingUp className="h-6 w-6 text-blue-700" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{statistics.total_events}</p>
                    <p className="text-sm text-gray-500">Total Events</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                    <CheckCircle className="h-6 w-6 text-green-700" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{statistics.success_rate.toFixed(1)}%</p>
                    <p className="text-sm text-gray-500">Success Rate</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-lg bg-red-100 flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-red-700" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{statistics.failed_auth_count}</p>
                    <p className="text-sm text-gray-500">Failed Auth</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                    <Shield className="h-6 w-6 text-purple-700" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{statistics.by_type?.authentication || 0}</p>
                    <p className="text-sm text-gray-500">Auth Events</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Charts Row */}
          <div className="grid gap-4 md:grid-cols-2">
            {/* Events Over Time Chart */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Events Over Time</CardTitle>
              </CardHeader>
              <CardContent>
                {statistics.events_per_day && statistics.events_per_day.length > 0 ? (
                  <div className="h-40 flex items-end gap-1">
                    {statistics.events_per_day.slice(-14).map((day, i) => (
                      <div key={i} className="flex-1 flex flex-col items-center">
                        <div
                          className="w-full bg-blue-500 rounded-t transition-all hover:bg-blue-600"
                          style={{
                            height: `${(day.count / maxDailyEvents) * 100}%`,
                            minHeight: day.count > 0 ? '4px' : '0',
                          }}
                          title={`${day.date}: ${day.count} events`}
                        />
                        <span className="text-[10px] text-gray-400 mt-1 rotate-45 origin-left">
                          {new Date(day.date).getDate()}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="h-40 flex items-center justify-center text-gray-400">
                    No data for selected period
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Events by Type */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Events by Type</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(statistics.by_type || {}).map(([type, count]) => {
                    const total = statistics.total_events || 1
                    const percentage = (count / total) * 100
                    return (
                      <div key={type}>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="capitalize">{type.replace('_', ' ')}</span>
                          <span className="text-gray-500">{count}</span>
                        </div>
                        <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              type === 'authentication' ? 'bg-blue-500' :
                              type === 'authorization' ? 'bg-purple-500' :
                              type === 'user_management' ? 'bg-green-500' :
                              type === 'configuration' ? 'bg-orange-500' :
                              'bg-gray-500'
                            }`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Outcome Distribution */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Outcome Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-8">
                {Object.entries(statistics.by_outcome || {}).map(([outcome, count]) => {
                  const total = statistics.total_events || 1
                  const percentage = ((count / total) * 100).toFixed(1)
                  return (
                    <div key={outcome} className="flex items-center gap-3">
                      <div className={`w-4 h-4 rounded ${
                        outcome === 'success' ? 'bg-green-500' :
                        outcome === 'failure' ? 'bg-red-500' :
                        'bg-yellow-500'
                      }`} />
                      <div>
                        <p className="font-medium capitalize">{outcome}</p>
                        <p className="text-sm text-gray-500">{count} ({percentage}%)</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search by action, actor, IP address..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-gray-500" />
              <select
                value={eventTypeFilter}
                onChange={(e) => { setEventTypeFilter(e.target.value); setPage(0) }}
                className="border rounded-md px-3 py-2 text-sm"
              >
                <option value="">All Event Types</option>
                {eventTypes.map(type => (
                  <option key={type} value={type}>{type.replace('_', ' ')}</option>
                ))}
              </select>
              <select
                value={outcomeFilter}
                onChange={(e) => { setOutcomeFilter(e.target.value); setPage(0) }}
                className="border rounded-md px-3 py-2 text-sm"
              >
                <option value="">All Outcomes</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="pending">Pending</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Timestamp</th>
                  <th className="p-3 text-left text-sm font-medium">Event Type</th>
                  <th className="p-3 text-left text-sm font-medium">Action</th>
                  <th className="p-3 text-left text-sm font-medium">Actor</th>
                  <th className="p-3 text-left text-sm font-medium">Target</th>
                  <th className="p-3 text-left text-sm font-medium">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="p-4 text-center">Loading...</td></tr>
                ) : filteredEvents?.length === 0 ? (
                  <tr><td colSpan={6} className="p-4 text-center">No audit events found</td></tr>
                ) : (
                  filteredEvents?.map((event) => (
                    <tr key={event.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <span className="text-sm text-gray-600">
                          {formatTimestamp(event.timestamp)}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${eventTypeColors[event.event_type] || 'bg-gray-100 text-gray-800'}`}>
                          {eventTypeIcons[event.event_type]}
                          {event.event_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="p-3">
                        <p className="font-medium text-sm">{event.action}</p>
                        <p className="text-xs text-gray-500">{event.category}</p>
                      </td>
                      <td className="p-3">
                        <div className="text-sm">
                          <p className="truncate max-w-[150px]" title={event.actor_id}>
                            {event.actor_id ? event.actor_id.substring(0, 8) + '...' : '-'}
                          </p>
                          <p className="text-xs text-gray-500">{event.actor_ip || '-'}</p>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="text-sm">
                          <p className="truncate max-w-[150px]" title={event.target_id}>
                            {event.target_id ? event.target_id.substring(0, 8) + '...' : '-'}
                          </p>
                          <p className="text-xs text-gray-500">{event.target_type || '-'}</p>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-1">
                          {outcomeIcons[event.outcome]}
                          <Badge variant={event.outcome === 'success' ? 'default' : event.outcome === 'failure' ? 'destructive' : 'secondary'}>
                            {event.outcome}
                          </Badge>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between pt-4">
            <p className="text-sm text-gray-500">
              {totalCount > 0
                ? `Showing ${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, totalCount)} of ${totalCount} events`
                : 'No events'}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Previous
              </Button>
              <span className="text-sm text-gray-600">
                Page {page + 1}{totalPages > 0 ? ` of ${totalPages}` : ''}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={(page + 1) >= totalPages}
              >
                Next
                <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
