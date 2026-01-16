import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Download, Shield, User, Settings, Database, AlertTriangle, CheckCircle, XCircle, Filter } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'

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

export function AuditLogsPage() {
  const [search, setSearch] = useState('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')

  const { data: events, isLoading } = useQuery({
    queryKey: ['audit-events', search, eventTypeFilter],
    queryFn: () => api.get<AuditEvent[]>('/api/v1/audit/events'),
  })

  const filteredEvents = events?.filter(event => {
    const matchesSearch = search === '' ||
      event.action.toLowerCase().includes(search.toLowerCase()) ||
      event.actor_id?.toLowerCase().includes(search.toLowerCase()) ||
      event.actor_ip?.toLowerCase().includes(search.toLowerCase()) ||
      event.target_id?.toLowerCase().includes(search.toLowerCase())

    const matchesType = eventTypeFilter === '' || event.event_type === eventTypeFilter

    return matchesSearch && matchesType
  })

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
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" /> Export Logs
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-blue-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {events?.filter(e => e.event_type === 'authentication').length || 0}
                </p>
                <p className="text-sm text-gray-500">Auth Events</p>
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
                <p className="text-2xl font-bold">
                  {events?.filter(e => e.outcome === 'success').length || 0}
                </p>
                <p className="text-sm text-gray-500">Successful</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-red-100 flex items-center justify-center">
                <XCircle className="h-6 w-6 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {events?.filter(e => e.outcome === 'failure').length || 0}
                </p>
                <p className="text-sm text-gray-500">Failed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                <Database className="h-6 w-6 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{events?.length || 0}</p>
                <p className="text-sm text-gray-500">Total Events</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

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
                onChange={(e) => setEventTypeFilter(e.target.value)}
                className="border rounded-md px-3 py-2 text-sm"
              >
                <option value="">All Event Types</option>
                {eventTypes.map(type => (
                  <option key={type} value={type}>{type.replace('_', ' ')}</option>
                ))}
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
        </CardContent>
      </Card>
    </div>
  )
}
