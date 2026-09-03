import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Search, Download, Shield, User, Settings, Database, AlertTriangle, CheckCircle, XCircle, Filter, Calendar, TrendingUp, BarChart3, ChevronLeft, ChevronRight, FileText } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { TableSkeleton } from '../components/ui/skeleton'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'

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
  system: 'bg-muted text-foreground',
}

const outcomeIcons: Record<string, React.ReactNode> = {
  success: <CheckCircle className="h-4 w-4 text-green-600" />,
  failure: <XCircle className="h-4 w-4 text-red-600" />,
  pending: <AlertTriangle className="h-4 w-4 text-yellow-600" />,
}

const PAGE_SIZE = 50

const EVENT_TYPES = [
  'authentication',
  'authorization',
  'user_management',
  'group_management',
  'role_management',
  'configuration',
  'data_access',
  'system',
] as const

const OUTCOMES = ['success', 'failure', 'pending'] as const

export function AuditLogsPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')
  const [outcomeFilter, setOutcomeFilter] = useState<string>('')
  const [showStats, setShowStats] = useState(true)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)

  // Date range defaults to last 30 days
  const defaultEndDate = new Date().toISOString().split('T')[0]
  const defaultStartDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  const [startDate, setStartDate] = useState(defaultStartDate)
  const [endDate, setEndDate] = useState(defaultEndDate)

  const { data: events, isLoading, isError, error } = useQuery({
    queryKey: ['audit-events', page, search, eventTypeFilter, outcomeFilter, startDate, endDate],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      if (eventTypeFilter) params.set('event_type', eventTypeFilter)
      if (outcomeFilter) params.set('outcome', outcomeFilter)
      if (startDate) params.set('start', startDate)
      if (endDate) params.set('end', endDate)
      const result = await api.getWithHeaders<AuditEvent[]>(`/api/v1/audit/events?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      // Normalize each row so fields the UI accesses (e.g. event_type.replace)
      // are never null/undefined even if the backend drops them.
      return (result.data ?? []).map((e) => ({
        ...e,
        event_type: e.event_type ?? '',
        category: e.category ?? '',
        action: e.action ?? '',
        outcome: e.outcome ?? '',
        actor_id: e.actor_id ?? '',
        actor_type: e.actor_type ?? '',
        actor_ip: e.actor_ip ?? '',
        target_id: e.target_id ?? '',
        target_type: e.target_type ?? '',
        resource_id: e.resource_id ?? '',
        session_id: e.session_id ?? '',
        request_id: e.request_id ?? '',
        details: e.details ?? {},
      }))
    },
  })

  const { data: statistics } = useQuery({
    queryKey: ['audit-statistics', startDate, endDate],
    queryFn: async () => {
      const s = await api.get<AuditStatistics>(`/api/v1/audit/statistics?start=${startDate}&end=${endDate}`)
      // Normalize so numeric/array/map fields the UI reads (.toFixed, .map,
      // Object.entries) never explode on null/undefined from the backend.
      return {
        ...s,
        total_events: s?.total_events ?? 0,
        by_type: s?.by_type ?? {},
        by_outcome: s?.by_outcome ?? {},
        by_category: s?.by_category ?? {},
        events_per_day: s?.events_per_day ?? [],
        failed_auth_count: s?.failed_auth_count ?? 0,
        success_rate: s?.success_rate ?? 0,
      } as AuditStatistics
    },
  })

  const exportMutation = useMutation({
    mutationFn: async () => {
      const data = await api.post<Blob>('/api/v1/audit/export', {
        start_time: new Date(startDate).toISOString(),
        end_time: new Date(endDate + 'T23:59:59').toISOString(),
        event_type: eventTypeFilter || undefined,
        outcome: outcomeFilter || undefined,
      })
      const blob = data instanceof Blob ? data : new Blob([JSON.stringify(data)], { type: 'text/csv' })
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
        title: t('pages.auditLogs.toast.exportComplete'),
        description: t('pages.auditLogs.toast.exportCompleteDesc'),
        variant: 'success',
      })
    },
    onError: () => {
      toast({
        title: t('pages.auditLogs.toast.exportFailed'),
        description: t('pages.auditLogs.toast.exportFailedDesc'),
        variant: 'destructive',
      })
    },
  })

  // Events are filtered server-side via search param
  const filteredEvents = events

  const totalPages = Math.ceil(totalCount / PAGE_SIZE)

  // Calculate max for chart scaling
  const maxDailyEvents = Math.max(...(statistics?.events_per_day?.map(d => d.count) || [1]))

  // Falls back to the raw value prettified, so an event_type the backend
  // adds later reads as "new thing" rather than a raw catalog key.
  const eventTypeLabel = (type: string) =>
    t(`pages.auditLogs.eventTypes.${type}`, { defaultValue: type.replace('_', ' ') })

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }


  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.auditLogs')}</h1>
          <p className="text-muted-foreground">{t('pages.auditLogs.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setShowStats(!showStats)}
          >
            <BarChart3 className="mr-2 h-4 w-4" />
            {t(showStats ? 'pages.auditLogs.hideStats' : 'pages.auditLogs.showStats')}
          </Button>
          <Button
            variant="outline"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
          >
            <Download className="mr-2 h-4 w-4" />
            {t(exportMutation.isPending ? 'pages.auditLogs.exporting' : 'pages.auditLogs.exportCsv')}
          </Button>
        </div>
      </div>

      <RelatedLinks
        links={[
          { to: '/unified-audit', label: t('nav.items.unifiedAudit') },
          { to: '/admin-audit-log', label: t('nav.items.adminAuditLog') },
        ]}
      />

      {/* Date Range Selector */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">{t('pages.auditLogs.dateRange')}</span>
            </div>
            <div className="flex items-center gap-2">
              <Input
                type="date"
                aria-label={t('pages.auditLogs.startDate')}
                value={startDate}
                onChange={(e) => { setStartDate(e.target.value); setPage(0) }}
                className="w-40"
              />
              <span className="text-muted-foreground">{t('pages.auditLogs.to')}</span>
              <Input
                type="date"
                aria-label={t('pages.auditLogs.endDate')}
                value={endDate}
                onChange={(e) => { setEndDate(e.target.value); setPage(0) }}
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
                  setPage(0)
                }}
              >
                {t('common.periods.d7')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setStartDate(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0])
                  setEndDate(new Date().toISOString().split('T')[0])
                  setPage(0)
                }}
              >
                {t('common.periods.d30')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setStartDate(new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0])
                  setEndDate(new Date().toISOString().split('T')[0])
                  setPage(0)
                }}
              >
                {t('common.periods.d90')}
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
                    <p className="text-sm text-muted-foreground">{t('pages.auditLogs.totalEvents')}</p>
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
                    <p className="text-sm text-muted-foreground">{t('pages.auditLogs.successRate')}</p>
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
                    <p className="text-sm text-muted-foreground">{t('pages.auditLogs.failedAuth')}</p>
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
                    <p className="text-sm text-muted-foreground">{t('pages.auditLogs.authEvents')}</p>
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
                <CardTitle className="text-sm font-medium">{t('pages.auditLogs.eventsOverTime')}</CardTitle>
              </CardHeader>
              <CardContent>
                {statistics.events_per_day && statistics.events_per_day.length > 0 ? (
                  <div className="h-40 flex items-end gap-1 overflow-x-auto">
                    {statistics.events_per_day.map((day, i) => (
                      <div key={i} className="flex-1 flex flex-col items-center">
                        <div
                          className="w-full bg-blue-500 rounded-t transition-all hover:bg-primary"
                          style={{
                            height: `${(day.count / maxDailyEvents) * 100}%`,
                            minHeight: day.count > 0 ? '4px' : '0',
                          }}
                          title={t('pages.auditLogs.dayEvents', { date: day.date, count: day.count })}
                        />
                        <span className="text-[10px] text-muted-foreground mt-1 rotate-45 origin-left">
                          {new Date(day.date).getDate()}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="h-40 flex items-center justify-center text-muted-foreground">
                    {t('pages.auditLogs.noDataForPeriod')}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Events by Type */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">{t('pages.auditLogs.eventsByType')}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(statistics.by_type || {}).map(([type, count]) => {
                    const total = statistics.total_events || 1
                    const percentage = (count / total) * 100
                    return (
                      <div key={type}>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="capitalize">{eventTypeLabel(type)}</span>
                          <span className="text-muted-foreground">{count}</span>
                        </div>
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
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
              <CardTitle className="text-sm font-medium">{t('pages.auditLogs.outcomeDistribution')}</CardTitle>
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
                        <p className="text-sm text-muted-foreground">{count} ({percentage}%)</p>
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
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.auditLogs.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Select value={eventTypeFilter || 'all'} onValueChange={(val) => { setEventTypeFilter(val === 'all' ? '' : val); setPage(0) }}>
                <SelectTrigger aria-label={t('pages.auditLogs.eventTypeFilterLabel')} className="w-[180px]">
                  <SelectValue placeholder={t('pages.auditLogs.allEventTypes')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('pages.auditLogs.allEventTypes')}</SelectItem>
                  {EVENT_TYPES.map(type => (
                    <SelectItem key={type} value={type}>{eventTypeLabel(type)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={outcomeFilter || 'all'} onValueChange={(val) => { setOutcomeFilter(val === 'all' ? '' : val); setPage(0) }}>
                <SelectTrigger aria-label={t('pages.auditLogs.outcomeFilterLabel')} className="w-[180px]">
                  <SelectValue placeholder={t('pages.auditLogs.allOutcomes')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('pages.auditLogs.allOutcomes')}</SelectItem>
                  {OUTCOMES.map(o => (
                    <SelectItem key={o} value={o}>{t(`pages.auditLogs.outcomes.${o}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : isError ? (
            <QueryError error={error} resource={t('pages.auditLogs.resourceName')} />
          ) : !filteredEvents || filteredEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <FileText className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.auditLogs.emptyTitle')}</p>
              <p className="text-sm">{t('pages.auditLogs.emptyDesc')}</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.timestamp')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.eventType')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.action')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.actor')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.target')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.auditLogs.columns.outcome')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEvents.map((event) => (
                    <TableRow key={event.id} onClick={() => setSelectedEvent(event)} className="border-b hover:bg-muted cursor-pointer">
                      <TableCell className="p-3">
                        <span className="text-sm text-muted-foreground">
                          {formatTimestamp(event.timestamp)}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${eventTypeColors[event.event_type] || 'bg-muted text-foreground'}`}>
                          {eventTypeIcons[event.event_type]}
                          {eventTypeLabel(event.event_type)}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <p className="font-medium text-sm">{event.action}</p>
                        <p className="text-xs text-muted-foreground">{event.category}</p>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="text-sm">
                          <p className="truncate max-w-[150px]" title={event.actor_id}>
                            {event.actor_id ? event.actor_id.substring(0, 8) + '...' : '-'}
                          </p>
                          <p className="text-xs text-muted-foreground">{event.actor_ip || '-'}</p>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="text-sm">
                          <p className="truncate max-w-[150px]" title={event.target_id}>
                            {event.target_id ? event.target_id.substring(0, 8) + '...' : '-'}
                          </p>
                          <p className="text-xs text-muted-foreground">{event.target_type || '-'}</p>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="flex items-center gap-1">
                          {outcomeIcons[event.outcome]}
                          <Badge variant={event.outcome === 'success' ? 'default' : event.outcome === 'failure' ? 'destructive' : 'secondary'}>
                            {event.outcome}
                          </Badge>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
          )}

          {/* Pagination Controls */}
          <div className="flex items-center justify-between pt-4">
            <p className="text-sm text-muted-foreground">
              {totalCount > 0
                ? t('pages.auditLogs.showingEvents', {
                    from: page * PAGE_SIZE + 1,
                    to: Math.min((page + 1) * PAGE_SIZE, totalCount),
                    total: totalCount,
                  })
                : t('pages.auditLogs.noEvents')}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                {t('common.pagination.previous')}
              </Button>
              <span className="text-sm text-muted-foreground">
                {totalPages > 0
                  ? t('common.pagination.pageOf', { page: page + 1, pages: totalPages })
                  : t('common.pagination.page', { page: page + 1 })}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={(page + 1) >= totalPages}
              >
                {t('common.pagination.next')}
                <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Audit Event Detail Modal */}
      <Dialog open={!!selectedEvent} onOpenChange={(open) => !open && setSelectedEvent(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('pages.auditLogs.detail.title')}</DialogTitle>
          </DialogHeader>
          {selectedEvent && (
            <div className="space-y-6">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.columns.timestamp')}</p>
                  <p className="text-sm">{formatTimestamp(selectedEvent.timestamp)}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.columns.eventType')}</p>
                  <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${eventTypeColors[selectedEvent.event_type] || 'bg-muted text-foreground'}`}>
                    {eventTypeIcons[selectedEvent.event_type]}
                    {eventTypeLabel(selectedEvent.event_type)}
                  </span>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.category')}</p>
                  <p className="text-sm capitalize">{selectedEvent.category}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.columns.action')}</p>
                  <p className="text-sm">{selectedEvent.action}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.columns.outcome')}</p>
                  <div className="flex items-center gap-1">
                    {outcomeIcons[selectedEvent.outcome]}
                    <Badge variant={selectedEvent.outcome === 'success' ? 'default' : selectedEvent.outcome === 'failure' ? 'destructive' : 'secondary'}>
                      {selectedEvent.outcome}
                    </Badge>
                  </div>
                </div>
              </div>

              {/* Actor Section */}
              <div>
                <h3 className="text-sm font-semibold mb-2">{t('pages.auditLogs.detail.actor')}</h3>
                <div className="grid grid-cols-2 gap-4 bg-muted p-3 rounded">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.id')}</p>
                    <p className="text-sm break-all">{selectedEvent.actor_id || '-'}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.type')}</p>
                    <p className="text-sm">{selectedEvent.actor_type || '-'}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.ipAddress')}</p>
                    <p className="text-sm">{selectedEvent.actor_ip || '-'}</p>
                  </div>
                </div>
              </div>

              {/* Target Section */}
              <div>
                <h3 className="text-sm font-semibold mb-2">{t('pages.auditLogs.detail.target')}</h3>
                <div className="grid grid-cols-2 gap-4 bg-muted p-3 rounded">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.id')}</p>
                    <p className="text-sm break-all">{selectedEvent.target_id || '-'}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.type')}</p>
                    <p className="text-sm">{selectedEvent.target_type || '-'}</p>
                  </div>
                </div>
              </div>

              {/* IDs Section */}
              <div>
                <h3 className="text-sm font-semibold mb-2">{t('pages.auditLogs.detail.ids')}</h3>
                <div className="grid grid-cols-2 gap-4 bg-muted p-3 rounded">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.resourceId')}</p>
                    <p className="text-sm break-all">{selectedEvent.resource_id || '-'}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.sessionId')}</p>
                    <p className="text-sm break-all">{selectedEvent.session_id || '-'}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">{t('pages.auditLogs.detail.requestId')}</p>
                    <p className="text-sm break-all">{selectedEvent.request_id || '-'}</p>
                  </div>
                </div>
              </div>

              {/* Details Section */}
              {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">{t('pages.auditLogs.detail.details')}</h3>
                  <pre className="bg-muted p-3 rounded text-xs overflow-auto max-h-60">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
