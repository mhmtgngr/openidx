import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  Download,
  ChevronDown,
  ChevronRight,
  Filter,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuditEntry {
  id: string
  actor_id: string
  actor_email: string
  action: string
  target_type: string
  target_id: string
  target_label: string
  timestamp: string
  before_state?: Record<string, unknown>
  after_state?: Record<string, unknown>
  metadata?: Record<string, unknown>
}

interface AuditResponse {
  items: AuditEntry[]
  total: number
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ACTION_TYPES = [
  { value: '', labelKey: 'all' },
  { value: 'create', labelKey: 'create' },
  { value: 'update', labelKey: 'update' },
  { value: 'delete', labelKey: 'delete' },
  { value: 'enable', labelKey: 'enable' },
  { value: 'disable', labelKey: 'disable' },
  { value: 'assign', labelKey: 'assign' },
  { value: 'revoke', labelKey: 'revoke' },
  { value: 'login', labelKey: 'login' },
  { value: 'logout', labelKey: 'logout' },
] as const

const TARGET_TYPES = [
  { value: '', labelKey: 'all' },
  { value: 'user', labelKey: 'user' },
  { value: 'group', labelKey: 'group' },
  { value: 'application', labelKey: 'application' },
  { value: 'policy', labelKey: 'policy' },
  { value: 'role', labelKey: 'role' },
  { value: 'settings', labelKey: 'settings' },
  { value: 'api_key', labelKey: 'apiKey' },
  { value: 'webhook', labelKey: 'webhook' },
] as const

const ACTION_BADGE_COLORS: Record<string, string> = {
  create: 'bg-green-100 text-green-800',
  update: 'bg-blue-100 text-blue-800',
  delete: 'bg-red-100 text-red-800',
  enable: 'bg-emerald-100 text-emerald-800',
  disable: 'bg-muted text-foreground',
  assign: 'bg-purple-100 text-purple-800',
  revoke: 'bg-orange-100 text-orange-800',
  login: 'bg-cyan-100 text-cyan-800',
  logout: 'bg-slate-100 text-slate-800',
}

const PAGE_SIZE = 20

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

// Build a CSV document from a full set of audit entries. Extracted so the
// "export all pages" flow is unit-testable without touching the DOM.
export function buildAuditCsv(entries: AuditEntry[]): string {
  // Deliberately not translated: these are the export's column names, a stable
  // machine-readable schema. Localizing them would break every consumer that
  // parses the CSV by header.
  const headers = ['Timestamp', 'Actor', 'Action', 'Target Type', 'Target', 'ID']
  const rows = entries.map((e) => [
    e.timestamp,
    e.actor_email,
    e.action,
    e.target_type,
    e.target_label,
    e.id,
  ])
  return [
    headers.join(','),
    ...rows.map((r) =>
      r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
    ),
  ].join('\n')
}

// Maximum pages to walk when exporting, as a safety cap.
const EXPORT_MAX_PAGES = 50

// Walk every page of the (filtered) audit log and accumulate all entries.
// `fetchPage(offset)` returns one page; the walk stops when a page returns
// fewer than PAGE_SIZE rows (the last page) or the safety cap is hit.
export async function fetchAllAuditEntries(
  fetchPage: (offset: number) => Promise<AuditResponse>
): Promise<AuditEntry[]> {
  const all: AuditEntry[] = []
  for (let page = 0; page < EXPORT_MAX_PAGES; page++) {
    const resp = await fetchPage(page * PAGE_SIZE)
    const items = resp?.items || []
    all.push(...items)
    if (items.length < PAGE_SIZE) break
  }
  return all
}

function renderJsonDiff(
  before: Record<string, unknown> | undefined,
  after: Record<string, unknown> | undefined,
  t: (key: string) => string
) {
  if (!before && !after) {
    return <p className="text-sm text-muted-foreground">{t('pages.adminAuditLog.noStateData')}</p>
  }

  const allKeys = new Set([
    ...Object.keys(before || {}),
    ...Object.keys(after || {}),
  ])

  return (
    <div className="grid grid-cols-2 gap-4">
      <div>
        <h4 className="text-xs font-semibold text-muted-foreground mb-1">{t('pages.adminAuditLog.before')}</h4>
        <div className="bg-red-50 border border-red-200 rounded p-3 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto">
          {before ? (
            Array.from(allKeys).map((key) => {
              const val = before[key]
              const changed = JSON.stringify(val) !== JSON.stringify(after?.[key])
              return (
                <div
                  key={key}
                  className={changed ? 'text-red-700 font-semibold' : 'text-muted-foreground'}
                >
                  {`"${key}": ${JSON.stringify(val, null, 2)}`}
                </div>
              )
            })
          ) : (
            <span className="text-muted-foreground">{t('pages.adminAuditLog.emptyValue')}</span>
          )}
        </div>
      </div>
      <div>
        <h4 className="text-xs font-semibold text-muted-foreground mb-1">{t('pages.adminAuditLog.after')}</h4>
        <div className="bg-green-50 border border-green-200 rounded p-3 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto">
          {after ? (
            Array.from(allKeys).map((key) => {
              const val = after[key]
              const changed = JSON.stringify(val) !== JSON.stringify(before?.[key])
              return (
                <div
                  key={key}
                  className={changed ? 'text-green-700 font-semibold' : 'text-muted-foreground'}
                >
                  {`"${key}": ${JSON.stringify(val, null, 2)}`}
                </div>
              )
            })
          ) : (
            <span className="text-muted-foreground">{t('pages.adminAuditLog.emptyValue')}</span>
          )}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AdminAuditLogPage() {
  const { t } = useTranslation()
  const { toast } = useToast()

  // Filters
  const [actorFilter, setActorFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [targetTypeFilter, setTargetTypeFilter] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [offset, setOffset] = useState(0)

  // Expanded rows
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Export in-flight state (drives the button's loading affordance).
  const [isExporting, setIsExporting] = useState(false)

  // Filter-only params (no limit/offset) — shared by the paged query and the
  // export-all walk so both apply the same filters.
  const filterParams = useMemo(() => {
    const params = new URLSearchParams()
    if (actorFilter.trim()) params.set('actor_id', actorFilter.trim())
    if (actionFilter) params.set('action', actionFilter)
    if (targetTypeFilter) params.set('target_type', targetTypeFilter)
    if (startDate) params.set('start_date', startDate)
    if (endDate) params.set('end_date', endDate)
    return params
  }, [actorFilter, actionFilter, targetTypeFilter, startDate, endDate])

  // Build query params for the current page
  const queryParams = useMemo(() => {
    const params = new URLSearchParams(filterParams)
    params.set('limit', String(PAGE_SIZE))
    params.set('offset', String(offset))
    return params.toString()
  }, [filterParams, offset])

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['admin-audit-log', queryParams],
    queryFn: () =>
      api.get<AuditResponse>(`/api/v1/audit-log?${queryParams}`),
  })

  const entries = data?.items || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const handleExportCSV = async () => {
    if (isExporting) return
    setIsExporting(true)
    try {
      // Walk every page (not just the current one) so the CSV is the full
      // filtered result set.
      const all = await fetchAllAuditEntries((offsetVal) => {
        const params = new URLSearchParams(filterParams)
        params.set('limit', String(PAGE_SIZE))
        params.set('offset', String(offsetVal))
        return api.get<AuditResponse>(`/api/v1/audit-log?${params.toString()}`)
      })

      const csvContent = buildAuditCsv(all)
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `admin-audit-${new Date().toISOString().slice(0, 10)}.csv`
      link.click()
      URL.revokeObjectURL(url)

      toast({
        title: t('pages.adminAuditLog.toast.exported'),
        description: t('pages.adminAuditLog.toast.exportedDesc', { count: all.length }),
      })
    } catch {
      toast({
        title: t('pages.adminAuditLog.toast.exportFailed'),
        description: t('pages.adminAuditLog.toast.exportFailedDesc'),
        variant: 'destructive',
      })
    } finally {
      setIsExporting(false)
    }
  }

  const resetFilters = () => {
    setActorFilter('')
    setActionFilter('')
    setTargetTypeFilter('')
    setStartDate('')
    setEndDate('')
    setOffset(0)
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.adminAuditLog')}</h1>
          <p className="text-muted-foreground">
            {t('pages.adminAuditLog.subtitle')}
          </p>
        </div>
        <Button
          variant="outline"
          onClick={handleExportCSV}
          disabled={entries.length === 0 || isExporting}
        >
          <Download className="mr-2 h-4 w-4" />
          {t(isExporting ? 'pages.adminAuditLog.exporting' : 'pages.adminAuditLog.exportCsv')}
        </Button>
      </div>

      <RelatedLinks
        links={[
          { to: '/audit-logs', label: t('nav.items.auditLogs') },
          { to: '/unified-audit', label: t('nav.items.unifiedAudit') },
        ]}
      />

      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-base">{t('pages.adminAuditLog.filters')}</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-5">
            <div className="space-y-1">
              <label htmlFor="aal-actor" className="text-xs font-medium text-muted-foreground">{t('pages.adminAuditLog.columns.actor')}</label>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  id="aal-actor"
                  placeholder={t('pages.adminAuditLog.actorPlaceholder')}
                  value={actorFilter}
                  onChange={(e) => {
                    setActorFilter(e.target.value)
                    setOffset(0)
                  }}
                  className="pl-8 h-9 text-sm"
                />
              </div>
            </div>
            <div className="space-y-1">
              <label htmlFor="aal-action" className="text-xs font-medium text-muted-foreground">{t('pages.adminAuditLog.columns.action')}</label>
              <select
                id="aal-action"
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value)
                  setOffset(0)
                }}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                {ACTION_TYPES.map((at) => (
                  <option key={at.value} value={at.value}>
                    {t(`pages.adminAuditLog.actions.${at.labelKey}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label htmlFor="aal-target-type" className="text-xs font-medium text-muted-foreground">{t('pages.adminAuditLog.columns.targetType')}</label>
              <select
                id="aal-target-type"
                value={targetTypeFilter}
                onChange={(e) => {
                  setTargetTypeFilter(e.target.value)
                  setOffset(0)
                }}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                {TARGET_TYPES.map((tt) => (
                  <option key={tt.value} value={tt.value}>
                    {t(`pages.adminAuditLog.targets.${tt.labelKey}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label htmlFor="aal-start-date" className="text-xs font-medium text-muted-foreground">{t('pages.adminAuditLog.startDate')}</label>
              <Input
                id="aal-start-date"
                type="date"
                value={startDate}
                onChange={(e) => {
                  setStartDate(e.target.value)
                  setOffset(0)
                }}
                className="h-9 text-sm"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="aal-end-date" className="text-xs font-medium text-muted-foreground">{t('pages.adminAuditLog.endDate')}</label>
              <Input
                id="aal-end-date"
                type="date"
                value={endDate}
                onChange={(e) => {
                  setEndDate(e.target.value)
                  setOffset(0)
                }}
                className="h-9 text-sm"
              />
            </div>
          </div>
          {(actorFilter || actionFilter || targetTypeFilter || startDate || endDate) && (
            <Button
              variant="ghost"
              size="sm"
              className="mt-2 text-xs"
              onClick={resetFilters}
            >
              {t('pages.adminAuditLog.clearFilters')}
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Results table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <p className="text-center py-8 text-muted-foreground">{t('pages.adminAuditLog.loading')}</p>
          ) : isError ? (
            <div className="p-4"><QueryError error={error} resource={t('pages.adminAuditLog.resourceName')} /></div>
          ) : entries.length === 0 ? (
            <p className="text-center py-8 text-muted-foreground">
              {t('pages.adminAuditLog.empty')}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>{t('pages.adminAuditLog.columns.actor')}</TableHead>
                  <TableHead>{t('pages.adminAuditLog.columns.action')}</TableHead>
                  <TableHead>{t('pages.adminAuditLog.columns.targetType')}</TableHead>
                  <TableHead>{t('pages.adminAuditLog.columns.target')}</TableHead>
                  <TableHead>{t('pages.adminAuditLog.columns.date')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => {
                  const isExpanded = expandedRows.has(entry.id)
                  const actionColor =
                    ACTION_BADGE_COLORS[entry.action] || 'bg-muted text-foreground'

                  return (
                    <>
                      <TableRow
                        key={entry.id}
                        className="cursor-pointer"
                        onClick={() => toggleRow(entry.id)}
                      >
                        <TableCell className="w-8 pr-0">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="font-medium text-sm">
                          {entry.actor_email}
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-block text-xs font-semibold px-2 py-0.5 rounded-full ${actionColor}`}
                          >
                            {entry.action}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {entry.target_type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm max-w-[200px] truncate">
                          {entry.target_label || entry.target_id}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {formatDate(entry.timestamp)}
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow key={`${entry.id}-detail`}>
                          <TableCell colSpan={6} className="bg-muted/30 p-4">
                            <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                  <span className="text-xs font-medium text-muted-foreground">
                                    {t('pages.adminAuditLog.entryId')}
                                  </span>
                                  <p className="font-mono text-xs">{entry.id}</p>
                                </div>
                                <div>
                                  <span className="text-xs font-medium text-muted-foreground">
                                    {t('pages.adminAuditLog.targetId')}
                                  </span>
                                  <p className="font-mono text-xs">{entry.target_id}</p>
                                </div>
                              </div>
                              {(entry.before_state || entry.after_state) && (
                                <div>
                                  <h4 className="text-sm font-semibold mb-2">{t('pages.adminAuditLog.stateChanges')}</h4>
                                  {renderJsonDiff(entry.before_state, entry.after_state, t)}
                                </div>
                              )}
                              {entry.metadata && Object.keys(entry.metadata).length > 0 && (
                                <div>
                                  <h4 className="text-sm font-semibold mb-1">{t('pages.adminAuditLog.metadata')}</h4>
                                  <pre className="text-xs bg-muted rounded p-2 overflow-x-auto">
                                    {JSON.stringify(entry.metadata, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {t('pages.adminAuditLog.showingEntries', {
              from: offset + 1,
              to: Math.min(offset + PAGE_SIZE, total),
              total,
            })}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              {t('common.pagination.previous')}
            </Button>
            <span className="text-sm text-muted-foreground">
              {t('common.pagination.pageOf', { page: currentPage, pages: totalPages })}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              {t('common.pagination.next')}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
