import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Search,
  Shield,
  Users2,
  AppWindow,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Package,
  Edit,
  MoreHorizontal,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface EntitlementEntry {
  id: string
  name: string
  type: string
  description: string
  member_count: number
  risk_level: string
  owner_id?: string
  tags: string[]
  review_required: boolean
  last_reviewed_at?: string
  created_at: string
}

interface EntitlementStats {
  total_entitlements: number
  by_type: Record<string, number>
  by_risk_level: Record<string, number>
  orphan_count: number
}

const typeIcons: Record<string, React.ReactNode> = {
  role: <Shield className="h-4 w-4" />,
  group: <Users2 className="h-4 w-4" />,
  application: <AppWindow className="h-4 w-4" />,
}

// Type labels resolve through i18n at render; keys pinned in i18n.test.ts.
const typeLabelKeys: Record<string, string> = {
  role: 'pages.entitlements.types.role',
  group: 'pages.entitlements.types.group',
  application: 'pages.entitlements.types.application',
}

const riskColors: Record<string, string> = {
  low: 'bg-green-100 text-green-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
}

export function EntitlementsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const [editModal, setEditModal] = useState(false)
  const [selectedEntry, setSelectedEntry] = useState<EntitlementEntry | null>(null)
  const [metadata, setMetadata] = useState({
    risk_level: 'low',
    description: '',
    review_required: false,
    tags: '',
  })
  const PAGE_SIZE = 25

  const { data: stats } = useQuery({
    queryKey: ['entitlement-stats'],
    queryFn: () => api.get<EntitlementStats>('/api/v1/entitlements/stats'),
  })

  const { data: entitlements, isLoading, isError, error } = useQuery({
    queryKey: ['entitlements', search, typeFilter, riskFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (typeFilter) params.set('type', typeFilter)
      if (riskFilter) params.set('risk_level', riskFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<EntitlementEntry[]>(`/api/v1/entitlements?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const updateMetadataMutation = useMutation({
    mutationFn: ({ type, id, data }: { type: string; id: string; data: Record<string, unknown> }) =>
      api.put(`/api/v1/entitlements/${type}/${id}/metadata`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entitlements'] })
      queryClient.invalidateQueries({ queryKey: ['entitlement-stats'] })
      toast({ title: t('common.success'), description: t('pages.entitlements.toasts.updated'), variant: 'success' })
      setEditModal(false)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    },
  })

  const handleEditMetadata = (entry: EntitlementEntry) => {
    setSelectedEntry(entry)
    setMetadata({
      risk_level: entry.risk_level || 'low',
      description: entry.description || '',
      review_required: entry.review_required,
      tags: (entry.tags || []).join(', '),
    })
    setEditModal(true)
  }

  const handleSaveMetadata = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedEntry) return
    updateMetadataMutation.mutate({
      type: selectedEntry.type,
      id: selectedEntry.id,
      data: {
        risk_level: metadata.risk_level,
        description: metadata.description,
        review_required: metadata.review_required,
        tags: metadata.tags.split(',').map(t => t.trim()).filter(Boolean),
      },
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.entitlements.title')}</h1>
        <p className="text-muted-foreground">{t('pages.entitlements.subtitle')}</p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <Package className="h-5 w-5 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.total_entitlements || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.entitlements.stats.total')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-5 w-5 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {stats?.by_type?.role || 0} / {stats?.by_type?.group || 0} / {stats?.by_type?.application || 0}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.entitlements.stats.byType')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-red-100 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {(stats?.by_risk_level?.high || 0) + (stats?.by_risk_level?.critical || 0)}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.entitlements.stats.highRisk')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Users2 className="h-5 w-5 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.orphan_count || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.entitlements.stats.orphan')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Catalog Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.entitlements.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={typeFilter || 'all'} onValueChange={(val) => { setTypeFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]" aria-label={t('pages.entitlements.typeFilter.label')}>
                <SelectValue placeholder={t('pages.entitlements.typeFilter.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.entitlements.typeFilter.all')}</SelectItem>
                <SelectItem value="role">{t('pages.entitlements.typeFilter.roles')}</SelectItem>
                <SelectItem value="group">{t('pages.entitlements.typeFilter.groups')}</SelectItem>
                <SelectItem value="application">{t('pages.entitlements.typeFilter.applications')}</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskFilter || 'all'} onValueChange={(val) => { setRiskFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]" aria-label={t('pages.entitlements.riskFilter.label')}>
                <SelectValue placeholder={t('pages.entitlements.riskFilter.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.entitlements.riskFilter.all')}</SelectItem>
                <SelectItem value="low">{t('pages.entitlements.riskFilter.low')}</SelectItem>
                <SelectItem value="medium">{t('pages.entitlements.riskFilter.medium')}</SelectItem>
                <SelectItem value="high">{t('pages.entitlements.riskFilter.high')}</SelectItem>
                <SelectItem value="critical">{t('pages.entitlements.riskFilter.critical')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.entitlements.loading')}</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.entitlements.resourceName')} />
          ) : !entitlements || entitlements.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Package className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.entitlements.empty')}</p>
              <p className="text-sm">{t('pages.entitlements.emptyHint')}</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.entitlements.table.entitlement')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.entitlements.table.type')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.entitlements.table.risk')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.entitlements.table.members')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.entitlements.table.tags')}</TableHead>
                      <TableHead className="p-3 text-right text-sm font-medium">{t('pages.entitlements.table.actions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {entitlements.map((entry) => (
                      <TableRow key={`${entry.type}-${entry.id}`} className="border-b hover:bg-muted">
                        <TableCell className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                              {typeIcons[entry.type] || <Package className="h-4 w-4" />}
                            </div>
                            <div>
                              <p className="font-medium">{entry.name}</p>
                              <p className="text-sm text-muted-foreground max-w-xs truncate">{entry.description || '-'}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="outline">{typeLabelKeys[entry.type] ? t(typeLabelKeys[entry.type]) : entry.type}</Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex px-2 py-1 rounded-full text-xs font-medium ${riskColors[entry.risk_level] || riskColors.low}`}>
                            {entry.risk_level}
                          </span>
                        </TableCell>
                        <TableCell className="p-3">
                          <span className="text-sm">{entry.member_count}</span>
                        </TableCell>
                        <TableCell className="p-3">
                          <div className="flex gap-1 flex-wrap">
                            {entry.tags?.length > 0 ? entry.tags.slice(0, 3).map((tag) => (
                              <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>
                            )) : (
                              <span className="text-sm text-muted-foreground">-</span>
                            )}
                            {entry.tags?.length > 3 && (
                              <Badge variant="secondary" className="text-xs">+{entry.tags.length - 3}</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleEditMetadata(entry)}>
                                <Edit className="h-4 w-4 mr-2" />
                                {t('pages.entitlements.editMetadata')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              {totalCount > PAGE_SIZE && (
                <div className="flex items-center justify-between pt-4 px-1">
                  <p className="text-sm text-muted-foreground">
                    {t('pages.entitlements.showing', { from: page * PAGE_SIZE + 1, to: Math.min((page + 1) * PAGE_SIZE, totalCount), total: totalCount })}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                      <ChevronLeft className="h-4 w-4 mr-1" /> {t('common.pagination.previous')}
                    </Button>
                    <span className="text-sm text-muted-foreground">{t('common.pagination.pageOf', { page: page + 1, pages: Math.ceil(totalCount / PAGE_SIZE) })}</span>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= totalCount}>
                      {t('common.pagination.next')} <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Edit Metadata Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.entitlements.dialog.title')}</DialogTitle>
          </DialogHeader>
          {selectedEntry && (
            <form onSubmit={handleSaveMetadata} className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
                {typeIcons[selectedEntry.type]}
                <span className="font-medium">{selectedEntry.name}</span>
                <Badge variant="outline" className="ml-auto">{typeLabelKeys[selectedEntry.type] ? t(typeLabelKeys[selectedEntry.type]) : selectedEntry.type}</Badge>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.entitlements.dialog.riskLevel')}</Label>
                <Select value={metadata.risk_level} onValueChange={(val) => setMetadata(prev => ({ ...prev, risk_level: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">{t('pages.entitlements.riskFilter.low')}</SelectItem>
                    <SelectItem value="medium">{t('pages.entitlements.riskFilter.medium')}</SelectItem>
                    <SelectItem value="high">{t('pages.entitlements.riskFilter.high')}</SelectItem>
                    <SelectItem value="critical">{t('pages.entitlements.riskFilter.critical')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.entitlements.dialog.description')}</Label>
                <Textarea
                  value={metadata.description}
                  onChange={(e) => setMetadata(prev => ({ ...prev, description: e.target.value }))}
                  rows={2}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.entitlements.dialog.tags')}</Label>
                <Input
                  value={metadata.tags}
                  onChange={(e) => setMetadata(prev => ({ ...prev, tags: e.target.value }))}
                  placeholder={t('pages.entitlements.dialog.tagsPlaceholder')}
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="review_required"
                  checked={metadata.review_required}
                  onChange={(e) => setMetadata(prev => ({ ...prev, review_required: e.target.checked }))}
                  className="rounded border-border"
                />
                <Label htmlFor="review_required">{t('pages.entitlements.dialog.reviewRequired')}</Label>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setEditModal(false)}>{t('common.cancel')}</Button>
                <Button type="submit" disabled={updateMetadataMutation.isPending}>
                  {updateMetadataMutation.isPending ? t('pages.entitlements.dialog.saving') : t('pages.entitlements.dialog.save')}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
