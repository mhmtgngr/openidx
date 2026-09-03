import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Plus,
  Search,
  Target,
  Clock,
  CheckCircle,
  Pause,
  Play,
  Trash2,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  CalendarClock,
  Eye,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
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
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'

interface Campaign {
  id: string
  name: string
  description: string
  type: string
  schedule: string
  reviewer_strategy: string
  reviewer_id?: string
  reviewer_role?: string
  auto_revoke: boolean
  grace_period_days: number
  duration_days: number
  status: string
  last_run_at?: string
  next_run_at?: string
  created_at: string
}

interface CampaignRun {
  id: string
  campaign_id: string
  review_id?: string
  status: string
  started_at: string
  deadline: string
  completed_at?: string
  total_items: number
  reviewed_items: number
  auto_revoked_items: number
  created_at: string
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  paused: 'bg-yellow-100 text-yellow-800',
  completed: 'bg-muted text-foreground',
}

const statusIcons: Record<string, React.ReactNode> = {
  active: <CheckCircle className="h-3 w-3" />,
  paused: <Pause className="h-3 w-3" />,
  completed: <CheckCircle className="h-3 w-3" />,
}

// Schedule and type labels resolve through i18n at render time; the keys are
// pinned in i18n.test.ts because `typeof en` cannot see runtime-map keys.
const SCHEDULES = ['once', 'quarterly', 'semi_annual', 'annual'] as const
const CAMPAIGN_TYPES = [
  'user_access',
  'role_assignment',
  'application_access',
  'privileged_access',
] as const

const formatDate = (dateStr: string | undefined) => {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

export function CertificationCampaignsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [runsModal, setRunsModal] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20
  const [newCampaign, setNewCampaign] = useState({
    name: '',
    description: '',
    type: 'user_access',
    schedule: 'quarterly',
    reviewer_strategy: 'manager',
    auto_revoke: false,
    grace_period_days: 7,
    duration_days: 30,
  })

  const { data: campaigns, isLoading, isError, error } = useQuery({
    queryKey: ['campaigns', search, statusFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<Campaign[]>(`/api/v1/governance/campaigns?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: runs } = useQuery({
    queryKey: ['campaign-runs', selectedCampaign?.id],
    queryFn: () => api.get<CampaignRun[]>(`/api/v1/governance/campaigns/${selectedCampaign!.id}/runs`),
    enabled: !!selectedCampaign && runsModal,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newCampaign) => api.post('/api/v1/governance/campaigns', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: t('common.success'), description: t('pages.certCampaigns.toasts.created'), variant: 'success' })
      setCreateModal(false)
      setNewCampaign({ name: '', description: '', type: 'user_access', schedule: 'quarterly', reviewer_strategy: 'manager', auto_revoke: false, grace_period_days: 7, duration_days: 30 })
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/campaigns/${id}/run`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: t('common.success'), description: t('pages.certCampaigns.toasts.runStarted'), variant: 'success' })
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/campaigns/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: t('common.success'), description: t('pages.certCampaigns.toasts.deleted'), variant: 'success' })
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const filteredCampaigns = campaigns?.filter(c =>
    !search || c.name.toLowerCase().includes(search.toLowerCase())
  )

  const handleViewRuns = (campaign: Campaign) => {
    setSelectedCampaign(campaign)
    setRunsModal(true)
  }

  const getRunProgress = (run: CampaignRun) => {
    if (run.total_items === 0) return 0
    return Math.round((run.reviewed_items / run.total_items) * 100)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.certCampaigns.title')}</h1>
          <p className="text-muted-foreground">{t('pages.certCampaigns.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.certCampaigns.createCampaign')}
        </Button>
      </div>

      <RelatedLinks
        links={[
          { to: '/access-reviews', label: t('nav.items.accessReviews') },
          { to: '/attestation-campaigns', label: t('nav.items.attestation') },
        ]}
      />

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-green-100 flex items-center justify-center">
                <Target className="h-5 w-5 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.status === 'active').length || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.certCampaigns.stats.active')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Pause className="h-5 w-5 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.status === 'paused').length || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.certCampaigns.stats.paused')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <CalendarClock className="h-5 w-5 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.next_run_at).length || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.certCampaigns.stats.scheduled')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Campaign Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.certCampaigns.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter || 'all'} onValueChange={(val) => { setStatusFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]" aria-label={t('pages.certCampaigns.filter.statusLabel')}>
                <SelectValue placeholder={t('pages.certCampaigns.filter.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.certCampaigns.filter.all')}</SelectItem>
                <SelectItem value="active">{t('pages.certCampaigns.filter.active')}</SelectItem>
                <SelectItem value="paused">{t('pages.certCampaigns.filter.paused')}</SelectItem>
                <SelectItem value="completed">{t('pages.certCampaigns.filter.completed')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource={t('pages.certCampaigns.resourceName')} />
          ) : isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.certCampaigns.loading')}</p>
            </div>
          ) : !filteredCampaigns || filteredCampaigns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Target className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.certCampaigns.empty')}</p>
              <p className="text-sm">{t('pages.certCampaigns.emptyHint')}</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.campaign')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.type')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.schedule')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.status')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.lastRun')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.table.nextRun')}</TableHead>
                      <TableHead className="p-3 text-right text-sm font-medium">{t('pages.certCampaigns.table.actions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredCampaigns.map((campaign) => (
                      <TableRow key={campaign.id} className="border-b hover:bg-muted">
                        <TableCell className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-lg bg-indigo-100 flex items-center justify-center">
                              <Target className="h-4 w-4 text-indigo-700" />
                            </div>
                            <div>
                              <p className="font-medium">{campaign.name}</p>
                              <p className="text-sm text-muted-foreground max-w-xs truncate">{campaign.description || '-'}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="outline">{(CAMPAIGN_TYPES as readonly string[]).includes(campaign.type) ? t(`pages.certCampaigns.types.${campaign.type}`) : campaign.type}</Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <div className="text-sm">
                            <p>{(SCHEDULES as readonly string[]).includes(campaign.schedule) ? t(`pages.certCampaigns.schedules.${campaign.schedule}`) : campaign.schedule}</p>
                            <p className="text-muted-foreground">{t('pages.certCampaigns.duration', { n: campaign.duration_days })}</p>
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[campaign.status] || 'bg-muted text-foreground'}`}>
                            {statusIcons[campaign.status]}
                            {campaign.status}
                          </span>
                        </TableCell>
                        <TableCell className="p-3 text-sm">{formatDate(campaign.last_run_at)}</TableCell>
                        <TableCell className="p-3 text-sm">{formatDate(campaign.next_run_at)}</TableCell>
                        <TableCell className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleViewRuns(campaign)}>
                                <Eye className="h-4 w-4 mr-2" /> {t('pages.certCampaigns.menu.viewRuns')}
                              </DropdownMenuItem>
                              {campaign.status === 'active' && (
                                <ConfirmAction
                                  title={t('pages.certCampaigns.confirmRun.title')}
                                  description={t(
                                    campaign.auto_revoke
                                      ? 'pages.certCampaigns.confirmRun.descAutoRevoke'
                                      : 'pages.certCampaigns.confirmRun.descPlain',
                                    { name: campaign.name },
                                  )}
                                  destructive
                                  requireReason
                                  confirmLabel={t('pages.certCampaigns.menu.runNow')}
                                  onConfirm={() => runMutation.mutateAsync(campaign.id)}
                                >
                                  {(open) => (
                                    <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }}>
                                      <Play className="h-4 w-4 mr-2" /> {t('pages.certCampaigns.menu.runNow')}
                                    </DropdownMenuItem>
                                  )}
                                </ConfirmAction>
                              )}
                              <ConfirmAction
                                title={t('pages.certCampaigns.confirmDelete.title')}
                                description={t('pages.certCampaigns.confirmDelete.description', { name: campaign.name })}
                                destructive
                                confirmLabel={t('common.delete')}
                                onConfirm={() => deleteMutation.mutateAsync(campaign.id)}
                              >
                                {(open) => (
                                  <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }} className="text-red-600">
                                    <Trash2 className="h-4 w-4 mr-2" /> {t('common.delete')}
                                  </DropdownMenuItem>
                                )}
                              </ConfirmAction>
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
                    {t('pages.certCampaigns.showing', { from: page * PAGE_SIZE + 1, to: Math.min((page + 1) * PAGE_SIZE, totalCount), total: totalCount })}
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

      {/* Create Campaign Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.certCampaigns.createDialog.title')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(newCampaign) }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.certCampaigns.createDialog.name')}</Label>
              <Input value={newCampaign.name} onChange={(e) => setNewCampaign(prev => ({ ...prev, name: e.target.value }))} placeholder={t('pages.certCampaigns.createDialog.namePlaceholder')} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="certification-campaigns-description">{t('pages.certCampaigns.createDialog.description')}</Label>
              <Textarea id="certification-campaigns-description" value={newCampaign.description} onChange={(e) => setNewCampaign(prev => ({ ...prev, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="certification-campaigns-review-type">{t('pages.certCampaigns.createDialog.reviewType')}</Label>
                <Select value={newCampaign.type} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, type: val }))}>
                  <SelectTrigger id="certification-campaigns-review-type"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user_access">{t('pages.certCampaigns.createDialog.typeUserAccess')}</SelectItem>
                    <SelectItem value="role_assignment">{t('pages.certCampaigns.createDialog.typeRoleAssignment')}</SelectItem>
                    <SelectItem value="application_access">{t('pages.certCampaigns.createDialog.typeAppAccess')}</SelectItem>
                    <SelectItem value="privileged_access">{t('pages.certCampaigns.createDialog.typePrivilegedAccess')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="certification-campaigns-schedule">{t('pages.certCampaigns.createDialog.schedule')}</Label>
                <Select value={newCampaign.schedule} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, schedule: val }))}>
                  <SelectTrigger id="certification-campaigns-schedule"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="once">{t('pages.certCampaigns.schedules.once')}</SelectItem>
                    <SelectItem value="quarterly">{t('pages.certCampaigns.schedules.quarterly')}</SelectItem>
                    <SelectItem value="semi_annual">{t('pages.certCampaigns.schedules.semi_annual')}</SelectItem>
                    <SelectItem value="annual">{t('pages.certCampaigns.schedules.annual')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="certification-campaigns-reviewer-strategy">{t('pages.certCampaigns.createDialog.reviewerStrategy')}</Label>
                <Select value={newCampaign.reviewer_strategy} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, reviewer_strategy: val }))}>
                  <SelectTrigger id="certification-campaigns-reviewer-strategy"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manager">{t('pages.certCampaigns.createDialog.strategyManager')}</SelectItem>
                    <SelectItem value="app_owner">{t('pages.certCampaigns.createDialog.strategyAppOwner')}</SelectItem>
                    <SelectItem value="specific_user">{t('pages.certCampaigns.createDialog.strategySpecificUser')}</SelectItem>
                    <SelectItem value="role_based">{t('pages.certCampaigns.createDialog.strategyRoleBased')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="certification-campaigns-duration">{t('pages.certCampaigns.createDialog.duration')}</Label>
                <Input id="certification-campaigns-duration" type="number" value={newCampaign.duration_days} onChange={(e) => setNewCampaign(prev => ({ ...prev, duration_days: parseInt(e.target.value) || 30 }))} min={1} />
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <input type="checkbox" id="auto_revoke" checked={newCampaign.auto_revoke} onChange={(e) => setNewCampaign(prev => ({ ...prev, auto_revoke: e.target.checked }))} className="rounded border-border" />
                <Label htmlFor="auto_revoke">{t('pages.certCampaigns.createDialog.autoRevoke')}</Label>
              </div>
              {newCampaign.auto_revoke && (
                <div className="flex items-center gap-2">
                  <Label htmlFor="certification-campaigns-grace-period">{t('pages.certCampaigns.createDialog.gracePeriod')}</Label>
                  <Input id="certification-campaigns-grace-period" type="number" value={newCampaign.grace_period_days} onChange={(e) => setNewCampaign(prev => ({ ...prev, grace_period_days: parseInt(e.target.value) || 7 }))} className="w-20" min={0} />
                  <span className="text-sm text-muted-foreground">{t('pages.certCampaigns.createDialog.days')}</span>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? t('pages.certCampaigns.createDialog.creating') : t('pages.certCampaigns.createCampaign')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Campaign Runs Modal */}
      <Dialog open={runsModal} onOpenChange={setRunsModal}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('pages.certCampaigns.runsDialog.title', { name: selectedCampaign?.name ?? '' })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!runs || runs.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p>{t('pages.certCampaigns.runsDialog.empty')}</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.runsDialog.started')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.runsDialog.deadline')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.runsDialog.status')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.runsDialog.progress')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.certCampaigns.runsDialog.autoRevoked')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((run) => (
                      <TableRow key={run.id} className="border-b">
                        <TableCell className="p-3 text-sm">{formatDate(run.started_at)}</TableCell>
                        <TableCell className="p-3 text-sm">{formatDate(run.deadline)}</TableCell>
                        <TableCell className="p-3">
                          <Badge variant={run.status === 'in_progress' ? 'default' : run.status === 'completed' ? 'secondary' : 'destructive'}>
                            {run.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <div className="w-28">
                            <div className="flex justify-between text-xs mb-1">
                              <span>{run.reviewed_items}/{run.total_items}</span>
                              <span>{getRunProgress(run)}%</span>
                            </div>
                            <div className="h-2 bg-muted rounded-full overflow-hidden">
                              <div className="h-full bg-indigo-600 rounded-full" style={{ width: `${getRunProgress(run)}%` }} />
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="p-3 text-sm">{run.auto_revoked_items}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
