import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  Workflow,
  UserPlus,
  UserMinus,
  ArrowRightLeft,
  Clock,
  CheckCircle,
  XCircle,
  Play,
  Trash2,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  Eye,
  LogOut,
  RotateCcw,
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
import { ConfirmAction } from '../components/confirm-action'

interface LifecycleWorkflow {
  id: string
  name: string
  description: string
  event_type: string
  trigger_type: string
  actions: Record<string, unknown>[]
  conditions: Record<string, unknown>
  require_approval: boolean
  approval_policy_id?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface LifecycleExecution {
  id: string
  workflow_id: string
  user_id: string
  triggered_by?: string
  trigger_type: string
  status: string
  actions_completed: Record<string, unknown>[]
  actions_failed: Record<string, unknown>[]
  error?: string
  started_at: string
  completed_at?: string
  created_at: string
}

const eventIcons: Record<string, React.ReactNode> = {
  onboard: <UserPlus className="h-4 w-4" />,
  transfer: <ArrowRightLeft className="h-4 w-4" />,
  offboard: <UserMinus className="h-4 w-4" />,
  leave: <LogOut className="h-4 w-4" />,
  return: <RotateCcw className="h-4 w-4" />,
}

const eventColors: Record<string, string> = {
  onboard: 'bg-green-100 text-green-800',
  transfer: 'bg-blue-100 text-blue-800',
  offboard: 'bg-red-100 text-red-800',
  leave: 'bg-yellow-100 text-yellow-800',
  return: 'bg-purple-100 text-purple-800',
}

// The wire values the lifecycle service accepts. Labels resolve through the
// catalog at render, so the filter, the badge and the form cannot drift.
const EVENT_TYPES = ['onboard', 'transfer', 'offboard', 'leave', 'return'] as const
const TRIGGER_TYPES = ['manual', 'scheduled', 'webhook'] as const
const ACTION_TYPES = [
  'assign_role',
  'remove_role',
  'assign_group',
  'remove_group',
  'enable_user',
  'disable_user',
  'revoke_sessions',
] as const

const executionStatusColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  rejected: 'bg-muted text-foreground',
}

interface ActionInput {
  type: string
  role_id?: string
  group_id?: string
}

const formatDate = (dateStr: string | undefined) => {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function LifecycleWorkflowsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [eventFilter, setEventFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [executeModal, setExecuteModal] = useState(false)
  const [executionsModal, setExecutionsModal] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState<LifecycleWorkflow | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20
  const [executeUserId, setExecuteUserId] = useState('')
  const [newWorkflow, setNewWorkflow] = useState({
    name: '',
    description: '',
    event_type: 'onboard',
    trigger_type: 'manual',
    actions: [] as ActionInput[],
    require_approval: false,
    enabled: true,
  })
  const [newAction, setNewAction] = useState<ActionInput>({ type: 'assign_role' })

  const { data: workflows, isLoading, isError, error } = useQuery({
    queryKey: ['lifecycle-workflows', search, eventFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (eventFilter) params.set('event_type', eventFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<LifecycleWorkflow[]>(`/api/v1/identity/lifecycle/workflows?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: executions } = useQuery({
    queryKey: ['lifecycle-executions', selectedWorkflow?.id],
    queryFn: () => {
      const params = new URLSearchParams()
      if (selectedWorkflow) params.set('workflow_id', selectedWorkflow.id)
      params.set('limit', '20')
      return api.get<LifecycleExecution[]>(`/api/v1/identity/lifecycle/executions?${params.toString()}`)
    },
    enabled: !!selectedWorkflow && executionsModal,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newWorkflow) => api.post('/api/v1/identity/lifecycle/workflows', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-workflows'] })
      toast({ title: t('common.success'), description: t('pages.lifecycleWorkflows.created'), variant: 'success' })
      setCreateModal(false)
      setNewWorkflow({ name: '', description: '', event_type: 'onboard', trigger_type: 'manual', actions: [], require_approval: false, enabled: true })
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const executeMutation = useMutation({
    mutationFn: ({ id, user_id }: { id: string; user_id: string }) =>
      api.post(`/api/v1/identity/lifecycle/workflows/${id}/execute`, { user_id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-executions'] })
      toast({ title: t('common.success'), description: t('pages.lifecycleWorkflows.executed'), variant: 'success' })
      setExecuteModal(false)
      setExecuteUserId('')
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/lifecycle/workflows/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-workflows'] })
      toast({ title: t('common.success'), description: t('pages.lifecycleWorkflows.deleted'), variant: 'success' })
    },
    onError: (error: Error) => toast({ title: t('common.error'), description: error.message, variant: 'destructive' }),
  })

  const filteredWorkflows = workflows?.filter(w =>
    !search || w.name.toLowerCase().includes(search.toLowerCase())
  )

  const addAction = () => {
    if (newAction.type) {
      setNewWorkflow(prev => ({
        ...prev,
        actions: [...prev.actions, { ...newAction }],
      }))
      setNewAction({ type: 'assign_role' })
    }
  }

  const removeAction = (idx: number) => {
    setNewWorkflow(prev => ({
      ...prev,
      actions: prev.actions.filter((_, i) => i !== idx),
    }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.lifecycleWorkflows.title')}</h1>
          <p className="text-muted-foreground">{t('pages.lifecycleWorkflows.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.lifecycleWorkflows.create')}
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-5">
        {EVENT_TYPES.map(evt => (
          <Card key={evt}>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className={`h-9 w-9 rounded-lg ${eventColors[evt].split(' ')[0]} flex items-center justify-center`}>
                  {eventIcons[evt]}
                </div>
                <div>
                  <p className="text-xl font-bold">{workflows?.filter(w => w.event_type === evt).length || 0}</p>
                  <p className="text-xs text-muted-foreground">{t(`pages.lifecycleWorkflows.events.${evt}`)}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Workflow Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.lifecycleWorkflows.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={eventFilter || 'all'} onValueChange={(val) => { setEventFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]" aria-label={t('pages.lifecycleWorkflows.eventFilterLabel')}>
                <SelectValue placeholder={t('pages.lifecycleWorkflows.allEvents')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.lifecycleWorkflows.allEvents')}</SelectItem>
                {EVENT_TYPES.map(evt => (
                  <SelectItem key={evt} value={evt}>{t(`pages.lifecycleWorkflows.events.${evt}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.lifecycleWorkflows.loading')}</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.lifecycleWorkflows.resource')} />
          ) : !filteredWorkflows || filteredWorkflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Workflow className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.lifecycleWorkflows.emptyTitle')}</p>
              <p className="text-sm">{t('pages.lifecycleWorkflows.emptyDesc')}</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.colWorkflow')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.colEvent')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.colTrigger')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.colActions')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.colStatus')}</TableHead>
                      <TableHead className="p-3 text-right text-sm font-medium">{t('pages.lifecycleWorkflows.colRowActions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredWorkflows.map((wf) => (
                      <TableRow key={wf.id} className="border-b hover:bg-muted">
                        <TableCell className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-lg bg-indigo-100 flex items-center justify-center">
                              <Workflow className="h-4 w-4 text-indigo-700" />
                            </div>
                            <div>
                              <p className="font-medium">{wf.name}</p>
                              <p className="text-sm text-muted-foreground max-w-xs truncate">{wf.description || '-'}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${eventColors[wf.event_type] || 'bg-muted text-foreground'}`}>
                            {eventIcons[wf.event_type]}
                            {t(`pages.lifecycleWorkflows.events.${wf.event_type}`, { defaultValue: wf.event_type })}
                          </span>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="outline">
                            {t(`pages.lifecycleWorkflows.triggers.${wf.trigger_type}`, {
                              defaultValue: wf.trigger_type,
                            })}
                          </Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <div className="flex gap-1 flex-wrap">
                            {(wf.actions || []).slice(0, 3).map((a, i) => (
                              <Badge key={i} variant="secondary" className="text-xs">
                                {t(`pages.lifecycleWorkflows.actionTypes.${(a as Record<string, string>).type}`, {
                                  defaultValue: (a as Record<string, string>).type,
                                })}
                              </Badge>
                            ))}
                            {(wf.actions || []).length > 3 && (
                              <Badge variant="secondary" className="text-xs">+{wf.actions.length - 3}</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant={wf.enabled ? 'default' : 'secondary'}>
                            {wf.enabled
                              ? t('pages.lifecycleWorkflows.enabled')
                              : t('pages.lifecycleWorkflows.disabled')}
                          </Badge>
                        </TableCell>
                        <TableCell className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => {
                                setSelectedWorkflow(wf)
                                setExecuteModal(true)
                              }}>
                                <Play className="h-4 w-4 mr-2" /> {t('pages.lifecycleWorkflows.execute')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => {
                                setSelectedWorkflow(wf)
                                setExecutionsModal(true)
                              }}>
                                <Eye className="h-4 w-4 mr-2" /> {t('pages.lifecycleWorkflows.viewHistory')}
                              </DropdownMenuItem>
                              <ConfirmAction
                                title={t('pages.lifecycleWorkflows.deleteTitle')}
                                description={t('pages.lifecycleWorkflows.deleteDesc', { name: wf.name })}
                                destructive
                                confirmLabel={t('pages.lifecycleWorkflows.delete')}
                                onConfirm={() => deleteMutation.mutateAsync(wf.id)}
                              >
                                {(open) => (
                                  <DropdownMenuItem
                                    onSelect={(e) => { e.preventDefault(); open() }}
                                    className="text-red-600"
                                  >
                                    <Trash2 className="h-4 w-4 mr-2" /> {t('pages.lifecycleWorkflows.delete')}
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
                    {t('pages.lifecycleWorkflows.showing', {
                      from: page * PAGE_SIZE + 1,
                      to: Math.min((page + 1) * PAGE_SIZE, totalCount),
                      total: totalCount,
                    })}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                      <ChevronLeft className="h-4 w-4 mr-1" /> {t('common.pagination.previous')}
                    </Button>
                    <span className="text-sm text-muted-foreground">
                      {t('common.pagination.pageOf', {
                        page: page + 1,
                        pages: Math.ceil(totalCount / PAGE_SIZE),
                      })}
                    </span>
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

      {/* Create Workflow Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('pages.lifecycleWorkflows.form.title')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(newWorkflow) }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.lifecycleWorkflows.form.name')}</Label>
              <Input value={newWorkflow.name} onChange={(e) => setNewWorkflow(prev => ({ ...prev, name: e.target.value }))} placeholder={t('pages.lifecycleWorkflows.form.namePlaceholder')} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="lifecycle-workflows-description">{t('pages.lifecycleWorkflows.form.description')}</Label>
              <Textarea id="lifecycle-workflows-description" value={newWorkflow.description} onChange={(e) => setNewWorkflow(prev => ({ ...prev, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="lifecycle-workflows-event-type">{t('pages.lifecycleWorkflows.form.eventType')}</Label>
                <Select value={newWorkflow.event_type} onValueChange={(val) => setNewWorkflow(prev => ({ ...prev, event_type: val }))}>
                  <SelectTrigger id="lifecycle-workflows-event-type"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {EVENT_TYPES.map(evt => (
                      <SelectItem key={evt} value={evt}>{t(`pages.lifecycleWorkflows.events.${evt}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="lifecycle-workflows-trigger">{t('pages.lifecycleWorkflows.form.trigger')}</Label>
                <Select value={newWorkflow.trigger_type} onValueChange={(val) => setNewWorkflow(prev => ({ ...prev, trigger_type: val }))}>
                  <SelectTrigger id="lifecycle-workflows-trigger"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {TRIGGER_TYPES.map(tt => (
                      <SelectItem key={tt} value={tt}>{t(`pages.lifecycleWorkflows.triggers.${tt}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Action Builder */}
            <div className="space-y-2">
              <Label>{t('pages.lifecycleWorkflows.form.actions')}</Label>
              {newWorkflow.actions.length > 0 && (
                <div className="space-y-2">
                  {newWorkflow.actions.map((action, idx) => (
                    <div key={idx} className="flex items-center gap-2 p-2 bg-muted rounded">
                      <Badge variant="secondary">{idx + 1}</Badge>
                      <span className="text-sm flex-1">
                        {t(`pages.lifecycleWorkflows.actionTypes.${action.type}`, { defaultValue: action.type })}
                      </span>
                      {action.role_id && (
                        <span className="text-xs text-muted-foreground">
                          {t('pages.lifecycleWorkflows.form.actionRole', { id: action.role_id.slice(0, 8) })}
                        </span>
                      )}
                      {action.group_id && (
                        <span className="text-xs text-muted-foreground">
                          {t('pages.lifecycleWorkflows.form.actionGroup', { id: action.group_id.slice(0, 8) })}
                        </span>
                      )}
                      <Button type="button" variant="ghost" size="sm" onClick={() => removeAction(idx)} className="h-6 w-6 p-0">
                        <XCircle className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex gap-2">
                <Select value={newAction.type} onValueChange={(val) => setNewAction(prev => ({ ...prev, type: val }))}>
                  <SelectTrigger aria-label={t('pages.lifecycleWorkflows.form.actionTypeLabel')} className="flex-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ACTION_TYPES.map(at => (
                      <SelectItem key={at} value={at}>{t(`pages.lifecycleWorkflows.actionTypes.${at}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {(newAction.type === 'assign_role' || newAction.type === 'remove_role') && (
                  <Input
                    placeholder={t('pages.lifecycleWorkflows.form.roleIdPlaceholder')}
                    value={newAction.role_id || ''}
                    onChange={(e) => setNewAction(prev => ({ ...prev, role_id: e.target.value }))}
                    className="w-40"
                  />
                )}
                {(newAction.type === 'assign_group' || newAction.type === 'remove_group') && (
                  <Input
                    placeholder={t('pages.lifecycleWorkflows.form.groupIdPlaceholder')}
                    value={newAction.group_id || ''}
                    onChange={(e) => setNewAction(prev => ({ ...prev, group_id: e.target.value }))}
                    className="w-40"
                  />
                )}
                <Button type="button" variant="outline" onClick={addAction}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input type="checkbox" id="require_approval" checked={newWorkflow.require_approval} onChange={(e) => setNewWorkflow(prev => ({ ...prev, require_approval: e.target.checked }))} className="rounded border-border" />
              <Label htmlFor="require_approval">{t('pages.lifecycleWorkflows.form.requireApproval')}</Label>
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending
                  ? t('pages.lifecycleWorkflows.form.creating')
                  : t('pages.lifecycleWorkflows.form.submit')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Execute Workflow Modal */}
      <Dialog open={executeModal} onOpenChange={setExecuteModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {t('pages.lifecycleWorkflows.executeDialog.title', { name: selectedWorkflow?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (selectedWorkflow && executeUserId) {
              executeMutation.mutate({ id: selectedWorkflow.id, user_id: executeUserId })
            }
          }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.lifecycleWorkflows.executeDialog.targetUser')}</Label>
              <Input
                value={executeUserId}
                onChange={(e) => setExecuteUserId(e.target.value)}
                placeholder={t('pages.lifecycleWorkflows.executeDialog.targetUserPlaceholder')}
                required
              />
            </div>
            {selectedWorkflow && (
              <div className="p-3 bg-muted rounded-lg text-sm">
                <p className="font-medium mb-2">{t('pages.lifecycleWorkflows.executeDialog.actionsToExecute')}</p>
                <ol className="list-decimal ml-4 space-y-1">
                  {(selectedWorkflow.actions || []).map((a, i) => (
                    <li key={i}>
                      {t(`pages.lifecycleWorkflows.actionTypes.${(a as Record<string, string>).type}`, {
                        defaultValue: (a as Record<string, string>).type,
                      })}
                    </li>
                  ))}
                </ol>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setExecuteModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={executeMutation.isPending}>
                {executeMutation.isPending
                  ? t('pages.lifecycleWorkflows.executeDialog.executing')
                  : t('pages.lifecycleWorkflows.executeDialog.submit')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Execution History Modal */}
      <Dialog open={executionsModal} onOpenChange={setExecutionsModal}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {t('pages.lifecycleWorkflows.history.title', { name: selectedWorkflow?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!executions || executions.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p>{t('pages.lifecycleWorkflows.history.empty')}</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.history.colStarted')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.history.colUserId')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.history.colStatus')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.history.colCompletedFailed')}</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">{t('pages.lifecycleWorkflows.history.colCompletedAt')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {executions.map((exec) => (
                      <TableRow key={exec.id} className="border-b">
                        <TableCell className="p-3 text-sm">{formatDate(exec.started_at)}</TableCell>
                        <TableCell className="p-3 text-sm font-mono">{exec.user_id.slice(0, 8)}...</TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${executionStatusColors[exec.status] || 'bg-muted text-foreground'}`}>
                            {exec.status === 'completed' ? <CheckCircle className="h-3 w-3" /> : exec.status === 'failed' ? <XCircle className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                            {t(`pages.lifecycleWorkflows.executionStatuses.${exec.status}`, {
                              defaultValue: exec.status,
                            })}
                          </span>
                        </TableCell>
                        <TableCell className="p-3 text-sm">
                          <span className="text-green-600">{exec.actions_completed?.length || 0}</span>
                          {' / '}
                          <span className="text-red-600">{exec.actions_failed?.length || 0}</span>
                        </TableCell>
                        <TableCell className="p-3 text-sm">{formatDate(exec.completed_at)}</TableCell>
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
