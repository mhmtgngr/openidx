import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { GitPullRequest, Plus, Clock, CheckCircle, XCircle, Ban, Timer, KeyRound, Undo2, Copy } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import { QueryError } from '../components/query-error'
import { api, VaultSecretMeta } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { useAuth } from '../lib/auth'

interface AccessRequest {
  id: string
  requester_id: string
  requester_name: string
  resource_name: string
  resource_type: string
  resource_id?: string
  status: string
  priority: string
  justification: string
  expires_at?: string
  created_at: string
  updated_at: string
}

// Minimal shapes for the resource pickers (role / group / application).
interface Role {
  id: string
  name: string
}
// Groups can come back SCIM-shaped (displayName) or flat (name).
type RawResource = { id?: unknown; name?: unknown; displayName?: unknown }
interface AppResource {
  id: string
  name: string
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    approved: 'bg-green-100 text-green-800',
    fulfilled: 'bg-green-100 text-green-800',
    denied: 'bg-red-100 text-red-800',
    cancelled: 'bg-muted text-foreground',
    expired: 'bg-orange-100 text-orange-800',
  }
  return map[status] || 'bg-muted text-foreground'
}

const DURATION_OPTIONS = [
  { value: '', labelKey: 'pages.accessRequests.durations.permanent' },
  { value: '4h', labelKey: 'pages.accessRequests.durations.h4' },
  { value: '8h', labelKey: 'pages.accessRequests.durations.h8' },
  { value: '1d', labelKey: 'pages.accessRequests.durations.d1' },
  { value: '3d', labelKey: 'pages.accessRequests.durations.d3' },
  { value: '7d', labelKey: 'pages.accessRequests.durations.d7' },
  { value: '30d', labelKey: 'pages.accessRequests.durations.d30' },
  { value: '90d', labelKey: 'pages.accessRequests.durations.d90' },
]

export function AccessRequestsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const { hasRole } = useAuth()
  // Only admins may see every user's requests (the "All Requests" org view).
  // The backend enforces this too; this just hides the control from users who
  // would otherwise get an empty/own-only list.
  const isAdmin = hasRole('admin') || hasRole('super_admin')
  const [activeTab, setActiveTab] = useState('my-requests')
  const [createOpen, setCreateOpen] = useState(false)
  const [approvalOpen, setApprovalOpen] = useState(false)
  const [approvalAction, setApprovalAction] = useState<'approve' | 'deny'>('approve')
  const [selectedRequest, setSelectedRequest] = useState<AccessRequest | null>(null)
  const [comments, setComments] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const [newReq, setNewReq] = useState({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '', secretId: '' })

  // Retrieve modal state (mirrors vault-secrets reveal pattern)
  const [retrieveOpen, setRetrieveOpen] = useState(false)
  const [selectedRetrieveId, setSelectedRetrieveId] = useState<string | null>(null)
  const [retrievedValue, setRetrievedValue] = useState<string | null>(null)

  const { data: myRequestsData, isLoading: myLoading, isError: myError, error: myErrorObj } = useQuery({
    queryKey: ['my-requests'],
    queryFn: () => api.get<{ requests: AccessRequest[] }>('/api/v1/governance/requests?requester_id=me'),
  })
  const myRequests = myRequestsData?.requests || []

  const { data: pendingData, isLoading: pendingLoading, isError: pendingError, error: pendingErrorObj } = useQuery({
    queryKey: ['my-approvals'],
    queryFn: () => api.get<{ pending_approvals: AccessRequest[] }>('/api/v1/governance/my-approvals'),
  })
  const pendingApprovals = pendingData?.pending_approvals || []

  const { data: allData, isLoading: allLoading, isError: allError, error: allErrorObj } = useQuery({
    queryKey: ['all-requests', statusFilter],
    enabled: isAdmin, // non-admins never fetch the org-wide list
    queryFn: () => {
      const params = statusFilter !== 'all' ? `?status=${statusFilter}` : ''
      return api.get<{ requests: AccessRequest[] }>(`/api/v1/governance/requests${params}`)
    },
  })
  const allRequests = allData?.requests || []

  const { data: vaultSecretsData } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
    enabled: newReq.resource_type === 'vault_credential',
  })
  const vaultSecrets: VaultSecretMeta[] = vaultSecretsData?.secrets || []

  // Resource pickers for the non-vault types. Requesters should choose a real,
  // existing resource rather than free-typing a name (a typo produces a request
  // that references nothing and stores a throwaway resource_id). Each list loads
  // only when its type is selected.
  const { data: rolesData } = useQuery({
    queryKey: ['ar-roles'],
    queryFn: () => api.get<Role[]>('/api/v1/identity/roles'),
    enabled: newReq.resource_type === 'role',
  })
  const { data: groupsData } = useQuery({
    queryKey: ['ar-groups'],
    queryFn: () => api.get<RawResource[]>('/api/v1/identity/groups'),
    enabled: newReq.resource_type === 'group',
  })
  const { data: appsData } = useQuery({
    queryKey: ['ar-apps'],
    queryFn: () => api.getWithHeaders<AppResource[]>('/api/v1/applications'),
    enabled: newReq.resource_type === 'application',
  })

  // Normalize each type's list to { id, name } picker options. Guard against
  // non-array payloads (some list endpoints wrap in {data:[]} / {items:[]}).
  const asArray = <T,>(v: unknown): T[] =>
    Array.isArray(v)
      ? (v as T[])
      : Array.isArray((v as { data?: unknown })?.data)
        ? ((v as { data: T[] }).data)
        : []
  const resourceOptions: { id: string; name: string }[] =
    newReq.resource_type === 'role'
      ? asArray<Role>(rolesData).map(r => ({ id: r.id, name: r.name }))
      : newReq.resource_type === 'group'
        ? asArray<RawResource>(groupsData).map(g => ({
            id: String(g.id ?? ''),
            name: String(g.displayName ?? g.name ?? ''),
          }))
        : newReq.resource_type === 'application'
          ? asArray<AppResource>(appsData?.data).map(a => ({ id: a.id, name: a.name }))
          : []
  const isPickerType =
    newReq.resource_type === 'role' ||
    newReq.resource_type === 'group' ||
    newReq.resource_type === 'application'

  const createMutation = useMutation({
    mutationFn: (data: typeof newReq) => {
      if (data.resource_type === 'vault_credential') {
        const payload = {
          resource_type: data.resource_type,
          resource_id: data.secretId,
          resource_name: data.resource_name,
          justification: data.justification,
          priority: data.priority,
          duration: data.duration,
        }
        return api.post('/api/v1/governance/requests', payload)
      }
      // role / group / application: send the picked resource_id alongside the
      // name so the request references a real resource (not a throwaway UUID).
      const payload = {
        resource_type: data.resource_type,
        resource_id: data.secretId || undefined,
        resource_name: data.resource_name,
        justification: data.justification,
        priority: data.priority,
        duration: data.duration === 'permanent' ? '' : data.duration,
      }
      return api.post('/api/v1/governance/requests', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: t('pages.accessRequests.toasts.submitted') })
      setCreateOpen(false)
      setNewReq({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '', secretId: '' })
    },
    onError: () => toast({ title: t('pages.accessRequests.toasts.submitFailed'), variant: 'destructive' }),
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      toast({ title: t('pages.accessRequests.toasts.cancelled') })
    },
  })

  const approveMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/approve`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: t('pages.accessRequests.toasts.approved') })
      setApprovalOpen(false)
    },
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/deny`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: t('pages.accessRequests.toasts.denied') })
      setApprovalOpen(false)
    },
  })

  const retrieveMutation = useMutation({
    mutationFn: (id: string) => api.post<{ value: string }>(`/api/v1/governance/requests/${id}/credential`),
    onSuccess: (data) => setRetrievedValue(data.value),
    onError: (err: { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error || t('pages.accessRequests.toasts.retrieveFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const returnMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/return`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: t('pages.accessRequests.toasts.returned') })
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error || t('pages.accessRequests.toasts.returnFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const formatDate = (d: string) => new Date(d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

  const openApproval = (req: AccessRequest, action: 'approve' | 'deny') => {
    setSelectedRequest(req)
    setApprovalAction(action)
    setComments('')
    setApprovalOpen(true)
  }

  const isVaultType = newReq.resource_type === 'vault_credential'
  const submitDisabled = isVaultType
    ? (!newReq.secretId || !newReq.duration || createMutation.isPending)
    : (!newReq.resource_type || !newReq.resource_name || createMutation.isPending)

  const durationOptions = isVaultType
    ? DURATION_OPTIONS.filter(opt => opt.value !== '')
    : DURATION_OPTIONS

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.accessRequests')}</h1>
          <p className="text-muted-foreground">{t('pages.accessRequests.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.accessRequests.requestAccess')}
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="my-requests"><GitPullRequest className="mr-2 h-4 w-4" />{t('pages.accessRequests.tabs.my')}</TabsTrigger>
          {/* Approver queue: caller-scoped (only requests awaiting THIS user).
              Hidden for standard users who aren't approvers and have none. */}
          {(isAdmin || pendingApprovals.length > 0) && (
            <TabsTrigger value="pending-approvals">
              <Clock className="mr-2 h-4 w-4" />{t('pages.accessRequests.tabs.pending')}
              {pendingApprovals.length > 0 && <Badge variant="secondary" className="ml-1">{pendingApprovals.length}</Badge>}
            </TabsTrigger>
          )}
          {/* Org-wide view — admins only. */}
          {isAdmin && <TabsTrigger value="all-requests">{t('pages.accessRequests.tabs.all')}</TabsTrigger>}
        </TabsList>

        <TabsContent value="my-requests">
          <Card>
            <CardHeader><CardTitle>{t('pages.accessRequests.myCard')}</CardTitle></CardHeader>
            <CardContent>
              {myLoading ? <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p> :
               myError ? <QueryError error={myErrorObj} resource={t('pages.accessRequests.resourceName')} /> :
               myRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.accessRequests.noRequests')}</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>{t('pages.accessRequests.table.resource')}</TableHead><TableHead>{t('pages.accessRequests.table.type')}</TableHead><TableHead>{t('pages.accessRequests.table.status')}</TableHead>
                    <TableHead>{t('pages.accessRequests.table.priority')}</TableHead><TableHead>{t('pages.accessRequests.table.created')}</TableHead><TableHead>{t('pages.accessRequests.table.actions')}</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {myRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-700 dark:text-orange-300" title={t('pages.accessRequests.expiresTitle', { date: new Date(r.expires_at).toLocaleString() })}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            {r.status === 'pending' && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="outline" size="sm"><Ban className="h-3 w-3 mr-1" />{t('pages.accessRequests.cancelDialog.trigger')}</Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>{t('pages.accessRequests.cancelDialog.title')}</AlertDialogTitle>
                                    <AlertDialogDescription>{t('pages.accessRequests.cancelDialog.description', { name: r.resource_name })}</AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>{t('pages.accessRequests.keep')}</AlertDialogCancel>
                                    <AlertDialogAction onClick={() => cancelMutation.mutate(r.id)}>{t('pages.accessRequests.cancelDialog.confirm')}</AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}
                            {r.resource_type === 'vault_credential' && r.status === 'fulfilled' && (
                              <>
                                <Button variant="outline" size="sm" onClick={() => { setSelectedRetrieveId(r.id); setRetrieveOpen(true) }}>
                                  <KeyRound className="h-3 w-3 mr-1" />{t('pages.accessRequests.retrieve')}
                                </Button>
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="outline" size="sm"><Undo2 className="h-3 w-3 mr-1" />{t('pages.accessRequests.returnDialog.trigger')}</Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>{t('pages.accessRequests.returnDialog.title')}</AlertDialogTitle>
                                      <AlertDialogDescription>{t('pages.accessRequests.returnDialog.description', { name: r.resource_name })}</AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>{t('pages.accessRequests.keep')}</AlertDialogCancel>
                                      <AlertDialogAction onClick={() => returnMutation.mutate(r.id)}>{t('pages.accessRequests.returnDialog.confirm')}</AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>
                              </>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pending-approvals">
          <Card>
            <CardHeader><CardTitle>{t('pages.accessRequests.tabs.pending')}</CardTitle></CardHeader>
            <CardContent>
              {pendingLoading ? <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p> :
               pendingError ? <QueryError error={pendingErrorObj} resource={t('pages.accessRequests.approvalsResourceName')} /> :
               pendingApprovals.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.accessRequests.noApprovals')}</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>{t('pages.accessRequests.table.requester')}</TableHead><TableHead>{t('pages.accessRequests.table.resource')}</TableHead><TableHead>{t('pages.accessRequests.table.type')}</TableHead>
                    <TableHead>{t('pages.accessRequests.table.priority')}</TableHead><TableHead>{t('pages.accessRequests.table.submitted')}</TableHead><TableHead>{t('pages.accessRequests.table.actions')}</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {pendingApprovals.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button size="sm" onClick={() => openApproval(r, 'approve')}><CheckCircle className="h-3 w-3 mr-1" />{t('pages.accessRequests.approve')}</Button>
                            <Button variant="destructive" size="sm" onClick={() => openApproval(r, 'deny')}><XCircle className="h-3 w-3 mr-1" />{t('pages.accessRequests.deny')}</Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="all-requests">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{t('pages.accessRequests.allCard')}</CardTitle>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[180px]"><SelectValue placeholder={t('pages.accessRequests.statusFilter.placeholder')} /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('pages.accessRequests.statusFilter.all')}</SelectItem>
                    <SelectItem value="pending">{t('pages.accessRequests.statusFilter.pending')}</SelectItem>
                    <SelectItem value="approved">{t('pages.accessRequests.statusFilter.approved')}</SelectItem>
                    <SelectItem value="denied">{t('pages.accessRequests.statusFilter.denied')}</SelectItem>
                    <SelectItem value="fulfilled">{t('pages.accessRequests.statusFilter.fulfilled')}</SelectItem>
                    <SelectItem value="cancelled">{t('pages.accessRequests.statusFilter.cancelled')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {allLoading ? <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p> :
               allError ? <QueryError error={allErrorObj} resource={t('pages.accessRequests.resourceName')} /> :
               allRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.accessRequests.noRequests')}</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>{t('pages.accessRequests.table.requester')}</TableHead><TableHead>{t('pages.accessRequests.table.resource')}</TableHead><TableHead>{t('pages.accessRequests.table.type')}</TableHead>
                    <TableHead>{t('pages.accessRequests.table.status')}</TableHead><TableHead>{t('pages.accessRequests.table.priority')}</TableHead><TableHead>{t('pages.accessRequests.table.created')}</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {allRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-700 dark:text-orange-300" title={t('pages.accessRequests.expiresTitle', { date: new Date(r.expires_at).toLocaleString() })}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.accessRequests.requestAccess')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.accessRequests.create.typeLabel')}</label>
              <Select value={newReq.resource_type} onValueChange={v => setNewReq(p => ({ ...p, resource_type: v, resource_name: '', secretId: '', duration: '' }))}>
                <SelectTrigger aria-label={t('pages.accessRequests.create.typeLabel')}><SelectValue placeholder={t('pages.accessRequests.create.typePlaceholder')} /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="role">{t('pages.accessRequests.create.types.role')}</SelectItem>
                  <SelectItem value="group">{t('pages.accessRequests.create.types.group')}</SelectItem>
                  <SelectItem value="application">{t('pages.accessRequests.create.types.application')}</SelectItem>
                  <SelectItem value="vault_credential">{t('pages.accessRequests.create.types.vault')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.accessRequests.create.nameLabel')}</label>
              {isVaultType ? (
                <Select value={newReq.secretId} onValueChange={v => {
                  const secret = vaultSecrets.find(s => s.id === v)
                  setNewReq(p => ({ ...p, secretId: v, resource_name: secret?.name || '' }))
                }}>
                  <SelectTrigger aria-label={t('pages.accessRequests.create.nameLabel')}><SelectValue placeholder={t('pages.accessRequests.create.vaultPlaceholder')} /></SelectTrigger>
                  <SelectContent>
                    {vaultSecrets.map(s => (
                      <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : isPickerType && resourceOptions.length > 0 ? (
                <Select value={newReq.secretId} onValueChange={v => {
                  const res = resourceOptions.find(r => r.id === v)
                  setNewReq(p => ({ ...p, secretId: v, resource_name: res?.name || '' }))
                }}>
                  <SelectTrigger aria-label={t('pages.accessRequests.create.nameLabel')}>
                    <SelectValue placeholder={t(`pages.accessRequests.create.pickerPlaceholder.${newReq.resource_type}`)} />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceOptions.map(r => (
                      <SelectItem key={r.id} value={r.id}>{r.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  placeholder={newReq.resource_type ? t('pages.accessRequests.create.namePlaceholder') : t('pages.accessRequests.create.nameFirst')}
                  disabled={!newReq.resource_type}
                  value={newReq.resource_name}
                  onChange={e => setNewReq(p => ({ ...p, resource_name: e.target.value, secretId: '' }))} />
              )}
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.accessRequests.create.justificationLabel')}</label>
              <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder={t('pages.accessRequests.create.justificationPlaceholder')}
                value={newReq.justification} onChange={e => setNewReq(p => ({ ...p, justification: e.target.value }))} />
            </div>
            <div>
              <label htmlFor="access-requests-priority-label" className="text-sm font-medium">{t('pages.accessRequests.create.priorityLabel')}</label>
              <Select value={newReq.priority} onValueChange={v => setNewReq(p => ({ ...p, priority: v }))}>
                <SelectTrigger id="access-requests-priority-label"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">{t('pages.accessRequests.create.priorities.low')}</SelectItem>
                  <SelectItem value="normal">{t('pages.accessRequests.create.priorities.normal')}</SelectItem>
                  <SelectItem value="high">{t('pages.accessRequests.create.priorities.high')}</SelectItem>
                  <SelectItem value="urgent">{t('pages.accessRequests.create.priorities.urgent')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.accessRequests.create.durationLabel')}{isVaultType && <span className="text-red-500 ml-1">*</span>}</label>
              <Select value={newReq.duration} onValueChange={v => setNewReq(p => ({ ...p, duration: v }))}>
                <SelectTrigger aria-label={t('pages.accessRequests.create.durationLabel')}><SelectValue placeholder={isVaultType ? t('pages.accessRequests.create.durationRequired') : t('pages.accessRequests.durations.permanent')} /></SelectTrigger>
                <SelectContent>
                  {durationOptions.map(opt => (
                    <SelectItem key={opt.value || 'permanent'} value={opt.value || 'permanent'}>
                      {t(opt.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {isVaultType
                  ? t('pages.accessRequests.create.durationHintVault')
                  : newReq.duration ? t('pages.accessRequests.create.durationHintExpires') : t('pages.accessRequests.create.durationHintPermanent')}
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)}>{t('common.cancel')}</Button>
              <Button disabled={submitDisabled}
                onClick={() => createMutation.mutate(newReq)}>
                {createMutation.isPending ? t('pages.accessRequests.create.submitting') : t('pages.accessRequests.create.submit')}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Approve/Deny Dialog */}
      <Dialog open={approvalOpen} onOpenChange={setApprovalOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{approvalAction === 'approve' ? t('pages.accessRequests.approval.approveTitle') : t('pages.accessRequests.approval.denyTitle')}</DialogTitle></DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <p><span className="font-medium">{t('pages.accessRequests.approval.requester')}</span> {selectedRequest.requester_name}</p>
                <p><span className="font-medium">{t('pages.accessRequests.approval.resource')}</span> {selectedRequest.resource_name}</p>
                <p><span className="font-medium">{t('pages.accessRequests.approval.type')}</span> {selectedRequest.resource_type}</p>
                {selectedRequest.justification && <p><span className="font-medium">{t('pages.accessRequests.approval.justification')}</span> {selectedRequest.justification}</p>}
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.accessRequests.approval.commentsLabel')}</label>
                <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder={t('pages.accessRequests.approval.commentsPlaceholder')}
                  value={comments} onChange={e => setComments(e.target.value)} />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setApprovalOpen(false)}>{t('common.cancel')}</Button>
                <Button variant={approvalAction === 'approve' ? 'default' : 'destructive'}
                  disabled={approveMutation.isPending || denyMutation.isPending}
                  onClick={() => {
                    if (approvalAction === 'approve') approveMutation.mutate({ id: selectedRequest.id, comments })
                    else denyMutation.mutate({ id: selectedRequest.id, comments })
                  }}>
                  {approvalAction === 'approve' ? t('pages.accessRequests.approve') : t('pages.accessRequests.deny')}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Retrieve Credential Modal — one-shot reveal (mirrors the vault-secrets reveal) */}
      <Dialog
        open={retrieveOpen}
        onOpenChange={(open) => {
          if (!open) {
            setRetrievedValue(null)
            setSelectedRetrieveId(null)
          }
          setRetrieveOpen(open)
        }}
      >
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.accessRequests.retrieveDialog.title')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            {!retrievedValue ? (
              <>
                <p className="text-sm text-muted-foreground">
                  {t('pages.accessRequests.retrieveDialog.hint')}
                </p>
                <Button
                  onClick={() => selectedRetrieveId && retrieveMutation.mutate(selectedRetrieveId)}
                  disabled={retrieveMutation.isPending || !selectedRetrieveId}
                  className="w-full"
                >
                  {retrieveMutation.isPending ? t('pages.accessRequests.retrieveDialog.getting') : t('pages.accessRequests.retrieveDialog.get')}
                </Button>
              </>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-md">
                  <p className="text-xs text-amber-800 font-medium">
                    {t('pages.accessRequests.retrieveDialog.shownOnce')}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={retrievedValue}
                    readOnly
                    className="font-mono text-sm"
                    type="text"
                    data-testid="retrieved-credential-value"
                  />
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => {
                      navigator.clipboard.writeText(retrievedValue)
                      toast({ title: t('pages.accessRequests.retrieveDialog.copied') })
                    }}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
