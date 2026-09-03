import { useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Smartphone, Check, X, Clock, Settings, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { Switch } from '../components/ui/switch'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

// The request lifecycle the trust service owns; labels resolve through the
// catalog so the filter and the badge cannot drift apart.
const REQUEST_STATUSES = ['pending', 'approved', 'rejected', 'expired'] as const

interface TrustRequest {
  id: string
  user_id: string
  user_email: string
  user_name: string
  device_name: string
  device_type: string
  ip_address: string
  justification: string
  status: string
  reviewed_by?: string
  reviewed_at?: string
  review_notes?: string
  created_at: string
}

interface TrustSettings {
  id: string
  require_approval: boolean
  auto_approve_known_ips: boolean
  auto_approve_corporate_devices: boolean
  request_expiry_hours: number
  notify_admins: boolean
  notify_user_on_decision: boolean
}

export function DeviceTrustApprovalPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('pending')
  const [selectedRequests, setSelectedRequests] = useState<string[]>([])
  const [reviewDialog, setReviewDialog] = useState(false)
  const [settingsDialog, setSettingsDialog] = useState(false)
  const [selectedRequest, setSelectedRequest] = useState<TrustRequest | null>(null)
  const [reviewNotes, setReviewNotes] = useState('')
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject'>('approve')

  // Fetch requests
  const { data: requestsData, isLoading, isError, error } = useQuery({
    queryKey: ['device-trust-requests', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.append('status', statusFilter)
      return api.get<{ requests: TrustRequest[] }>(`/api/v1/identity/device-trust-requests?${params}`)
    }
  })

  const requests: TrustRequest[] = requestsData?.requests || []

  // Fetch settings
  const { data: settings } = useQuery({
    queryKey: ['device-trust-settings'],
    queryFn: async () => {
      return api.get<TrustSettings>('/api/v1/identity/device-trust-settings')
    }
  })

  // Fetch pending count
  const { data: pendingData } = useQuery({
    queryKey: ['device-trust-pending-count'],
    queryFn: async () => {
      return api.get<{ count: number }>('/api/v1/identity/device-trust-requests/pending-count')
    }
  })

  const pendingCount = pendingData?.count || 0

  // Mutations
  const approveMutation = useMutation({
    mutationFn: ({ requestId, notes }: { requestId: string; notes: string }) =>
      api.post(`/api/v1/identity/device-trust-requests/${requestId}/approve`, { notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      // Sync Ziti attributes so network access is granted immediately
      if (selectedRequest?.user_id) {
        api.post(`/api/v1/access/ziti/sync/device-trust/${selectedRequest.user_id}`).catch(() => {})
      }
      toast({ title: t('pages.deviceTrustApproval.approved'), description: t('pages.deviceTrustApproval.approvedDesc') })
      setReviewDialog(false)
    }
  })

  const rejectMutation = useMutation({
    mutationFn: ({ requestId, notes }: { requestId: string; notes: string }) =>
      api.post(`/api/v1/identity/device-trust-requests/${requestId}/reject`, { notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({ title: t('pages.deviceTrustApproval.rejected'), description: t('pages.deviceTrustApproval.rejectedDesc') })
      setReviewDialog(false)
    }
  })

  const bulkApproveMutation = useMutation({
    mutationFn: (requestIds: string[]) =>
      api.post<{ approved: number }>('/api/v1/identity/device-trust-requests/bulk-approve', { request_ids: requestIds, notes: 'Bulk approved' }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({
        title: t('pages.deviceTrustApproval.bulkApproveTitle'),
        description: t('pages.deviceTrustApproval.bulkApproveDesc', { n: data.approved }),
      })
      setSelectedRequests([])
    }
  })

  const bulkRejectMutation = useMutation({
    mutationFn: (requestIds: string[]) =>
      api.post<{ rejected: number }>('/api/v1/identity/device-trust-requests/bulk-reject', { request_ids: requestIds, notes: 'Bulk rejected' }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({
        title: t('pages.deviceTrustApproval.bulkRejectTitle'),
        description: t('pages.deviceTrustApproval.bulkRejectDesc', { n: data.rejected }),
      })
      setSelectedRequests([])
    }
  })

  const updateSettingsMutation = useMutation({
    mutationFn: (newSettings: TrustSettings) =>
      api.put('/api/v1/identity/device-trust-settings', newSettings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-settings'] })
      toast({ title: t('pages.deviceTrustApproval.settingsUpdated') })
      setSettingsDialog(false)
    }
  })

  // A component rather than a plain function, so the label re-resolves on a
  // language switch instead of freezing at first render.
  const StatusBadge = ({ status }: { status: string }) => {
    const label = t(`pages.deviceTrustApproval.statuses.${status}`, { defaultValue: status })
    switch (status) {
      case 'pending':
        return <Badge className="bg-amber-100 text-amber-800"><Clock className="h-3 w-3 mr-1" />{label}</Badge>
      case 'approved':
        return <Badge className="bg-green-100 text-green-800"><CheckCircle2 className="h-3 w-3 mr-1" />{label}</Badge>
      case 'rejected':
        return <Badge className="bg-red-100 text-red-800"><XCircle className="h-3 w-3 mr-1" />{label}</Badge>
      case 'expired':
        return <Badge className="bg-muted text-foreground"><AlertCircle className="h-3 w-3 mr-1" />{label}</Badge>
      default:
        return <Badge>{label}</Badge>
    }
  }

  const handleReview = (request: TrustRequest, action: 'approve' | 'reject') => {
    setSelectedRequest(request)
    setReviewAction(action)
    setReviewNotes('')
    setReviewDialog(true)
  }

  const submitReview = () => {
    if (!selectedRequest) return
    if (reviewAction === 'approve') {
      approveMutation.mutate({ requestId: selectedRequest.id, notes: reviewNotes })
    } else {
      rejectMutation.mutate({ requestId: selectedRequest.id, notes: reviewNotes })
    }
  }

  const toggleSelectRequest = (id: string) => {
    setSelectedRequests(prev =>
      prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id]
    )
  }

  const selectAll = () => {
    if (selectedRequests.length === requests.length) {
      setSelectedRequests([])
    } else {
      setSelectedRequests(requests.map(r => r.id))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('pages.deviceTrustApproval.title')}</h1>
          <p className="text-muted-foreground">{t('pages.deviceTrustApproval.subtitle')}</p>
        </div>
        <Button variant="outline" onClick={() => setSettingsDialog(true)}>
          <Settings className="h-4 w-4 mr-2" />
          {t('pages.deviceTrustApproval.settings')}
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.deviceTrustApproval.stats.pending')}</CardTitle>
            <Clock className="h-4 w-4 text-amber-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{pendingCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.deviceTrustApproval.stats.approvalRequired')}</CardTitle>
            <Smartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {settings?.require_approval
                ? t('pages.deviceTrustApproval.yes')
                : t('pages.deviceTrustApproval.no')}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.deviceTrustApproval.stats.autoApprove')}</CardTitle>
            <Check className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-sm">
              {settings?.auto_approve_known_ips && (
                <span className="mr-2">{t('pages.deviceTrustApproval.stats.knownIps')}</span>
              )}
              {settings?.auto_approve_corporate_devices && (
                <span>{t('pages.deviceTrustApproval.stats.corporate')}</span>
              )}
              {!settings?.auto_approve_known_ips &&
                !settings?.auto_approve_corporate_devices &&
                t('pages.deviceTrustApproval.stats.disabled')}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Bulk Actions */}
      <div className="flex items-center justify-between">
        <Select value={statusFilter || 'all'} onValueChange={(v) => setStatusFilter(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[180px]" aria-label={t('pages.deviceTrustApproval.filterStatus')}>
            <SelectValue placeholder={t('pages.deviceTrustApproval.filterStatus')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('pages.deviceTrustApproval.all')}</SelectItem>
            {REQUEST_STATUSES.map((status) => (
              <SelectItem key={status} value={status}>
                {t(`pages.deviceTrustApproval.statuses.${status}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {statusFilter === 'pending' && selectedRequests.length > 0 && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => bulkApproveMutation.mutate(selectedRequests)}
              className="text-green-600"
            >
              <Check className="h-4 w-4 mr-1" />
              {t('pages.deviceTrustApproval.bulkApprove', { n: selectedRequests.length })}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => bulkRejectMutation.mutate(selectedRequests)}
              className="text-red-600"
            >
              <X className="h-4 w-4 mr-1" />
              {t('pages.deviceTrustApproval.bulkReject', { n: selectedRequests.length })}
            </Button>
          </div>
        )}
      </div>

      {/* Requests List */}
      <Card>
        <CardHeader>
          <CardTitle>{t('pages.deviceTrustApproval.listHeading')}</CardTitle>
          <CardDescription>{t('pages.deviceTrustApproval.listDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.deviceTrustApproval.resource')} />
          ) : requests.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Smartphone className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>{t('pages.deviceTrustApproval.empty')}</p>
            </div>
          ) : (
            <Table className="text-sm">
                <TableHeader>
                  <TableRow className="border-b">
                    {statusFilter === 'pending' && (
                      <TableHead className="py-3 px-2">
                        <Checkbox
                          checked={selectedRequests.length === requests.length}
                          onCheckedChange={selectAll}
                        />
                      </TableHead>
                    )}
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colUser')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colDevice')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colIp')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colJustification')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colStatus')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colRequested')}</TableHead>
                    <TableHead className="text-left py-3 px-2 font-medium">{t('pages.deviceTrustApproval.colActions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {requests.map((request) => (
                    <TableRow key={request.id} className="border-b hover:bg-muted/50">
                      {statusFilter === 'pending' && (
                        <TableCell className="py-3 px-2">
                          <Checkbox
                            checked={selectedRequests.includes(request.id)}
                            onCheckedChange={() => toggleSelectRequest(request.id)}
                          />
                        </TableCell>
                      )}
                      <TableCell className="py-3 px-2">
                        <div>
                          <p className="font-medium">{request.user_name}</p>
                          <p className="text-xs text-muted-foreground">{request.user_email}</p>
                        </div>
                      </TableCell>
                      <TableCell className="py-3 px-2">
                        <div>
                          <p>{request.device_name}</p>
                          <p className="text-xs text-muted-foreground">{request.device_type}</p>
                        </div>
                      </TableCell>
                      <TableCell className="py-3 px-2 font-mono text-xs">{request.ip_address}</TableCell>
                      <TableCell className="py-3 px-2 max-w-[200px] truncate" title={request.justification}>
                        {request.justification || '-'}
                      </TableCell>
                      <TableCell className="py-3 px-2"><StatusBadge status={request.status} /></TableCell>
                      <TableCell className="py-3 px-2 whitespace-nowrap">
                        {new Date(request.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="py-3 px-2">
                        {request.status === 'pending' && (
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleReview(request, 'approve')}
                              className="text-green-600 hover:text-green-700"
                            >
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleReview(request, 'reject')}
                              className="text-red-600 hover:text-red-700"
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                        {request.status !== 'pending' && request.review_notes && (
                          <span className="text-xs text-muted-foreground" title={request.review_notes}>
                            {request.review_notes.substring(0, 20)}...
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
          )}
        </CardContent>
      </Card>

      {/* Review Dialog */}
      <Dialog open={reviewDialog} onOpenChange={setReviewDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {reviewAction === 'approve'
                ? t('pages.deviceTrustApproval.review.approveTitle')
                : t('pages.deviceTrustApproval.review.rejectTitle')}
            </DialogTitle>
          </DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="bg-muted p-4 rounded-lg space-y-2">
                <p><strong>{t('pages.deviceTrustApproval.review.user')}</strong> {selectedRequest.user_name} ({selectedRequest.user_email})</p>
                <p><strong>{t('pages.deviceTrustApproval.review.device')}</strong> {selectedRequest.device_name}</p>
                <p><strong>{t('pages.deviceTrustApproval.review.ip')}</strong> {selectedRequest.ip_address}</p>
                {selectedRequest.justification && (
                  <p><strong>{t('pages.deviceTrustApproval.review.justification')}</strong> {selectedRequest.justification}</p>
                )}
              </div>
              {reviewAction === 'approve' && (
                <p className="text-sm text-blue-700 bg-blue-50 p-3 rounded-md">
                  <Trans
                    i18nKey="pages.deviceTrustApproval.review.approveHint"
                    components={[<code key="0" className="font-mono bg-blue-100 px-1 rounded" />]}
                  />
                </p>
              )}
              <div className="space-y-2">
                <Label>{t('pages.deviceTrustApproval.review.notes')}</Label>
                <Textarea
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder={t('pages.deviceTrustApproval.review.notesPlaceholder')}
                  rows={3}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setReviewDialog(false)}>{t('common.cancel')}</Button>
            <Button
              onClick={submitReview}
              className={reviewAction === 'approve' ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}
            >
              {reviewAction === 'approve'
                ? t('pages.deviceTrustApproval.review.approve')
                : t('pages.deviceTrustApproval.review.reject')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Settings Dialog */}
      <Dialog open={settingsDialog} onOpenChange={setSettingsDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.deviceTrustApproval.settingsDialog.title')}</DialogTitle>
          </DialogHeader>
          {settings && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('pages.deviceTrustApproval.settingsDialog.requireApproval')}</Label>
                  <p className="text-xs text-muted-foreground">{t('pages.deviceTrustApproval.settingsDialog.requireApprovalHint')}</p>
                </div>
                <Switch
                  checked={settings.require_approval}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, require_approval: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('pages.deviceTrustApproval.settingsDialog.autoApproveIps')}</Label>
                  <p className="text-xs text-muted-foreground">{t('pages.deviceTrustApproval.settingsDialog.autoApproveIpsHint')}</p>
                </div>
                <Switch
                  checked={settings.auto_approve_known_ips}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, auto_approve_known_ips: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('pages.deviceTrustApproval.settingsDialog.autoApproveCorporate')}</Label>
                  <p className="text-xs text-muted-foreground">{t('pages.deviceTrustApproval.settingsDialog.autoApproveCorporateHint')}</p>
                </div>
                <Switch
                  checked={settings.auto_approve_corporate_devices}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, auto_approve_corporate_devices: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('pages.deviceTrustApproval.settingsDialog.notifyAdmins')}</Label>
                  <p className="text-xs text-muted-foreground">{t('pages.deviceTrustApproval.settingsDialog.notifyAdminsHint')}</p>
                </div>
                <Switch
                  checked={settings.notify_admins}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, notify_admins: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>{t('pages.deviceTrustApproval.settingsDialog.notifyUser')}</Label>
                  <p className="text-xs text-muted-foreground">{t('pages.deviceTrustApproval.settingsDialog.notifyUserHint')}</p>
                </div>
                <Switch
                  checked={settings.notify_user_on_decision}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, notify_user_on_decision: checked })
                  }
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setSettingsDialog(false)}>{t('common.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
