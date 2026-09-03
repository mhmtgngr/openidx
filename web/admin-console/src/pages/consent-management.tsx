import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  FileCheck,
  Clock,
  Trash2,
  Plus,
  Play,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
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
import { Switch } from '../components/ui/switch'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { api } from '../lib/api'
import { ConfirmAction } from '../components/confirm-action'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

// --- Interfaces ---

interface Consent {
  id: string
  user_id: string
  username: string
  consent_type: string
  version: string
  granted: boolean
  granted_at: string
  revoked_at: string | null
}

interface DSAR {
  id: string
  user_id: string
  username: string
  request_type: string
  status: string
  reason: string
  due_date: string
  created_at: string
  completed_at: string | null
}

interface RetentionPolicy {
  id: string
  name: string
  data_category: string
  retention_days: number
  action: string
  enabled: boolean
  created_at: string
}

interface ImpactAssessment {
  id: string
  title: string
  description: string
  risk_level: string
  status: string
  assessor: string
  data_categories: string[]
  processing_purposes: string[]
  created_at: string
}

// --- Helpers ---

// Labels resolve from pages.consentManagement.tabs.<key> at render.
const tabs = [
  { key: 'consents', icon: Shield },
  { key: 'dsars', icon: FileCheck },
  { key: 'retention', icon: Clock },
  { key: 'assessments', icon: AlertTriangle },
] as const

type TabKey = (typeof tabs)[number]['key']

// A DSAR's user_id is a uuid column server-side, so the create form must submit
// a real UUID (not a username or email) or the backend rejects it. Validate on
// the client so we fail fast with a clear hint instead of a round-trip error.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function isUuid(value: string): boolean {
  return UUID_RE.test(value)
}

// Status and risk are backend enums. Both render through the catalog with a
// raw fallback, so a value the server adds later still reads as itself.
function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation()
  const styles: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    in_progress: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    rejected: 'bg-red-100 text-red-800',
    draft: 'bg-muted text-foreground',
    in_review: 'bg-blue-100 text-blue-800',
    approved: 'bg-green-100 text-green-800',
  }
  return (
    <Badge className={styles[status] || 'bg-muted text-foreground'}>
      {t(`pages.consentManagement.statuses.${status}`, { defaultValue: status })}
    </Badge>
  )
}

function RiskBadge({ level }: { level: string }) {
  const { t } = useTranslation()
  const styles: Record<string, string> = {
    low: 'bg-green-100 text-green-800',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-orange-100 text-orange-800',
    critical: 'bg-red-100 text-red-800',
  }
  return (
    <Badge className={styles[level] || 'bg-muted text-foreground'}>
      {t(`pages.consentManagement.risks.${level}`, {
        defaultValue: level.charAt(0).toUpperCase() + level.slice(1),
      })}
    </Badge>
  )
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  // Browser locale, not a pinned en-US: the date follows the reader.
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

// --- Tab Components ---

function UserConsentsTab() {
  const { t } = useTranslation()
  const [filterType, setFilterType] = useState<string>('all')

  const { data: consentsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-consents'],
    queryFn: () => api.get<{ data: Consent[] }>('/api/v1/privacy/consents'),
  })

  const consents = consentsData?.data || []
  const filtered = filterType === 'all'
    ? consents
    : consents.filter((c) => c.consent_type === filterType)

  const consentTypes = Array.from(new Set(consents.map((c) => c.consent_type)))

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.consentManagement.consents.resourceName')} />

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Label className="text-sm font-medium">{t('pages.consentManagement.consents.filterLabel')}</Label>
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder={t('pages.consentManagement.consents.allTypesPlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('pages.consentManagement.consents.allTypes')}</SelectItem>
            {/* Consent types are the server's own vocabulary, shown as sent. */}
            {consentTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type.replace(/_/g, ' ')}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">{t('pages.consentManagement.consents.empty')}</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow className="border-b bg-muted">
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.user')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.type')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.version')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.granted')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.grantedAt')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.consents.revokedAt')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((consent) => (
                <TableRow key={consent.id} className="border-b last:border-0 hover:bg-muted">
                  <TableCell className="py-3 px-4 font-medium">{consent.username}</TableCell>
                  <TableCell className="py-3 px-4 capitalize">{consent.consent_type.replace(/_/g, ' ')}</TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{consent.version}</TableCell>
                  <TableCell className="py-3 px-4">
                    <Badge className={consent.granted ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                      {consent.granted ? t('pages.consentManagement.consents.yes') : t('pages.consentManagement.consents.no')}
                    </Badge>
                  </TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{formatDate(consent.granted_at)}</TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{formatDate(consent.revoked_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}

function DSARsTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const [formUserId, setFormUserId] = useState('')
  const [formType, setFormType] = useState('export')
  const [formReason, setFormReason] = useState('')

  const { data: dsarsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-dsars'],
    queryFn: () => api.get<{ data: DSAR[] }>('/api/v1/privacy/dsars'),
  })

  const createMutation = useMutation({
    mutationFn: (data: { user_id: string; request_type: string; reason: string }) =>
      api.post('/api/v1/privacy/dsars', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      setShowCreate(false)
      setFormUserId('')
      setFormType('export')
      setFormReason('')
      toast({ title: t('pages.consentManagement.dsars.toast.created') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.dsars.toast.createFailed'), variant: 'destructive' })
    },
  })

  const processMutation = useMutation({
    mutationFn: (id: string) =>
      api.put(`/api/v1/privacy/dsars/${id}`, { status: 'in_progress' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      toast({ title: t('pages.consentManagement.dsars.toast.processed') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.dsars.toast.processFailed'), variant: 'destructive' })
    },
  })

  const executeMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/privacy/dsars/${id}/execute`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsars'] })
      queryClient.invalidateQueries({ queryKey: ['privacy-dashboard'] })
      toast({ title: t('pages.consentManagement.dsars.toast.executed') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.dsars.toast.executeFailed'), variant: 'destructive' })
    },
  })

  const dsars = dsarsData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.consentManagement.dsars.resourceName')} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">{t('pages.consentManagement.dsars.heading')}</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.consentManagement.dsars.create')}
        </Button>
      </div>

      {dsars.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">{t('pages.consentManagement.dsars.empty')}</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow className="border-b bg-muted">
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.id')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.user')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.type')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.status')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.dueDate')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.created')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.dsars.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dsars.map((dsar) => (
                <TableRow key={dsar.id} className="border-b last:border-0 hover:bg-muted">
                  <TableCell className="py-3 px-4 font-mono text-xs">{dsar.id.slice(0, 8)}...</TableCell>
                  <TableCell className="py-3 px-4 font-medium">{dsar.username}</TableCell>
                  <TableCell className="py-3 px-4">
                    {t(`pages.consentManagement.requestTypes.${dsar.request_type}`, { defaultValue: dsar.request_type })}
                  </TableCell>
                  <TableCell className="py-3 px-4"><StatusBadge status={dsar.status} /></TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{formatDate(dsar.due_date)}</TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{formatDate(dsar.created_at)}</TableCell>
                  <TableCell className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      {dsar.status === 'pending' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => processMutation.mutate(dsar.id)}
                          disabled={processMutation.isPending}
                        >
                          <Play className="h-3 w-3 mr-1" />
                          {t('pages.consentManagement.dsars.process')}
                        </Button>
                      )}
                      {dsar.status === 'in_progress' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => executeMutation.mutate(dsar.id)}
                          disabled={executeMutation.isPending}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" />
                          {t('pages.consentManagement.dsars.execute')}
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create DSAR Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.consentManagement.dsars.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="dsar-user-id">{t('pages.consentManagement.dsars.userId')}</Label>
              <Input
                id="dsar-user-id"
                placeholder="e.g. 00000000-0000-0000-0000-000000000000"
                value={formUserId}
                onChange={(e) => setFormUserId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {t('pages.consentManagement.dsars.userIdHint')}
              </p>
              {formUserId.trim() !== '' && !isUuid(formUserId.trim()) && (
                <p className="text-xs text-destructive">
                  {t('pages.consentManagement.dsars.userIdInvalid')}
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="dsar-type">{t('pages.consentManagement.dsars.requestType')}</Label>
              <Select value={formType} onValueChange={setFormType}>
                <SelectTrigger>
                  <SelectValue placeholder={t('pages.consentManagement.dsars.typePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="export">{t('pages.consentManagement.requestTypes.export')}</SelectItem>
                  <SelectItem value="delete">{t('pages.consentManagement.requestTypes.delete')}</SelectItem>
                  <SelectItem value="restrict">{t('pages.consentManagement.requestTypes.restrict')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="dsar-reason">{t('pages.consentManagement.dsars.reason')}</Label>
              <Textarea
                id="dsar-reason"
                placeholder={t('pages.consentManagement.dsars.reasonPlaceholder')}
                value={formReason}
                onChange={(e) => setFormReason(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  user_id: formUserId,
                  request_type: formType,
                  reason: formReason,
                })
              }
              disabled={!isUuid(formUserId.trim()) || !formReason || createMutation.isPending}
            >
              {createMutation.isPending ? t('pages.consentManagement.dsars.creating') : t('pages.consentManagement.dsars.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function RetentionPoliciesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const [formName, setFormName] = useState('')
  const [formCategory, setFormCategory] = useState('')
  const [formDays, setFormDays] = useState(365)
  const [formAction, setFormAction] = useState('delete')

  const { data: retentionData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-retention'],
    queryFn: () => api.get<{ data: RetentionPolicy[] }>('/api/v1/privacy/retention'),
  })

  const createMutation = useMutation({
    mutationFn: (data: {
      name: string
      data_category: string
      retention_days: number
      action: string
    }) => api.post('/api/v1/privacy/retention', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      setShowCreate(false)
      setFormName('')
      setFormCategory('')
      setFormDays(365)
      setFormAction('delete')
      toast({ title: t('pages.consentManagement.retention.toast.created') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.retention.toast.createFailed'), variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/privacy/retention/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      toast({ title: t('pages.consentManagement.retention.toast.updated') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.retention.toast.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/privacy/retention/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-retention'] })
      toast({ title: t('pages.consentManagement.retention.toast.deleted') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.retention.toast.deleteFailed'), variant: 'destructive' })
    },
  })

  const policies = retentionData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.consentManagement.retention.resourceName')} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">{t('pages.consentManagement.retention.heading')}</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.consentManagement.retention.create')}
        </Button>
      </div>

      {policies.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">{t('pages.consentManagement.retention.empty')}</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow className="border-b bg-muted">
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.name')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.category')}</TableHead>
                <TableHead className="text-right py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.days')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.action')}</TableHead>
                <TableHead className="text-center py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.enabled')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.retention.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow key={policy.id} className="border-b last:border-0 hover:bg-muted">
                  <TableCell className="py-3 px-4 font-medium">{policy.name}</TableCell>
                  <TableCell className="py-3 px-4 capitalize">{policy.data_category.replace(/_/g, ' ')}</TableCell>
                  <TableCell className="py-3 px-4 text-right">{policy.retention_days}</TableCell>
                  <TableCell className="py-3 px-4">
                    <Badge className={policy.action === 'delete' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'}>
                      {policy.action === 'delete'
                        ? t('pages.consentManagement.retention.actionDelete')
                        : t('pages.consentManagement.retention.actionAnonymize')}
                    </Badge>
                  </TableCell>
                  <TableCell className="py-3 px-4 text-center">
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: policy.id, enabled: checked })
                      }
                    />
                  </TableCell>
                  <TableCell className="py-3 px-4">
                    <ConfirmAction
                      title={t('pages.consentManagement.retention.deleteTitle')}
                      description={t('pages.consentManagement.retention.deleteDesc', {
                        name: policy.name,
                        category: policy.data_category,
                      })}
                      destructive
                      confirmLabel={t('common.delete')}
                      onConfirm={() => deleteMutation.mutateAsync(policy.id)}
                    >
                      {(open) => (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={open}
                          disabled={deleteMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </ConfirmAction>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create Policy Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.consentManagement.retention.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="retention-name">{t('pages.consentManagement.retention.policyName')}</Label>
              <Input
                id="retention-name"
                placeholder="e.g., Audit Log Retention"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-category">{t('pages.consentManagement.retention.dataCategory')}</Label>
              <Input
                id="retention-category"
                placeholder="e.g., audit_logs, session_data, user_profiles"
                value={formCategory}
                onChange={(e) => setFormCategory(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-days">{t('pages.consentManagement.retention.period')}</Label>
              <Input
                id="retention-days"
                type="number"
                min={1}
                value={formDays}
                onChange={(e) => setFormDays(parseInt(e.target.value) || 365)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="retention-action">{t('pages.consentManagement.retention.actionLabel')}</Label>
              <Select value={formAction} onValueChange={setFormAction}>
                <SelectTrigger>
                  <SelectValue placeholder={t('pages.consentManagement.retention.actionPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="delete">{t('pages.consentManagement.retention.actionDelete')}</SelectItem>
                  <SelectItem value="anonymize">{t('pages.consentManagement.retention.actionAnonymize')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  name: formName,
                  data_category: formCategory,
                  retention_days: formDays,
                  action: formAction,
                })
              }
              disabled={!formName || !formCategory || createMutation.isPending}
            >
              {createMutation.isPending ? t('pages.consentManagement.retention.creating') : t('pages.consentManagement.retention.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function ImpactAssessmentsTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const [formTitle, setFormTitle] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [formRiskLevel, setFormRiskLevel] = useState('medium')
  const [formCategories, setFormCategories] = useState('')
  const [formPurposes, setFormPurposes] = useState('')

  const { data: assessmentsData, isLoading, isError, error } = useQuery({
    queryKey: ['privacy-assessments'],
    queryFn: () => api.get<{ data: ImpactAssessment[] }>('/api/v1/privacy/assessments'),
  })

  const createMutation = useMutation({
    mutationFn: (data: {
      title: string
      description: string
      risk_level: string
      data_categories: string[]
      processing_purposes: string[]
    }) => api.post('/api/v1/privacy/assessments', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-assessments'] })
      setShowCreate(false)
      setFormTitle('')
      setFormDescription('')
      setFormRiskLevel('medium')
      setFormCategories('')
      setFormPurposes('')
      toast({ title: t('pages.consentManagement.assessments.toast.created') })
    },
    onError: () => {
      toast({ title: t('pages.consentManagement.assessments.toast.createFailed'), variant: 'destructive' })
    },
  })

  const assessments = assessmentsData?.data || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.consentManagement.assessments.resourceName')} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">{t('pages.consentManagement.assessments.heading')}</h3>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.consentManagement.assessments.create')}
        </Button>
      </div>

      {assessments.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">{t('pages.consentManagement.assessments.empty')}</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow className="border-b bg-muted">
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.assessments.colTitle')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.assessments.riskLevel')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.assessments.status')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.assessments.assessor')}</TableHead>
                <TableHead className="text-left py-3 px-4 font-medium text-muted-foreground">{t('pages.consentManagement.assessments.created')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assessments.map((assessment) => (
                <TableRow key={assessment.id} className="border-b last:border-0 hover:bg-muted">
                  <TableCell className="py-3 px-4">
                    <div>
                      <p className="font-medium">{assessment.title}</p>
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                        {assessment.description}
                      </p>
                    </div>
                  </TableCell>
                  <TableCell className="py-3 px-4"><RiskBadge level={assessment.risk_level} /></TableCell>
                  <TableCell className="py-3 px-4"><StatusBadge status={assessment.status} /></TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{assessment.assessor}</TableCell>
                  <TableCell className="py-3 px-4 text-muted-foreground">{formatDate(assessment.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Create Assessment Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.consentManagement.assessments.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="assessment-title">{t('pages.consentManagement.assessments.titleLabel')}</Label>
              <Input
                id="assessment-title"
                placeholder="e.g., User Analytics Processing Assessment"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-description">{t('pages.consentManagement.assessments.description')}</Label>
              <Textarea
                id="assessment-description"
                placeholder={t('pages.consentManagement.assessments.descriptionPlaceholder')}
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-risk">{t('pages.consentManagement.assessments.riskLevel')}</Label>
              <Select value={formRiskLevel} onValueChange={setFormRiskLevel}>
                <SelectTrigger>
                  <SelectValue placeholder={t('pages.consentManagement.assessments.riskPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">{t('pages.consentManagement.risks.low')}</SelectItem>
                  <SelectItem value="medium">{t('pages.consentManagement.risks.medium')}</SelectItem>
                  <SelectItem value="high">{t('pages.consentManagement.risks.high')}</SelectItem>
                  <SelectItem value="critical">{t('pages.consentManagement.risks.critical')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-categories">{t('pages.consentManagement.assessments.categories')}</Label>
              <Input
                id="assessment-categories"
                placeholder="e.g., personal_data, behavioral_data, financial_data"
                value={formCategories}
                onChange={(e) => setFormCategories(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="assessment-purposes">{t('pages.consentManagement.assessments.purposes')}</Label>
              <Input
                id="assessment-purposes"
                placeholder="e.g., analytics, fraud_detection, personalization"
                value={formPurposes}
                onChange={(e) => setFormPurposes(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() =>
                createMutation.mutate({
                  title: formTitle,
                  description: formDescription,
                  risk_level: formRiskLevel,
                  data_categories: formCategories
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean),
                  processing_purposes: formPurposes
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              disabled={!formTitle || !formDescription || createMutation.isPending}
            >
              {createMutation.isPending ? t('pages.consentManagement.assessments.creating') : t('pages.consentManagement.assessments.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

// --- Main Page ---

export function ConsentManagementPage() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<TabKey>('consents')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.consentManagement.title')}</h1>
        <p className="text-muted-foreground">
          {t('pages.consentManagement.subtitle')}
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b">
        <nav className="flex gap-4" aria-label="Tabs">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-medium transition-colors ${
                  activeTab === tab.key
                    ? 'border-blue-600 text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
                }`}
              >
                <Icon className="h-4 w-4" />
                {t(`pages.consentManagement.tabs.${tab.key}`)}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <Card>
        <CardContent className="pt-6">
          {activeTab === 'consents' && <UserConsentsTab />}
          {activeTab === 'dsars' && <DSARsTab />}
          {activeTab === 'retention' && <RetentionPoliciesTab />}
          {activeTab === 'assessments' && <ImpactAssessmentsTab />}
        </CardContent>
      </Card>
    </div>
  )
}
