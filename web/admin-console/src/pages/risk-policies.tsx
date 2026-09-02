import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Shield, Plus, Edit2, Trash2, AlertTriangle, Activity, Info } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
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
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface PolicyCondition {
  risk_score_min?: number
  risk_score_max?: number
  new_device?: boolean
  new_location?: boolean
  impossible_travel?: boolean
  off_hours?: boolean
  failed_attempts?: number
  untrusted_device?: boolean
  countries?: string[]
  exclude_countries?: string[]
}

interface PolicyAction {
  require_mfa: boolean
  mfa_methods?: string[]
  step_up?: boolean
  deny?: boolean
  notify_user?: boolean
  notify_admin?: boolean
  log_level?: string
  session_duration?: number
  require_reason?: boolean
}

interface RiskPolicy {
  id: string
  name: string
  description: string
  enabled: boolean
  priority: number
  conditions: PolicyCondition
  actions: PolicyAction
  created_at: string
  updated_at: string
}

interface RiskStats {
  high_risk_logins_today: number
  new_devices_today: number
  total_devices: number
  trusted_devices: number
  failed_logins_today: number
  avg_risk_score_today: number
}

const emptyPolicy: Partial<RiskPolicy> = {
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  conditions: {},
  actions: { require_mfa: true }
}

export function RiskPoliciesPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [testDialog, setTestDialog] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<RiskPolicy | null>(null)
  const [formData, setFormData] = useState<Partial<RiskPolicy>>(emptyPolicy)

  // Test form state
  const [testForm, setTestForm] = useState({
    user_id: '',
    ip_address: '',
    user_agent: navigator.userAgent
  })

  // Fetch policies
  const { data: policiesData, isLoading, isError, error } = useQuery({
    queryKey: ['risk-policies'],
    queryFn: async () => {
      return api.get<{ policies: RiskPolicy[] }>('/api/v1/identity/risk/policies')
    }
  })

  const policies: RiskPolicy[] = policiesData?.policies || []

  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['risk-stats'],
    queryFn: async () => {
      return api.get<{ stats: RiskStats }>('/api/v1/identity/risk/stats')
    }
  })

  const stats: RiskStats = statsData?.stats || {
    high_risk_logins_today: 0,
    new_devices_today: 0,
    total_devices: 0,
    trusted_devices: 0,
    failed_logins_today: 0,
    avg_risk_score_today: 0
  }

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<RiskPolicy>) =>
      api.post('/api/v1/identity/risk/policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({
        title: t('pages.riskPolicies.toasts.createdTitle'),
        description: t('pages.riskPolicies.toasts.createdDesc'),
      })
      setEditDialog(false)
      setFormData(emptyPolicy)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RiskPolicy> }) =>
      api.put(`/api/v1/identity/risk/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({
        title: t('pages.riskPolicies.toasts.updatedTitle'),
        description: t('pages.riskPolicies.toasts.updatedDesc'),
      })
      setEditDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/risk/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({
        title: t('pages.riskPolicies.toasts.deletedTitle'),
        description: t('pages.riskPolicies.toasts.deletedDesc'),
      })
    }
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/api/v1/identity/risk/policies/${id}/toggle`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
    }
  })

  // Test evaluation
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null)
  const testMutation = useMutation({
    mutationFn: (data: typeof testForm) =>
      api.post<Record<string, unknown>>('/api/v1/identity/risk/evaluate', data),
    onSuccess: (response) => {
      setTestResult(response)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const openCreate = () => {
    setSelectedPolicy(null)
    setFormData(emptyPolicy)
    setEditDialog(true)
  }

  const openEdit = (policy: RiskPolicy) => {
    setSelectedPolicy(policy)
    setFormData(policy)
    setEditDialog(true)
  }


  const handleSave = () => {
    if (selectedPolicy) {
      updateMutation.mutate({ id: selectedPolicy.id, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const getDecisionBadge = (action: PolicyAction) => {
    if (action.deny) {
      return <Badge className="bg-red-100 text-red-800">{t('pages.riskPolicies.decisions.deny')}</Badge>
    }
    if (action.step_up) {
      return <Badge className="bg-amber-100 text-amber-800">{t('pages.riskPolicies.decisions.stepUp')}</Badge>
    }
    if (action.require_mfa) {
      return <Badge className="bg-blue-100 text-blue-800">{t('pages.riskPolicies.decisions.requireMfa')}</Badge>
    }
    return <Badge className="bg-green-100 text-green-800">{t('pages.riskPolicies.decisions.allow')}</Badge>
  }

  const formatConditions = (cond: PolicyCondition): string[] => {
    const parts: string[] = []
    if (cond.risk_score_min !== undefined)
      parts.push(t('pages.riskPolicies.conditions.riskMin', { n: cond.risk_score_min }))
    if (cond.risk_score_max !== undefined)
      parts.push(t('pages.riskPolicies.conditions.riskMax', { n: cond.risk_score_max }))
    if (cond.new_device) parts.push(t('pages.riskPolicies.conditions.newDevice'))
    if (cond.new_location) parts.push(t('pages.riskPolicies.conditions.newLocation'))
    if (cond.impossible_travel) parts.push(t('pages.riskPolicies.conditions.impossibleTravel'))
    if (cond.off_hours) parts.push(t('pages.riskPolicies.conditions.offHours'))
    if (cond.untrusted_device) parts.push(t('pages.riskPolicies.conditions.untrustedDevice'))
    if (cond.failed_attempts)
      parts.push(t('pages.riskPolicies.conditions.failedAttempts', { n: cond.failed_attempts }))
    if (cond.countries?.length)
      parts.push(t('pages.riskPolicies.conditions.countries', { list: cond.countries.join(', ') }))
    return parts.length ? parts : [t('pages.riskPolicies.conditions.any')]
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.riskPolicies.resourceName')} />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('pages.riskPolicies.title')}</h1>
          <p className="text-muted-foreground">{t('pages.riskPolicies.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestDialog(true)}>
            <Activity className="h-4 w-4 mr-2" />
            {t('pages.riskPolicies.testEvaluation')}
          </Button>
          <Button onClick={openCreate}>
            <Plus className="h-4 w-4 mr-2" />
            {t('pages.riskPolicies.create')}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.highRiskToday')}</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.high_risk_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.avgRiskScore')}</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.avg_risk_score_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.newDevices')}</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.new_devices_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.failedLogins')}</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{stats.failed_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.totalDevices')}</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_devices}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.riskPolicies.stats.trusted')}</CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.trusted_devices}</div>
          </CardContent>
        </Card>
      </div>

      {/* Info Banner */}
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-blue-900">{t('pages.riskPolicies.info.title')}</p>
              <p className="text-sm text-blue-800">{t('pages.riskPolicies.info.body')}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Policies List */}
      <Card>
        <CardHeader>
          <CardTitle>{t('pages.riskPolicies.list.title')}</CardTitle>
          <CardDescription>{t('pages.riskPolicies.list.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          {policies.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>{t('pages.riskPolicies.list.empty')}</p>
              <Button variant="link" onClick={openCreate}>
                {t('pages.riskPolicies.list.createFirst')}
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {policies.map((policy) => (
                <div
                  key={policy.id}
                  className={`flex items-center justify-between p-4 border rounded-lg ${
                    policy.enabled ? 'bg-background' : 'bg-muted opacity-60'
                  }`}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono bg-muted px-2 py-1 rounded">
                        #{policy.priority}
                      </span>
                      <h3 className="font-medium">{policy.name}</h3>
                      {getDecisionBadge(policy.actions)}
                      {!policy.enabled && (
                        <Badge variant="secondary">{t('pages.riskPolicies.disabled')}</Badge>
                      )}
                    </div>
                    {policy.description && (
                      <p className="text-sm text-muted-foreground mt-1">{policy.description}</p>
                    )}
                    <div className="flex flex-wrap gap-1 mt-2">
                      {formatConditions(policy.conditions).map((cond, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{cond}</Badge>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: policy.id, enabled: checked })
                      }
                    />
                    <Button variant="ghost" size="icon" onClick={() => openEdit(policy)}>
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <ConfirmAction
                      title={t('pages.riskPolicies.confirmDelete.title')}
                      description={t('pages.riskPolicies.confirmDelete.description', {
                        name: policy.name,
                      })}
                      destructive
                      confirmLabel={t('common.delete')}
                      onConfirm={() => deleteMutation.mutateAsync(policy.id)}
                    >
                      {(open) => (
                        <Button variant="ghost" size="icon" onClick={open}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </ConfirmAction>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {selectedPolicy
                ? t('pages.riskPolicies.dialog.editTitle')
                : t('pages.riskPolicies.dialog.createTitle')}
            </DialogTitle>
            <DialogDescription>{t('pages.riskPolicies.dialog.description')}</DialogDescription>
          </DialogHeader>

          <div className="space-y-6">
            {/* Basic Info */}
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>{t('pages.riskPolicies.dialog.name')}</Label>
                  <Input
                    value={formData.name || ''}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder={t('pages.riskPolicies.dialog.namePlaceholder')}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('pages.riskPolicies.dialog.priority')}</Label>
                  <Input
                    type="number"
                    value={formData.priority || 100}
                    onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.riskPolicies.dialog.descriptionLabel')}</Label>
                <Textarea
                  value={formData.description || ''}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder={t('pages.riskPolicies.dialog.descriptionPlaceholder')}
                  rows={2}
                />
              </div>
            </div>

            {/* Conditions */}
            <div className="space-y-4">
              <h4 className="font-medium">{t('pages.riskPolicies.dialog.conditionsHeading')}</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>{t('pages.riskPolicies.dialog.minRisk')}</Label>
                  <Input
                    type="number"
                    value={formData.conditions?.risk_score_min ?? ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      conditions: {
                        ...formData.conditions,
                        risk_score_min: e.target.value ? parseInt(e.target.value) : undefined
                      }
                    })}
                    placeholder="0"
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('pages.riskPolicies.dialog.maxRisk')}</Label>
                  <Input
                    type="number"
                    value={formData.conditions?.risk_score_max ?? ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      conditions: {
                        ...formData.conditions,
                        risk_score_max: e.target.value ? parseInt(e.target.value) : undefined
                      }
                    })}
                    placeholder="100"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="new_device"
                    checked={formData.conditions?.new_device || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, new_device: checked === true }
                    })}
                  />
                  <label htmlFor="new_device" className="text-sm">
                    {t('pages.riskPolicies.conditions.newDevice')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="new_location"
                    checked={formData.conditions?.new_location || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, new_location: checked === true }
                    })}
                  />
                  <label htmlFor="new_location" className="text-sm">
                    {t('pages.riskPolicies.conditions.newLocation')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="impossible_travel"
                    checked={formData.conditions?.impossible_travel || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, impossible_travel: checked === true }
                    })}
                  />
                  <label htmlFor="impossible_travel" className="text-sm">
                    {t('pages.riskPolicies.conditions.impossibleTravel')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="off_hours"
                    checked={formData.conditions?.off_hours || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, off_hours: checked === true }
                    })}
                  />
                  <label htmlFor="off_hours" className="text-sm">
                    {t('pages.riskPolicies.conditions.offHours')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="untrusted_device"
                    checked={formData.conditions?.untrusted_device || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, untrusted_device: checked === true }
                    })}
                  />
                  <label htmlFor="untrusted_device" className="text-sm">
                    {t('pages.riskPolicies.conditions.untrustedDevice')}
                  </label>
                </div>
              </div>

              <div className="space-y-2">
                <Label>{t('pages.riskPolicies.dialog.failedThreshold')}</Label>
                <Input
                  type="number"
                  value={formData.conditions?.failed_attempts ?? ''}
                  onChange={(e) => setFormData({
                    ...formData,
                    conditions: {
                      ...formData.conditions,
                      failed_attempts: e.target.value ? parseInt(e.target.value) : undefined
                    }
                  })}
                  placeholder={t('pages.riskPolicies.dialog.failedThresholdPlaceholder')}
                />
              </div>
            </div>

            {/* Actions */}
            <div className="space-y-4">
              <h4 className="font-medium">{t('pages.riskPolicies.dialog.actionsHeading')}</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="require_mfa"
                    checked={formData.actions?.require_mfa || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, require_mfa: checked === true }
                    })}
                  />
                  <label htmlFor="require_mfa" className="text-sm">
                    {t('pages.riskPolicies.dialog.requireMfa')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="step_up"
                    checked={formData.actions?.step_up || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, step_up: checked === true }
                    })}
                  />
                  <label htmlFor="step_up" className="text-sm">
                    {t('pages.riskPolicies.dialog.stepUp')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="deny"
                    checked={formData.actions?.deny || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, deny: checked === true }
                    })}
                  />
                  <label htmlFor="deny" className="text-sm font-medium text-red-600">
                    {t('pages.riskPolicies.dialog.deny')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="notify_admin"
                    checked={formData.actions?.notify_admin || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, notify_admin: checked === true }
                    })}
                  />
                  <label htmlFor="notify_admin" className="text-sm">
                    {t('pages.riskPolicies.dialog.notifyAdmin')}
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="notify_user"
                    checked={formData.actions?.notify_user || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, notify_user: checked === true }
                    })}
                  />
                  <label htmlFor="notify_user" className="text-sm">
                    {t('pages.riskPolicies.dialog.notifyUser')}
                  </label>
                </div>
              </div>

              <div className="space-y-2">
                <Label>{t('pages.riskPolicies.dialog.logLevel')}</Label>
                <Select
                  value={formData.actions?.log_level || 'info'}
                  onValueChange={(value) => setFormData({
                    ...formData,
                    actions: { ...formData.actions!, log_level: value }
                  })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="info">{t('pages.riskPolicies.dialog.logInfo')}</SelectItem>
                    <SelectItem value="warning">{t('pages.riskPolicies.dialog.logWarning')}</SelectItem>
                    <SelectItem value="critical">{t('pages.riskPolicies.dialog.logCritical')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>
              {t('common.cancel')}
            </Button>
            <Button onClick={handleSave} disabled={!formData.name}>
              {selectedPolicy
                ? t('pages.riskPolicies.dialog.update')
                : t('pages.riskPolicies.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Test Evaluation Dialog */}
      <Dialog open={testDialog} onOpenChange={setTestDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('pages.riskPolicies.testDialog.title')}</DialogTitle>
            <DialogDescription>{t('pages.riskPolicies.testDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('pages.riskPolicies.testDialog.userId')}</Label>
                <Input
                  value={testForm.user_id}
                  onChange={(e) => setTestForm({ ...testForm, user_id: e.target.value })}
                  placeholder={t('pages.riskPolicies.testDialog.userIdPlaceholder')}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.riskPolicies.testDialog.ip')}</Label>
                <Input
                  value={testForm.ip_address}
                  onChange={(e) => setTestForm({ ...testForm, ip_address: e.target.value })}
                  placeholder={t('pages.riskPolicies.testDialog.ipPlaceholder')}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.riskPolicies.testDialog.userAgent')}</Label>
              <Input
                value={testForm.user_agent}
                onChange={(e) => setTestForm({ ...testForm, user_agent: e.target.value })}
              />
            </div>
            <Button
              onClick={() => testMutation.mutate(testForm)}
              disabled={!testForm.user_id || !testForm.ip_address}
            >
              <Activity className="h-4 w-4 mr-2" />
              {t('pages.riskPolicies.testDialog.evaluate')}
            </Button>

            {testResult && (
              <div className="mt-4 p-4 bg-muted rounded-lg">
                <h4 className="font-medium mb-2">{t('pages.riskPolicies.testDialog.result')}</h4>
                <pre className="text-xs overflow-auto max-h-60">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setTestDialog(false); setTestResult(null); }}>
              {t('common.close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
