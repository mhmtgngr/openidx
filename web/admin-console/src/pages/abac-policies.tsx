import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Search, Edit, Trash2, X, ChevronLeft, ChevronRight,
  MoreHorizontal, Shield, ShieldOff, FlaskConical, Filter,
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ABACCondition {
  attribute: string
  operator: string
  value: unknown
}

interface ABACPolicy {
  id: string
  name: string
  description: string
  resource_type: string
  resource_id?: string
  conditions: ABACCondition[]
  effect: string
  priority: number
  enabled: boolean
  created_at: string
  updated_at: string
}

interface ABACEvaluationResult {
  allowed: boolean
  reason?: string
  policy_id?: string
}

// These lists are module-level, so they carry catalog keys rather than
// English. `value` is the wire value; `labelKey` is the catalog key -- they
// differ only for the '*' wildcard, which is not a valid key segment.
const resourceTypes = [
  { value: 'application', labelKey: 'application' },
  { value: 'route', labelKey: 'route' },
  { value: 'service', labelKey: 'service' },
  { value: '*', labelKey: 'all' },
]

const attributeOptions = [
  'department',
  'location',
  'device_trust_level',
  'time_of_day',
  'risk_score',
  'group_membership',
  'ip_range',
]

const operatorOptions = [
  'eq',
  'neq',
  'in',
  'not_in',
  'gt',
  'gte',
  'lt',
  'lte',
  'between',
  'contains',
]

const emptyCondition: ABACCondition = { attribute: 'department', operator: 'eq', value: '' }

function parseConditionValue(raw: string, operator: string): unknown {
  if (operator === 'in' || operator === 'not_in') {
    return raw.split(',').map(s => s.trim()).filter(Boolean)
  }
  if (operator === 'between') {
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean)
    if (parts.length === 2) return [parseFloat(parts[0]) || parts[0], parseFloat(parts[1]) || parts[1]]
    return parts
  }
  const num = parseFloat(raw)
  if (!isNaN(num) && raw.trim() === String(num)) return num
  return raw
}

function conditionValueToString(val: unknown): string {
  if (Array.isArray(val)) return val.join(', ')
  return String(val ?? '')
}

export function ABACPoliciesPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [resourceTypeFilter, setResourceTypeFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [testDialogOpen, setTestDialogOpen] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<ABACPolicy | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const limit = 20

  // Form state
  const [formName, setFormName] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [formResourceType, setFormResourceType] = useState('application')
  const [formResourceId, setFormResourceId] = useState('')
  const [formEffect, setFormEffect] = useState('allow')
  const [formPriority, setFormPriority] = useState(0)
  const [formEnabled, setFormEnabled] = useState(true)
  const [formConditions, setFormConditions] = useState<ABACCondition[]>([{ ...emptyCondition }])
  const [conditionInputs, setConditionInputs] = useState<string[]>([''])

  // Test state
  const [testResourceType, setTestResourceType] = useState('application')
  const [testResourceId, setTestResourceId] = useState('')
  const [testAttributes, setTestAttributes] = useState('{\n  "department": "engineering",\n  "risk_score": 25\n}')
  const [testResult, setTestResult] = useState<ABACEvaluationResult | null>(null)

  const { data: policies, isLoading, isError, error } = useQuery({
    queryKey: ['abac-policies', offset, limit, resourceTypeFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(limit) })
      if (resourceTypeFilter) params.set('resource_type', resourceTypeFilter)
      const result = await api.getWithHeaders<ABACPolicy[]>(`/api/v1/governance/abac-policies?${params}`)
      return {
        items: result.data,
        total: parseInt(result.headers['x-total-count'] || '0', 10),
      }
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: Partial<ABACPolicy>) =>
      api.post<ABACPolicy>('/api/v1/governance/abac-policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setEditDialogOpen(false)
      toast({ title: t('pages.abacPolicies.toast.created') })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.abacPolicies.toast.createFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ABACPolicy> }) =>
      api.put<ABACPolicy>(`/api/v1/governance/abac-policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setEditDialogOpen(false)
      toast({ title: t('pages.abacPolicies.toast.updated') })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.abacPolicies.toast.updateFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/abac-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setDeleteDialogOpen(false)
      toast({ title: t('pages.abacPolicies.toast.deleted') })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.abacPolicies.toast.deleteFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (policy: ABACPolicy) =>
      api.put<ABACPolicy>(`/api/v1/governance/abac-policies/${policy.id}`, {
        ...policy,
        enabled: !policy.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
    },
  })

  const evaluateMutation = useMutation({
    mutationFn: (data: { user_attributes: Record<string, unknown>; resource_type: string; resource_id: string }) =>
      api.post<ABACEvaluationResult>('/api/v1/governance/abac-policies/evaluate', data),
    onSuccess: (result) => {
      setTestResult(result)
    },
    onError: (err: Error) => {
      toast({ title: t('pages.abacPolicies.toast.evalFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormName('')
    setFormDescription('')
    setFormResourceType('application')
    setFormResourceId('')
    setFormEffect('allow')
    setFormPriority(0)
    setFormEnabled(true)
    setFormConditions([{ ...emptyCondition }])
    setConditionInputs([''])
  }

  const openCreate = () => {
    setIsCreating(true)
    setSelectedPolicy(null)
    resetForm()
    setEditDialogOpen(true)
  }

  const openEdit = (policy: ABACPolicy) => {
    setIsCreating(false)
    setSelectedPolicy(policy)
    setFormName(policy.name)
    setFormDescription(policy.description)
    setFormResourceType(policy.resource_type)
    setFormResourceId(policy.resource_id || '')
    setFormEffect(policy.effect)
    setFormPriority(policy.priority)
    setFormEnabled(policy.enabled)
    const conds = policy.conditions.length > 0 ? policy.conditions : [{ ...emptyCondition }]
    setFormConditions(conds)
    setConditionInputs(conds.map(c => conditionValueToString(c.value)))
    setEditDialogOpen(true)
  }

  const openDelete = (policy: ABACPolicy) => {
    setSelectedPolicy(policy)
    setDeleteDialogOpen(true)
  }

  const handleSave = () => {
    const conditions = formConditions.map((c, i) => ({
      ...c,
      value: parseConditionValue(conditionInputs[i] || '', c.operator),
    }))
    const payload: Partial<ABACPolicy> = {
      name: formName,
      description: formDescription,
      resource_type: formResourceType,
      resource_id: formResourceId || undefined,
      conditions,
      effect: formEffect,
      priority: formPriority,
      enabled: formEnabled,
    }

    if (isCreating) {
      createMutation.mutate(payload)
    } else if (selectedPolicy) {
      updateMutation.mutate({ id: selectedPolicy.id, data: payload })
    }
  }

  const addCondition = () => {
    setFormConditions([...formConditions, { ...emptyCondition }])
    setConditionInputs([...conditionInputs, ''])
  }

  const removeCondition = (index: number) => {
    setFormConditions(formConditions.filter((_, i) => i !== index))
    setConditionInputs(conditionInputs.filter((_, i) => i !== index))
  }

  const updateCondition = (index: number, field: keyof ABACCondition, value: string) => {
    const updated = [...formConditions]
    updated[index] = { ...updated[index], [field]: value }
    setFormConditions(updated)
  }

  const updateConditionInput = (index: number, value: string) => {
    const updated = [...conditionInputs]
    updated[index] = value
    setConditionInputs(updated)
  }

  const handleTest = () => {
    setTestResult(null)
    try {
      const attrs = JSON.parse(testAttributes)
      evaluateMutation.mutate({
        user_attributes: attrs,
        resource_type: testResourceType,
        resource_id: testResourceId,
      })
    } catch {
      toast({
        title: t('pages.abacPolicies.toast.invalidJson'),
        description: t('pages.abacPolicies.toast.invalidJsonDesc'),
        variant: 'destructive',
      })
    }
  }

  const filtered = (policies?.items || []).filter(p =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.description.toLowerCase().includes(search.toLowerCase())
  )

  const totalPages = Math.ceil((policies?.total || 0) / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('nav.items.abacPolicies')}</h1>
          <p className="text-muted-foreground">
            {t('pages.abacPolicies.subtitle')}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestDialogOpen(true)}>
            <FlaskConical className="mr-2 h-4 w-4" />
            {t('pages.abacPolicies.testPolicy')}
          </Button>
          <Button onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            {t('pages.abacPolicies.createPolicy')}
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.abacPolicies.searchPlaceholder')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={resourceTypeFilter} onValueChange={(val) => { setResourceTypeFilter(val === 'all' ? '' : val); setOffset(0) }}>
              <SelectTrigger className="w-[200px]" aria-label={t('pages.abacPolicies.resourceTypeFilterLabel')}>
                <SelectValue placeholder={t('pages.abacPolicies.allResourceTypes')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.abacPolicies.allResourceTypes')}</SelectItem>
                {resourceTypes.map(rt => (
                  <SelectItem key={rt.value} value={rt.value}>{t(`pages.abacPolicies.resourceTypes.${rt.labelKey}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : isError ? (
        <QueryError error={error} resource={t('pages.abacPolicies.resourceName')} />
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {t('pages.abacPolicies.policyCount', { count: policies?.total || 0 })}
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow className="border-b bg-muted/50">
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.name')}</TableHead>
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.resourceType')}</TableHead>
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.conditions')}</TableHead>
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.effect')}</TableHead>
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.priority')}</TableHead>
                    <TableHead className="p-3 text-left text-sm font-medium">{t('pages.abacPolicies.columns.enabled')}</TableHead>
                    <TableHead className="p-3 text-right text-sm font-medium">{t('pages.abacPolicies.columns.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="p-8 text-center text-muted-foreground">
                        <Filter className="mx-auto mb-2 h-8 w-8 opacity-50" />
                        <p>{t('pages.abacPolicies.empty')}</p>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map(policy => (
                      <TableRow key={policy.id} className="border-b last:border-b-0 hover:bg-muted/25">
                        <TableCell className="p-3">
                          <div>
                            <p className="font-medium">{policy.name}</p>
                            {policy.description && (
                              <p className="text-sm text-muted-foreground truncate max-w-[250px]">{policy.description}</p>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="outline">{policy.resource_type}</Badge>
                          {policy.resource_id && (
                            <span className="ml-1 text-xs text-muted-foreground">({policy.resource_id})</span>
                          )}
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="secondary">{t('pages.abacPolicies.conditionCount', { count: policy.conditions?.length || 0 })}</Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge className={policy.effect === 'allow' ? 'bg-green-100 text-green-800 hover:bg-green-100' : 'bg-red-100 text-red-800 hover:bg-red-100'}>
                            {policy.effect === 'allow' ? <Shield className="mr-1 h-3 w-3" /> : <ShieldOff className="mr-1 h-3 w-3" />}
                            {policy.effect}
                          </Badge>
                        </TableCell>
                        <TableCell className="p-3 text-sm">{policy.priority}</TableCell>
                        <TableCell className="p-3">
                          <Switch aria-label={t('pages.abacPolicies.togglePolicy', { name: policy.name })}
                            checked={policy.enabled}
                            onCheckedChange={() => toggleMutation.mutate(policy)}
                          />
                        </TableCell>
                        <TableCell className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => openEdit(policy)}>
                                <Edit className="mr-2 h-4 w-4" /> {t('pages.abacPolicies.edit')}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => openDelete(policy)} className="text-red-600">
                                <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-4">
                <p className="text-sm text-muted-foreground">
                  {t('common.pagination.pageOf', { page: currentPage, pages: totalPages })}
                </p>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                    disabled={offset === 0}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    {t('common.pagination.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(offset + limit)}
                    disabled={currentPage >= totalPages}
                  >
                    {t('common.pagination.next')}
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t(isCreating ? 'pages.abacPolicies.dialog.createTitle' : 'pages.abacPolicies.dialog.editTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('pages.abacPolicies.dialog.name')}</Label>
                <Input
                  placeholder={t('pages.abacPolicies.dialog.namePlaceholder')}
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.abacPolicies.dialog.priority')}</Label>
                <Input
                  type="number"
                  placeholder="0"
                  value={formPriority}
                  onChange={(e) => setFormPriority(parseInt(e.target.value) || 0)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.abacPolicies.dialog.description')}</Label>
              <Textarea
                placeholder={t('pages.abacPolicies.dialog.descriptionPlaceholder')}
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="abac-policies-resource-type">{t('pages.abacPolicies.dialog.resourceType')}</Label>
                <Select value={formResourceType} onValueChange={setFormResourceType}>
                  <SelectTrigger id="abac-policies-resource-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceTypes.map(rt => (
                      <SelectItem key={rt.value} value={rt.value}>{t(`pages.abacPolicies.resourceTypes.${rt.labelKey}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.abacPolicies.dialog.resourceId')}</Label>
                <Input
                  placeholder={t('pages.abacPolicies.dialog.resourceIdPlaceholder')}
                  value={formResourceId}
                  onChange={(e) => setFormResourceId(e.target.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="abac-policies-effect">{t('pages.abacPolicies.dialog.effect')}</Label>
                <Select value={formEffect} onValueChange={setFormEffect}>
                  <SelectTrigger id="abac-policies-effect">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="allow">{t('pages.abacPolicies.dialog.allow')}</SelectItem>
                    <SelectItem value="deny">{t('pages.abacPolicies.dialog.deny')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-3 pt-6">
                <Switch id="abac-policies-enabled" checked={formEnabled} onCheckedChange={setFormEnabled} />
                <Label htmlFor="abac-policies-enabled">{t('pages.abacPolicies.dialog.enabled')}</Label>
              </div>
            </div>

            {/* Conditions Builder */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="text-base font-semibold">{t('pages.abacPolicies.dialog.conditions')}</Label>
                <Button type="button" variant="outline" size="sm" onClick={addCondition}>
                  <Plus className="mr-1 h-3 w-3" /> {t('pages.abacPolicies.dialog.addCondition')}
                </Button>
              </div>
              <p className="text-sm text-muted-foreground">{t('pages.abacPolicies.dialog.conditionsHint')}</p>
              {formConditions.map((cond, i) => (
                <div key={i} className="flex gap-2 items-start rounded-md border p-3 bg-muted/30">
                  <div className="flex-1 space-y-2">
                    <div className="grid grid-cols-3 gap-2">
                      <Select value={cond.attribute} onValueChange={(val) => updateCondition(i, 'attribute', val)}>
                        <SelectTrigger aria-label={t('pages.abacPolicies.dialog.attribute')} className="text-xs">
                          <SelectValue placeholder={t('pages.abacPolicies.dialog.attribute')} />
                        </SelectTrigger>
                        <SelectContent>
                          {attributeOptions.map(a => (
                            <SelectItem key={a} value={a}>{t(`pages.abacPolicies.attributes.${a}`)}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Select value={cond.operator} onValueChange={(val) => updateCondition(i, 'operator', val)}>
                        <SelectTrigger aria-label={t('pages.abacPolicies.dialog.operator')} className="text-xs">
                          <SelectValue placeholder={t('pages.abacPolicies.dialog.operator')} />
                        </SelectTrigger>
                        <SelectContent>
                          {operatorOptions.map(o => (
                            <SelectItem key={o} value={o}>{t(`pages.abacPolicies.operators.${o}`)}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Input
                        placeholder={t(
                          cond.operator === 'in' || cond.operator === 'not_in'
                            ? 'pages.abacPolicies.dialog.listPlaceholder'
                            : cond.operator === 'between'
                              ? 'pages.abacPolicies.dialog.rangePlaceholder'
                              : 'pages.abacPolicies.dialog.valuePlaceholder',
                        )}
                        value={conditionInputs[i] || ''}
                        onChange={(e) => updateConditionInput(i, e.target.value)}
                        className="text-xs"
                      />
                    </div>
                  </div>
                  {formConditions.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => removeCondition(i)}
                      className="text-muted-foreground hover:text-red-600 mt-0.5"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button variant="outline" onClick={() => setEditDialogOpen(false)}>{t('common.cancel')}</Button>
              <Button
                onClick={handleSave}
                disabled={!formName || !formResourceType || createMutation.isPending || updateMutation.isPending}
              >
                {(createMutation.isPending || updateMutation.isPending) && <LoadingSpinner className="mr-2 h-4 w-4" />}
                {t(isCreating ? 'pages.abacPolicies.dialog.create' : 'pages.abacPolicies.dialog.saveChanges')}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.abacPolicies.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.abacPolicies.deleteDesc', { name: selectedPolicy?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedPolicy && deleteMutation.mutate(selectedPolicy.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              {deleteMutation.isPending ? <LoadingSpinner className="mr-2 h-4 w-4" /> : null}
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Test Policy Dialog */}
      <Dialog open={testDialogOpen} onOpenChange={(open) => { setTestDialogOpen(open); if (!open) setTestResult(null) }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.abacPolicies.test.title')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="abac-policies-resource-type-2">{t('pages.abacPolicies.dialog.resourceType')}</Label>
                <Select value={testResourceType} onValueChange={setTestResourceType}>
                  <SelectTrigger id="abac-policies-resource-type-2">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceTypes.filter(rt => rt.value !== '*').map(rt => (
                      <SelectItem key={rt.value} value={rt.value}>{t(`pages.abacPolicies.resourceTypes.${rt.labelKey}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.abacPolicies.test.resourceId')}</Label>
                <Input
                  placeholder={t('pages.abacPolicies.test.resourceIdPlaceholder')}
                  value={testResourceId}
                  onChange={(e) => setTestResourceId(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="abac-policies-attributes">{t('pages.abacPolicies.test.attributes')}</Label>
              <Textarea id="abac-policies-attributes"
                className="font-mono text-sm"
                rows={6}
                value={testAttributes}
                onChange={(e) => setTestAttributes(e.target.value)}
              />
            </div>
            <Button onClick={handleTest} disabled={evaluateMutation.isPending} className="w-full">
              {evaluateMutation.isPending && <LoadingSpinner className="mr-2 h-4 w-4" />}
              {t('pages.abacPolicies.test.evaluate')}
            </Button>

            {testResult && (
              <div className={`rounded-md border p-4 ${testResult.allowed ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}`}>
                <div className="flex items-center gap-2">
                  {testResult.allowed
                    ? <Shield className="h-5 w-5 text-green-600" />
                    : <ShieldOff className="h-5 w-5 text-red-600" />
                  }
                  <span className={`font-semibold ${testResult.allowed ? 'text-green-800' : 'text-red-800'}`}>
                    {t(testResult.allowed ? 'pages.abacPolicies.test.allowed' : 'pages.abacPolicies.test.denied')}
                  </span>
                </div>
                {testResult.reason && (
                  <p className={`mt-1 text-sm ${testResult.allowed ? 'text-green-700' : 'text-red-700'}`}>
                    {testResult.reason}
                  </p>
                )}
                {testResult.policy_id && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {t('pages.abacPolicies.test.matchedPolicy', { id: testResult.policy_id })}
                  </p>
                )}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
