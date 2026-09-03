import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Scale, Shield, Clock, MapPin, AlertTriangle, Edit, Trash2, ToggleLeft, ToggleRight, X, ChevronLeft, ChevronRight, Fingerprint, MoreHorizontal } from 'lucide-react'
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
import { TableSkeleton } from '../components/ui/skeleton'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
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

interface Policy {
  id: string
  name: string
  description: string
  type: string
  enabled: boolean
  priority: number
  rules: PolicyRule[]
  created_at: string
  updated_at: string
}

interface PolicyRule {
  id: string
  condition: Record<string, unknown>
  effect: string
  priority: number
}

const policyTypeIcons: Record<string, React.ReactNode> = {
  separation_of_duty: <Shield className="h-4 w-4" />,
  risk_based: <AlertTriangle className="h-4 w-4" />,
  timebound: <Clock className="h-4 w-4" />,
  location: <MapPin className="h-4 w-4" />,
  conditional_access: <Fingerprint className="h-4 w-4" />,
}

const policyTypeColors: Record<string, string> = {
  separation_of_duty: 'bg-purple-100 text-purple-800',
  risk_based: 'bg-red-100 text-red-800',
  timebound: 'bg-blue-100 text-blue-800',
  location: 'bg-green-100 text-green-800',
  conditional_access: 'bg-orange-100 text-orange-800',
}

// Condition rows are module-level, so they carry catalog keys rather than
// English. `key` doubles as the catalog key -- both are the backend's own
// condition field name -- except where one field needs a different example
// per policy type (`placeholderKey`).
const conditionTemplates: Record<string, { key: string; placeholderKey?: string }[]> = {
  separation_of_duty: [{ key: 'conflicting_roles' }],
  risk_based: [{ key: 'min_risk_score' }, { key: 'max_risk_score' }],
  timebound: [{ key: 'start_hour' }, { key: 'end_hour' }, { key: 'days' }],
  location: [{ key: 'allowed_ips' }, { key: 'blocked_ips' }],
  conditional_access: [
    { key: 'require_mfa' },
    { key: 'device_trust_required' },
    { key: 'allowed_locations' },
    { key: 'blocked_locations' },
    { key: 'max_risk_score', placeholderKey: 'conditional_max_risk_score' },
  ],
}

const effectOptions = ['allow', 'deny', 'require_approval', 'step_up_mfa']

const POLICY_FORM_TYPES = ['separation_of_duty', 'risk_based', 'timebound', 'location'] as const

interface FormRule {
  condition: Record<string, string>
  effect: string
  priority: number
}

export function PoliciesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'separation_of_duty',
    enabled: true,
    priority: 0,
  })
  const [rules, setRules] = useState<FormRule[]>([])
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: policies, isLoading, isError, error } = useQuery({
    queryKey: ['policies', search, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<Policy[]>(`/api/v1/governance/policies?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const createPolicyMutation = useMutation({
    mutationFn: (policyData: Partial<Policy>) => api.post('/api/v1/governance/policies', policyData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: t('pages.policies.toast.success'),
        description: t('pages.policies.toast.created'),
        variant: 'success',
      })
      setCreateModal(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.policies.toast.error'),
        description: t('pages.policies.toast.createFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Policy> }) =>
      api.put(`/api/v1/governance/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: t('pages.policies.toast.success'),
        description: t('pages.policies.toast.updated'),
        variant: 'success',
      })
      setEditModal(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.policies.toast.error'),
        description: t('pages.policies.toast.updateFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  const deletePolicyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: t('pages.policies.toast.success'),
        description: t('pages.policies.toast.deleted'),
        variant: 'success',
      })
      setDeleteDialog(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.policies.toast.error'),
        description: t('pages.policies.toast.deleteFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  const togglePolicyMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/governance/policies/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: t('pages.policies.toast.success'),
        description: t('pages.policies.toast.statusUpdated'),
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.policies.toast.error'),
        description: t('pages.policies.toast.updateFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  // Policies are filtered server-side via search param
  const filteredPolicies = policies

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      type: 'separation_of_duty',
      enabled: true,
      priority: 0,
    })
    setRules([])
  }

  const handleFormChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'number' ? parseInt(value) || 0 : value,
    }))
  }

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createPolicyMutation.mutate({
      id: crypto.randomUUID(),
      ...formData,
      rules: rules.map((r, i) => ({ id: crypto.randomUUID(), condition: r.condition, effect: r.effect, priority: r.priority || i })),
    })
  }

  const handleEditClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setFormData({
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      enabled: policy.enabled,
      priority: policy.priority,
    })
    setRules(
      (policy.rules || []).map(r => ({
        condition: Object.fromEntries(Object.entries(r.condition).map(([k, v]) => [k, String(v)])),
        effect: r.effect,
        priority: r.priority,
      }))
    )
    setEditModal(true)
  }

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedPolicy) return
    updatePolicyMutation.mutate({
      id: selectedPolicy.id,
      data: {
        ...formData,
        rules: rules.map((r, i) => ({ id: crypto.randomUUID(), condition: r.condition, effect: r.effect, priority: r.priority || i })),
      },
    })
  }

  const addRule = () => {
    const templates = conditionTemplates[formData.type] || []
    const emptyCondition: Record<string, string> = {}
    templates.forEach(t => { emptyCondition[t.key] = '' })
    setRules(prev => [...prev, { condition: emptyCondition, effect: 'deny', priority: prev.length }])
  }

  const removeRule = (index: number) => {
    setRules(prev => prev.filter((_, i) => i !== index))
  }

  const updateRuleCondition = (ruleIndex: number, key: string, value: string) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, condition: { ...r.condition, [key]: value } } : r))
  }

  const updateRuleEffect = (ruleIndex: number, effect: string) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, effect } : r))
  }

  const updateRulePriority = (ruleIndex: number, priority: number) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, priority } : r))
  }

  const renderRuleBuilder = () => {
    const templates = conditionTemplates[formData.type] || []
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <Label className="text-base font-semibold">{t('pages.policies.rules.title')}</Label>
          <Button type="button" variant="outline" size="sm" onClick={addRule}>
            <Plus className="h-3 w-3 mr-1" /> {t('pages.policies.rules.add')}
          </Button>
        </div>
        {rules.length === 0 && (
          <p className="text-sm text-muted-foreground">{t('pages.policies.rules.empty')}</p>
        )}
        {rules.map((rule, ruleIndex) => (
          <div key={ruleIndex} className="border rounded-lg p-3 space-y-3 relative">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{t('pages.policies.rules.ruleN', { n: ruleIndex + 1 })}</span>
              <Button type="button" variant="ghost" size="sm" onClick={() => removeRule(ruleIndex)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="grid gap-2">
              {templates.map(template => (
                <div key={template.key} className="grid grid-cols-3 gap-2 items-center">
                  <Label className="text-xs">{t(`pages.policies.conditions.${template.key}`)}</Label>
                  <Input
                    className="col-span-2 h-8 text-sm"
                    placeholder={t(`pages.policies.placeholders.${template.placeholderKey || template.key}`)}
                    value={rule.condition[template.key] || ''}
                    onChange={(e) => updateRuleCondition(ruleIndex, template.key, e.target.value)}
                  />
                </div>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label htmlFor={`policy-rule-${ruleIndex}-effect`} className="text-xs">{t('pages.policies.rules.effect')}</Label>
                <Select value={rule.effect} onValueChange={(value) => updateRuleEffect(ruleIndex, value)}>
                  <SelectTrigger id={`policy-rule-${ruleIndex}-effect`} className="h-8 text-sm">
                    <SelectValue placeholder={t('pages.policies.rules.selectEffect')} />
                  </SelectTrigger>
                  <SelectContent>
                    {effectOptions.map(opt => (
                      <SelectItem key={opt} value={opt}>{t(`pages.policies.effects.${opt}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor={`policy-rule-${ruleIndex}-priority`} className="text-xs">{t('pages.policies.rules.priority')}</Label>
                <Input
                  id={`policy-rule-${ruleIndex}-priority`}
                  type="number"
                  className="h-8 text-sm"
                  value={rule.priority}
                  onChange={(e) => updateRulePriority(ruleIndex, parseInt(e.target.value) || 0)}
                  min={0}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  const handleDeleteClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setDeleteDialog(true)
  }

  const handleToggleEnabled = (policy: Policy) => {
    togglePolicyMutation.mutate({
      id: policy.id,
      enabled: !policy.enabled,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.policies')}</h1>
          <p className="text-muted-foreground">{t('pages.policies.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.policies.createPolicy')}
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'separation_of_duty').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.policies.sodPolicies')}</p>
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
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'risk_based').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.policies.riskBased')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                <ToggleRight className="h-6 w-6 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.enabled).length || 0}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.policies.active')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-muted flex items-center justify-center">
                <Scale className="h-6 w-6 text-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold">{policies?.length || 0}</p>
                <p className="text-sm text-muted-foreground">{t('pages.policies.totalPolicies')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.policies.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={8} cols={5} />
          ) : isError ? (
            <QueryError error={error} resource={t('pages.policies.resourceName')} />
          ) : !filteredPolicies || filteredPolicies.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.policies.emptyTitle')}</p>
              <p className="text-sm">{t('pages.policies.emptyDesc')}</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.policies.columns.policy')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.policies.columns.type')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.policies.columns.status')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.policies.columns.priority')}</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">{t('pages.policies.columns.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPolicies?.map((policy) => (
                    <TableRow key={policy.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className={`h-10 w-10 rounded-lg ${policyTypeColors[policy.type]?.split(' ')[0] || 'bg-muted'} flex items-center justify-center`}>
                            {policyTypeIcons[policy.type] || <Scale className="h-5 w-5" />}
                          </div>
                          <div>
                            <p className="font-medium">{policy.name}</p>
                            <p className="text-sm text-muted-foreground max-w-xs truncate">{policy.description || '-'}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${policyTypeColors[policy.type] || 'bg-muted text-foreground'}`}>
                          {policyTypeIcons[policy.type]}
                          {t(`pages.policies.types.${policy.type}`, { defaultValue: policy.type })}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <button
                          onClick={() => handleToggleEnabled(policy)}
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium cursor-pointer ${
                            policy.enabled
                              ? 'bg-green-100 text-green-800'
                              : 'bg-muted text-muted-foreground'
                          }`}
                        >
                          {policy.enabled ? (
                            <>
                              <ToggleRight className="h-4 w-4" />
                              {t('pages.policies.enabled')}
                            </>
                          ) : (
                            <>
                              <ToggleLeft className="h-4 w-4" />
                              {t('pages.policies.disabled')}
                            </>
                          )}
                        </button>
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge variant="outline">{policy.priority}</Badge>
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditClick(policy)}>
                              <Edit className="h-4 w-4 mr-2" />
                              {t('pages.policies.edit')}
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleToggleEnabled(policy)}>
                              {policy.enabled ? (
                                <>
                                  <ToggleLeft className="h-4 w-4 mr-2" />
                                  {t('pages.policies.disable')}
                                </>
                              ) : (
                                <>
                                  <ToggleRight className="h-4 w-4 mr-2" />
                                  {t('pages.policies.enable')}
                                </>
                              )}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() => handleDeleteClick(policy)}
                              className="text-red-600 focus:text-red-600"
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              {t('common.delete')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
          )}

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-muted-foreground">
                {t('pages.policies.showingPolicies', {
                  from: page * PAGE_SIZE + 1,
                  to: Math.min((page + 1) * PAGE_SIZE, totalCount),
                  total: totalCount,
                })}
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
                  {t('common.pagination.pageOf', { page: page + 1, pages: Math.ceil(totalCount / PAGE_SIZE) })}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => p + 1)}
                  disabled={(page + 1) * PAGE_SIZE >= totalCount}
                >
                  {t('common.pagination.next')}
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Policy Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('pages.policies.dialog.createTitle')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t('pages.policies.dialog.name')}</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                placeholder={t('pages.policies.dialog.namePlaceholder')}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">{t('pages.policies.dialog.description')}</Label>
              <Textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                placeholder={t('pages.policies.dialog.descriptionPlaceholder')}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">{t('pages.policies.dialog.type')}</Label>
              <Select value={formData.type} onValueChange={(value) => { setFormData(prev => ({ ...prev, type: value })); setRules([]) }}>
                <SelectTrigger id="type">
                  <SelectValue placeholder={t('pages.policies.dialog.selectType')} />
                </SelectTrigger>
                <SelectContent>
                  {POLICY_FORM_TYPES.map(pt => (
                    <SelectItem key={pt} value={pt}>{t(`pages.policies.formTypes.${pt}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="priority">{t('pages.policies.dialog.priority')}</Label>
              <Input
                id="priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
              <p className="text-xs text-muted-foreground">{t('pages.policies.dialog.priorityHint')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="enabled">{t('pages.policies.dialog.enableNow')}</Label>
            </div>
            {renderRuleBuilder()}
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setCreateModal(false); resetForm(); }}
                disabled={createPolicyMutation.isPending}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={createPolicyMutation.isPending}>
                {t(createPolicyMutation.isPending ? 'pages.policies.dialog.creating' : 'pages.policies.createPolicy')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Policy Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('pages.policies.dialog.editTitle')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">{t('pages.policies.dialog.name')}</Label>
              <Input
                id="edit-name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">{t('pages.policies.dialog.description')}</Label>
              <Textarea
                id="edit-description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">{t('pages.policies.dialog.type')}</Label>
              <Select value={formData.type} onValueChange={(value) => { setFormData(prev => ({ ...prev, type: value })); setRules([]) }}>
                <SelectTrigger id="edit-type">
                  <SelectValue placeholder={t('pages.policies.dialog.selectType')} />
                </SelectTrigger>
                <SelectContent>
                  {POLICY_FORM_TYPES.map(pt => (
                    <SelectItem key={pt} value={pt}>{t(`pages.policies.formTypes.${pt}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-priority">{t('pages.policies.dialog.priority')}</Label>
              <Input
                id="edit-priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="edit-enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="edit-enabled">{t('pages.policies.dialog.enabled')}</Label>
            </div>
            {renderRuleBuilder()}
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setEditModal(false); setSelectedPolicy(null); }}
                disabled={updatePolicyMutation.isPending}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={updatePolicyMutation.isPending}>
                {t(updatePolicyMutation.isPending ? 'pages.policies.dialog.saving' : 'pages.policies.dialog.saveChanges')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.policies.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.policies.deleteDesc', { name: selectedPolicy?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePolicyMutation.isPending}>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedPolicy && deletePolicyMutation.mutate(selectedPolicy.id)}
              disabled={deletePolicyMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {t(deletePolicyMutation.isPending ? 'pages.policies.deleting' : 'common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
