import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Shield, Key, Smartphone, Mail, Fingerprint, Plus, Edit2, Trash2, CheckCircle2, XCircle, Users } from 'lucide-react'
import { Card, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Switch } from '../components/ui/switch'
import { Label } from '../components/ui/label'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface EnrollmentStats {
  total_users: number
  mfa_enabled_count: number
  totp_count: number
  sms_count: number
  email_otp_count: number
  push_count: number
  webauthn_count: number
}

interface MFAPolicy {
  id: string
  name: string
  description: string
  enabled: boolean
  priority: number
  conditions: Record<string, unknown>
  required_methods: string[]
  grace_period_hours: number
  created_at: string
  updated_at: string
}

interface UserMFAStatus {
  user_id: string
  username: string
  email: string
  totp_enabled: boolean
  sms_enabled: boolean
  email_otp_enabled: boolean
  push_enabled: boolean
  webauthn_enabled: boolean
}

// What a policy does at password sign-in (evaluateMFA). With no required
// methods, every user who has a second factor enrolled is challenged, and any
// enrolled factor satisfies it. With required methods, only those do; a user
// who has none of them gets the grace period, from their first sign-in under
// the policy, to add one, and is refused after it unless they have a bypass
// code. Conditions are not enforced, so the form does not offer them (#990).
const emptyPolicy: Partial<MFAPolicy> = {
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  required_methods: [],
  grace_period_hours: 0,
}

// The methods a policy can require, in the order the form lists them.
const policyMethods = ['totp', 'webauthn', 'push', 'sms', 'email']

// The API's bound on the grace period: 30 days.
const maxGraceHours = 720

// storesUnenforcedConditions reports a policy written before #990 that still
// stores conditions, which nothing enforces, so the table can say so.
function storesUnenforcedConditions(p: Pick<MFAPolicy, 'conditions'>): boolean {
  return Object.keys(p.conditions ?? {}).length > 0
}

function sameMethods(a: string[] = [], b: string[] = []): boolean {
  return a.length === b.length && a.every((m) => b.includes(m))
}

export default function MFAManagement() {
  const { t } = useTranslation()
  const methodLabels: Record<string, string> = {
    totp: t('pages.mfaManagement.methods.totp'),
    sms: t('pages.mfaManagement.methods.sms'),
    email: t('pages.mfaManagement.methods.email'),
    push: t('pages.mfaManagement.methods.push'),
    webauthn: t('pages.mfaManagement.methods.webauthn'),
  }
  const { toast } = useToast()
  const queryClient = useQueryClient()

  // Policy dialog state
  const [policyDialogOpen, setPolicyDialogOpen] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<MFAPolicy | null>(null)
  const [formData, setFormData] = useState<Partial<MFAPolicy>>(emptyPolicy)


  // Pagination state for policies and users
  const [policyPage, setPolicyPage] = useState(1)
  const [userPage, setUserPage] = useState(1)
  const pageSize = 20

  // Fetch enrollment stats
  const { data: statsData, isLoading: statsLoading, isError: statsIsError, error: statsError } = useQuery({
    queryKey: ['mfa-enrollment-stats'],
    queryFn: () => api.get<EnrollmentStats>('/api/v1/mfa/enrollment-stats'),
  })

  const stats: EnrollmentStats = statsData || {
    total_users: 0,
    mfa_enabled_count: 0,
    totp_count: 0,
    sms_count: 0,
    email_otp_count: 0,
    push_count: 0,
    webauthn_count: 0,
  }

  const mfaPercentage = stats.total_users > 0
    ? Math.round((stats.mfa_enabled_count / stats.total_users) * 100)
    : 0

  // Fetch policies
  const { data: policiesData, isLoading: policiesLoading, isError: policiesIsError, error: policiesError } = useQuery({
    queryKey: ['mfa-policies', policyPage],
    queryFn: () =>
      api.get<{ policies: MFAPolicy[]; total: number; page: number; page_size: number }>(
        `/api/v1/mfa/policies?page=${policyPage}&page_size=${pageSize}`
      ),
  })

  const policies = policiesData?.policies || []
  const policiesTotalPages = Math.ceil((policiesData?.total || 0) / pageSize)

  // Fetch user MFA status
  const { data: usersData, isLoading: usersLoading, isError: usersIsError, error: usersError } = useQuery({
    queryKey: ['mfa-user-status', userPage],
    queryFn: () =>
      api.get<{ users: UserMFAStatus[]; total: number; page: number; page_size: number }>(
        `/api/v1/mfa/user-status?page=${userPage}&page_size=${pageSize}`
      ),
  })

  const users = usersData?.users || []
  const usersTotalPages = Math.ceil((usersData?.total || 0) / pageSize)

  // Mutations
  const createPolicyMutation = useMutation({
    mutationFn: (data: Partial<MFAPolicy>) => api.post('/api/v1/mfa/policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: t('common.success'), description: t('pages.mfaManagement.toasts.created') })
      setPolicyDialogOpen(false)
      setFormData(emptyPolicy)
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: t('common.error'), description: error.message })
    },
  })

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<MFAPolicy> }) =>
      api.put(`/api/v1/mfa/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: t('common.success'), description: t('pages.mfaManagement.toasts.updated') })
      setPolicyDialogOpen(false)
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: t('common.error'), description: error.message })
    },
  })

  const deletePolicyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/mfa/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-policies'] })
      toast({ title: t('common.success'), description: t('pages.mfaManagement.toasts.deleted') })
    },
    onError: (error: Error) => {
      toast({ variant: 'destructive', title: t('common.error'), description: error.message })
    },
  })

  const openCreatePolicy = () => {
    setSelectedPolicy(null)
    setFormData(emptyPolicy)
    setPolicyDialogOpen(true)
  }

  const openEditPolicy = (policy: MFAPolicy) => {
    setSelectedPolicy(policy)
    // Only what the form edits is sent back, so stored conditions, which
    // nothing enforces, are left as they are rather than re-submitted.
    setFormData({
      name: policy.name,
      description: policy.description,
      enabled: policy.enabled,
      priority: policy.priority,
      required_methods: [...(policy.required_methods ?? [])],
      grace_period_hours: policy.grace_period_hours ?? 0,
    })
    setPolicyDialogOpen(true)
  }

  // A grace period is the time to add a required method, so a policy with none
  // has none: unchecking the last method clears it.
  const toggleMethod = (method: string, checked: boolean) => {
    const current = formData.required_methods || []
    const updated = checked
      ? policyMethods.filter((m) => m === method || current.includes(m))
      : current.filter((m) => m !== method)
    setFormData({
      ...formData,
      required_methods: updated,
      grace_period_hours: updated.length === 0 ? 0 : formData.grace_period_hours,
    })
  }

  const hasMethods = (formData.required_methods?.length ?? 0) > 0
  const graceHours = formData.grace_period_hours ?? 0
  const graceInvalid = !Number.isInteger(graceHours) || graceHours < 0 || graceHours > maxGraceHours
  const methodsChanged =
    selectedPolicy !== null && !sameMethods(selectedPolicy.required_methods, formData.required_methods)


  const handleSavePolicy = () => {
    if (selectedPolicy) {
      updatePolicyMutation.mutate({ id: selectedPolicy.id, data: formData })
    } else {
      createPolicyMutation.mutate(formData)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.mfaManagement')}</h1>
        <p className="text-muted-foreground">{t('pages.mfaManagement.subtitle')}</p>
      </div>

      <Tabs defaultValue="enrollment">
        <TabsList>
          <TabsTrigger value="enrollment">
            <Shield className="mr-2 h-4 w-4" />
            {t('pages.mfaManagement.tabs.enrollment')}
          </TabsTrigger>
          <TabsTrigger value="policies">
            <Key className="mr-2 h-4 w-4" />
            {t('pages.mfaManagement.tabs.policies')}
          </TabsTrigger>
          <TabsTrigger value="users">
            <Users className="mr-2 h-4 w-4" />
            {t('pages.mfaManagement.tabs.users')}
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Enrollment Overview */}
        <TabsContent value="enrollment">
          {statsLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.mfaManagement.enrollment.loading')}</p>
            </div>
          ) : statsIsError ? (
            <QueryError error={statsError} resource={t('pages.mfaManagement.enrollment.resourceName')} />
          ) : (
            <div className="grid gap-4 md:grid-cols-4">
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.total_users}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.totalUsers')}</p>
                    </div>
                    <Users className="h-8 w-8 text-muted-foreground" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.mfa_enabled_count}</div>
                      <p className="text-xs text-muted-foreground">
                        {t('pages.mfaManagement.enrollment.mfaEnabled', { pct: mfaPercentage })}
                      </p>
                    </div>
                    <Shield className="h-8 w-8 text-green-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.totp_count}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.totp')}</p>
                    </div>
                    <Key className="h-8 w-8 text-blue-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.sms_count}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.sms')}</p>
                    </div>
                    <Smartphone className="h-8 w-8 text-purple-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.email_otp_count}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.emailOtp')}</p>
                    </div>
                    <Mail className="h-8 w-8 text-orange-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.push_count}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.push')}</p>
                    </div>
                    <Smartphone className="h-8 w-8 text-teal-500" />
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-2xl font-bold">{stats.webauthn_count}</div>
                      <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.enrollment.webauthn')}</p>
                    </div>
                    <Fingerprint className="h-8 w-8 text-indigo-500" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Tab 2: MFA Policies */}
        <TabsContent value="policies">
          <Card>
            <div className="flex items-center justify-between p-6 pb-0">
              <h2 className="text-lg font-semibold">{t('pages.mfaManagement.policies.title')}</h2>
              <Button onClick={openCreatePolicy}>
                <Plus className="mr-2 h-4 w-4" />
                {t('pages.mfaManagement.policies.create')}
              </Button>
            </div>
            <CardContent className="pt-6">
              <p className="mb-4 text-sm text-muted-foreground">{t('pages.mfaManagement.policies.whatItDoes')}</p>
              {policiesLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">{t('pages.mfaManagement.policies.loading')}</p>
                </div>
              ) : policiesIsError ? (
                <QueryError error={policiesError} resource={t('pages.mfaManagement.policies.resourceName')} />
              ) : policies.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Key className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">{t('pages.mfaManagement.policies.empty')}</p>
                  <p className="text-sm">{t('pages.mfaManagement.policies.emptyHint')}</p>
                </div>
              ) : (
                <>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('pages.mfaManagement.policies.table.name')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.policies.table.description')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.policies.table.methods')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.policies.table.gracePeriod')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.policies.table.priority')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.policies.table.enabled')}</TableHead>
                          <TableHead className="w-[100px]">{t('pages.mfaManagement.policies.table.actions')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {policies.map((policy) => (
                          <TableRow key={policy.id}>
                            <TableCell className="font-medium">
                              {policy.name}
                              {storesUnenforcedConditions(policy) && (
                                <Badge
                                  variant="outline"
                                  className="ml-2 text-xs"
                                  title={t('pages.mfaManagement.policies.notEnforcedBody')}
                                >
                                  {t('pages.mfaManagement.policies.notEnforcedBadge')}
                                </Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">
                              {policy.description}
                            </TableCell>
                            <TableCell>
                              {(policy.required_methods?.length ?? 0) > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {policy.required_methods.map((method) => (
                                    <Badge key={method} variant="outline">
                                      {methodLabels[method] || method}
                                    </Badge>
                                  ))}
                                </div>
                              ) : (
                                <span className="text-sm text-muted-foreground">
                                  {t('pages.mfaManagement.policies.anyFactor')}
                                </span>
                              )}
                            </TableCell>
                            <TableCell className="text-sm">
                              {(policy.required_methods?.length ?? 0) > 0
                                ? policy.grace_period_hours > 0
                                  ? t('pages.mfaManagement.policies.graceHours', { n: policy.grace_period_hours })
                                  : t('pages.mfaManagement.policies.noGrace')
                                : ''}
                            </TableCell>
                            <TableCell>
                              <span className="text-xs font-mono bg-muted px-2 py-1 rounded">
                                #{policy.priority}
                              </span>
                            </TableCell>
                            <TableCell>
                              <Switch aria-label={t('pages.mfaManagement.togglePolicy', { name: policy.name })}
                                checked={policy.enabled}
                                onCheckedChange={(checked) => {
                                  updatePolicyMutation.mutate({
                                    id: policy.id,
                                    data: { enabled: checked },
                                  })
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1">
                                <Button variant="ghost" size="icon" onClick={() => openEditPolicy(policy)}>
                                  <Edit2 className="h-4 w-4" />
                                </Button>
                                <ConfirmAction
                                  title={t('pages.mfaManagement.policies.confirmDelete.title')}
                                  description={t('pages.mfaManagement.policies.confirmDelete.description', {
                                    name: policy.name,
                                  })}
                                  destructive
                                  confirmLabel={t('common.delete')}
                                  onConfirm={() => deletePolicyMutation.mutateAsync(policy.id)}
                                >
                                  {(open) => (
                                    <Button variant="ghost" size="icon" onClick={open}>
                                      <Trash2 className="h-4 w-4 text-red-500" />
                                    </Button>
                                  )}
                                </ConfirmAction>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {policiesTotalPages > 1 && (
                    <div className="flex items-center justify-between pt-4">
                      <p className="text-sm text-muted-foreground">
                        {t('common.pagination.pageOf', { page: policyPage, pages: policiesTotalPages })}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={policyPage <= 1}
                          onClick={() => setPolicyPage((p) => p - 1)}
                        >
                          {t('common.pagination.previous')}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={policyPage >= policiesTotalPages}
                          onClick={() => setPolicyPage((p) => p + 1)}
                        >
                          {t('common.pagination.next')}
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 3: User MFA Status */}
        <TabsContent value="users">
          <Card>
            <CardContent className="pt-6">
              {usersLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">{t('pages.mfaManagement.users.loading')}</p>
                </div>
              ) : usersIsError ? (
                <QueryError error={usersError} resource={t('pages.mfaManagement.users.resourceName')} />
              ) : users.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Users className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">{t('pages.mfaManagement.users.empty')}</p>
                  <p className="text-sm">{t('pages.mfaManagement.users.emptyHint')}</p>
                </div>
              ) : (
                <>
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('pages.mfaManagement.users.table.username')}</TableHead>
                          <TableHead>{t('pages.mfaManagement.users.table.email')}</TableHead>
                          <TableHead className="text-center">{methodLabels.totp}</TableHead>
                          <TableHead className="text-center">{methodLabels.sms}</TableHead>
                          <TableHead className="text-center">{methodLabels.email}</TableHead>
                          <TableHead className="text-center">{methodLabels.push}</TableHead>
                          <TableHead className="text-center">{methodLabels.webauthn}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {users.map((user) => (
                          <TableRow key={user.user_id}>
                            <TableCell className="font-medium">{user.username}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">{user.email}</TableCell>
                            <TableCell className="text-center">
                              {user.totp_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.sms_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.email_otp_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.push_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              {user.webauthn_enabled ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                              ) : (
                                <XCircle className="h-5 w-5 text-muted-foreground mx-auto" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {usersTotalPages > 1 && (
                    <div className="flex items-center justify-between pt-4">
                      <p className="text-sm text-muted-foreground">
                        {t('common.pagination.pageOf', { page: userPage, pages: usersTotalPages })}
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={userPage <= 1}
                          onClick={() => setUserPage((p) => p - 1)}
                        >
                          {t('common.pagination.previous')}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={userPage >= usersTotalPages}
                          onClick={() => setUserPage((p) => p + 1)}
                        >
                          {t('common.pagination.next')}
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create/Edit Policy Dialog */}
      <Dialog open={policyDialogOpen} onOpenChange={setPolicyDialogOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {selectedPolicy
                ? t('pages.mfaManagement.dialog.editTitle')
                : t('pages.mfaManagement.dialog.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.mfaManagement.dialog.name')}</Label>
              <Input
                value={formData.name || ''}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder={t('pages.mfaManagement.dialog.namePlaceholder')}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('pages.mfaManagement.dialog.description')}</Label>
              <Input
                value={formData.description || ''}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder={t('pages.mfaManagement.dialog.descriptionPlaceholder')}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mfa-management-priority">{t('pages.mfaManagement.dialog.priority')}</Label>
              <Input id="mfa-management-priority"
                type="number"
                value={formData.priority ?? 100}
                onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
              />
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('pages.mfaManagement.dialog.requiredMethods')}</legend>
              <div className="grid grid-cols-2 gap-3 pt-1">
                {policyMethods.map((method) => (
                  <div key={method} className="flex items-center space-x-2">
                    <Checkbox
                      id={`mfa-policy-method-${method}`}
                      checked={(formData.required_methods || []).includes(method)}
                      onCheckedChange={(checked) => toggleMethod(method, checked === true)}
                    />
                    <label htmlFor={`mfa-policy-method-${method}`} className="text-sm">
                      {methodLabels[method]}
                    </label>
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                {hasMethods
                  ? t('pages.mfaManagement.dialog.requiredMethodsHelp')
                  : t('pages.mfaManagement.dialog.anyFactorHelp')}
              </p>
            </fieldset>
            <div className="space-y-2">
              <Label htmlFor="mfa-management-grace-period">{t('pages.mfaManagement.dialog.gracePeriod')}</Label>
              <Input id="mfa-management-grace-period"
                type="number"
                min={0}
                max={maxGraceHours}
                step={1}
                disabled={!hasMethods}
                aria-invalid={hasMethods && graceInvalid}
                aria-describedby="mfa-management-grace-period-help"
                value={graceHours}
                onChange={(e) => setFormData({ ...formData, grace_period_hours: Number(e.target.value) })}
              />
              <p id="mfa-management-grace-period-help" className="text-xs text-muted-foreground">
                {hasMethods && graceInvalid
                  ? t('pages.mfaManagement.dialog.gracePeriodInvalid', { max: maxGraceHours })
                  : hasMethods
                    ? t('pages.mfaManagement.dialog.gracePeriodHelp')
                    : t('pages.mfaManagement.dialog.gracePeriodNeedsMethods')}
              </p>
              {methodsChanged && hasMethods && (
                <p className="text-xs font-medium text-amber-700">
                  {t('pages.mfaManagement.dialog.methodsChangedWarning')}
                </p>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t('pages.mfaManagement.dialog.whatItDoes')}</p>
            {selectedPolicy && storesUnenforcedConditions(selectedPolicy) && (
              <p className="text-xs text-muted-foreground">
                <span className="font-medium">{t('pages.mfaManagement.policies.notEnforcedBadge')}:</span>{' '}
                {t('pages.mfaManagement.policies.notEnforcedBody')}
              </p>
            )}
            <div className="flex items-center space-x-2">
              <Switch
                id="policy-enabled"
                checked={formData.enabled ?? true}
                onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
              />
              <Label htmlFor="policy-enabled">{t('pages.mfaManagement.dialog.enabled')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPolicyDialogOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={handleSavePolicy}
              disabled={
                !formData.name ||
                (hasMethods && graceInvalid) ||
                createPolicyMutation.isPending ||
                updatePolicyMutation.isPending
              }
            >
              {createPolicyMutation.isPending || updatePolicyMutation.isPending
                ? t('pages.mfaManagement.dialog.saving')
                : selectedPolicy
                  ? t('pages.mfaManagement.dialog.update')
                  : t('pages.mfaManagement.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  )
}
