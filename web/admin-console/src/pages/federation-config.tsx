import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Plus, Pencil, Trash2, Search, Link2, FileCode, ShieldCheck,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Switch } from '../components/ui/switch'
import { Checkbox } from '../components/ui/checkbox'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

// --- Federation Rules ---

interface FederationRule {
  id: string
  name: string
  email_domain: string
  provider_id: string
  provider_name: string
  priority: number
  auto_redirect: boolean
  enabled: boolean
}

interface RuleFormData {
  name: string
  email_domain: string
  provider_id: string
  priority: number
  auto_redirect: boolean
  enabled: boolean
}

const emptyRuleForm: RuleFormData = {
  name: '',
  email_domain: '',
  provider_id: '',
  priority: 0,
  auto_redirect: false,
  enabled: true,
}

// --- Identity Links ---

interface IdentityLink {
  id: string
  provider_name: string
  external_id: string
  external_email: string
  display_name: string
  is_primary: boolean
  linked_at: string
}

// --- Claims Mapping ---

interface CustomClaim {
  id: string
  application_id: string
  claim_name: string
  source_type: string
  source_value: string
  claim_type: string
  include_in_id_token: boolean
  include_in_access_token: boolean
  include_in_userinfo: boolean
  enabled: boolean
}

interface ClaimFormData {
  claim_name: string
  source_type: string
  source_value: string
  claim_type: string
  include_in_id_token: boolean
  include_in_access_token: boolean
  include_in_userinfo: boolean
  enabled: boolean
}

const emptyClaimForm: ClaimFormData = {
  claim_name: '',
  source_type: 'user_attribute',
  source_value: '',
  claim_type: 'string',
  include_in_id_token: true,
  include_in_access_token: false,
  include_in_userinfo: true,
  enabled: true,
}

interface SimpleProvider {
  id: string
  name: string
}

interface SimpleApplication {
  id: string
  name: string
}

type TabKey = 'rules' | 'links' | 'claims'

export function FederationConfigPage() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<TabKey>('rules')

  const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
    { key: 'rules', label: t('pages.federation.tabs.rules'), icon: <ShieldCheck className="h-4 w-4" /> },
    { key: 'links', label: t('pages.federation.tabs.links'), icon: <Link2 className="h-4 w-4" /> },
    { key: 'claims', label: t('pages.federation.tabs.claims'), icon: <FileCode className="h-4 w-4" /> },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.federation.title')}</h1>
        <p className="text-muted-foreground">
          {t('pages.federation.subtitle')}
        </p>
      </div>

      <div className="flex border-b">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'rules' && <FederationRulesTab />}
      {activeTab === 'links' && <IdentityLinksTab />}
      {activeTab === 'claims' && <ClaimsMappingTab />}
    </div>
  )
}

// ============================================================
// Tab 1: Federation Rules
// ============================================================

function FederationRulesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [formOpen, setFormOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<FederationRule | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<FederationRule | null>(null)
  const [form, setForm] = useState<RuleFormData>(emptyRuleForm)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['federation-rules'],
    queryFn: () =>
      api.get<{ data: FederationRule[] }>('/api/v1/federation/rules'),
  })

  const rules = data?.data || []

  const { data: providersData } = useQuery({
    queryKey: ['identity-providers-list'],
    queryFn: () =>
      api.get<SimpleProvider[]>('/api/v1/identity/providers'),
  })

  const providers = providersData || []

  const createMutation = useMutation({
    mutationFn: (body: RuleFormData) =>
      api.post('/api/v1/federation/rules', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['federation-rules'] })
      setFormOpen(false)
      setForm(emptyRuleForm)
      toast({ title: t('pages.federation.rules.toasts.created') })
    },
    onError: () => {
      toast({ title: t('pages.federation.rules.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: RuleFormData }) =>
      api.put(`/api/v1/federation/rules/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['federation-rules'] })
      setEditTarget(null)
      setFormOpen(false)
      setForm(emptyRuleForm)
      toast({ title: t('pages.federation.rules.toasts.updated') })
    },
    onError: () => {
      toast({ title: t('pages.federation.rules.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/federation/rules/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['federation-rules'] })
      setDeleteTarget(null)
      toast({ title: t('pages.federation.rules.toasts.deleted') })
    },
    onError: () => {
      toast({ title: t('pages.federation.rules.toasts.deleteFailed'), variant: 'destructive' })
    },
  })

  function openCreate() {
    setEditTarget(null)
    setForm(emptyRuleForm)
    setFormOpen(true)
  }

  function openEdit(rule: FederationRule) {
    setEditTarget(rule)
    setForm({
      name: rule.name,
      email_domain: rule.email_domain,
      provider_id: rule.provider_id,
      priority: rule.priority,
      auto_redirect: rule.auto_redirect,
      enabled: rule.enabled,
    })
    setFormOpen(true)
  }

  function handleSubmit() {
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, body: form })
    } else {
      createMutation.mutate(form)
    }
  }

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-muted-foreground">{t('pages.federation.rules.loading')}</p>
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.federation.rules.resourceName')} />
  }

  return (
    <>
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {t('pages.federation.rules.intro')}
        </p>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t('pages.federation.rules.addRule')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('pages.federation.rules.cardTitle', { n: rules.length })}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.federation.rules.table.name')}</TableHead>
                <TableHead>{t('pages.federation.rules.table.emailDomain')}</TableHead>
                <TableHead>{t('pages.federation.rules.table.provider')}</TableHead>
                <TableHead>{t('pages.federation.rules.table.priority')}</TableHead>
                <TableHead>{t('pages.federation.rules.table.autoRedirect')}</TableHead>
                <TableHead>{t('pages.federation.rules.table.enabled')}</TableHead>
                <TableHead className="text-right">{t('pages.federation.rules.table.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {t('pages.federation.rules.empty')}
                  </TableCell>
                </TableRow>
              ) : (
                rules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {rule.email_domain}
                      </Badge>
                    </TableCell>
                    <TableCell>{rule.provider_name}</TableCell>
                    <TableCell>{rule.priority}</TableCell>
                    <TableCell>
                      <Badge variant={rule.auto_redirect ? 'default' : 'secondary'}>
                        {rule.auto_redirect ? t('pages.federation.rules.yes') : t('pages.federation.rules.no')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          rule.enabled
                            ? 'bg-green-100 text-green-800 hover:bg-green-100'
                            : 'bg-muted text-foreground hover:bg-muted'
                        }
                      >
                        {rule.enabled ? t('pages.federation.rules.enabled') : t('pages.federation.rules.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(rule)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(rule)}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Create / Edit Dialog */}
      <Dialog open={formOpen} onOpenChange={(open) => { if (!open) { setFormOpen(false); setEditTarget(null) } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editTarget ? t('pages.federation.rules.dialog.editTitle') : t('pages.federation.rules.dialog.addTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="rule_name">{t('pages.federation.rules.dialog.name')}</Label>
              <Input
                id="rule_name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder={t('pages.federation.rules.dialog.namePlaceholder')}
              />
            </div>
            <div>
              <Label htmlFor="email_domain">{t('pages.federation.rules.dialog.emailDomain')}</Label>
              <Input
                id="email_domain"
                value={form.email_domain}
                onChange={(e) => setForm((f) => ({ ...f, email_domain: e.target.value }))}
                placeholder={t('pages.federation.rules.dialog.emailDomainPlaceholder')}
              />
            </div>
            <div>
              <Label htmlFor="federation-config-provider">{t('pages.federation.rules.dialog.provider')}</Label>
              <Select
                value={form.provider_id}
                onValueChange={(v) => setForm((f) => ({ ...f, provider_id: v }))}
              >
                <SelectTrigger id="federation-config-provider" className="mt-1">
                  <SelectValue placeholder={t('pages.federation.rules.dialog.providerPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {providers.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="priority">{t('pages.federation.rules.dialog.priority')}</Label>
              <Input
                id="priority"
                type="number"
                value={form.priority}
                onChange={(e) => setForm((f) => ({ ...f, priority: parseInt(e.target.value, 10) || 0 }))}
                placeholder="0"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {t('pages.federation.rules.dialog.priorityHint')}
              </p>
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="federation-config-auto-redirect">{t('pages.federation.rules.dialog.autoRedirect')}</Label>
              <Switch id="federation-config-auto-redirect"
                checked={form.auto_redirect}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, auto_redirect: checked }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="federation-config-enabled">{t('pages.federation.rules.dialog.enabled')}</Label>
              <Switch id="federation-config-enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, enabled: checked }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setFormOpen(false); setEditTarget(null) }}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={
                !form.name.trim() ||
                !form.email_domain.trim() ||
                !form.provider_id ||
                createMutation.isPending ||
                updateMutation.isPending
              }
            >
              {createMutation.isPending || updateMutation.isPending
                ? t('pages.federation.rules.dialog.saving')
                : editTarget
                  ? t('pages.federation.rules.dialog.update')
                  : t('pages.federation.rules.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.federation.rules.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.federation.rules.deleteDialog.description', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ============================================================
// Tab 2: Identity Links
// ============================================================

function IdentityLinksTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [userId, setUserId] = useState('')
  const [searchUserId, setSearchUserId] = useState('')
  const [unlinkTarget, setUnlinkTarget] = useState<IdentityLink | null>(null)

  const { data, isLoading, isFetching, isError, error } = useQuery({
    queryKey: ['identity-links', searchUserId],
    queryFn: () =>
      api.get<{ data: IdentityLink[] }>(
        `/api/v1/users/${searchUserId}/identity-links`
      ),
    enabled: !!searchUserId,
  })

  const links = data?.data || []

  const unlinkMutation = useMutation({
    mutationFn: (linkId: string) =>
      api.delete(`/api/v1/users/${searchUserId}/identity-links/${linkId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-links', searchUserId] })
      setUnlinkTarget(null)
      toast({ title: t('pages.federation.links.toasts.unlinked') })
    },
    onError: () => {
      toast({ title: t('pages.federation.links.toasts.unlinkFailed'), variant: 'destructive' })
    },
  })

  function handleSearch() {
    if (userId.trim()) {
      setSearchUserId(userId.trim())
    }
  }

  return (
    <>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          {t('pages.federation.links.intro')}
        </p>
        <div className="flex items-center gap-2">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t('pages.federation.links.searchPlaceholder')}
              className="pl-9"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
          </div>
          <Button onClick={handleSearch} disabled={!userId.trim()}>
            <Search className="mr-2 h-4 w-4" />
            {t('pages.federation.links.search')}
          </Button>
        </div>

        {!searchUserId ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Link2 className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.federation.links.prompt')}</p>
            <p className="text-sm">{t('pages.federation.links.promptHint')}</p>
          </div>
        ) : isLoading || isFetching ? (
          <div className="flex flex-col items-center justify-center py-12">
            <LoadingSpinner size="lg" />
            <p className="mt-4 text-sm text-muted-foreground">{t('pages.federation.links.loading')}</p>
          </div>
        ) : isError ? (
          <QueryError error={error} resource={t('pages.federation.links.resourceName')} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('pages.federation.links.cardTitle', { user: searchUserId, n: links.length })}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.federation.links.table.provider')}</TableHead>
                    <TableHead>{t('pages.federation.links.table.externalId')}</TableHead>
                    <TableHead>{t('pages.federation.links.table.externalEmail')}</TableHead>
                    <TableHead>{t('pages.federation.links.table.displayName')}</TableHead>
                    <TableHead>{t('pages.federation.links.table.primary')}</TableHead>
                    <TableHead>{t('pages.federation.links.table.linkedAt')}</TableHead>
                    <TableHead className="text-right">{t('pages.federation.links.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {links.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center text-muted-foreground">
                        {t('pages.federation.links.empty')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    links.map((link) => (
                      <TableRow key={link.id}>
                        <TableCell>
                          <Badge variant="outline">{link.provider_name}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[150px] truncate">
                          {link.external_id}
                        </TableCell>
                        <TableCell>{link.external_email}</TableCell>
                        <TableCell>{link.display_name}</TableCell>
                        <TableCell>
                          <Badge variant={link.is_primary ? 'default' : 'secondary'}>
                            {link.is_primary ? t('pages.federation.links.isPrimary') : t('pages.federation.links.isSecondary')}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(link.linked_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setUnlinkTarget(link)}
                          >
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Unlink Confirmation */}
      <AlertDialog open={!!unlinkTarget} onOpenChange={(open) => !open && setUnlinkTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.federation.links.unlinkDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.federation.links.unlinkDialog.description', {
                provider: unlinkTarget?.provider_name ?? '',
                email: unlinkTarget?.external_email ?? '',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => unlinkTarget && unlinkMutation.mutate(unlinkTarget.id)}
            >
              {t('pages.federation.links.unlinkDialog.unlink')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ============================================================
// Tab 3: Claims Mapping
// ============================================================

function ClaimsMappingTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [selectedAppId, setSelectedAppId] = useState('')
  const [formOpen, setFormOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<CustomClaim | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<CustomClaim | null>(null)
  const [form, setForm] = useState<ClaimFormData>(emptyClaimForm)

  const { data: appsData } = useQuery({
    queryKey: ['applications-list'],
    queryFn: () =>
      api.get<SimpleApplication[]>('/api/v1/applications'),
  })

  const applications = appsData || []

  const { data: claimsData, isLoading: claimsLoading, isError: claimsError, error: claimsErrorObj } = useQuery({
    queryKey: ['custom-claims', selectedAppId],
    queryFn: () =>
      api.get<{ data: CustomClaim[] }>(
        `/api/v1/applications/${selectedAppId}/claims`
      ),
    enabled: !!selectedAppId,
  })

  const claims = claimsData?.data || []

  const createMutation = useMutation({
    mutationFn: (body: ClaimFormData) =>
      api.post(`/api/v1/applications/${selectedAppId}/claims`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-claims', selectedAppId] })
      setFormOpen(false)
      setForm(emptyClaimForm)
      toast({ title: t('pages.federation.claims.toasts.created') })
    },
    onError: () => {
      toast({ title: t('pages.federation.claims.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: ClaimFormData }) =>
      api.put(`/api/v1/applications/${selectedAppId}/claims/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-claims', selectedAppId] })
      setEditTarget(null)
      setFormOpen(false)
      setForm(emptyClaimForm)
      toast({ title: t('pages.federation.claims.toasts.updated') })
    },
    onError: () => {
      toast({ title: t('pages.federation.claims.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/applications/${selectedAppId}/claims/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-claims', selectedAppId] })
      setDeleteTarget(null)
      toast({ title: t('pages.federation.claims.toasts.deleted') })
    },
    onError: () => {
      toast({ title: t('pages.federation.claims.toasts.deleteFailed'), variant: 'destructive' })
    },
  })

  function openCreate() {
    setEditTarget(null)
    setForm(emptyClaimForm)
    setFormOpen(true)
  }

  function openEdit(claim: CustomClaim) {
    setEditTarget(claim)
    setForm({
      claim_name: claim.claim_name,
      source_type: claim.source_type,
      source_value: claim.source_value,
      claim_type: claim.claim_type,
      include_in_id_token: claim.include_in_id_token,
      include_in_access_token: claim.include_in_access_token,
      include_in_userinfo: claim.include_in_userinfo,
      enabled: claim.enabled,
    })
    setFormOpen(true)
  }

  function handleSubmit() {
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, body: form })
    } else {
      createMutation.mutate(form)
    }
  }

  return (
    <>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          {t('pages.federation.claims.intro')}
        </p>
        <div className="flex items-center gap-4">
          <div className="w-80">
            <Label htmlFor="federation-config-application">{t('pages.federation.claims.application')}</Label>
            <Select value={selectedAppId} onValueChange={setSelectedAppId}>
              <SelectTrigger id="federation-config-application" className="mt-1">
                <SelectValue placeholder={t('pages.federation.claims.applicationPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {applications.map((app) => (
                  <SelectItem key={app.id} value={app.id}>
                    {app.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {selectedAppId && (
            <div className="pt-5">
              <Button onClick={openCreate}>
                <Plus className="mr-2 h-4 w-4" />
                {t('pages.federation.claims.addClaim')}
              </Button>
            </div>
          )}
        </div>

        {!selectedAppId ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <FileCode className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.federation.claims.prompt')}</p>
            <p className="text-sm">{t('pages.federation.claims.promptHint')}</p>
          </div>
        ) : claimsLoading ? (
          <div className="flex flex-col items-center justify-center py-12">
            <LoadingSpinner size="lg" />
            <p className="mt-4 text-sm text-muted-foreground">{t('pages.federation.claims.loading')}</p>
          </div>
        ) : claimsError ? (
          <QueryError error={claimsErrorObj} resource={t('pages.federation.claims.resourceName')} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {t('pages.federation.claims.cardTitle', { n: claims.length })}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.federation.claims.table.claimName')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.sourceType')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.sourceValue')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.type')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.idToken')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.accessToken')}</TableHead>
                    <TableHead>{t('pages.federation.claims.table.userInfo')}</TableHead>
                    <TableHead className="text-right">{t('pages.federation.claims.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {claims.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center text-muted-foreground">
                        {t('pages.federation.claims.empty')}
                      </TableCell>
                    </TableRow>
                  ) : (
                    claims.map((claim) => (
                      <TableRow key={claim.id}>
                        <TableCell className="font-medium font-mono text-sm">
                          {claim.claim_name}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {claim.source_type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm max-w-[150px] truncate">
                          {claim.source_value}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="text-xs">
                            {claim.claim_type}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={claim.include_in_id_token ? 'default' : 'secondary'} className="text-xs">
                            {claim.include_in_id_token ? t('pages.federation.claims.yes') : t('pages.federation.claims.no')}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={claim.include_in_access_token ? 'default' : 'secondary'} className="text-xs">
                            {claim.include_in_access_token ? t('pages.federation.claims.yes') : t('pages.federation.claims.no')}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={claim.include_in_userinfo ? 'default' : 'secondary'} className="text-xs">
                            {claim.include_in_userinfo ? t('pages.federation.claims.yes') : t('pages.federation.claims.no')}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            <Button variant="ghost" size="sm" onClick={() => openEdit(claim)}>
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(claim)}>
                              <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Create / Edit Claim Dialog */}
      <Dialog open={formOpen} onOpenChange={(open) => { if (!open) { setFormOpen(false); setEditTarget(null) } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editTarget ? t('pages.federation.claims.dialog.editTitle') : t('pages.federation.claims.dialog.addTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="claim_name">{t('pages.federation.claims.dialog.claimName')}</Label>
              <Input
                id="claim_name"
                value={form.claim_name}
                onChange={(e) => setForm((f) => ({ ...f, claim_name: e.target.value }))}
                placeholder={t('pages.federation.claims.dialog.claimNamePlaceholder')}
              />
            </div>
            <div>
              <Label htmlFor="federation-config-source-type">{t('pages.federation.claims.dialog.sourceType')}</Label>
              <Select
                value={form.source_type}
                onValueChange={(v) => setForm((f) => ({ ...f, source_type: v }))}
              >
                <SelectTrigger id="federation-config-source-type" className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_attribute">{t('pages.federation.claims.dialog.sourceTypes.userAttribute')}</SelectItem>
                  <SelectItem value="group_membership">{t('pages.federation.claims.dialog.sourceTypes.groupMembership')}</SelectItem>
                  <SelectItem value="static_value">{t('pages.federation.claims.dialog.sourceTypes.staticValue')}</SelectItem>
                  <SelectItem value="expression">{t('pages.federation.claims.dialog.sourceTypes.expression')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="source_value">{t('pages.federation.claims.dialog.sourceValue')}</Label>
              <Input
                id="source_value"
                value={form.source_value}
                onChange={(e) => setForm((f) => ({ ...f, source_value: e.target.value }))}
                placeholder={
                  form.source_type === 'user_attribute'
                    ? t('pages.federation.claims.dialog.sourceValuePlaceholders.userAttribute')
                    : form.source_type === 'group_membership'
                      ? t('pages.federation.claims.dialog.sourceValuePlaceholders.groupMembership')
                      : form.source_type === 'static_value'
                        ? t('pages.federation.claims.dialog.sourceValuePlaceholders.staticValue')
                        : t('pages.federation.claims.dialog.sourceValuePlaceholders.expression')
                }
              />
              <p className="text-xs text-muted-foreground mt-1">
                {form.source_type === 'user_attribute' && t('pages.federation.claims.dialog.sourceHints.userAttribute')}
                {form.source_type === 'group_membership' && t('pages.federation.claims.dialog.sourceHints.groupMembership')}
                {form.source_type === 'static_value' && t('pages.federation.claims.dialog.sourceHints.staticValue')}
                {form.source_type === 'expression' && t('pages.federation.claims.dialog.sourceHints.expression')}
              </p>
            </div>
            <div>
              <Label htmlFor="federation-config-claim-type">{t('pages.federation.claims.dialog.claimType')}</Label>
              <Select
                value={form.claim_type}
                onValueChange={(v) => setForm((f) => ({ ...f, claim_type: v }))}
              >
                <SelectTrigger id="federation-config-claim-type" className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="string">{t('pages.federation.claims.dialog.claimTypes.string')}</SelectItem>
                  <SelectItem value="number">{t('pages.federation.claims.dialog.claimTypes.number')}</SelectItem>
                  <SelectItem value="boolean">{t('pages.federation.claims.dialog.claimTypes.boolean')}</SelectItem>
                  <SelectItem value="array">{t('pages.federation.claims.dialog.claimTypes.array')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-3 pt-2">
              <Label className="text-sm font-medium">{t('pages.federation.claims.dialog.includeIn')}</Label>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="include_id_token"
                  checked={form.include_in_id_token}
                  onCheckedChange={(checked) =>
                    setForm((f) => ({ ...f, include_in_id_token: checked === true }))
                  }
                />
                <Label htmlFor="include_id_token" className="font-normal">{t('pages.federation.claims.dialog.idToken')}</Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="include_access_token"
                  checked={form.include_in_access_token}
                  onCheckedChange={(checked) =>
                    setForm((f) => ({ ...f, include_in_access_token: checked === true }))
                  }
                />
                <Label htmlFor="include_access_token" className="font-normal">{t('pages.federation.claims.dialog.accessToken')}</Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="include_userinfo"
                  checked={form.include_in_userinfo}
                  onCheckedChange={(checked) =>
                    setForm((f) => ({ ...f, include_in_userinfo: checked === true }))
                  }
                />
                <Label htmlFor="include_userinfo" className="font-normal">{t('pages.federation.claims.dialog.userInfo')}</Label>
              </div>
            </div>
            <div className="flex items-center justify-between pt-2">
              <Label htmlFor="federation-config-enabled-2">{t('pages.federation.claims.dialog.enabled')}</Label>
              <Switch id="federation-config-enabled-2"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, enabled: checked }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setFormOpen(false); setEditTarget(null) }}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={
                !form.claim_name.trim() ||
                !form.source_value.trim() ||
                createMutation.isPending ||
                updateMutation.isPending
              }
            >
              {createMutation.isPending || updateMutation.isPending
                ? t('pages.federation.claims.dialog.saving')
                : editTarget
                  ? t('pages.federation.claims.dialog.update')
                  : t('pages.federation.claims.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Claim Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.federation.claims.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.federation.claims.deleteDialog.description', { name: deleteTarget?.claim_name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
