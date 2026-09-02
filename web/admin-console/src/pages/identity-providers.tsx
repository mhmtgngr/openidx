import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Plus, Search, MoreHorizontal, Edit, Trash2, ChevronLeft, ChevronRight, KeyRound, Shield, ExternalLink } from 'lucide-react'
import { PROVIDER_TEMPLATES, ProviderTemplate } from '../lib/provider-templates'
import { GoogleIcon, GitHubIcon, MicrosoftIcon } from '../components/icons/social-providers'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
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
import { api, IdentityProvider } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { SecretField } from '../components/secret-field'

interface ProviderFormData {
  name: string
  provider_type: 'oidc' | 'saml'
  issuer_url: string
  client_id: string
  client_secret: string
  client_secret_changed: boolean
  scopes: string
  enabled: boolean
}

const emptyForm: ProviderFormData = {
  name: '',
  provider_type: 'oidc',
  issuer_url: '',
  client_id: '',
  client_secret: '',
  client_secret_changed: false,
  scopes: 'openid,profile,email',
  enabled: true,
}

export function IdentityProvidersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [addModal, setAddModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState<IdentityProvider | null>(null)
  const [formData, setFormData] = useState<ProviderFormData>(emptyForm)
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<ProviderTemplate | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: providers, isLoading, isError, error } = useQuery({
    queryKey: ['identity-providers', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const { data, headers } = await api.getWithHeaders<IdentityProvider[]>(
        `/api/v1/identity/providers?${params.toString()}`
      )
      setTotalCount(parseInt(headers['x-total-count'] || '0', 10))
      return data
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: ProviderFormData) =>
      api.createIdentityProvider({
        name: data.name,
        provider_type: data.provider_type,
        issuer_url: data.issuer_url,
        client_id: data.client_id,
        client_secret: data.client_secret,
        scopes: data.scopes.split(',').map((s) => s.trim()).filter(Boolean),
        enabled: data.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      setAddModal(false)
      setFormData(emptyForm)
      toast({ title: t('pages.identityProviders.toasts.created') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.identityProviders.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ProviderFormData }) =>
      api.updateIdentityProvider(id, {
        name: data.name,
        provider_type: data.provider_type,
        issuer_url: data.issuer_url,
        client_id: data.client_id,
        // Only transmit a new client_secret when the user actually typed one;
        // otherwise omit it so the stored secret is preserved.
        client_secret: data.client_secret_changed ? data.client_secret : undefined,
        scopes: data.scopes.split(',').map((s) => s.trim()).filter(Boolean),
        enabled: data.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      setEditModal(false)
      setSelectedProvider(null)
      toast({ title: t('pages.identityProviders.toasts.updated') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.identityProviders.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteIdentityProvider(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      toast({ title: t('pages.identityProviders.toasts.deleted') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.identityProviders.toasts.deleteFailed'), variant: 'destructive' })
    },
  })

  const handleQuickSetup = (template: ProviderTemplate) => {
    setSelectedTemplate(template)
    setFormData({
      name: template.name,
      provider_type: template.provider_type,
      issuer_url: template.issuer_url,
      client_id: '',
      client_secret: '',
      client_secret_changed: false,
      scopes: template.scopes,
      enabled: true,
    })
    setAddModal(true)
  }

  const handleAdd = () => {
    setSelectedTemplate(null)
    setFormData(emptyForm)
    setAddModal(true)
  }

  const handleEdit = (provider: IdentityProvider) => {
    setSelectedProvider(provider)
    setFormData({
      name: provider.name,
      provider_type: provider.provider_type,
      issuer_url: provider.issuer_url,
      client_id: provider.client_id,
      // Never prefill a stored secret into the form; start blank on edit.
      client_secret: '',
      client_secret_changed: false,
      scopes: (provider.scopes || []).join(', '),
      enabled: provider.enabled,
    })
    setEditModal(true)
  }

  const handleDelete = (provider: IdentityProvider) => {
    setDeleteTarget({ id: provider.id, name: provider.name })
  }

  const handleFormSubmit = () => {
    if (editModal && selectedProvider) {
      updateMutation.mutate({ id: selectedProvider.id, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  // Providers are filtered server-side via search param
  const filteredProviders = providers || []

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.identityProviders.resourceName')} />
  }

  const formContent = (
    <div className="space-y-4">
      <div>
        <Label htmlFor="name">{t('pages.identityProviders.form.name')}</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder={t('pages.identityProviders.form.namePlaceholder')}
        />
      </div>
      <div>
        <Label>{t('pages.identityProviders.form.providerType')}</Label>
        <Select
          value={formData.provider_type}
          onValueChange={(v) => setFormData({ ...formData, provider_type: v as 'oidc' | 'saml' })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="oidc">OIDC</SelectItem>
            <SelectItem value="saml">SAML</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label htmlFor="issuer_url">{t('pages.identityProviders.form.issuerUrl')}</Label>
        <Input
          id="issuer_url"
          value={formData.issuer_url}
          onChange={(e) => setFormData({ ...formData, issuer_url: e.target.value })}
          placeholder="https://accounts.google.com"
        />
      </div>
      <div>
        <Label htmlFor="client_id">{t('pages.identityProviders.form.clientId')}</Label>
        <Input
          id="client_id"
          value={formData.client_id}
          onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
          placeholder={t('pages.identityProviders.form.clientIdPlaceholder')}
        />
      </div>
      <div>
        <Label htmlFor="client_secret">{t('pages.identityProviders.form.clientSecret')}</Label>
        <SecretField
          id="client_secret"
          mode={editModal ? 'edit' : 'create'}
          value={formData.client_secret}
          onChange={(v, changed) => setFormData({ ...formData, client_secret: v, client_secret_changed: changed })}
          placeholder={t('pages.identityProviders.form.clientSecretPlaceholder')}
        />
      </div>
      <div>
        <Label htmlFor="scopes">{t('pages.identityProviders.form.scopes')}</Label>
        <Input
          id="scopes"
          value={formData.scopes}
          onChange={(e) => setFormData({ ...formData, scopes: e.target.value })}
          placeholder="openid, profile, email"
        />
      </div>
      <div className="flex items-center gap-2">
        <Switch
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
        />
        <Label>{t('pages.identityProviders.form.enabled')}</Label>
      </div>
      <div className="flex justify-end gap-2 pt-4">
        <Button variant="outline" onClick={() => { setAddModal(false); setEditModal(false) }}>
          {t('common.cancel')}
        </Button>
        <Button onClick={handleFormSubmit} disabled={createMutation.isPending || updateMutation.isPending}>
          {editModal ? t('pages.identityProviders.form.update') : t('pages.identityProviders.form.create')}
        </Button>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('nav.items.identityProviders')}</h1>
        <Button onClick={handleAdd}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.identityProviders.addProvider')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('pages.identityProviders.quickSetup.title')}</CardTitle>
          <CardDescription>
            {t('pages.identityProviders.quickSetup.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {PROVIDER_TEMPLATES.map((template) => {
              const IconComponent = template.id === 'google' ? GoogleIcon
                : template.id === 'github' ? GitHubIcon
                : template.id === 'microsoft' ? MicrosoftIcon
                : null
              return (
                <button
                  key={template.id}
                  onClick={() => handleQuickSetup(template)}
                  className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:border-blue-400 hover:bg-blue-50/50 dark:hover:bg-blue-950/20 transition-colors text-left"
                >
                  {IconComponent && <IconComponent className="h-8 w-8" />}
                  <span className="font-medium text-sm">{template.name}</span>
                  <span className="text-xs text-muted-foreground text-center">{t(template.descriptionKey)}</span>
                </button>
              )
            })}
            <button
              onClick={handleAdd}
              className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:border-blue-400 hover:bg-blue-50/50 dark:hover:bg-blue-950/20 transition-colors"
            >
              <KeyRound className="h-8 w-8 text-muted-foreground" />
              <span className="font-medium text-sm">{t('pages.identityProviders.quickSetup.customOidc')}</span>
              <span className="text-xs text-muted-foreground text-center">{t('pages.identityProviders.quickSetup.customOidcDesc')}</span>
            </button>
            <button
              onClick={() => { setSelectedTemplate(null); setFormData({ ...emptyForm, provider_type: 'saml' }); setAddModal(true) }}
              className="flex flex-col items-center gap-2 p-4 border rounded-lg hover:border-blue-400 hover:bg-blue-50/50 dark:hover:bg-blue-950/20 transition-colors"
            >
              <Shield className="h-8 w-8 text-muted-foreground" />
              <span className="font-medium text-sm">{t('pages.identityProviders.quickSetup.customSaml')}</span>
              <span className="text-xs text-muted-foreground text-center">{t('pages.identityProviders.quickSetup.customSamlDesc')}</span>
            </button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('pages.identityProviders.configured.title')}</CardTitle>
          <CardDescription>
            {t('pages.identityProviders.configured.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t('pages.identityProviders.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-10"
              />
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.identityProviders.table.name')}</TableHead>
                <TableHead>{t('pages.identityProviders.table.type')}</TableHead>
                <TableHead>{t('pages.identityProviders.table.issuerUrl')}</TableHead>
                <TableHead>{t('pages.identityProviders.table.enabled')}</TableHead>
                <TableHead>{t('pages.identityProviders.table.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredProviders.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    {t('pages.identityProviders.empty')}
                  </TableCell>
                </TableRow>
              ) : (
                filteredProviders.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell className="font-medium">{provider.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {provider.provider_type.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-xs truncate">{provider.issuer_url}</TableCell>
                    <TableCell>
                      <Badge variant={provider.enabled ? 'default' : 'secondary'}>
                        {provider.enabled ? t('pages.identityProviders.enabled') : t('pages.identityProviders.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleEdit(provider)}>
                            <Edit className="mr-2 h-4 w-4" />
                            {t('pages.directories.menu.edit')}
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDelete(provider)} className="text-red-600">
                            <Trash2 className="mr-2 h-4 w-4" />
                            {t('common.delete')}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>

          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-muted-foreground">
                {t('common.pagination.pageOf', { page: page + 1, pages: Math.ceil(totalCount / PAGE_SIZE) })}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  {t('common.pagination.previous')}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => p + 1)}
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

      {/* Add Provider Dialog */}
      <Dialog open={addModal} onOpenChange={(open) => { setAddModal(open); if (!open) setSelectedTemplate(null) }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {selectedTemplate
                ? t('pages.identityProviders.addDialog.titleTemplate', { name: selectedTemplate.name })
                : t('pages.identityProviders.addDialog.title')}
            </DialogTitle>
            {selectedTemplate && (
              <a
                href={selectedTemplate.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
              >
                {t('pages.identityProviders.addDialog.setupGuide')} <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Edit Provider Dialog */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.identityProviders.editDialog.title')}</DialogTitle>
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Delete Provider Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('common.areYouSure')}</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? t('pages.identityProviders.deleteDialog.description', { name: deleteTarget.name }) : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
