import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Search, Plus, Pencil, Trash2, Download, ShieldCheck, ToggleLeft, ToggleRight,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface SAMLServiceProvider {
  id: string
  name: string
  entity_id: string
  acs_url: string
  slo_url?: string
  name_id_format: string
  certificate: string
  enabled: boolean
  created_at: string
  updated_at: string
}

// Labels resolve through i18n; the keys are pinned in i18n.test.ts because the
// `typeof en` check cannot see keys held in a runtime map.
const NAME_ID_FORMATS = [
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', labelKey: 'pages.samlProviders.formats.email' },
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', labelKey: 'pages.samlProviders.formats.unspecified' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', labelKey: 'pages.samlProviders.formats.persistent' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', labelKey: 'pages.samlProviders.formats.transient' },
]

interface SPFormState {
  name: string
  entity_id: string
  acs_url: string
  slo_url: string
  name_id_format: string
  certificate: string
}

const emptyForm: SPFormState = {
  name: '',
  entity_id: '',
  acs_url: '',
  slo_url: '',
  name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  certificate: '',
}

export function SAMLServiceProvidersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')

  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<SAMLServiceProvider | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SAMLServiceProvider | null>(null)
  const [form, setForm] = useState<SPFormState>(emptyForm)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['saml-service-providers', search],
    queryFn: () =>
      api.get<{ service_providers: SAMLServiceProvider[] }>(
        `/api/v1/saml/service-providers?search=${encodeURIComponent(search)}`
      ),
  })

  const providers = data?.service_providers || []

  const filteredProviders = providers.filter((sp) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      sp.name.toLowerCase().includes(q) ||
      sp.entity_id.toLowerCase().includes(q) ||
      sp.acs_url.toLowerCase().includes(q)
    )
  })

  const createMutation = useMutation({
    mutationFn: (body: SPFormState) =>
      api.post('/api/v1/saml/service-providers', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setCreateOpen(false)
      setForm(emptyForm)
      toast({ title: t('pages.samlProviders.toasts.created') })
    },
    onError: () => {
      toast({ title: t('pages.samlProviders.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: SPFormState }) =>
      api.put(`/api/v1/saml/service-providers/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setEditTarget(null)
      setForm(emptyForm)
      toast({ title: t('pages.samlProviders.toasts.updated') })
    },
    onError: () => {
      toast({ title: t('pages.samlProviders.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/saml/service-providers/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setDeleteTarget(null)
      toast({ title: t('pages.samlProviders.toasts.deleted') })
    },
    onError: () => {
      toast({ title: t('pages.samlProviders.toasts.deleteFailed'), variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/saml/service-providers/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      toast({ title: t('pages.samlProviders.toasts.statusUpdated') })
    },
    onError: () => {
      toast({ title: t('pages.samlProviders.toasts.statusFailed'), variant: 'destructive' })
    },
  })

  function openCreate() {
    setForm(emptyForm)
    setCreateOpen(true)
  }

  function openEdit(sp: SAMLServiceProvider) {
    setForm({
      name: sp.name,
      entity_id: sp.entity_id,
      acs_url: sp.acs_url,
      slo_url: sp.slo_url || '',
      name_id_format: sp.name_id_format,
      certificate: sp.certificate,
    })
    setEditTarget(sp)
  }

  async function downloadIdPMetadata() {
    try {
      const metadata = await api.get<string>('/saml/idp/metadata', {
        responseType: 'text',
        headers: { Accept: 'application/xml' },
      })
      const blob = new Blob([metadata as unknown as string], { type: 'application/xml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'idp-metadata.xml'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast({ title: t('pages.samlProviders.toasts.metadataDownloaded') })
    } catch {
      toast({ title: t('pages.samlProviders.toasts.metadataFailed'), variant: 'destructive' })
    }
  }

  function formatNameIdLabel(format: string): string {
    const found = NAME_ID_FORMATS.find((f) => f.value === format)
    return found ? t(found.labelKey) : format.split(':').pop() || format
  }

  const isFormValid = form.name.trim() && form.entity_id.trim() && form.acs_url.trim()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.samlProviders.title')}</h1>
          <p className="text-muted-foreground">
            {t('pages.samlProviders.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={downloadIdPMetadata}>
            <Download className="mr-2 h-4 w-4" />
            {t('pages.samlProviders.downloadMetadata')}
          </Button>
          <Button onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            {t('pages.samlProviders.addProvider')}
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t('pages.samlProviders.searchPlaceholder')}
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">{t('pages.samlProviders.loading')}</p>
        </div>
      ) : isError ? (
        <QueryError error={error} resource={t('pages.samlProviders.resourceName')} />
      ) : filteredProviders.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <ShieldCheck className="h-12 w-12 text-muted-foreground/40 mb-3" />
          <p className="font-medium">{t('pages.samlProviders.empty')}</p>
          <p className="text-sm">{t('pages.samlProviders.emptyHint')}</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('pages.samlProviders.registered', { n: filteredProviders.length })}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.samlProviders.table.name')}</TableHead>
                  <TableHead>{t('pages.samlProviders.table.entityId')}</TableHead>
                  <TableHead>{t('pages.samlProviders.table.acsUrl')}</TableHead>
                  <TableHead>{t('pages.samlProviders.table.nameIdFormat')}</TableHead>
                  <TableHead>{t('pages.samlProviders.table.status')}</TableHead>
                  <TableHead>{t('pages.samlProviders.table.created')}</TableHead>
                  <TableHead className="text-right">{t('pages.samlProviders.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredProviders.map((sp) => (
                  <TableRow key={sp.id}>
                    <TableCell className="font-medium">{sp.name}</TableCell>
                    <TableCell>
                      <span className="font-mono text-xs max-w-[200px] truncate block" title={sp.entity_id}>
                        {sp.entity_id}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs max-w-[200px] truncate block" title={sp.acs_url}>
                        {sp.acs_url}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {formatNameIdLabel(sp.name_id_format)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          sp.enabled
                            ? 'bg-green-100 text-green-800 hover:bg-green-100'
                            : 'bg-muted text-foreground hover:bg-muted'
                        }
                      >
                        {sp.enabled ? t('pages.samlProviders.enabled') : t('pages.samlProviders.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(sp.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            toggleMutation.mutate({ id: sp.id, enabled: !sp.enabled })
                          }
                          title={sp.enabled ? t('pages.samlProviders.disable') : t('pages.samlProviders.enable')}
                        >
                          {sp.enabled ? (
                            <ToggleRight className="h-4 w-4 text-green-600" />
                          ) : (
                            <ToggleLeft className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEdit(sp)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(sp)}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.samlProviders.createDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('pages.samlProviders.createDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <SPForm form={form} setForm={setForm} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              disabled={!isFormValid || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {createMutation.isPending ? t('pages.samlProviders.createDialog.creating') : t('pages.samlProviders.createDialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editTarget} onOpenChange={(open) => !open && setEditTarget(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.samlProviders.editDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('pages.samlProviders.editDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <SPForm form={form} setForm={setForm} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              disabled={!isFormValid || updateMutation.isPending}
              onClick={() =>
                editTarget && updateMutation.mutate({ id: editTarget.id, body: form })
              }
            >
              {updateMutation.isPending ? t('pages.samlProviders.editDialog.saving') : t('pages.samlProviders.editDialog.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.samlProviders.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.samlProviders.deleteDialog.description', { name: deleteTarget?.name ?? '' })}
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
    </div>
  )
}

function SPForm({
  form,
  setForm,
}: {
  form: SPFormState
  setForm: React.Dispatch<React.SetStateAction<SPFormState>>
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <div>
        <label className="text-sm font-medium">{t('pages.samlProviders.form.name')}</label>
        <Input
          placeholder={t('pages.samlProviders.form.namePlaceholder')}
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">{t('pages.samlProviders.form.entityId')}</label>
        <Input
          placeholder="https://app.example.com/saml/metadata"
          value={form.entity_id}
          onChange={(e) => setForm((f) => ({ ...f, entity_id: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">{t('pages.samlProviders.form.acsUrl')}</label>
        <Input
          placeholder="https://app.example.com/saml/acs"
          value={form.acs_url}
          onChange={(e) => setForm((f) => ({ ...f, acs_url: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">{t('pages.samlProviders.form.sloUrl')}</label>
        <Input
          placeholder="https://app.example.com/saml/slo"
          value={form.slo_url}
          onChange={(e) => setForm((f) => ({ ...f, slo_url: e.target.value }))}
        />
      </div>
      <div>
        <label htmlFor="saml-service-providers-name-id-format" className="text-sm font-medium">{t('pages.samlProviders.form.nameIdFormat')}</label>
        <Select
          value={form.name_id_format}
          onValueChange={(value) => setForm((f) => ({ ...f, name_id_format: value }))}
        >
          <SelectTrigger id="saml-service-providers-name-id-format" className="mt-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {NAME_ID_FORMATS.map((fmt) => (
              <SelectItem key={fmt.value} value={fmt.value}>
                {t(fmt.labelKey)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div>
        <label className="text-sm font-medium">{t('pages.samlProviders.form.certificate')}</label>
        <Textarea
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          className="font-mono text-xs"
          rows={5}
          value={form.certificate}
          onChange={(e) => setForm((f) => ({ ...f, certificate: e.target.value }))}
        />
        <p className="text-xs text-muted-foreground mt-1">
          {t('pages.samlProviders.form.certificateHint')}
        </p>
      </div>
    </div>
  )
}
