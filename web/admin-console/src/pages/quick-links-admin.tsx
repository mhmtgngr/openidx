import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Link2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { api, QuickLink, QuickLinkInput } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

/**
 * The category is stored as written, so these are wire values: the select
 * and the row badge both resolve their label from one catalog map keyed by
 * the stored string, with the raw value as the fallback.
 */
const CATEGORIES = ['Support', 'Collaboration', 'Monitoring', 'IT', 'Other']
/** Role names are the JWT's own vocabulary and render as they are stored. */
const ROLES = ['user', 'operator', 'admin', 'super_admin']
/** lucide icon identifiers, not prose. */
const ICONS = ['Link2', 'Video', 'MessageSquare', 'Headphones', 'LifeBuoy', 'Monitor', 'Server', 'Ticket', 'Globe', 'Mail', 'Phone', 'Terminal']

const emptyForm: QuickLinkInput = {
  title: '', description: '', category: 'Support', icon: 'Link2',
  type: 'external', url: '', pam_entry_id: '', min_role: 'user',
  sort_order: 0, enabled: true, open_in_new: true,
}

export function QuickLinksAdminPage() {
  const qc = useQueryClient()
  const { t } = useTranslation()
  const { toast } = useToast()
  const [showDialog, setShowDialog] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<QuickLinkInput>(emptyForm)
  const [deleteLink, setDeleteLink] = useState<QuickLink | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['quick-links-admin'],
    queryFn: () => api.quickLinks.list(),
  })
  // PAM entries to reference for type='pam' links (session entries only).
  const { data: pamData } = useQuery({
    queryKey: ['pam-entries-for-quicklinks'],
    queryFn: () => api.pam.listEntries(),
  })
  const sessionEntries = (pamData?.entries || []).filter((e) => e.kind === 'session')

  const invalidate = () => qc.invalidateQueries({ queryKey: ['quick-links-admin'] })

  const save = useMutation({
    mutationFn: async () => {
      if (editingId) return api.quickLinks.update(editingId, form)
      await api.quickLinks.create(form)
      return { status: 'created' }
    },
    onSuccess: () => {
      invalidate()
      setShowDialog(false)
      toast({
        title: editingId
          ? t('pages.quickLinks.toasts.updated')
          : t('pages.quickLinks.toasts.created'),
      })
    },
    onError: (e: Error) =>
      toast({
        title: t('pages.quickLinks.toasts.saveFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.quickLinks.remove(id),
    onSuccess: () => {
      invalidate()
      setDeleteLink(null)
      toast({ title: t('pages.quickLinks.toasts.deleted') })
    },
    onError: (e: Error) =>
      toast({
        title: t('pages.quickLinks.toasts.deleteFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const openCreate = () => { setEditingId(null); setForm(emptyForm); setShowDialog(true) }
  const openEdit = (l: QuickLink) => {
    setEditingId(l.id)
    setForm({
      title: l.title, description: l.description, category: l.category, icon: l.icon,
      type: l.type, url: l.url, pam_entry_id: l.pam_entry_id, min_role: l.min_role,
      sort_order: l.sort_order, enabled: l.enabled, open_in_new: l.open_in_new,
    })
    setShowDialog(true)
  }

  const links = data?.quick_links || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.quickLinks')}</h1>
          <p className="text-muted-foreground">{t('pages.quickLinks.subtitle')}</p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="h-4 w-4 mr-1" /> {t('pages.quickLinks.add')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('pages.quickLinks.allTitle')}</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-center py-8 text-muted-foreground">
              {t('pages.quickLinks.loading')}
            </p>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.quickLinks.resource')} />
          ) : links.length === 0 ? (
            <div className="text-center py-8">
              <Link2 className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
              <p className="font-medium">{t('pages.quickLinks.emptyTitle')}</p>
              <p className="text-sm text-muted-foreground">
                {t('pages.quickLinks.emptyHint')}
              </p>
            </div>
          ) : (
            <div className="divide-y">
              {links.map((l) => (
                <div key={l.id} className="flex items-center gap-3 py-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">{l.title}</span>
                      <Badge variant={l.type === 'pam' ? 'secondary' : 'outline'} className="text-xs">
                        {t(`pages.quickLinks.types.${l.type}`, { defaultValue: l.type })}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {t(`pages.quickLinks.categories.${l.category}`, {
                          defaultValue: l.category,
                        })}
                      </Badge>
                      {!l.enabled && (
                        <Badge variant="destructive" className="text-xs">
                          {t('pages.quickLinks.disabled')}
                        </Badge>
                      )}
                      {/* The role is a wire value the token carries. */}
                      <Badge variant="outline" className="text-xs">≥ {l.min_role}</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground truncate">
                      {l.type === 'external'
                        ? l.url
                        : t('pages.quickLinks.pamTarget', { id: l.pam_entry_id || '' })}
                    </p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => openEdit(l)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="sm" variant="ghost" onClick={() => setDeleteLink(l)}><Trash2 className="h-4 w-4 text-red-500" /></Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / edit dialog */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingId
                ? t('pages.quickLinks.dialog.editTitle')
                : t('pages.quickLinks.dialog.addTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium">{t('pages.quickLinks.dialog.title')}</label>
              {/* A sample of what belongs in the field, not prose. */}
              <Input value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} placeholder="Microsoft Teams" />
            </div>
            <div>
              <label htmlFor="quick-links-admin-description" className="text-sm font-medium">
                {t('pages.quickLinks.dialog.description')}
              </label>
              <Textarea id="quick-links-admin-description" value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="quick-links-admin-type" className="text-sm font-medium">{t('pages.quickLinks.dialog.type')}</label>
                <Select value={form.type} onValueChange={(v) => setForm((f) => ({ ...f, type: v as 'external' | 'pam' }))}>
                  <SelectTrigger id="quick-links-admin-type"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="external">{t('pages.quickLinks.typeOptions.external')}</SelectItem>
                    <SelectItem value="pam">{t('pages.quickLinks.typeOptions.pam')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label htmlFor="quick-links-admin-category" className="text-sm font-medium">{t('pages.quickLinks.dialog.category')}</label>
                <Select value={form.category} onValueChange={(v) => setForm((f) => ({ ...f, category: v }))}>
                  <SelectTrigger id="quick-links-admin-category"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {t(`pages.quickLinks.categories.${c}`, { defaultValue: c })}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {form.type === 'external' ? (
              <div>
                <label className="text-sm font-medium">{t('pages.quickLinks.dialog.url')}</label>
                {/* Another sample value, so it stays as typed. */}
                <Input value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder="https://teams.microsoft.com" />
              </div>
            ) : (
              <div>
                <label htmlFor="quick-links-admin-pam-connection" className="text-sm font-medium">
                  {t('pages.quickLinks.dialog.pamConnection')}
                </label>
                <Select value={form.pam_entry_id || ''} onValueChange={(v) => setForm((f) => ({ ...f, pam_entry_id: v }))}>
                  <SelectTrigger id="quick-links-admin-pam-connection">
                    <SelectValue placeholder={t('pages.quickLinks.dialog.selectConnection')} />
                  </SelectTrigger>
                  <SelectContent>
                    {sessionEntries.map((e) => (
                      <SelectItem key={e.id} value={e.id}>{e.name} ({e.entry_type})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="quick-links-admin-icon" className="text-sm font-medium">{t('pages.quickLinks.dialog.icon')}</label>
                <Select value={form.icon} onValueChange={(v) => setForm((f) => ({ ...f, icon: v }))}>
                  <SelectTrigger id="quick-links-admin-icon"><SelectValue /></SelectTrigger>
                  <SelectContent>{ICONS.map((i) => <SelectItem key={i} value={i}>{i}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              <div>
                <label htmlFor="quick-links-admin-min-role" className="text-sm font-medium">
                  {t('pages.quickLinks.dialog.minRole')}
                </label>
                <Select value={form.min_role} onValueChange={(v) => setForm((f) => ({ ...f, min_role: v }))}>
                  <SelectTrigger id="quick-links-admin-min-role"><SelectValue /></SelectTrigger>
                  <SelectContent>{ROLES.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap gap-4 pt-1">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.enabled} onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: !!v }))} />
                {t('pages.quickLinks.dialog.enabled')}
              </label>
              {form.type === 'external' && (
                <label htmlFor="quick-links-admin-checkbox-checked-on-checked-change" className="flex items-center gap-2 text-sm">
                  <Checkbox checked={form.open_in_new} onCheckedChange={(v) => setForm((f) => ({ ...f, open_in_new: !!v }))} />
                  {t('pages.quickLinks.dialog.openInNew')}
                </label>
              )}
              <div className="flex items-center gap-2 text-sm">
                <span>{t('pages.quickLinks.dialog.sort')}</span>
                <Input id="quick-links-admin-checkbox-checked-on-checked-change" type="number" className="w-20 h-8" value={form.sort_order} onChange={(e) => setForm((f) => ({ ...f, sort_order: Number(e.target.value) }))} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDialog(false)}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending || !form.title}>
              {editingId ? t('pages.quickLinks.dialog.save') : t('pages.quickLinks.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteLink} onOpenChange={(o) => { if (!o) setDeleteLink(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.quickLinks.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.quickLinks.deleteBody', { title: deleteLink?.title ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteLink && del.mutate(deleteLink.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
