import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Plus, Pencil, Trash2, ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ApprovalPolicy {
  id: string
  name: string
  resource_type: string
  resource_id?: string
  approval_steps: Record<string, unknown>[]
  max_wait_hours: number
  enabled: boolean
  created_at: string
  updated_at: string
}

export function ApprovalPoliciesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [editOpen, setEditOpen] = useState(false)
  const [editPolicy, setEditPolicy] = useState<ApprovalPolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ApprovalPolicy | null>(null)

  const [form, setForm] = useState({
    name: '',
    resource_type: 'role',
    max_wait_hours: 72,
    enabled: true,
    approval_steps: '[]',
  })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['approval-policies'],
    queryFn: () => api.get<{ policies: ApprovalPolicy[] }>('/api/v1/governance/approval-policies'),
  })
  const policies = data?.policies || []

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/governance/approval-policies', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approval-policies'] })
      toast({ title: editPolicy ? t('pages.approvalPolicies.toasts.updated') : t('pages.approvalPolicies.toasts.created') })
      setEditOpen(false)
    },
    onError: () => toast({ title: t('pages.approvalPolicies.toasts.saveFailed'), variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.put(`/api/v1/governance/approval-policies/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approval-policies'] })
      toast({ title: t('pages.approvalPolicies.toasts.updated') })
      setEditOpen(false)
    },
    onError: () => toast({ title: t('pages.approvalPolicies.toasts.updateFailed'), variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/approval-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approval-policies'] })
      toast({ title: t('pages.approvalPolicies.toasts.deleted') })
      setDeleteTarget(null)
    },
  })

  const openCreate = () => {
    setEditPolicy(null)
    setForm({ name: '', resource_type: 'role', max_wait_hours: 72, enabled: true, approval_steps: '[]' })
    setEditOpen(true)
  }

  const openEdit = (p: ApprovalPolicy) => {
    setEditPolicy(p)
    setForm({
      name: p.name,
      resource_type: p.resource_type,
      max_wait_hours: p.max_wait_hours,
      enabled: p.enabled,
      approval_steps: JSON.stringify(p.approval_steps || [], null, 2),
    })
    setEditOpen(true)
  }

  const handleSave = () => {
    let steps: Record<string, unknown>[]
    try {
      steps = JSON.parse(form.approval_steps)
    } catch {
      toast({ title: t('pages.approvalPolicies.toasts.invalidJson'), variant: 'destructive' })
      return
    }

    const body = {
      name: form.name,
      resource_type: form.resource_type,
      max_wait_hours: form.max_wait_hours,
      enabled: form.enabled,
      approval_steps: steps,
    }

    if (editPolicy) {
      updateMutation.mutate({ id: editPolicy.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const formatDate = (d: string) => new Date(d).toLocaleDateString()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.approvalPolicies')}</h1>
          <p className="text-muted-foreground">{t('pages.approvalPolicies.subtitle')}</p>
        </div>
        <Button onClick={openCreate}><Plus className="mr-2 h-4 w-4" />{t('pages.approvalPolicies.createPolicy')}</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" />{t('pages.approvalPolicies.cardTitle')}</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? <p className="text-center py-8 text-muted-foreground">{t('pages.approvalPolicies.loading')}</p> :
           isError ? <QueryError error={error} resource={t('pages.approvalPolicies.resourceName')} /> :
           policies.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.approvalPolicies.empty')}</p> : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>{t('pages.approvalPolicies.table.name')}</TableHead><TableHead>{t('pages.approvalPolicies.table.resourceType')}</TableHead>
                <TableHead>{t('pages.approvalPolicies.table.steps')}</TableHead><TableHead>{t('pages.approvalPolicies.table.maxWait')}</TableHead>
                <TableHead>{t('pages.approvalPolicies.table.status')}</TableHead><TableHead>{t('pages.approvalPolicies.table.created')}</TableHead><TableHead>{t('pages.approvalPolicies.table.actions')}</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {policies.map(p => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.name}</TableCell>
                    <TableCell><Badge variant="outline">{p.resource_type}</Badge></TableCell>
                    <TableCell>{t('pages.approvalPolicies.stepCount', { n: p.approval_steps?.length || 0 })}</TableCell>
                    <TableCell>{t('pages.approvalPolicies.waitHours', { n: p.max_wait_hours })}</TableCell>
                    <TableCell>
                      <Badge variant={p.enabled ? 'default' : 'secondary'}>
                        {p.enabled ? t('pages.approvalPolicies.enabled') : t('pages.approvalPolicies.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatDate(p.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(p)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(p)}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Dialog */}
      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>{editPolicy ? t('pages.approvalPolicies.dialog.editTitle') : t('pages.approvalPolicies.dialog.createTitle')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.approvalPolicies.dialog.name')}</label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder={t('pages.approvalPolicies.dialog.namePlaceholder')} />
            </div>
            <div>
              <label htmlFor="approval-policies-resource-type" className="text-sm font-medium">{t('pages.approvalPolicies.dialog.resourceType')}</label>
              <Select value={form.resource_type} onValueChange={v => setForm(p => ({ ...p, resource_type: v }))}>
                <SelectTrigger id="approval-policies-resource-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="role">{t('pages.approvalPolicies.dialog.typeRole')}</SelectItem>
                  <SelectItem value="group">{t('pages.approvalPolicies.dialog.typeGroup')}</SelectItem>
                  <SelectItem value="application">{t('pages.approvalPolicies.dialog.typeApplication')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label htmlFor="approval-policies-max-wait-hours" className="text-sm font-medium">{t('pages.approvalPolicies.dialog.maxWaitHours')}</label>
              <Input id="approval-policies-max-wait-hours" type="number" value={form.max_wait_hours}
                onChange={e => setForm(p => ({ ...p, max_wait_hours: parseInt(e.target.value) || 72 }))} />
            </div>
            <div>
              <label htmlFor="approval-policies-steps" className="text-sm font-medium">{t('pages.approvalPolicies.dialog.steps')}</label>
              <textarea id="approval-policies-steps" className="w-full rounded-md border p-2 font-mono text-sm" rows={4}
                value={form.approval_steps}
                onChange={e => setForm(p => ({ ...p, approval_steps: e.target.value }))} />
              <p className="text-xs text-muted-foreground mt-1">
                Example: [{"{"}"approver_id": "user-uuid", "role": "manager"{"}"}]
              </p>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={form.enabled}
                onChange={e => setForm(p => ({ ...p, enabled: e.target.checked }))} />
              {t('pages.approvalPolicies.dialog.enabled')}
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditOpen(false)}>{t('common.cancel')}</Button>
            <Button disabled={!form.name || createMutation.isPending || updateMutation.isPending}
              onClick={handleSave}>
              {editPolicy ? t('pages.approvalPolicies.dialog.update') : t('pages.approvalPolicies.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.approvalPolicies.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.approvalPolicies.deleteDialog.description', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
