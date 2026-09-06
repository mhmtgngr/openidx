import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Building2, Plus, Users, Pencil, Trash2 } from 'lucide-react'
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
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'

interface Organization {
  id: string
  name: string
  slug: string
  domain?: string
  plan: string
  status: string
  max_users: number
  max_applications: number
  member_count: number
  created_at: string
  updated_at: string
}

/**
 * The plan and the member role each render lowercase on a badge and title
 * case in a form select. Each shape has its own catalog map, both keyed off
 * the list below so the two cannot come to offer different members.
 */
const PLANS = ['free', 'team', 'enterprise'] as const
const MEMBER_ROLES = ['member', 'admin', 'owner'] as const

interface OrgMember {
  id: string
  organization_id: string
  user_id: string
  role: string
  joined_at: string
  user_email: string
  user_name: string
}

export function OrganizationsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [createOpen, setCreateOpen] = useState(false)
  const [editOrg, setEditOrg] = useState<Organization | null>(null)
  const [membersOrg, setMembersOrg] = useState<Organization | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Organization | null>(null)
  const [addMemberOpen, setAddMemberOpen] = useState(false)

  const [form, setForm] = useState({ name: '', slug: '', plan: 'free', max_users: 10, max_applications: 5 })
  const [memberForm, setMemberForm] = useState({ user_id: '', role: 'member' })

  // The backend returns a bare JSON array with an X-Total-Count header (the
  // convention across list endpoints), not a wrapped { organizations, total }
  // object — reading a wrapper key left the org list permanently empty.
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => api.get<Organization[]>('/api/v1/organizations'),
  })
  const orgs = data || []

  const { data: membersData } = useQuery({
    queryKey: ['org-members', membersOrg?.id],
    queryFn: () => api.get<OrgMember[]>(`/api/v1/organizations/${membersOrg!.id}/members`),
    enabled: !!membersOrg,
  })
  const members = membersData || []

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/organizations', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: t('pages.organizations.toasts.created') })
      setCreateOpen(false)
    },
    onError: () =>
      toast({
        title: t('pages.organizations.toasts.createFailed'),
        variant: 'destructive',
      }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.put(`/api/v1/organizations/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: t('pages.organizations.toasts.updated') })
      setEditOrg(null)
    },
    onError: () =>
      toast({
        title: t('pages.organizations.toasts.updateFailed'),
        variant: 'destructive',
      }),
  })

  const addMemberMutation = useMutation({
    mutationFn: ({ orgId, body }: { orgId: string; body: Record<string, unknown> }) =>
      api.post(`/api/v1/organizations/${orgId}/members`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-members', membersOrg?.id] })
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: t('pages.organizations.toasts.memberAdded') })
      setAddMemberOpen(false)
    },
    onError: () =>
      toast({
        title: t('pages.organizations.toasts.memberAddFailed'),
        variant: 'destructive',
      }),
  })

  const removeMemberMutation = useMutation({
    mutationFn: ({ orgId, userId }: { orgId: string; userId: string }) =>
      api.delete(`/api/v1/organizations/${orgId}/members/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-members', membersOrg?.id] })
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: t('pages.organizations.toasts.memberRemoved') })
    },
  })

  const openCreate = () => {
    setEditOrg(null)
    setForm({ name: '', slug: '', plan: 'free', max_users: 10, max_applications: 5 })
    setCreateOpen(true)
  }

  const openEdit = (org: Organization) => {
    setEditOrg(org)
    setForm({ name: org.name, slug: org.slug, plan: org.plan, max_users: org.max_users, max_applications: org.max_applications })
    setCreateOpen(true)
  }

  const handleSave = () => {
    if (editOrg) {
      updateMutation.mutate({ id: editOrg.id, body: { name: form.name, plan: form.plan, status: editOrg.status } })
    } else {
      createMutation.mutate(form)
    }
  }

  const planColor = (plan: string) => {
    switch (plan) {
      case 'enterprise': return 'default'
      case 'team': return 'secondary'
      default: return 'outline'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.organizations')}</h1>
          <p className="text-muted-foreground">{t('pages.organizations.subtitle')}</p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t('pages.organizations.create')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Building2 className="h-5 w-5" />
            {t('pages.organizations.listTitle')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">
                {t('pages.organizations.loading')}
              </p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.organizations.resource')} />
          ) : orgs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Building2 className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.organizations.emptyTitle')}</p>
              <p className="text-sm">{t('pages.organizations.emptyHint')}</p>
            </div>
          ) : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>{t('pages.organizations.colName')}</TableHead>
                <TableHead>{t('pages.organizations.colSlug')}</TableHead>
                <TableHead>{t('pages.organizations.colPlan')}</TableHead>
                <TableHead>{t('pages.organizations.colStatus')}</TableHead>
                <TableHead>{t('pages.organizations.colMembers')}</TableHead>
                <TableHead>{t('pages.organizations.colCreated')}</TableHead>
                <TableHead>{t('pages.organizations.colActions')}</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {orgs.map(org => (
                  <TableRow key={org.id}>
                    <TableCell className="font-medium">{org.name}</TableCell>
                    <TableCell className="text-muted-foreground">/{org.slug}</TableCell>
                    <TableCell>
                      <Badge variant={planColor(org.plan) as 'default' | 'secondary' | 'outline'}>
                        {t(`pages.organizations.plans.${org.plan}`, { defaultValue: org.plan })}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={org.status === 'active' ? 'default' : 'secondary'}>
                        {t(`pages.organizations.statuses.${org.status}`, {
                          defaultValue: org.status,
                        })}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <button className="flex items-center gap-1 text-primary hover:underline" onClick={() => setMembersOrg(org)}>
                        <Users className="h-3 w-3" />{org.member_count}
                      </button>
                    </TableCell>
                    <TableCell>{new Date(org.created_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(org)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(org)}>
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
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editOrg
                ? t('pages.organizations.form.editTitle')
                : t('pages.organizations.form.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.organizations.form.name')}</label>
              <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder={t('pages.organizations.form.namePlaceholder')} />
            </div>
            {!editOrg && (
              <div>
                <label className="text-sm font-medium">{t('pages.organizations.form.slug')}</label>
                {/* The example teaches the characters the field accepts. */}
                <Input value={form.slug} onChange={e => setForm(f => ({ ...f, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') }))} placeholder="org-slug" />
              </div>
            )}
            <div>
              <label htmlFor="organizations-plan" className="text-sm font-medium">{t('pages.organizations.form.plan')}</label>
              <Select value={form.plan} onValueChange={v => setForm(f => ({ ...f, plan: v }))}>
                <SelectTrigger id="organizations-plan"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PLANS.map(plan => (
                    <SelectItem key={plan} value={plan}>
                      {t(`pages.organizations.form.planOptions.${plan}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="organizations-max-users" className="text-sm font-medium">{t('pages.organizations.form.maxUsers')}</label>
                <Input id="organizations-max-users" type="number" value={form.max_users} onChange={e => setForm(f => ({ ...f, max_users: parseInt(e.target.value) || 10 }))} />
              </div>
              <div>
                <label htmlFor="organizations-max-applications" className="text-sm font-medium">
                  {t('pages.organizations.form.maxApplications')}
                </label>
                <Input id="organizations-max-applications" type="number" value={form.max_applications} onChange={e => setForm(f => ({ ...f, max_applications: parseInt(e.target.value) || 5 }))} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button disabled={!form.name || createMutation.isPending || updateMutation.isPending} onClick={handleSave}>
              {editOrg
                ? t('pages.organizations.form.update')
                : t('pages.organizations.form.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Members Dialog */}
      <Dialog open={!!membersOrg} onOpenChange={open => { if (!open) setMembersOrg(null) }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {t('pages.organizations.members.title', { org: membersOrg?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex justify-end">
              <Button size="sm" onClick={() => { setMemberForm({ user_id: '', role: 'member' }); setAddMemberOpen(true) }}>
                <Plus className="mr-2 h-4 w-4" />
                {t('pages.organizations.members.add')}
              </Button>
            </div>
            <Table>
              <TableHeader><TableRow>
                <TableHead>{t('pages.organizations.members.colName')}</TableHead>
                <TableHead>{t('pages.organizations.members.colEmail')}</TableHead>
                <TableHead>{t('pages.organizations.members.colRole')}</TableHead>
                <TableHead>{t('pages.organizations.members.colJoined')}</TableHead>
                <TableHead>{t('pages.organizations.members.colActions')}</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {members.map(m => (
                  <TableRow key={m.id}>
                    <TableCell>{m.user_name}</TableCell>
                    <TableCell>{m.user_email}</TableCell>
                    <TableCell>
                      <Badge variant={m.role === 'owner' ? 'default' : 'outline'}>
                        {t(`pages.organizations.members.roles.${m.role}`, {
                          defaultValue: m.role,
                        })}
                      </Badge>
                    </TableCell>
                    <TableCell>{new Date(m.joined_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      {m.role !== 'owner' && (
                        <Button variant="ghost" size="sm" onClick={() => membersOrg && removeMemberMutation.mutate({ orgId: membersOrg.id, userId: m.user_id })}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </DialogContent>
      </Dialog>

      {/* Add Member Dialog */}
      <Dialog open={addMemberOpen} onOpenChange={setAddMemberOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.organizations.members.addTitle')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.organizations.members.userId')}</label>
              <Input value={memberForm.user_id} onChange={e => setMemberForm(f => ({ ...f, user_id: e.target.value }))} placeholder={t('pages.organizations.members.userIdPlaceholder')} />
            </div>
            <div>
              <label htmlFor="organizations-role" className="text-sm font-medium">{t('pages.organizations.members.role')}</label>
              <Select value={memberForm.role} onValueChange={v => setMemberForm(f => ({ ...f, role: v }))}>
                <SelectTrigger id="organizations-role"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {MEMBER_ROLES.map(role => (
                    <SelectItem key={role} value={role}>
                      {t(`pages.organizations.members.roleOptions.${role}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddMemberOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button disabled={!memberForm.user_id} onClick={() => membersOrg && addMemberMutation.mutate({ orgId: membersOrg.id, body: memberForm })}>
              {t('pages.organizations.members.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.organizations.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.organizations.deleteDialog.desc', {
                name: deleteTarget?.name ?? '',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteTarget && api.delete(`/api/v1/organizations/${deleteTarget.id}`).then(() => {
              queryClient.invalidateQueries({ queryKey: ['organizations'] })
              toast({ title: t('pages.organizations.toasts.deleted') })
              setDeleteTarget(null)
            })}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
