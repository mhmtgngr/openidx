import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Building2, Copy, MoreHorizontal, Plus, UserPlus, Users } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { TableSkeleton } from '../components/ui/skeleton'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// External (vendor) accounts, their invitations and their vendor
// organizations: the console half of Phase 1 of the third-party access
// framework. Every value shown here is the one the identity service enforces
// (GET /external-users, /invitations, /vendor-orgs); every change goes through
// the route that checks it, with the reason the route requires.

export interface ExternalUser {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
  status: string
  enabled: boolean
  vendor_org_id: string
  vendor_name: string
  sponsor_user_id?: string
  sponsor_name: string
  account_expires_at?: string
  status_changed_at?: string
  last_login_at?: string
  created_at: string
  expiring_soon: boolean
  has_strong_factor: boolean
  reactivate_until?: string
}

export interface VendorOrg {
  id: string
  name: string
  status: string
  contact_name: string
  contact_email: string
  contract_start?: string | null
  contract_end?: string | null
  allowed_email_domains: string[] | null
  default_expiry_days: number
  default_sponsor_user_id: string
  notes: string
  closed_at?: string
  external_users?: Record<string, number>
}

interface Invitation {
  id: string
  email: string
  token: string
  status: string
  expires_at: string
  user_type: string
  vendor_org_id?: string
  sponsor_user_id?: string
  account_expires_at?: string
}

type ApiError = { response?: { data?: { error?: string } }; message?: string }
const apiErrorText = (err: unknown, fallback: string) =>
  (err as ApiError)?.response?.data?.error || fallback

const ACCOUNT_STATUSES = ['pending_mfa', 'active', 'suspended', 'expired', 'disabled'] as const

const accountStatusClass: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  pending_mfa: 'bg-amber-100 text-amber-800',
  suspended: 'bg-orange-100 text-orange-800',
  expired: 'bg-gray-200 text-gray-800',
  disabled: 'bg-red-100 text-red-800',
}

const vendorStatusClass: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  suspended: 'bg-amber-100 text-amber-800',
  closed: 'bg-gray-200 text-gray-800',
}

const formatDate = (s?: string | null) => (s ? new Date(s).toLocaleDateString() : '—')
const displayName = (u: { first_name?: string; last_name?: string; username: string }) =>
  [u.first_name, u.last_name].filter(Boolean).join(' ') || u.username

const invitationLink = (token: string) => `${window.location.origin}/accept-invite?token=${encodeURIComponent(token)}`

// ---- Sponsor picker ----

interface Candidate { id: string; label: string }

// An enabled internal user of the organization: the only kind the identity
// service accepts as a sponsor (externalid.CheckSponsor). The filter here is a
// convenience; the route refuses anyone else.
function toCandidate(u: Record<string, unknown>): Candidate | null {
  const userType = String(u.userType ?? u.user_type ?? 'internal')
  const enabled = Boolean(u.enabled ?? u.active ?? false)
  if (userType === 'external' || userType === 'service' || !enabled) return null
  const name = (u.name ?? {}) as Record<string, unknown>
  const emails = (u.emails ?? []) as Array<{ value?: string }>
  const username = String(u.userName ?? u.username ?? '')
  const full = [name.givenName, name.familyName].filter(Boolean).join(' ')
  const email = String(emails[0]?.value ?? u.email ?? '')
  return { id: String(u.id ?? ''), label: `${full || username}${email ? ` <${email}>` : ''}` }
}

function SponsorPicker({ id, value, onChange, optional }: {
  id: string
  value: string
  onChange: (v: string) => void
  optional?: boolean
}) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  useEffect(() => {
    const h = setTimeout(() => setDebounced(search.trim()), 250)
    return () => clearTimeout(h)
  }, [search])
  const { data: candidates = [] } = useQuery({
    queryKey: ['sponsor-candidates', debounced],
    queryFn: async () => {
      const params = new URLSearchParams({ offset: '0', limit: '50' })
      if (debounced) params.set('search', debounced)
      const res = await api.getWithHeaders<Record<string, unknown>[]>(`/api/v1/identity/users?${params.toString()}`)
      return (res.data || []).map(toCandidate).filter((c): c is Candidate => c !== null)
    },
  })
  return (
    <div className="space-y-2">
      <Input
        aria-label={t('pages.externalUsers.sponsor.search')}
        placeholder={t('pages.externalUsers.sponsor.search')}
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <select
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
      >
        <option value="">{optional ? t('pages.externalUsers.sponsor.default') : t('pages.externalUsers.sponsor.choose')}</option>
        {value && !candidates.some((c) => c.id === value) && (
          <option value={value}>{t('pages.externalUsers.sponsor.current')}</option>
        )}
        {candidates.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
      </select>
    </div>
  )
}

// ---- The page ----

export function ExternalUsersPage() {
  const { t } = useTranslation()
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.externalUsers')}</h1>
        <p className="text-muted-foreground">{t('pages.externalUsers.subtitle')}</p>
      </div>
      <Tabs defaultValue="accounts">
        <TabsList>
          <TabsTrigger value="accounts">{t('pages.externalUsers.tabs.accounts')}</TabsTrigger>
          <TabsTrigger value="invitations">{t('pages.externalUsers.tabs.invitations')}</TabsTrigger>
          <TabsTrigger value="vendors">{t('pages.externalUsers.tabs.vendors')}</TabsTrigger>
        </TabsList>
        <TabsContent value="accounts"><AccountsTab /></TabsContent>
        <TabsContent value="invitations"><InvitationsTab /></TabsContent>
        <TabsContent value="vendors"><VendorsTab /></TabsContent>
      </Tabs>
    </div>
  )
}

function useVendors() {
  return useQuery({
    queryKey: ['vendor-orgs'],
    queryFn: async () => (await api.get<{ vendor_organizations: VendorOrg[] }>('/api/v1/identity/vendor-orgs')).vendor_organizations ?? [],
  })
}

// ---- Accounts ----

// A row of the account list: the API's view plus what the list derived from it.
type AccountRow = ExternalUser & { reactivatable: boolean }

type AccountDialog =
  | { kind: 'extend'; user: ExternalUser }
  | { kind: 'reactivate'; user: ExternalUser }
  | { kind: 'sponsor'; user: ExternalUser }

function AccountsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [vendorFilter, setVendorFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [dialog, setDialog] = useState<AccountDialog | null>(null)
  const { data: vendors = [] } = useVendors()

  const { data: accounts = [], isLoading, isError, error } = useQuery({
    queryKey: ['external-users', vendorFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (vendorFilter) params.set('vendor_org_id', vendorFilter)
      if (statusFilter) params.set('status', statusFilter)
      const qs = params.toString()
      const res = await api.get<{ external_users: ExternalUser[] }>(`/api/v1/identity/external-users${qs ? `?${qs}` : ''}`)
      // Whether the grace period is still open is read when the list is,
      // not on every render.
      const now = Date.now()
      return (res.external_users ?? []).map((u): AccountRow => ({
        ...u,
        reactivatable: u.status === 'suspended' && !!u.reactivate_until && Date.parse(u.reactivate_until) > now,
      }))
    },
  })

  const change = useMutation({
    mutationFn: ({ user, action, body }: { user: ExternalUser; action: string; body: Record<string, unknown> }) =>
      api.post(`/api/v1/identity/external-users/${user.id}/${action}`, body),
    onSuccess: (_data, { user, action }) => {
      queryClient.invalidateQueries({ queryKey: ['external-users'] })
      queryClient.invalidateQueries({ queryKey: ['vendor-orgs'] })
      toast({
        title: t('common.success'),
        description: t(`pages.externalUsers.toasts.${action}`, { name: displayName(user) }),
        variant: 'success',
      })
      setDialog(null)
    },
    onError: (err) => {
      toast({
        title: t('common.error'),
        description: apiErrorText(err, t('pages.externalUsers.toasts.failed')),
        variant: 'destructive',
      })
    },
  })
  const act = (user: ExternalUser, action: string, body: Record<string, unknown>) =>
    change.mutateAsync({ user, action, body }).catch(() => undefined)

  const live = (u: ExternalUser) => u.status === 'active' || u.status === 'pending_mfa'

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <label htmlFor="xu-vendor-filter" className="text-xs font-medium text-muted-foreground">{t('pages.externalUsers.filters.vendor')}</label>
            <select
              id="xu-vendor-filter"
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
              className="flex h-9 w-56 rounded-md border border-input bg-background px-3 py-1 text-sm"
            >
              <option value="">{t('pages.externalUsers.filters.allVendors')}</option>
              {vendors.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
          </div>
          <div className="space-y-1">
            <label htmlFor="xu-status-filter" className="text-xs font-medium text-muted-foreground">{t('pages.externalUsers.filters.status')}</label>
            <select
              id="xu-status-filter"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="flex h-9 w-44 rounded-md border border-input bg-background px-3 py-1 text-sm"
            >
              <option value="">{t('pages.externalUsers.filters.allStatuses')}</option>
              {ACCOUNT_STATUSES.map((s) => <option key={s} value={s}>{t(`pages.externalUsers.status.${s}`)}</option>)}
            </select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <TableSkeleton rows={6} cols={6} />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.externalUsers.resourceName')} />
        ) : accounts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Users className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.externalUsers.accounts.empty')}</p>
            <p className="text-sm">{t('pages.externalUsers.accounts.emptyHint')}</p>
          </div>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3">{t('pages.externalUsers.accounts.table.account')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.accounts.table.vendor')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.accounts.table.sponsor')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.accounts.table.status')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.accounts.table.ends')}</TableHead>
                  <TableHead className="p-3 text-right">{t('pages.externalUsers.accounts.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.map((u) => (
                  <TableRow key={u.id} className="border-b">
                    <TableCell className="p-3">
                      <p className="font-medium">{displayName(u)}</p>
                      <p className="text-sm text-muted-foreground">{u.email}</p>
                    </TableCell>
                    <TableCell className="p-3">{u.vendor_name}</TableCell>
                    <TableCell className="p-3">{u.sponsor_name || '—'}</TableCell>
                    <TableCell className="p-3">
                      <div className="flex flex-wrap gap-1">
                        <Badge className={accountStatusClass[u.status] ?? ''}>{t(`pages.externalUsers.status.${u.status}`, { defaultValue: u.status })}</Badge>
                        {live(u) && !u.has_strong_factor && (
                          <Badge variant="outline" className="border-amber-300 text-amber-800">{t('pages.externalUsers.accounts.noFactor')}</Badge>
                        )}
                      </div>
                      {u.status === 'suspended' && u.reactivate_until && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {t('pages.externalUsers.accounts.reactivateUntil', { date: formatDate(u.reactivate_until) })}
                        </p>
                      )}
                    </TableCell>
                    <TableCell className="p-3">
                      <span>{formatDate(u.account_expires_at)}</span>
                      {u.expiring_soon && (
                        <Badge variant="outline" className="ml-2 border-amber-300 text-amber-800">{t('pages.externalUsers.accounts.expiringSoon')}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="p-3 text-right">
                      {(live(u) || u.status === 'suspended') && (
                        <AccountActions
                          user={u}
                          live={live(u)}
                          canReactivate={u.reactivatable}
                          onDialog={setDialog}
                          onSuspend={(reason) => act(u, 'suspend', { reason })}
                          onDisable={(reason) => act(u, 'disable', { reason })}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      {dialog?.kind === 'extend' && (
        <ExtendDialog
          user={dialog.user}
          busy={change.isPending}
          onClose={() => setDialog(null)}
          onSubmit={(body) => act(dialog.user, 'extend', body)}
        />
      )}
      {(dialog?.kind === 'reactivate' || dialog?.kind === 'sponsor') && (
        <SponsorDialog
          kind={dialog.kind}
          user={dialog.user}
          busy={change.isPending}
          onClose={() => setDialog(null)}
          onSubmit={(body) => act(dialog.user, dialog.kind, body)}
        />
      )}
    </Card>
  )
}

function AccountActions({ user, live, canReactivate, onDialog, onSuspend, onDisable }: {
  user: ExternalUser
  live: boolean
  canReactivate: boolean
  onDialog: (d: AccountDialog) => void
  onSuspend: (reason?: string) => Promise<unknown>
  onDisable: (reason?: string) => Promise<unknown>
}) {
  const { t } = useTranslation()
  const name = displayName(user)
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('pages.externalUsers.actions.menu', { name })}>
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onDialog({ kind: 'extend', user })}>
          {t('pages.externalUsers.actions.extend')}
        </DropdownMenuItem>
        {live && (
          <DropdownMenuItem onClick={() => onDialog({ kind: 'sponsor', user })}>
            {t('pages.externalUsers.actions.sponsor')}
          </DropdownMenuItem>
        )}
        {canReactivate && (
          <DropdownMenuItem onClick={() => onDialog({ kind: 'reactivate', user })}>
            {t('pages.externalUsers.actions.reactivate')}
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        {live && (
          <ConfirmAction
            title={t('pages.externalUsers.confirm.suspendTitle', { name })}
            description={t('pages.externalUsers.confirm.suspendDescription')}
            confirmLabel={t('pages.externalUsers.actions.suspend')}
            requireReason
            onConfirm={onSuspend}
          >
            {(open) => (
              <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }}>
                {t('pages.externalUsers.actions.suspend')}
              </DropdownMenuItem>
            )}
          </ConfirmAction>
        )}
        <ConfirmAction
          title={t('pages.externalUsers.confirm.disableTitle', { name })}
          description={t('pages.externalUsers.confirm.disableDescription')}
          confirmLabel={t('pages.externalUsers.actions.disable')}
          destructive
          requireReason
          onConfirm={onDisable}
        >
          {(open) => (
            <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }} className="text-red-600">
              {t('pages.externalUsers.actions.disable')}
            </DropdownMenuItem>
          )}
        </ConfirmAction>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ExtendDialog({ user, busy, onClose, onSubmit }: {
  user: ExternalUser
  busy: boolean
  onClose: () => void
  onSubmit: (body: Record<string, unknown>) => Promise<unknown>
}) {
  const { t } = useTranslation()
  const [days, setDays] = useState('30')
  const [reason, setReason] = useState('')
  const n = parseInt(days, 10)
  const valid = Number.isFinite(n) && n > 0 && reason.trim() !== ''
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('pages.externalUsers.extendDialog.title', { name: displayName(user) })}</DialogTitle>
          <DialogDescription>
            {t('pages.externalUsers.extendDialog.description', { date: formatDate(user.account_expires_at) })}
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => { e.preventDefault(); if (valid) void onSubmit({ extend_days: n, reason: reason.trim() }) }}
        >
          <div className="space-y-1">
            <Label htmlFor="xu-extend-days">{t('pages.externalUsers.extendDialog.days')}</Label>
            <Input id="xu-extend-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="xu-extend-reason">{t('pages.externalUsers.reason')}</Label>
            <Textarea id="xu-extend-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!valid || busy}>{t('pages.externalUsers.actions.extend')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function SponsorDialog({ kind, user, busy, onClose, onSubmit }: {
  kind: 'reactivate' | 'sponsor'
  user: ExternalUser
  busy: boolean
  onClose: () => void
  onSubmit: (body: Record<string, unknown>) => Promise<unknown>
}) {
  const { t } = useTranslation()
  const [sponsor, setSponsor] = useState('')
  const [reason, setReason] = useState('')
  const valid = sponsor !== '' && reason.trim() !== ''
  const name = displayName(user)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t(`pages.externalUsers.${kind}Dialog.title`, { name })}</DialogTitle>
          <DialogDescription>{t(`pages.externalUsers.${kind}Dialog.description`, { sponsor: user.sponsor_name || '—' })}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => { e.preventDefault(); if (valid) void onSubmit({ sponsor_user_id: sponsor, reason: reason.trim() }) }}
        >
          <div className="space-y-1">
            <Label htmlFor="xu-new-sponsor">{t('pages.externalUsers.sponsor.label')}</Label>
            <SponsorPicker id="xu-new-sponsor" value={sponsor} onChange={setSponsor} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="xu-sponsor-reason">{t('pages.externalUsers.reason')}</Label>
            <Textarea id="xu-sponsor-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!valid || busy}>{t(`pages.externalUsers.actions.${kind}`)}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Invitations ----

function InvitationsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [inviteOpen, setInviteOpen] = useState(false)
  const { data: vendors = [] } = useVendors()
  const vendorName = (id?: string) => vendors.find((v) => v.id === id)?.name ?? '—'

  const { data: invitations = [], isLoading, isError, error } = useQuery({
    queryKey: ['invitations'],
    queryFn: async () => (await api.get<{ invitations: Invitation[] }>('/api/v1/identity/invitations')).invitations ?? [],
  })
  const external = invitations.filter((i) => i.user_type === 'external')

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/invitations/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] })
      toast({ title: t('common.success'), description: t('pages.externalUsers.toasts.revoked'), variant: 'success' })
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  const copy = async (token: string) => {
    try {
      await navigator.clipboard.writeText(invitationLink(token))
      toast({ title: t('pages.externalUsers.toasts.linkCopied'), variant: 'success' })
    } catch {
      toast({ title: t('common.error'), description: invitationLink(token), variant: 'destructive' })
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">{t('pages.externalUsers.invitations.hint')}</p>
          <Button onClick={() => setInviteOpen(true)}>
            <UserPlus className="mr-2 h-4 w-4" /> {t('pages.externalUsers.invitations.invite')}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <TableSkeleton rows={4} cols={5} />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.externalUsers.invitations.resourceName')} />
        ) : external.length === 0 ? (
          <p className="py-8 text-center text-muted-foreground">{t('pages.externalUsers.invitations.empty')}</p>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3">{t('pages.externalUsers.invitations.table.email')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.invitations.table.vendor')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.invitations.table.status')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.invitations.table.linkExpires')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.invitations.table.accountEnds')}</TableHead>
                  <TableHead className="p-3 text-right">{t('pages.externalUsers.accounts.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {external.map((inv) => (
                  <TableRow key={inv.id} className="border-b">
                    <TableCell className="p-3">{inv.email}</TableCell>
                    <TableCell className="p-3">{vendorName(inv.vendor_org_id)}</TableCell>
                    <TableCell className="p-3">
                      <Badge variant="outline">{t(`pages.externalUsers.invitations.status.${inv.status}`, { defaultValue: inv.status })}</Badge>
                    </TableCell>
                    <TableCell className="p-3">{formatDate(inv.expires_at)}</TableCell>
                    <TableCell className="p-3">{formatDate(inv.account_expires_at)}</TableCell>
                    <TableCell className="p-3 text-right space-x-2">
                      {inv.status === 'pending' && (
                        <>
                          <Button variant="outline" size="sm" onClick={() => void copy(inv.token)}>
                            <Copy className="mr-1 h-3.5 w-3.5" /> {t('pages.externalUsers.invitations.copyLink')}
                          </Button>
                          <ConfirmAction
                            title={t('pages.externalUsers.confirm.revokeTitle', { email: inv.email })}
                            description={t('pages.externalUsers.confirm.revokeDescription')}
                            confirmLabel={t('pages.externalUsers.invitations.revoke')}
                            destructive
                            onConfirm={() => revoke.mutateAsync(inv.id).catch(() => undefined)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" className="text-red-600" onClick={open}>
                                {t('pages.externalUsers.invitations.revoke')}
                              </Button>
                            )}
                          </ConfirmAction>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      {inviteOpen && (
        <InviteDialog
          vendors={vendors.filter((v) => v.status === 'active')}
          onClose={() => setInviteOpen(false)}
          onCopy={copy}
        />
      )}
    </Card>
  )
}

function InviteDialog({ vendors, onClose, onCopy }: {
  vendors: VendorOrg[]
  onClose: () => void
  onCopy: (token: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [email, setEmail] = useState('')
  const [vendor, setVendor] = useState('')
  const [sponsor, setSponsor] = useState('')
  const [days, setDays] = useState('')
  const [groups, setGroups] = useState<string[]>([])
  const [created, setCreated] = useState<{ token: string; email: string } | null>(null)

  // Only the groups an administrator opened to external users (invariant I3);
  // the route refuses any other.
  const { data: openGroups = [] } = useQuery({
    queryKey: ['groups-external-allowed'],
    queryFn: async () => {
      const res = await api.getWithHeaders<Record<string, unknown>[]>('/api/v1/identity/groups?offset=0&limit=100')
      return (res.data || [])
        .filter((g) => ((g.attributes ?? {}) as Record<string, unknown>).externalAllowed === 'true')
        .map((g) => ({ id: String(g.id ?? ''), name: String(g.displayName ?? g.name ?? '') }))
    },
  })

  const invite = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { email: email.trim(), user_type: 'external', vendor_org_id: vendor }
      if (sponsor) body.sponsor_user_id = sponsor
      const n = parseInt(days, 10)
      if (Number.isFinite(n) && n > 0) body.expires_in_days = n
      if (groups.length) body.groups = groups
      return api.post<{ id: string; token: string; email: string }>('/api/v1/identity/invitations', body)
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['invitations'] })
      setCreated({ token: data.token, email: data.email })
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  const valid = email.trim() !== '' && vendor !== ''
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('pages.externalUsers.inviteDialog.title')}</DialogTitle>
          <DialogDescription>{t('pages.externalUsers.inviteDialog.description')}</DialogDescription>
        </DialogHeader>
        {created ? (
          <div className="space-y-4">
            <p className="text-sm">{t('pages.externalUsers.inviteDialog.created', { email: created.email })}</p>
            <Input readOnly aria-label={t('pages.externalUsers.inviteDialog.link')} value={invitationLink(created.token)} />
            <DialogFooter>
              <Button variant="outline" onClick={() => void onCopy(created.token)}>
                <Copy className="mr-2 h-4 w-4" /> {t('pages.externalUsers.invitations.copyLink')}
              </Button>
              <Button onClick={onClose}>{t('pages.externalUsers.inviteDialog.done')}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid) invite.mutate() }}>
            <div className="space-y-1">
              <Label htmlFor="xu-invite-email">{t('pages.externalUsers.inviteDialog.email')}</Label>
              <Input id="xu-invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xu-invite-vendor">{t('pages.externalUsers.inviteDialog.vendor')}</Label>
              <select
                id="xu-invite-vendor"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                <option value="">{t('pages.externalUsers.inviteDialog.chooseVendor')}</option>
                {vendors.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="xu-invite-sponsor">{t('pages.externalUsers.sponsor.label')}</Label>
              <SponsorPicker id="xu-invite-sponsor" value={sponsor} onChange={setSponsor} optional />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xu-invite-days">{t('pages.externalUsers.inviteDialog.days')}</Label>
              <Input
                id="xu-invite-days"
                type="number"
                min={1}
                max={365}
                placeholder={t('pages.externalUsers.inviteDialog.daysPlaceholder')}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </div>
            {openGroups.length > 0 && (
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('pages.externalUsers.inviteDialog.groups')}</legend>
                {openGroups.map((g) => (
                  <label key={g.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={groups.includes(g.id)}
                      onChange={(e) => setGroups((prev) => e.target.checked ? [...prev, g.id] : prev.filter((x) => x !== g.id))}
                    />
                    {g.name}
                  </label>
                ))}
              </fieldset>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={!valid || invite.isPending}>{t('pages.externalUsers.invitations.invite')}</Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ---- Vendor organizations ----

function VendorsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [editing, setEditing] = useState<VendorOrg | 'new' | null>(null)
  const { data: vendors = [], isLoading, isError, error } = useVendors()

  const close = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/identity/vendor-orgs/${id}/close`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-orgs'] })
      queryClient.invalidateQueries({ queryKey: ['external-users'] })
      toast({ title: t('common.success'), description: t('pages.externalUsers.toasts.vendorClosed'), variant: 'success' })
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  const counts = (v: VendorOrg) =>
    Object.entries(v.external_users ?? {})
      .filter(([, n]) => n > 0)
      .map(([s, n]) => `${t(`pages.externalUsers.status.${s}`, { defaultValue: s })}: ${n}`)
      .join(', ') || '—'

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">{t('pages.externalUsers.vendors.hint')}</p>
          <Button onClick={() => setEditing('new')}>
            <Plus className="mr-2 h-4 w-4" /> {t('pages.externalUsers.vendors.create')}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <TableSkeleton rows={4} cols={5} />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.externalUsers.vendors.resourceName')} />
        ) : vendors.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Building2 className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.externalUsers.vendors.empty')}</p>
          </div>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3">{t('pages.externalUsers.vendors.table.name')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.vendors.table.status')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.vendors.table.contract')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.vendors.table.lifetime')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.vendors.table.accounts')}</TableHead>
                  <TableHead className="p-3 text-right">{t('pages.externalUsers.accounts.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vendors.map((v) => (
                  <TableRow key={v.id} className="border-b">
                    <TableCell className="p-3">
                      <p className="font-medium">{v.name}</p>
                      {(v.allowed_email_domains ?? []).length > 0 && (
                        <p className="text-xs text-muted-foreground">{(v.allowed_email_domains ?? []).join(', ')}</p>
                      )}
                    </TableCell>
                    <TableCell className="p-3">
                      <Badge className={vendorStatusClass[v.status] ?? ''}>{t(`pages.externalUsers.vendors.status.${v.status}`, { defaultValue: v.status })}</Badge>
                    </TableCell>
                    <TableCell className="p-3">{v.contract_end ? t('pages.externalUsers.vendors.until', { date: v.contract_end }) : '—'}</TableCell>
                    <TableCell className="p-3">{t('pages.externalUsers.vendors.days', { n: v.default_expiry_days })}</TableCell>
                    <TableCell className="p-3 text-sm">{counts(v)}</TableCell>
                    <TableCell className="p-3 text-right space-x-2">
                      {v.status !== 'closed' && (
                        <>
                          <Button variant="outline" size="sm" onClick={() => setEditing(v)}>{t('pages.externalUsers.vendors.edit')}</Button>
                          <ConfirmAction
                            title={t('pages.externalUsers.confirm.closeTitle', { name: v.name })}
                            description={t('pages.externalUsers.confirm.closeDescription')}
                            confirmLabel={t('pages.externalUsers.vendors.close')}
                            destructive
                            requireReason
                            onConfirm={(reason) => close.mutateAsync({ id: v.id, reason: reason ?? '' }).catch(() => undefined)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" className="text-red-600" onClick={open}>
                                {t('pages.externalUsers.vendors.close')}
                              </Button>
                            )}
                          </ConfirmAction>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      {editing && <VendorDialog vendor={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </Card>
  )
}

function VendorDialog({ vendor, onClose }: { vendor: VendorOrg | null; onClose: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [form, setForm] = useState({
    name: vendor?.name ?? '',
    status: vendor?.status ?? 'active',
    contact_name: vendor?.contact_name ?? '',
    contact_email: vendor?.contact_email ?? '',
    contract_start: vendor?.contract_start?.slice(0, 10) ?? '',
    contract_end: vendor?.contract_end?.slice(0, 10) ?? '',
    domains: (vendor?.allowed_email_domains ?? []).join(', '),
    default_expiry_days: String(vendor?.default_expiry_days ?? 90),
    default_sponsor_user_id: vendor?.default_sponsor_user_id ?? '',
    notes: vendor?.notes ?? '',
  })
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }))

  // The update writes every field, so the body always carries all of them.
  const save = useMutation({
    mutationFn: () => {
      const body = {
        name: form.name.trim(),
        status: form.status,
        contact_name: form.contact_name.trim(),
        contact_email: form.contact_email.trim(),
        contract_start: form.contract_start,
        contract_end: form.contract_end,
        allowed_email_domains: form.domains.split(',').map((d) => d.trim()).filter(Boolean),
        default_expiry_days: parseInt(form.default_expiry_days, 10) || 90,
        default_sponsor_user_id: form.default_sponsor_user_id,
        notes: form.notes,
      }
      return vendor
        ? api.put(`/api/v1/identity/vendor-orgs/${vendor.id}`, body)
        : api.post('/api/v1/identity/vendor-orgs', body)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-orgs'] })
      toast({ title: t('common.success'), description: t('pages.externalUsers.toasts.vendorSaved', { name: form.name }), variant: 'success' })
      onClose()
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{vendor ? t('pages.externalUsers.vendorDialog.editTitle', { name: vendor.name }) : t('pages.externalUsers.vendorDialog.createTitle')}</DialogTitle>
          <DialogDescription>{t('pages.externalUsers.vendorDialog.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (form.name.trim()) save.mutate() }}>
          <div className="space-y-1">
            <Label htmlFor="xv-name">{t('pages.externalUsers.vendorDialog.name')}</Label>
            <Input id="xv-name" value={form.name} onChange={set('name')} />
          </div>
          {vendor && (
            <div className="space-y-1">
              <Label htmlFor="xv-status">{t('pages.externalUsers.vendorDialog.status')}</Label>
              <select id="xv-status" value={form.status} onChange={set('status')}
                className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm">
                <option value="active">{t('pages.externalUsers.vendors.status.active')}</option>
                <option value="suspended">{t('pages.externalUsers.vendors.status.suspended')}</option>
              </select>
              <p className="text-xs text-muted-foreground">{t('pages.externalUsers.vendorDialog.suspendedHint')}</p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="xv-contact-name">{t('pages.externalUsers.vendorDialog.contactName')}</Label>
              <Input id="xv-contact-name" value={form.contact_name} onChange={set('contact_name')} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xv-contact-email">{t('pages.externalUsers.vendorDialog.contactEmail')}</Label>
              <Input id="xv-contact-email" type="email" value={form.contact_email} onChange={set('contact_email')} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xv-contract-start">{t('pages.externalUsers.vendorDialog.contractStart')}</Label>
              <Input id="xv-contract-start" type="date" value={form.contract_start} onChange={set('contract_start')} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xv-contract-end">{t('pages.externalUsers.vendorDialog.contractEnd')}</Label>
              <Input id="xv-contract-end" type="date" value={form.contract_end} onChange={set('contract_end')} />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="xv-domains">{t('pages.externalUsers.vendorDialog.domains')}</Label>
            <Input id="xv-domains" placeholder="supplier.example" value={form.domains} onChange={set('domains')} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="xv-days">{t('pages.externalUsers.vendorDialog.defaultDays')}</Label>
            <Input id="xv-days" type="number" min={1} max={365} value={form.default_expiry_days} onChange={set('default_expiry_days')} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="xv-sponsor">{t('pages.externalUsers.vendorDialog.defaultSponsor')}</Label>
            <SponsorPicker id="xv-sponsor" value={form.default_sponsor_user_id}
              onChange={(v) => setForm((f) => ({ ...f, default_sponsor_user_id: v }))} optional />
          </div>
          <div className="space-y-1">
            <Label htmlFor="xv-notes">{t('pages.externalUsers.vendorDialog.notes')}</Label>
            <Textarea id="xv-notes" value={form.notes} onChange={set('notes')} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!form.name.trim() || save.isPending}>{t('pages.externalUsers.vendorDialog.save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
