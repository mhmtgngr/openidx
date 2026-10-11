import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Briefcase, Plus } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Textarea } from './ui/textarea'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader } from './ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { TableSkeleton } from './ui/skeleton'
import { QueryError } from './query-error'
import { ConfirmAction } from './confirm-action'
import { api } from '../lib/api'
import { SponsorPicker, apiErrorText, useVendors, type VendorOrg } from '../lib/external-access'
import { useToast } from '../hooks/use-toast'

// Vendor engagements (migration v234): a vendor's work with its window, its
// people and its targets. While one runs, the identity service gives its
// members what it covers and takes it back at its end; a vendor that requires
// engagements reaches nothing outside one. Every rule shown here is the API's
// (/api/v1/identity/engagements), and every refusal is the API's text.

export type EngagementTargetType = 'application' | 'pam_entry' | 'device'

export interface EngagementTarget {
  target_type: EngagementTargetType
  target_id: string
  target_name: string
}

export interface Engagement {
  id: string
  vendor_org_id: string
  vendor_name: string
  sponsor_user_id: string
  sponsor_name: string
  title: string
  purpose: string
  ticket_ref: string
  starts_at: string
  ends_at: string
  member_user_ids: string[]
  status: 'open' | 'closed'
  state: 'scheduled' | 'running' | 'ended' | 'closed'
  closed_at?: string
  close_reason?: string
  targets: EngagementTarget[]
  created_at: string
  updated_at: string
}

interface EngagementReport {
  engagement: Engagement
  generated_at: string
  window_start: string
  window_end: string
  members: Array<{ user_id: string; username: string; email: string; account_status: string }>
  pam_sessions: Array<{ id: string; entry_name: string; username: string; protocol: string; started_at: string; ended_at?: string; status: string; recorded: boolean; in_scope: boolean }>
  access_requests: Array<{ id: string; resource_type: string; resource_name: string; status: string; created_at: string }>
  remote_support_sessions: Array<{ id: string; agent_id: string; status: string; started_at: string; ended_at?: string; recorded: boolean; consent_status: string }>
  audited_actions: Array<{ action: string; count: number }>
  grants_held: Record<string, number>
}

const stateClass: Record<string, string> = {
  scheduled: 'bg-blue-100 text-blue-800',
  running: 'bg-green-100 text-green-800',
  ended: 'bg-muted text-muted-foreground',
  closed: 'bg-muted text-muted-foreground',
}

const formatDateTime = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

// toLocalInput renders an ISO time for a datetime-local input, in local time.
const toLocalInput = (iso?: string) => {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const fromLocalInput = (v: string) => (v ? new Date(v).toISOString() : undefined)

export function EngagementsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [state, setState] = useState<string>('')
  const [editing, setEditing] = useState<Engagement | 'new' | null>(null)
  const [reportFor, setReportFor] = useState<Engagement | null>(null)
  const { data: engagements = [], isLoading, isError, error } = useQuery({
    queryKey: ['engagements', state],
    queryFn: async () =>
      (await api.get<{ engagements: Engagement[] }>(`/api/v1/identity/engagements${state ? `?state=${state}` : ''}`)).engagements ?? [],
  })
  const close = useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) => api.post(`/api/v1/identity/engagements/${id}/close`, { note }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engagements'] })
      toast({ title: t('common.success'), description: t('pages.externalUsers.engagements.closed'), variant: 'success' })
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-muted-foreground max-w-2xl">{t('pages.externalUsers.engagements.hint')}</p>
          <div className="flex items-center gap-2">
            <select aria-label={t('pages.externalUsers.engagements.filter')} value={state} onChange={(e) => setState(e.target.value)}
              className="flex h-9 rounded-md border border-input bg-background px-3 py-1 text-sm">
              <option value="">{t('pages.externalUsers.engagements.allStates')}</option>
              {(['scheduled', 'running', 'ended', 'closed'] as const).map((s) => (
                <option key={s} value={s}>{t(`pages.externalUsers.engagements.state.${s}`)}</option>
              ))}
            </select>
            <Button onClick={() => setEditing('new')}>
              <Plus className="mr-2 h-4 w-4" /> {t('pages.externalUsers.engagements.create')}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <TableSkeleton rows={4} cols={6} />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.externalUsers.engagements.resourceName')} />
        ) : engagements.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Briefcase className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.externalUsers.engagements.empty')}</p>
          </div>
        ) : (
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3">{t('pages.externalUsers.engagements.table.title')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.engagements.table.vendor')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.engagements.table.window')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.engagements.table.state')}</TableHead>
                  <TableHead className="p-3">{t('pages.externalUsers.engagements.table.covers')}</TableHead>
                  <TableHead className="p-3 text-right">{t('pages.externalUsers.accounts.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {engagements.map((e) => (
                  <TableRow key={e.id} className="border-b">
                    <TableCell className="p-3">
                      <p className="font-medium">{e.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {[e.ticket_ref, e.sponsor_name && t('pages.externalUsers.engagements.sponsoredBy', { name: e.sponsor_name })].filter(Boolean).join(' · ')}
                      </p>
                    </TableCell>
                    <TableCell className="p-3">{e.vendor_name}</TableCell>
                    <TableCell className="p-3 text-sm whitespace-nowrap">
                      {formatDateTime(e.starts_at)}<br />→ {formatDateTime(e.closed_at && e.closed_at < e.ends_at ? e.closed_at : e.ends_at)}
                    </TableCell>
                    <TableCell className="p-3">
                      <Badge className={stateClass[e.state] ?? ''}>{t(`pages.externalUsers.engagements.state.${e.state}`)}</Badge>
                      {e.close_reason && e.close_reason !== 'closed' && (
                        <p className="text-xs text-muted-foreground">{t(`pages.externalUsers.engagements.reason.${e.close_reason}`, { defaultValue: e.close_reason })}</p>
                      )}
                    </TableCell>
                    <TableCell className="p-3 text-sm">
                      {t('pages.externalUsers.engagements.coverSummary', {
                        targets: e.targets.length,
                        members: e.member_user_ids.length || t('pages.externalUsers.engagements.allMembers'),
                      })}
                    </TableCell>
                    <TableCell className="p-3 text-right space-x-2 whitespace-nowrap">
                      <Button variant="outline" size="sm" onClick={() => setReportFor(e)}>{t('pages.externalUsers.engagements.report')}</Button>
                      {e.status === 'open' && (
                        <>
                          <Button variant="outline" size="sm" onClick={() => setEditing(e)}>{t('pages.externalUsers.vendors.edit')}</Button>
                          <ConfirmAction
                            title={t('pages.externalUsers.engagements.closeTitle', { title: e.title })}
                            description={t('pages.externalUsers.engagements.closeDescription')}
                            confirmLabel={t('pages.externalUsers.engagements.close')}
                            destructive
                            requireReason
                            onConfirm={(reason) => close.mutateAsync({ id: e.id, note: reason ?? '' }).catch(() => undefined)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" className="text-red-600" onClick={open}>
                                {t('pages.externalUsers.engagements.close')}
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
      {editing && <EngagementDialog engagement={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      {reportFor && <EngagementReportDialog engagement={reportFor} onClose={() => setReportFor(null)} />}
    </Card>
  )
}

interface Option { id: string; name: string }

// useTargetOptions lists what an engagement can cover: applications (network
// resources included), PAM entries and enrolled devices.
function useTargetOptions(type: EngagementTargetType) {
  return useQuery({
    queryKey: ['engagement-target-options', type],
    queryFn: async (): Promise<Option[]> => {
      if (type === 'application') {
        const res = await api.getWithHeaders<Array<{ id: string; name: string }>>('/api/v1/applications')
        return Array.isArray(res.data) ? res.data.map((a) => ({ id: a.id, name: a.name })) : []
      }
      if (type === 'pam_entry') {
        return ((await api.pam.listEntries()).entries ?? []).map((e: { id: string; name: string }) => ({ id: e.id, name: e.name }))
      }
      const agents = await api.get<Array<{ agent_id?: string; hostname?: string; status?: string }>>('/api/v1/access/agents')
      return (agents ?? [])
        .filter((a) => a.agent_id && a.status !== 'revoked')
        .map((a) => ({ id: a.agent_id as string, name: a.hostname ? `${a.hostname} (${a.agent_id})` : (a.agent_id as string) }))
    },
  })
}

interface VendorMember { id: string; username: string; first_name: string; last_name: string; status: string }

function EngagementDialog({ engagement, onClose }: { engagement: Engagement | null; onClose: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { data: vendors = [] } = useVendors()
  const started = !!engagement && new Date(engagement.starts_at) <= new Date()
  const [form, setForm] = useState({
    vendor_org_id: engagement?.vendor_org_id ?? '',
    title: engagement?.title ?? '',
    purpose: engagement?.purpose ?? '',
    ticket_ref: engagement?.ticket_ref ?? '',
    sponsor_user_id: engagement?.sponsor_user_id ?? '',
    starts_at: toLocalInput(engagement?.starts_at),
    ends_at: toLocalInput(engagement?.ends_at),
  })
  const [members, setMembers] = useState<string[]>(engagement?.member_user_ids ?? [])
  const [targets, setTargets] = useState<EngagementTarget[]>(engagement?.targets ?? [])
  const [type, setType] = useState<EngagementTargetType>('application')
  const [pick, setPick] = useState('')
  const { data: options = [] } = useTargetOptions(type)
  const vendor: VendorOrg | undefined = vendors.find((v) => v.id === form.vendor_org_id)
  const { data: vendorUsers = [] } = useQuery({
    queryKey: ['engagement-vendor-users', form.vendor_org_id],
    enabled: !!form.vendor_org_id,
    queryFn: async () =>
      (await api.get<{ external_users: VendorMember[] }>(`/api/v1/identity/external-users?vendor_org_id=${form.vendor_org_id}`)).external_users ?? [],
  })
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }))
  const chosen = new Set(targets.map((x) => `${x.target_type}:${x.target_id}`))

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        title: form.title.trim(),
        purpose: form.purpose,
        ticket_ref: form.ticket_ref.trim(),
        sponsor_user_id: form.sponsor_user_id,
        ends_at: fromLocalInput(form.ends_at),
        member_user_ids: members,
        targets: targets.map(({ target_type, target_id }) => ({ target_type, target_id })),
      }
      if (!started && form.starts_at) body.starts_at = fromLocalInput(form.starts_at)
      return engagement
        ? api.put(`/api/v1/identity/engagements/${engagement.id}`, body)
        : api.post(`/api/v1/identity/vendor-orgs/${form.vendor_org_id}/engagements`, body)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engagements'] })
      toast({ title: t('common.success'), description: t('pages.externalUsers.engagements.saved', { title: form.title }), variant: 'success' })
      onClose()
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('pages.externalUsers.toasts.failed')), variant: 'destructive' }),
  })

  const canSave = form.title.trim() && form.ends_at && form.vendor_org_id && targets.length > 0 && !save.isPending

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{engagement ? t('pages.externalUsers.engagements.editTitle', { title: engagement.title }) : t('pages.externalUsers.engagements.createTitle')}</DialogTitle>
          <DialogDescription>{t('pages.externalUsers.engagements.dialogDescription')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (canSave) save.mutate() }}>
          <div className="space-y-1">
            <Label htmlFor="xe-vendor">{t('pages.externalUsers.engagements.vendor')}</Label>
            <select id="xe-vendor" value={form.vendor_org_id} disabled={!!engagement}
              onChange={(e) => { setForm((f) => ({ ...f, vendor_org_id: e.target.value })); setMembers([]) }}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm">
              <option value="">{t('pages.externalUsers.engagements.chooseVendor')}</option>
              {vendors.filter((v) => v.status === 'active' || v.id === form.vendor_org_id).map((v) => (
                <option key={v.id} value={v.id}>{v.name}</option>
              ))}
            </select>
            {vendor?.closed_list && <p className="text-xs text-muted-foreground">{t('pages.externalUsers.engagements.closedListNote')}</p>}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="xe-title">{t('pages.externalUsers.engagements.title')}</Label>
              <Input id="xe-title" value={form.title} maxLength={200} onChange={set('title')} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xe-ticket">{t('pages.externalUsers.engagements.ticket')}</Label>
              <Input id="xe-ticket" value={form.ticket_ref} maxLength={200} placeholder="CHG-1234" onChange={set('ticket_ref')} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="xe-starts">{t('pages.externalUsers.engagements.starts')}</Label>
              <Input id="xe-starts" type="datetime-local" value={form.starts_at} disabled={started} onChange={set('starts_at')} />
              {!engagement && <p className="text-xs text-muted-foreground">{t('pages.externalUsers.engagements.startsHint')}</p>}
            </div>
            <div className="space-y-1">
              <Label htmlFor="xe-ends">{t('pages.externalUsers.engagements.ends')}</Label>
              <Input id="xe-ends" type="datetime-local" value={form.ends_at} onChange={set('ends_at')} />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="xe-purpose">{t('pages.externalUsers.engagements.purpose')}</Label>
            <Textarea id="xe-purpose" value={form.purpose} onChange={set('purpose')} />
          </div>
          <div className="space-y-1">
            <Label id="xe-sponsor-label" htmlFor="xe-sponsor">{t('pages.externalUsers.engagements.sponsor')}</Label>
            <SponsorPicker id="xe-sponsor" value={form.sponsor_user_id}
              onChange={(v) => setForm((f) => ({ ...f, sponsor_user_id: v }))} optional />
          </div>

          <fieldset className="space-y-2 rounded-md border p-3">
            <legend className="px-1 text-sm font-medium">{t('pages.externalUsers.engagements.members')}</legend>
            <p className="text-xs text-muted-foreground">{t('pages.externalUsers.engagements.membersHint')}</p>
            {!form.vendor_org_id ? null : vendorUsers.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('pages.externalUsers.engagements.noVendorUsers')}</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1">
                {vendorUsers.map((u) => (
                  <label key={u.id} className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={members.includes(u.id)}
                      onChange={(e) => setMembers((m) => (e.target.checked ? [...m, u.id] : m.filter((x) => x !== u.id)))} />
                    <span>{[u.first_name, u.last_name].filter(Boolean).join(' ') || u.username}</span>
                    {u.status !== 'active' && <Badge variant="outline">{t(`pages.externalUsers.status.${u.status}`, { defaultValue: u.status })}</Badge>}
                  </label>
                ))}
              </div>
            )}
          </fieldset>

          <fieldset className="space-y-2 rounded-md border p-3">
            <legend className="px-1 text-sm font-medium">{t('pages.externalUsers.engagements.targets')}</legend>
            {targets.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('pages.externalUsers.engagements.noTargets')}</p>
            ) : (
              <ul className="space-y-1">
                {targets.map((x) => (
                  <li key={`${x.target_type}:${x.target_id}`} className="flex items-center justify-between gap-2 text-sm">
                    <span><Badge variant="outline" className="mr-2">{t(`pages.externalUsers.engagements.types.${x.target_type}`)}</Badge>{x.target_name || x.target_id}</span>
                    <Button type="button" variant="ghost" size="sm" className="text-red-600"
                      onClick={() => setTargets((ts) => ts.filter((y) => !(y.target_type === x.target_type && y.target_id === x.target_id)))}>
                      {t('pages.externalUsers.engagements.removeTarget')}
                    </Button>
                  </li>
                ))}
              </ul>
            )}
            <div className="flex flex-wrap items-end gap-2">
              <div className="space-y-1">
                <Label htmlFor="xe-type">{t('pages.externalUsers.targetsDialog.type')}</Label>
                <select id="xe-type" value={type} onChange={(e) => { setType(e.target.value as EngagementTargetType); setPick('') }}
                  className="flex h-9 rounded-md border border-input bg-background px-3 py-1 text-sm">
                  {(['application', 'pam_entry', 'device'] as const).map((k) => (
                    <option key={k} value={k}>{t(`pages.externalUsers.engagements.types.${k}`)}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1 flex-1 min-w-48">
                <Label htmlFor="xe-target">{t('pages.externalUsers.targetsDialog.target')}</Label>
                <select id="xe-target" value={pick} onChange={(e) => setPick(e.target.value)}
                  className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm">
                  <option value="">{t('pages.externalUsers.targetsDialog.choose')}</option>
                  {options.filter((o) => !chosen.has(`${type}:${o.id}`)).map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select>
              </div>
              <Button type="button" variant="outline" disabled={!pick}
                onClick={() => {
                  const o = options.find((x) => x.id === pick)
                  setTargets((ts) => [...ts, { target_type: type, target_id: pick, target_name: o?.name ?? pick }])
                  setPick('')
                }}>
                {t('pages.externalUsers.engagements.addTarget')}
              </Button>
            </div>
          </fieldset>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!canSave}>{t('pages.externalUsers.vendorDialog.save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function EngagementReportDialog({ engagement, onClose }: { engagement: Engagement; onClose: () => void }) {
  const { t } = useTranslation()
  const { data: report, isLoading, isError, error } = useQuery({
    queryKey: ['engagement-report', engagement.id],
    queryFn: () => api.get<EngagementReport>(`/api/v1/identity/engagements/${engagement.id}/report`),
  })
  const section = (title: string, n: number) => (
    <h3 className="text-sm font-semibold pt-3">{title} <span className="text-muted-foreground font-normal">({n})</span></h3>
  )
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t('pages.externalUsers.engagements.reportTitle', { title: engagement.title })}</DialogTitle>
          <DialogDescription>
            {report ? `${formatDateTime(report.window_start)} → ${formatDateTime(report.window_end)} · ${engagement.vendor_name}` : engagement.vendor_name}
          </DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <TableSkeleton rows={4} cols={4} />
        ) : isError || !report ? (
          <QueryError error={error} resource={t('pages.externalUsers.engagements.reportResource')} />
        ) : (
          <div className="space-y-1 text-sm">
            {engagement.purpose && <p className="text-muted-foreground whitespace-pre-wrap">{engagement.purpose}</p>}
            <p>{t('pages.externalUsers.engagements.grantsHeld', { pam: report.grants_held.pam_entry ?? 0, apps: report.grants_held.application ?? 0 })}</p>

            {section(t('pages.externalUsers.engagements.members'), report.members.length)}
            <ul className="list-disc pl-5">
              {report.members.map((m) => <li key={m.user_id}>{m.username} {m.email && `<${m.email}>`} — {t(`pages.externalUsers.status.${m.account_status}`, { defaultValue: m.account_status })}</li>)}
            </ul>

            {section(t('pages.externalUsers.engagements.pamSessions'), report.pam_sessions.length)}
            {report.pam_sessions.length > 0 && (
              <Table>
                <TableBody>
                  {report.pam_sessions.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="p-2">{p.username}</TableCell>
                      <TableCell className="p-2">{p.entry_name} {!p.in_scope && <Badge variant="outline">{t('pages.externalUsers.engagements.outOfScope')}</Badge>}</TableCell>
                      <TableCell className="p-2 whitespace-nowrap">{formatDateTime(p.started_at)} → {formatDateTime(p.ended_at)}</TableCell>
                      <TableCell className="p-2">{p.recorded ? t('pages.externalUsers.engagements.recorded') : t('pages.externalUsers.engagements.notRecorded')}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}

            {section(t('pages.externalUsers.engagements.requests'), report.access_requests.length)}
            <ul className="list-disc pl-5">
              {report.access_requests.map((r) => <li key={r.id}>{r.resource_name || r.resource_type} — {r.status} ({formatDateTime(r.created_at)})</li>)}
            </ul>

            {section(t('pages.externalUsers.engagements.remoteSupport'), report.remote_support_sessions.length)}
            <ul className="list-disc pl-5">
              {report.remote_support_sessions.map((r) => (
                <li key={r.id}>{r.agent_id} — {r.status}, {formatDateTime(r.started_at)} → {formatDateTime(r.ended_at)}{r.recorded ? ` · ${t('pages.externalUsers.engagements.recorded')}` : ''}</li>
              ))}
            </ul>

            {section(t('pages.externalUsers.engagements.actions'), report.audited_actions.length)}
            <ul className="list-disc pl-5">
              {report.audited_actions.map((a) => <li key={a.action}><code>{a.action}</code> × {a.count}</li>)}
            </ul>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{t('common.close')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
