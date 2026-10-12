import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Network, Plus, Users } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Switch } from './ui/switch'
import { Textarea } from './ui/textarea'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { ConfirmAction } from './confirm-action'
import { ManageAppAccessDialog } from './manage-app-access-dialog'
import { useToast } from '../hooks/use-toast'
import { api } from '../lib/api'
import {
  EMPTY_DRAFT, draftFromTarget, formatPorts, targetFromDraft,
  type NetworkPolicy, type NetworkResource, type NetworkTarget, type TargetDraft,
} from '../lib/network-target'

// Network resources: the server side of the VPN replacement. A network
// resource is an application of kind "network"; its network target says what
// the device's OpenZiti tunneler intercepts and where the hosting router
// forwards. GET/POST /api/v1/access/network-resources,
// GET/PUT/DELETE /api/v1/access/resources/:id/network-target,
// GET/PUT /api/v1/access/network-policy.

function apiError(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

/** NetworkTargetSection is the "Network target" part of a network resource's editor. */
export function NetworkTargetSection({ value, onChange }: { value: TargetDraft; onChange: (d: TargetDraft) => void }) {
  const { t } = useTranslation()
  const set = (k: keyof TargetDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    onChange({ ...value, [k]: e.target.value })
  return (
    <fieldset className="space-y-3">
      <legend className="text-sm font-medium">{t('pages.networkResources.target.title')}</legend>
      <p className="text-xs text-muted-foreground">{t('pages.networkResources.target.help')}</p>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="space-y-1">
          <Label htmlFor="nt-hosts">{t('pages.networkResources.target.hosts')}</Label>
          <Textarea id="nt-hosts" rows={3} value={value.hosts} onChange={set('hosts')} placeholder="fs1.corp.example" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="nt-cidrs">{t('pages.networkResources.target.cidrs')}</Label>
          <Textarea id="nt-cidrs" rows={3} value={value.cidrs} onChange={set('cidrs')} placeholder="10.0.0.0/16" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="nt-dns">{t('pages.networkResources.target.dnsNames')}</Label>
          <Textarea id="nt-dns" rows={3} value={value.dns_names} onChange={set('dns_names')} placeholder="*.corp.example" />
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="nt-ports">{t('pages.networkResources.target.ports')}</Label>
          <Input id="nt-ports" value={value.ports} onChange={set('ports')} placeholder="445, 8000-8100" />
          <p className="text-xs text-muted-foreground">{t('pages.networkResources.target.portsHint')}</p>
        </div>
        <div className="space-y-1">
          <span className="text-sm font-medium">{t('pages.networkResources.target.protocols')}</span>
          <div className="flex items-center gap-4 pt-1">
            <label className="flex items-center gap-2 text-sm">
              <Switch
                checked={value.tcp}
                onCheckedChange={(v) => onChange({ ...value, tcp: v })}
                aria-label="TCP"
              />
              TCP
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch
                checked={value.udp}
                onCheckedChange={(v) => onChange({ ...value, udp: v })}
                aria-label="UDP"
              />
              UDP
            </label>
          </div>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="nt-fwd-addr">{t('pages.networkResources.target.forwardAddress')}</Label>
          <Input id="nt-fwd-addr" value={value.forward_address} onChange={set('forward_address')} />
        </div>
        <div className="space-y-1">
          <Label htmlFor="nt-fwd-port">{t('pages.networkResources.target.forwardPort')}</Label>
          <Input id="nt-fwd-port" inputMode="numeric" value={value.forward_port} onChange={set('forward_port')} />
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{t('pages.networkResources.target.forwardHint')}</p>
    </fieldset>
  )
}

/** NetworkPolicyCard is the organization's tunnel policy. */
export function NetworkPolicyCard() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['network-policy'],
    queryFn: () => api.get<NetworkPolicy>('/api/v1/access/network-policy'),
  })
  const save = useMutation({
    mutationFn: (patch: Partial<NetworkPolicy>) => api.put<NetworkPolicy>('/api/v1/access/network-policy', patch),
    onSuccess: (resp) => {
      qc.setQueryData(['network-policy'], resp)
      toast({ title: t('pages.networkResources.policy.saved') })
    },
    onError: (err: unknown) =>
      toast({ title: apiError(err, t('pages.networkResources.policy.saveFailed')), variant: 'destructive' }),
  })
  const toggle = (key: 'always_on' | 'split_tunnel' | 'block_direct_corporate_cidrs', id: string) => (
    <div className="flex items-start justify-between gap-4">
      <div>
        <Label htmlFor={id}>{t(`pages.networkResources.policy.${key}`)}</Label>
        <p className="text-xs text-muted-foreground">{t(`pages.networkResources.policy.${key}Hint`)}</p>
      </div>
      <Switch
        id={id}
        checked={!!data?.[key]}
        disabled={save.isPending}
        onCheckedChange={(v) => save.mutate({ [key]: v })}
      />
    </div>
  )
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t('pages.networkResources.policy.title')}</CardTitle>
        <CardDescription>{t('pages.networkResources.policy.subtitle')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <LoadingSpinner />
        ) : (
          <>
            {toggle('always_on', 'np-always-on')}
            {toggle('split_tunnel', 'np-split')}
            {data && !data.split_tunnel && (
              <p className="text-xs text-amber-700 dark:text-amber-400" data-testid="np-full-tunnel-gap">
                {t('pages.networkResources.policy.fullTunnelGap')}
              </p>
            )}
            {toggle('block_direct_corporate_cidrs', 'np-block')}
            {data?.block_direct_corporate_cidrs && (
              <p className="text-xs text-muted-foreground" data-testid="np-block-scope">
                {t('pages.networkResources.policy.blockDirectScope')}
              </p>
            )}
            {data?.devices && (
              <div className="border-t pt-3 text-xs text-muted-foreground" data-testid="np-rollout">
                <p>{t('pages.networkResources.policy.rollout', data.devices)}</p>
                {data.version && (
                  <p className="font-mono">{t('pages.networkResources.policy.version', { version: data.version })}</p>
                )}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function summarize(t: NetworkTarget | null): string {
  if (!t) return ''
  return [...t.hosts, ...t.cidrs, ...t.dns_names].join(', ')
}

/** NetworkResourcesPanel lists the organization's network resources and edits them. */
export function NetworkResourcesPanel() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const qc = useQueryClient()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['network-resources'],
    queryFn: () => api.get<{ resources: NetworkResource[]; total: number }>('/api/v1/access/network-resources'),
  })

  // The editor: a new resource (id null) or an existing one's target.
  const [editing, setEditing] = useState<{ id: string | null; name: string; description: string; draft: TargetDraft } | null>(null)
  const [formError, setFormError] = useState('')
  const [access, setAccess] = useState<NetworkResource | null>(null)

  const invalidate = () => qc.invalidateQueries({ queryKey: ['network-resources'] })
  const saveMutation = useMutation({
    mutationFn: async (e: { id: string | null; name: string; description: string; target: NetworkTarget }) => {
      if (e.id) return api.put(`/api/v1/access/resources/${e.id}/network-target`, e.target)
      return api.post('/api/v1/access/network-resources', { name: e.name, description: e.description, target: e.target })
    },
    onSuccess: () => {
      invalidate()
      setEditing(null)
      toast({ title: t('pages.networkResources.saved') })
    },
    onError: (err: unknown) => setFormError(apiError(err, t('pages.networkResources.saveFailed'))),
  })
  const removeTarget = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/resources/${id}/network-target`),
    onSuccess: () => {
      invalidate()
      toast({ title: t('pages.networkResources.targetRemoved') })
    },
    onError: (err: unknown) =>
      toast({ title: apiError(err, t('pages.networkResources.saveFailed')), variant: 'destructive' }),
  })

  const submit = () => {
    if (!editing) return
    if (!editing.id && editing.name.trim() === '') {
      setFormError(t('pages.networkResources.errors.needName'))
      return
    }
    const { target, error: err } = targetFromDraft(editing.draft)
    if (!target) {
      setFormError(t(`pages.networkResources.errors.${err}`))
      return
    }
    setFormError('')
    saveMutation.mutate({ id: editing.id, name: editing.name.trim(), description: editing.description, target })
  }

  const resources = data?.resources ?? []
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center justify-between text-base">
            <span className="flex items-center gap-2">
              <Network className="h-4 w-4" />
              {t('pages.networkResources.title')}
            </span>
            <Button
              size="sm"
              onClick={() => {
                setFormError('')
                setEditing({ id: null, name: '', description: '', draft: EMPTY_DRAFT })
              }}
            >
              <Plus className="mr-1.5 h-4 w-4" />
              {t('pages.networkResources.add')}
            </Button>
          </CardTitle>
          <CardDescription>{t('pages.networkResources.subtitle')}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingSpinner />
          ) : isError ? (
            <QueryError error={error} resource={t('pages.networkResources.resource')} />
          ) : resources.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">{t('pages.networkResources.empty')}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.networkResources.colName')}</TableHead>
                  <TableHead>{t('pages.networkResources.colCovers')}</TableHead>
                  <TableHead>{t('pages.networkResources.colPorts')}</TableHead>
                  <TableHead>{t('pages.networkResources.colStatus')}</TableHead>
                  <TableHead className="text-right">{t('pages.networkResources.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resources.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <div className="font-medium">{r.name}</div>
                      <div className="text-xs text-muted-foreground">{r.service_name}</div>
                    </TableCell>
                    <TableCell className="max-w-xs truncate">
                      {r.target ? summarize(r.target) : (
                        <Badge variant="outline">{t('pages.networkResources.noTarget')}</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {r.target
                        ? `${formatPorts(r.target.port_ranges) || t('pages.networkResources.allPorts')} · ${r.target.protocols.join('/').toUpperCase()}`
                        : '—'}
                    </TableCell>
                    <TableCell>
                      {r.sync_status === 'synced' ? (
                        <Badge variant="success">{t('pages.networkResources.synced')}</Badge>
                      ) : r.sync_status ? (
                        <Badge variant="destructive" title={r.sync_status}>{t('pages.networkResources.syncError')}</Badge>
                      ) : (
                        <Badge variant="outline">{t('pages.networkResources.pending')}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="space-x-2 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setFormError('')
                          setEditing({ id: r.id, name: r.name, description: r.description, draft: draftFromTarget(r.target) })
                        }}
                      >
                        {t('pages.networkResources.editTarget')}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setAccess(r)}>
                        <Users className="mr-1 h-4 w-4" />
                        {t('pages.networkResources.manageAccess')}
                      </Button>
                      {r.target && (
                        <ConfirmAction
                          title={t('pages.networkResources.removeTitle', { name: r.name })}
                          description={t('pages.networkResources.removeDesc')}
                          destructive
                          confirmLabel={t('pages.networkResources.removeTarget')}
                          onConfirm={() => removeTarget.mutateAsync(r.id)}
                        >
                          {(open) => (
                            <Button variant="outline" size="sm" onClick={open} disabled={removeTarget.isPending}>
                              {t('pages.networkResources.removeTarget')}
                            </Button>
                          )}
                        </ConfirmAction>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <NetworkPolicyCard />

      <Dialog open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {editing?.id
                ? t('pages.networkResources.editTitle', { name: editing.name })
                : t('pages.networkResources.addTitle')}
            </DialogTitle>
          </DialogHeader>
          {editing && (
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault()
                submit()
              }}
            >
              {!editing.id && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <Label htmlFor="nr-name">{t('pages.networkResources.name')}</Label>
                    <Input
                      id="nr-name"
                      value={editing.name}
                      onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="nr-desc">{t('pages.networkResources.description')}</Label>
                    <Input
                      id="nr-desc"
                      value={editing.description}
                      onChange={(e) => setEditing({ ...editing, description: e.target.value })}
                    />
                  </div>
                </div>
              )}
              <NetworkTargetSection value={editing.draft} onChange={(draft) => setEditing({ ...editing, draft })} />
              {formError && (
                <p role="alert" className="text-sm text-destructive">{formError}</p>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setEditing(null)}>
                  {t('pages.networkResources.cancel')}
                </Button>
                <Button type="submit" disabled={saveMutation.isPending}>
                  {t('pages.networkResources.save')}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {access && (
        <ManageAppAccessDialog
          appId={access.id}
          appName={access.name}
          open={!!access}
          onOpenChange={(o) => !o && setAccess(null)}
        />
      )}
    </div>
  )
}
