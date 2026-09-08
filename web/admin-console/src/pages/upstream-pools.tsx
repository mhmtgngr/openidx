import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Server, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
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
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

/**
 * Upstream pools: a route's backend set, with weights and active health checks.
 *
 * The page is built around one fact the API reports and a table of rows would
 * hide: a pool can be fully configured and not be serving anything. The data
 * plane refuses to render an upstream with no usable node — it would black-hole
 * the route — so routes on a drained pool quietly fall back to their single
 * address. Every row therefore leads with whether the pool is IN EFFECT, and
 * says why when it is not.
 */

interface PoolMember {
  id: string
  host: string
  port: number
  weight: number
  enabled: boolean
}

interface UpstreamPool {
  id: string
  name: string
  description?: string
  algorithm: string
  hash_on: string
  hash_key: string
  health_check_enabled: boolean
  health_check_path: string
  healthy_threshold: number
  unhealthy_threshold: number
  health_check_interval: number
  health_check_timeout: number
  retries: number | null
  members: PoolMember[]
  routes_using: number
  in_effect: boolean
  not_in_effect_reason?: string
}

/** The shape the API answers a refused delete with. */
interface InUseError {
  response?: { status?: number; data?: { routes?: string[] } }
}

export function UpstreamPoolsPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [createModal, setCreateModal] = useState(false)
  const [memberModalPool, setMemberModalPool] = useState<UpstreamPool | null>(null)
  const [form, setForm] = useState({ name: '', description: '', algorithm: 'roundrobin', health_check_enabled: true })
  const [memberForm, setMemberForm] = useState({ host: '', port: '' })
  // Both deletions move production traffic, so both are confirmed. Deleting a
  // pool sends every route on it back to one backend; removing the last usable
  // backend does the same thing without deleting anything.
  const [poolToDelete, setPoolToDelete] = useState<UpstreamPool | null>(null)
  const [memberToRemove, setMemberToRemove] = useState<{ pool: UpstreamPool; member: PoolMember } | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['upstream-pools'],
    queryFn: async () => api.get<{ pools: UpstreamPool[]; total: number }>('/api/v1/access/upstream-pools'),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['upstream-pools'] })

  const createMutation = useMutation({
    mutationFn: async (body: Record<string, unknown>) => api.post('/api/v1/access/upstream-pools', body),
    onSuccess: () => {
      invalidate()
      setCreateModal(false)
      setForm({ name: '', description: '', algorithm: 'roundrobin', health_check_enabled: true })
      toast({ title: t('pages.upstreamPools.toast.created'), description: t('pages.upstreamPools.toast.createdDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.upstreamPools.toast.createFailed'), variant: 'destructive' })
    },
  })

  const addMemberMutation = useMutation({
    mutationFn: async ({ poolId, body }: { poolId: string; body: Record<string, unknown> }) =>
      api.post(`/api/v1/access/upstream-pools/${poolId}/members`, body),
    onSuccess: () => {
      invalidate()
      setMemberForm({ host: '', port: '' })
      toast({ title: t('pages.upstreamPools.toast.memberAdded') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.upstreamPools.toast.memberAddFailed'), variant: 'destructive' })
    },
  })

  // Draining a member is the change most likely to surprise: the response
  // carries the pool's resulting state, and when the pool has stopped serving
  // the toast says so rather than reporting a bare success.
  const updateMemberMutation = useMutation({
    mutationFn: async ({ poolId, memberId, body }: { poolId: string; memberId: string; body: Record<string, unknown> }) =>
      api.put<{ message: string; pool?: UpstreamPool }>(
        `/api/v1/access/upstream-pools/${poolId}/members/${memberId}`, body),
    onSuccess: (result) => {
      invalidate()
      if (result?.pool && !result.pool.in_effect && result.pool.routes_using > 0) {
        toast({
          title: t('pages.upstreamPools.toast.poolNotServing'),
          description: t('pages.upstreamPools.toast.poolNotServingDesc', { count: result.pool.routes_using }),
          variant: 'destructive',
        })
        return
      }
      toast({ title: t('pages.upstreamPools.toast.memberUpdated') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.upstreamPools.toast.memberUpdateFailed'), variant: 'destructive' })
    },
  })

  const removeMemberMutation = useMutation({
    mutationFn: async ({ poolId, memberId }: { poolId: string; memberId: string }) =>
      api.delete<{ message: string; pool?: UpstreamPool }>(
        `/api/v1/access/upstream-pools/${poolId}/members/${memberId}`),
    onSuccess: (result) => {
      invalidate()
      if (result?.pool && !result.pool.in_effect && result.pool.routes_using > 0) {
        toast({
          title: t('pages.upstreamPools.toast.poolNotServing'),
          description: t('pages.upstreamPools.toast.poolNotServingDesc', { count: result.pool.routes_using }),
          variant: 'destructive',
        })
        return
      }
      toast({ title: t('pages.upstreamPools.toast.memberRemoved') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.upstreamPools.toast.memberRemoveFailed'), variant: 'destructive' })
    },
  })

  // The API refuses to delete a pool routes still name, and answers with their
  // names. Showing them is the whole value of the refusal: "detach these first"
  // is actionable, "conflict" is not.
  const deleteMutation = useMutation({
    mutationFn: async (poolId: string) => api.delete(`/api/v1/access/upstream-pools/${poolId}`),
    onSuccess: () => {
      invalidate()
      toast({ title: t('pages.upstreamPools.toast.deleted') })
    },
    onError: (err: InUseError) => {
      const routes = err?.response?.data?.routes
      if (err?.response?.status === 409 && routes?.length) {
        toast({
          title: t('pages.upstreamPools.toast.stillInUse'),
          description: t('pages.upstreamPools.toast.stillInUseDesc', { routes: routes.join(', ') }),
          variant: 'destructive',
        })
        return
      }
      toast({ title: t('common.error'), description: t('pages.upstreamPools.toast.deleteFailed'), variant: 'destructive' })
    },
  })

  const pools = data?.pools ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t('pages.upstreamPools.title')}</h1>
          <p className="text-sm text-muted-foreground">{t('pages.upstreamPools.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
          {t('pages.upstreamPools.addPool')}
        </Button>
      </div>

      {isLoading && <LoadingSpinner />}
      {isError && <QueryError error={error} resource={t('pages.upstreamPools.resourceName')} />}

      {!isLoading && !isError && pools.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            {t('pages.upstreamPools.empty')}
          </CardContent>
        </Card>
      )}

      {!isLoading && !isError && pools.map((pool) => (
        <Card key={pool.id}>
          <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-medium">{pool.name}</h2>
                <Badge variant="outline">{pool.algorithm}</Badge>
                {pool.in_effect ? (
                  <Badge className="gap-1">
                    <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                    {t('pages.upstreamPools.inEffect')}
                  </Badge>
                ) : (
                  <Badge variant="destructive" className="gap-1">
                    <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                    {t('pages.upstreamPools.notInEffect')}
                  </Badge>
                )}
              </div>
              {pool.description && <p className="mt-1 text-sm text-muted-foreground">{pool.description}</p>}
              {/* The reason is the point of the badge. Without it, "not in
                  effect" is a colour, and the operator still has to guess
                  whether traffic is moving. */}
              {!pool.in_effect && pool.not_in_effect_reason && (
                <p className="mt-2 text-sm text-destructive">{pool.not_in_effect_reason}</p>
              )}
              <p className="mt-2 text-sm text-muted-foreground">
                {t('pages.upstreamPools.routesUsing', { count: pool.routes_using })}
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <Button variant="outline" size="sm" onClick={() => setMemberModalPool(pool)}>
                <Server className="mr-2 h-4 w-4" aria-hidden="true" />
                {t('pages.upstreamPools.manageBackends')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPoolToDelete(pool)}
                aria-label={t('pages.upstreamPools.deletePoolNamed', { name: pool.name })}
              >
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {pool.members.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('pages.upstreamPools.noBackends')}</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {pool.members.map((m) => (
                  <li key={m.id} className="flex items-center gap-3">
                    <span className="font-mono">{m.host}:{m.port}</span>
                    <span className="text-muted-foreground">
                      {t('pages.upstreamPools.weight', { weight: m.weight })}
                    </span>
                    {!m.enabled && <Badge variant="outline">{t('pages.upstreamPools.disabled')}</Badge>}
                    {m.enabled && m.weight === 0 && (
                      <Badge variant="outline">{t('pages.upstreamPools.draining')}</Badge>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      ))}

      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.upstreamPools.addPool')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="pool-name">{t('pages.upstreamPools.form.name')}</Label>
              <Input id="pool-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pool-description">{t('pages.upstreamPools.form.description')}</Label>
              <Input
                id="pool-description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="pool-algorithm">{t('pages.upstreamPools.form.algorithm')}</Label>
              <Select value={form.algorithm} onValueChange={(v) => setForm({ ...form, algorithm: v })}>
                <SelectTrigger id="pool-algorithm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="roundrobin">{t('pages.upstreamPools.form.roundrobin')}</SelectItem>
                  <SelectItem value="chash">{t('pages.upstreamPools.form.chash')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="pool-health">{t('pages.upstreamPools.form.healthChecks')}</Label>
              <Switch
                id="pool-health"
                checked={form.health_check_enabled}
                onCheckedChange={(v) => setForm({ ...form, health_check_enabled: v })}
              />
            </div>
            {/* Said before the pool exists, because it is the state every new
                pool is in and the first thing an operator will wonder about. */}
            <p className="text-sm text-muted-foreground">{t('pages.upstreamPools.form.notYetInEffect')}</p>
            <Button
              className="w-full"
              disabled={!form.name.trim() || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {t('pages.upstreamPools.form.create')}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={memberModalPool !== null} onOpenChange={(open) => !open && setMemberModalPool(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('pages.upstreamPools.backendsFor', { name: memberModalPool?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {memberModalPool?.members.map((m) => (
              <div key={m.id} className="flex items-center justify-between gap-3">
                <span className="font-mono text-sm">{m.host}:{m.port}</span>
                <div className="flex items-center gap-2">
                  <Switch
                    id={`member-${m.id}`}
                    checked={m.enabled}
                    aria-label={t('pages.upstreamPools.enabledFor', { host: m.host, port: m.port })}
                    onCheckedChange={(v) =>
                      updateMemberMutation.mutate({
                        poolId: memberModalPool.id, memberId: m.id, body: { enabled: v },
                      })
                    }
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={t('pages.upstreamPools.removeBackend', { host: m.host, port: m.port })}
                    onClick={() => setMemberToRemove({ pool: memberModalPool, member: m })}
                  >
                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                  </Button>
                </div>
              </div>
            ))}
            <div className="flex items-end gap-2">
              <div className="flex-1 space-y-2">
                <Label htmlFor="member-host">{t('pages.upstreamPools.form.host')}</Label>
                <Input
                  id="member-host"
                  value={memberForm.host}
                  onChange={(e) => setMemberForm({ ...memberForm, host: e.target.value })}
                />
              </div>
              <div className="w-28 space-y-2">
                <Label htmlFor="member-port">{t('pages.upstreamPools.form.port')}</Label>
                <Input
                  id="member-port"
                  value={memberForm.port}
                  onChange={(e) => setMemberForm({ ...memberForm, port: e.target.value })}
                />
              </div>
              <Button
                disabled={!memberForm.host.trim() || !memberForm.port.trim() || addMemberMutation.isPending}
                onClick={() =>
                  memberModalPool && addMemberMutation.mutate({
                    poolId: memberModalPool.id,
                    body: { host: memberForm.host.trim(), port: Number(memberForm.port) },
                  })
                }
              >
                {t('pages.upstreamPools.form.addBackend')}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={poolToDelete !== null} onOpenChange={(open) => !open && setPoolToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('pages.upstreamPools.confirmDelete.title', { name: poolToDelete?.name ?? '' })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {poolToDelete && poolToDelete.routes_using > 0
                ? t('pages.upstreamPools.confirmDelete.inUse', { count: poolToDelete.routes_using })
                : t('pages.upstreamPools.confirmDelete.unused')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (poolToDelete) deleteMutation.mutate(poolToDelete.id)
                setPoolToDelete(null)
              }}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={memberToRemove !== null} onOpenChange={(open) => !open && setMemberToRemove(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('pages.upstreamPools.confirmRemoveBackend.title', {
                host: memberToRemove?.member.host ?? '',
                port: memberToRemove?.member.port ?? 0,
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.upstreamPools.confirmRemoveBackend.body')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (memberToRemove) {
                  removeMemberMutation.mutate({
                    poolId: memberToRemove.pool.id, memberId: memberToRemove.member.id,
                  })
                }
                setMemberToRemove(null)
              }}
            >
              {t('pages.upstreamPools.form.remove')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
