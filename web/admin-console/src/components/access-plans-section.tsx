import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Check { checked: boolean; allowed: boolean; why?: string }

export interface AccessPlan {
  id?: string
  status: 'pending' | 'applied' | 'rejected' | 'expired' | 'superseded' | 'undone' | 'ready' | 'noop' | 'blocked'
  resource: { id: string; name: string; kind?: string }
  group: { id: string; name: string; members: number }
  plan: { status: string; blockers: string[]; notes: string[]; risks: string[] }
  now?: Check
  outcome?: { granted?: boolean; after?: Check }
}

const KNOWN = [
  'RESOURCE_NOT_FOUND', 'GROUP_NOT_FOUND', 'RESOURCE_DISABLED', 'ALREADY_GRANTED',
  'EMPTY_GROUP', 'WIDE_GROUP', 'PRIVILEGED_RESOURCE',
]

/**
 * Opens an application to a group with a plan: the rules lay it out, an
 * administrator approves it, and the result is checked with the same decision
 * engine the proxy uses. Nothing changes until approval, and an applied plan can
 * be undone.
 */
export function AccessPlansSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [resource, setResource] = useState('')
  const [group, setGroup] = useState('')
  const [preview, setPreview] = useState<AccessPlan | null>(null)

  const list = useQuery({
    queryKey: ['access-plans'],
    queryFn: () => api.get<{ plans: AccessPlan[] }>('/api/v1/access/plans'),
  })
  const word = (code: string) => (KNOWN.includes(code) ? t(`accessPlans.code.${code}`) : code)
  const statusOf = (e: unknown) => (e as { response?: { status?: number; data?: AccessPlan } })?.response
  const check = (c: Check | undefined, when: 'now' | 'after') => {
    if (!c || !c.checked) return t(`accessPlans.${when}.none`)
    return c.allowed ? t(`accessPlans.${when}.allowed`) : t(`accessPlans.${when}.blocked`, { why: c.why ?? '' })
  }

  const make = useMutation({
    mutationFn: () => api.post<AccessPlan>('/api/v1/access/plans', { resource: resource.trim(), group: group.trim() }),
    onSuccess: (p) => {
      setPreview(p)
      queryClient.invalidateQueries({ queryKey: ['access-plans'] })
    },
    onError: (e) => {
      const r = statusOf(e)
      if (r?.status === 422 && r.data?.plan) {
        setPreview(r.data)
        return
      }
      toast({ title: t(r?.status === 409 ? 'accessPlans.ambiguous' : 'accessPlans.failed'), variant: 'destructive' })
    },
  })
  const act = useMutation({
    mutationFn: (v: { id: string; op: 'approve' | 'reject' | 'undo' }) =>
      api.post(`/api/v1/access/plans/${v.id}/${v.op}`, {}),
    onSuccess: (_d, v) => {
      setPreview(null)
      queryClient.invalidateQueries({ queryKey: ['access-plans'] })
      toast({ title: t(v.op === 'approve' ? 'accessPlans.approved' : v.op === 'undo' ? 'accessPlans.undone' : 'accessPlans.dismissed') })
    },
    onError: (e) => {
      queryClient.invalidateQueries({ queryKey: ['access-plans'] })
      toast({ title: t(statusOf(e)?.status === 409 ? 'accessPlans.stale' : 'accessPlans.failed'), variant: 'destructive' })
    },
  })

  const plans = list.data?.plans ?? []
  const renderPlan = (p: AccessPlan, actions?: React.ReactNode) => (
    <div key={p.id ?? 'preview'} className="rounded-md border p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{t('accessPlans.step', { group: p.group.name, resource: p.resource.name })}</span>
        <Badge variant={p.status === 'blocked' ? 'destructive' : 'secondary'}>{t(`accessPlans.status.${p.status === 'ready' ? 'pending' : p.status}`)}</Badge>
      </div>
      {p.group.id && <p className="text-muted-foreground">{t('accessPlans.members', { count: p.group.members })}</p>}
      <ul className="list-disc pl-5 space-y-1">
        {[...p.plan.blockers, ...p.plan.notes, ...p.plan.risks].map((c) => <li key={c}>{word(c)}</li>)}
      </ul>
      {p.now && <p className="text-muted-foreground">{check(p.now, 'now')}</p>}
      {p.outcome?.after && <p className="text-muted-foreground">{check(p.outcome.after, 'after')}</p>}
      {actions}
    </div>
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('accessPlans.title')}</CardTitle>
        <CardDescription>{t('accessPlans.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            if (resource.trim() && group.trim()) make.mutate()
          }}
        >
          <div>
            <label htmlFor="plan-resource" className="font-medium block">{t('accessPlans.resource')}</label>
            <Input id="plan-resource" value={resource} onChange={(e) => setResource(e.target.value)} />
          </div>
          <div>
            <label htmlFor="plan-group" className="font-medium block">{t('accessPlans.group')}</label>
            <Input id="plan-group" value={group} onChange={(e) => setGroup(e.target.value)} />
          </div>
          <Button type="submit" disabled={make.isPending || !resource.trim() || !group.trim()}>
            {make.isPending ? t('accessPlans.planning') : t('accessPlans.plan')}
          </Button>
        </form>

        {preview && renderPlan(preview)}

        <div className="space-y-2">
          <h3 className="font-medium">{t('accessPlans.recent')}</h3>
          {plans.length === 0 ? (
            <p className="text-muted-foreground">{t('accessPlans.none')}</p>
          ) : (
            plans.map((p) =>
              renderPlan(
                p,
                p.id && (
                  <div className="flex gap-2">
                    {p.status === 'pending' && (
                      <>
                        <Button size="sm" disabled={act.isPending} onClick={() => act.mutate({ id: p.id!, op: 'approve' })}>{t('accessPlans.approve')}</Button>
                        <Button size="sm" variant="outline" disabled={act.isPending} onClick={() => act.mutate({ id: p.id!, op: 'reject' })}>{t('accessPlans.dismiss')}</Button>
                      </>
                    )}
                    {p.status === 'applied' && p.outcome?.granted && (
                      <Button size="sm" variant="outline" disabled={act.isPending} onClick={() => act.mutate({ id: p.id!, op: 'undo' })}>{t('accessPlans.undo')}</Button>
                    )}
                  </div>
                ),
              ),
            )
          )}
        </div>
      </CardContent>
    </Card>
  )
}
