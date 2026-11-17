import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

export interface RolloutProposal {
  id: string
  kind: 'rollout_pause' | 'rollout_advance'
  params: { action: string; percent?: number }
  reasons: string[]
}

export interface RolloutAssessment {
  target: string
  target_source: 'pin' | 'channel' | ''
  verdict: {
    status: 'no_target' | 'paused' | 'unhealthy' | 'soaking' | 'ready' | 'complete'
    reasons: string[]
    counts: { in_ring: number; on_target: number; behind: number; failed: number; offline: number }
  }
  pending: RolloutProposal[]
}

const KNOWN_REASONS = [
  'NO_TARGET', 'PAUSED', 'FAILURES', 'SOAKING', 'APPLYING', 'WAITING_ON_DEVICES',
  'READY', 'EMPTY_RING', 'ALL_ON_TARGET', 'OFFLINE_IGNORED',
]

/**
 * The rollout assistant: how the agent update is going, in words, and the one
 * step the rules recommend. The rules decide everything shown here; a step that
 * widens the rollout is only ever applied when an administrator approves it.
 */
export function RolloutAssistantSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const q = useQuery({
    queryKey: ['agent-rollout'],
    queryFn: () => api.get<RolloutAssessment>('/api/v1/access/agent/rollout'),
    refetchInterval: 60_000,
  })
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['agent-rollout'] })
    queryClient.invalidateQueries({ queryKey: ['agent-settings'] })
  }
  const decide = useMutation({
    mutationFn: (v: { id: string; op: 'approve' | 'reject' }) =>
      api.post(`/api/v1/access/agent/rollout/proposals/${v.id}/${v.op}`, {}),
    onSuccess: (_d, v) => {
      refresh()
      toast({ title: t(v.op === 'approve' ? 'pages.agentFleet.rollout.approved' : 'pages.agentFleet.rollout.dismissed') })
    },
    onError: (e) => {
      refresh()
      const status = (e as { response?: { status?: number } })?.response?.status
      toast({
        title: t(status === 409 ? 'pages.agentFleet.rollout.stale' : 'pages.agentFleet.rollout.failed'),
        variant: 'destructive',
      })
    },
  })

  if (q.isLoading) return <LoadingSpinner />
  if (q.isError) return <QueryError error={q.error} />
  // An answer without a verdict is not an assessment; show nothing rather than guess.
  if (!q.data?.verdict) return null
  const a = q.data
  const c = a.verdict.counts
  const reason = (code: string) =>
    KNOWN_REASONS.includes(code) ? t(`pages.agentFleet.rollout.reason.${code}`) : code

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {t('pages.agentFleet.rollout.title')}
          <Badge variant={a.verdict.status === 'unhealthy' ? 'destructive' : 'secondary'}>
            {t(`pages.agentFleet.rollout.status.${a.verdict.status}`)}
          </Badge>
        </CardTitle>
        <CardDescription>{t('pages.agentFleet.rollout.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p>
          <span className="font-medium">{t('pages.agentFleet.rollout.target')}: </span>
          {a.target || t('pages.agentFleet.rollout.targetNone')}
        </p>
        {a.target && (
          <p className="text-muted-foreground">
            {t('pages.agentFleet.rollout.counts', {
              inRing: c.in_ring, onTarget: c.on_target, behind: c.behind, failed: c.failed, offline: c.offline,
            })}
          </p>
        )}
        <ul className="list-disc pl-5 space-y-1">
          {a.verdict.reasons.map((code) => (
            <li key={code}>{reason(code)}</li>
          ))}
        </ul>
        {a.pending.length === 0 ? (
          <p className="text-muted-foreground">{t('pages.agentFleet.rollout.none')}</p>
        ) : (
          a.pending.map((p) => (
            <div key={p.id} className="flex flex-wrap items-center gap-2 rounded-md border p-3">
              <span className="font-medium">
                {t(`pages.agentFleet.rollout.proposal.${p.kind}`, { percent: p.params.percent })}
              </span>
              <div className="ml-auto flex gap-2">
                <Button size="sm" disabled={decide.isPending} onClick={() => decide.mutate({ id: p.id, op: 'approve' })}>
                  {t('pages.agentFleet.rollout.approve')}
                </Button>
                <Button size="sm" variant="outline" disabled={decide.isPending} onClick={() => decide.mutate({ id: p.id, op: 'reject' })}>
                  {t('pages.agentFleet.rollout.dismiss')}
                </Button>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  )
}
