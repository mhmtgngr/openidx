import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// The organization's agent settings (GET/PUT /agent/settings): claim mode
// and the update ring (Faz B8.5).
export interface AgentSettings {
  claim_mode: string
  update_channel: 'stable' | 'beta'
  update_pin_version: string
  update_rollout_percent: number
  update_paused: boolean
}

// AgentUpdatesSection is the "Updates" card: which release channel the fleet
// follows, an optional pinned version, how much of the fleet a new release
// reaches, and a pause.
export function AgentUpdatesSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['agent-settings'],
    queryFn: () => api.get<AgentSettings>('/api/v1/access/agent/settings'),
  })
  const [channel, setChannel] = useState<'stable' | 'beta'>('stable')
  const [pin, setPin] = useState('')
  const [percent, setPercent] = useState(100)
  const [paused, setPaused] = useState(false)

  useEffect(() => {
    if (!data) return
    setChannel(data.update_channel === 'beta' ? 'beta' : 'stable')
    setPin(data.update_pin_version ?? '')
    setPercent(data.update_rollout_percent ?? 100)
    setPaused(!!data.update_paused)
  }, [data])

  const save = useMutation({
    mutationFn: () =>
      api.put<AgentSettings>('/api/v1/access/agent/settings', {
        update_channel: channel,
        update_pin_version: pin.trim(),
        update_rollout_percent: percent,
        update_paused: paused,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-settings'] })
      toast({ title: t('pages.agentFleet.updates.saved') })
    },
    onError: () => toast({ title: t('pages.agentFleet.updates.saveFailed'), variant: 'destructive' }),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('pages.agentFleet.updates.heading')}</CardTitle>
        <p className="text-sm text-muted-foreground">{t('pages.agentFleet.updates.intro')}</p>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSpinner />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.agentFleet.updates.heading')} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div>
              <label htmlFor="agent-update-channel" className="text-sm font-medium">
                {t('pages.agentFleet.updates.channel')}
              </label>
              <select
                id="agent-update-channel"
                value={channel}
                onChange={(e) => setChannel(e.target.value as 'stable' | 'beta')}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="stable">{t('pages.agentFleet.updates.stable')}</option>
                <option value="beta">{t('pages.agentFleet.updates.beta')}</option>
              </select>
            </div>
            <div>
              <label htmlFor="agent-update-pin" className="text-sm font-medium">
                {t('pages.agentFleet.updates.pin')}
              </label>
              <Input
                id="agent-update-pin"
                placeholder={t('pages.agentFleet.updates.pinPlaceholder')}
                value={pin}
                onChange={(e) => setPin(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="agent-update-rollout" className="text-sm font-medium">
                {t('pages.agentFleet.updates.rollout')}
              </label>
              <Input
                id="agent-update-rollout"
                type="number"
                min={0}
                max={100}
                value={percent}
                onChange={(e) => setPercent(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
              />
            </div>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={paused} onChange={(e) => setPaused(e.target.checked)} />
                {t('pages.agentFleet.updates.paused')}
              </label>
              <Button onClick={() => save.mutate()} disabled={save.isPending}>
                {t('pages.agentFleet.updates.save')}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// updateStateLabel reads the state of an agent row's last update outcome.
export function updateStateLabel(state: unknown): string | null {
  if (!state || typeof state !== 'object') return null
  const s = (state as { state?: string }).state
  return typeof s === 'string' && s ? s : null
}
