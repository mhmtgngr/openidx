import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

export const AGENTIC_MODES = ['off', 'observe', 'tier0', 'tier1'] as const
type Mode = (typeof AGENTIC_MODES)[number]

export interface AgenticSettings {
  mode: Mode
  kill_switch: boolean
  effective_mode: Mode
}

export interface AgenticAction {
  id: string
  agent_id: string
  action: string
  cause: string
  outcome: 'observed' | 'applied' | 'suppressed'
  reason?: string
  created_at: string
}

const KNOWN_REASONS = ['observe_mode', 'mode_below_fix', 'anti_flap', 'kill_switch', 'queue_busy']
const KNOWN_ACTIONS = ['restart_tunnel', 'collect_logs', 'update_agent']

/**
 * How far the platform may fix devices by itself, the kill switch, and what it
 * did lately. The server decides everything; this only shows and sets it.
 */
export function AgenticSettingsSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const settings = useQuery({
    queryKey: ['agentic-settings'],
    queryFn: () => api.get<AgenticSettings>('/api/v1/access/agentic/settings'),
  })
  const actions = useQuery({
    queryKey: ['agentic-actions'],
    queryFn: () => api.get<{ actions: AgenticAction[] }>('/api/v1/access/agentic/actions'),
  })
  const save = useMutation({
    mutationFn: (body: { mode?: Mode; kill_switch?: boolean }) =>
      api.put<AgenticSettings>('/api/v1/access/agentic/settings', body),
    onSuccess: (data) => {
      queryClient.setQueryData(['agentic-settings'], data)
      toast({ title: t('pages.agentFleet.agentic.saved') })
    },
    onError: () => toast({ title: t('pages.agentFleet.agentic.saveFailed'), variant: 'destructive' }),
  })

  if (settings.isLoading) return <LoadingSpinner />
  if (settings.isError || !settings.data) return <QueryError error={settings.error} />
  const s = settings.data
  const rows = actions.data?.actions ?? []
  const word = (known: string[], group: string, key?: string) =>
    key && known.includes(key) ? t(`pages.agentFleet.agentic.${group}.${key}`) : (key ?? '')

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('pages.agentFleet.agentic.title')}</CardTitle>
        <CardDescription>{t('pages.agentFleet.agentic.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label htmlFor="agentic-mode" className="text-sm font-medium block">
              {t('pages.agentFleet.agentic.mode')}
            </label>
            <select
              id="agentic-mode"
              value={s.mode}
              disabled={save.isPending}
              onChange={(e) => save.mutate({ mode: e.target.value as Mode })}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              {AGENTIC_MODES.map((m) => (
                <option key={m} value={m}>{t(`pages.agentFleet.agentic.modes.${m}`)}</option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={s.kill_switch}
              disabled={save.isPending}
              onChange={(e) => save.mutate({ kill_switch: e.target.checked })}
            />
            {t('pages.agentFleet.agentic.killSwitch')}
          </label>
        </div>
        {s.effective_mode !== s.mode && (
          <p className="text-sm text-muted-foreground">
            {t('pages.agentFleet.agentic.capped', { mode: s.effective_mode })}
          </p>
        )}
        {s.kill_switch && (
          <p role="status" className="text-sm font-medium text-destructive">
            {t('pages.agentFleet.agentic.killOn')}
          </p>
        )}
        <div>
          <h3 className="text-sm font-medium mb-2">{t('pages.agentFleet.agentic.recent')}</h3>
          {rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('pages.agentFleet.agentic.none')}</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {rows.slice(0, 10).map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-2">
                  <Badge variant={r.outcome === 'applied' ? 'default' : 'secondary'}>
                    {t(`pages.agentFleet.agentic.outcome.${r.outcome}`)}
                  </Badge>
                  <span>{word(KNOWN_ACTIONS, 'action', r.action)}</span>
                  <span className="text-muted-foreground">
                    {r.agent_id}
                    {r.reason ? ` · ${word(KNOWN_REASONS, 'reason', r.reason)}` : ''}
                    {' · '}
                    {new Date(r.created_at).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
