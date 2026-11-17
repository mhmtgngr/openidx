import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

export const AGENTIC_MODES = ['off', 'observe', 'tier0', 'tier1'] as const
type Mode = (typeof AGENTIC_MODES)[number]

export const PROVIDERS = ['none', 'anthropic', 'openai_compat'] as const
export const REDACTIONS = ['off', 'mask', 'strict'] as const
type Provider = (typeof PROVIDERS)[number]
type Redaction = (typeof REDACTIONS)[number]

export interface AgenticSettings {
  mode: Mode
  kill_switch: boolean
  effective_mode: Mode
  provider: Provider
  model: string
  base_url: string
  redaction: Redaction
  has_api_key: boolean
  cloud_consent_at?: string
}

interface ProviderBody {
  provider: Provider
  model: string
  base_url: string
  redaction: Redaction
  api_key?: string
  cloud_consent?: boolean
}

/** The assistant's model: none, Claude (with the organization's consent), or one it runs itself. */
function ProviderForm({
  s, saving, onSave,
}: { s: AgenticSettings; saving: boolean; onSave: (b: ProviderBody) => void }) {
  const { t } = useTranslation()
  const [provider, setProvider] = useState<Provider>(s.provider)
  const [model, setModel] = useState(s.model)
  const [baseUrl, setBaseUrl] = useState(s.base_url)
  const [redaction, setRedaction] = useState<Redaction>(s.redaction)
  const [apiKey, setApiKey] = useState('')
  const [consent, setConsent] = useState(Boolean(s.cloud_consent_at))
  const cloud = provider === 'anthropic'
  const local = provider === 'openai_compat'
  const field = 'h-9 rounded-md border border-input bg-background px-3 text-sm block'
  return (
    <form
      className="space-y-3 border-t pt-4"
      onSubmit={(e) => {
        e.preventDefault()
        onSave({
          provider, model, base_url: baseUrl, redaction,
          ...(apiKey ? { api_key: apiKey } : {}),
          ...(cloud && consent ? { cloud_consent: true } : {}),
        })
        setApiKey('')
      }}
    >
      <h3 className="text-sm font-medium">{t('pages.agentFleet.agentic.assistant.title')}</h3>
      <p className="text-sm text-muted-foreground">{t('pages.agentFleet.agentic.assistant.description')}</p>
      <div className="flex flex-wrap items-end gap-4">
        <div>
          <label htmlFor="agentic-provider" className="text-sm font-medium block">{t('pages.agentFleet.agentic.assistant.provider')}</label>
          <select id="agentic-provider" value={provider} onChange={(e) => setProvider(e.target.value as Provider)} className={field}>
            {PROVIDERS.map((p) => (
              <option key={p} value={p}>{t(`pages.agentFleet.agentic.assistant.providers.${p}`)}</option>
            ))}
          </select>
        </div>
        {provider !== 'none' && (
          <div>
            <label htmlFor="agentic-model" className="text-sm font-medium block">{t('pages.agentFleet.agentic.assistant.model')}</label>
            <Input id="agentic-model" value={model} onChange={(e) => setModel(e.target.value)} placeholder={cloud ? 'claude-sonnet-5-5' : 'llama3.1'} />
          </div>
        )}
        {local && (
          <div>
            <label htmlFor="agentic-base-url" className="text-sm font-medium block">{t('pages.agentFleet.agentic.assistant.baseUrl')}</label>
            <Input id="agentic-base-url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://ollama.internal:11434/v1" />
          </div>
        )}
        {provider !== 'none' && (
          <div>
            <label htmlFor="agentic-key" className="text-sm font-medium block">{t('pages.agentFleet.agentic.assistant.apiKey')}</label>
            <Input
              id="agentic-key" type="password" autoComplete="off" value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={s.has_api_key ? t('pages.agentFleet.agentic.assistant.keyKept') : ''}
            />
          </div>
        )}
        {provider !== 'none' && (
          <div>
            <label htmlFor="agentic-redaction" className="text-sm font-medium block">{t('pages.agentFleet.agentic.assistant.redaction')}</label>
            <select id="agentic-redaction" value={redaction} onChange={(e) => setRedaction(e.target.value as Redaction)} className={field}>
              {REDACTIONS.filter((r) => !(cloud && r === 'off')).map((r) => (
                <option key={r} value={r}>{t(`pages.agentFleet.agentic.assistant.redactions.${r}`)}</option>
              ))}
            </select>
          </div>
        )}
      </div>
      {cloud && (
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>{t('pages.agentFleet.agentic.assistant.consent')}</span>
        </label>
      )}
      <Button type="submit" disabled={saving || (cloud && !consent)}>{t('pages.agentFleet.agentic.assistant.save')}</Button>
    </form>
  )
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
    mutationFn: (body: { mode?: Mode; kill_switch?: boolean } | ProviderBody) =>
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
        <ProviderForm key={`${s.provider}|${s.model}|${s.base_url}|${s.redaction}|${s.has_api_key}`} s={s} saving={save.isPending} onSave={(b) => save.mutate(b)} />
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
