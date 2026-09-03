import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { SelectableRow } from '../components/selectable-row'
import { ConfirmAction } from '../components/confirm-action'
import { Bot, Plus, RotateCw, Pause, Play, Trash2, Shield, Activity, Key, Clock } from 'lucide-react'

interface AIAgent {
  id: string
  name: string
  description: string
  agent_type: string
  owner_id: string | null
  owner_email: string
  status: string
  capabilities: string[]
  trust_level: string
  rate_limits: { requests_per_minute: number; requests_per_hour: number }
  allowed_scopes: string[]
  ip_allowlist: string[]
  metadata: Record<string, unknown>
  last_active_at: string | null
  created_at: string
  updated_at: string
}

interface AIAgentCredential {
  id: string
  credential_type: string
  key_prefix: string
  status: string
  expires_at: string | null
  last_used_at: string | null
  created_at: string
}

interface AgentAnalytics {
  total_agents: number
  active_agents: number
  suspended_agents: number
  by_type: Array<{ type: string; count: number }>
  top_agents_24h: Array<{ id: string; name: string; type: string; activity_count: number }>
  expiring_credentials_30d: number
  recent_failures_24h: number
}

/**
 * The agent lifecycle vocabularies the API owns. Each drives both a row
 * badge (lowercase) and a form select (title case) through its own catalog
 * map, so the two renderings cannot come to hold different members.
 */
const AGENT_TYPES = ['assistant', 'autonomous', 'workflow', 'integration'] as const
const TRUST_LEVELS = ['low', 'medium', 'high'] as const

const typeColors: Record<string, string> = {
  assistant: 'bg-blue-100 text-blue-800',
  autonomous: 'bg-purple-100 text-purple-800',
  workflow: 'bg-green-100 text-green-800',
  integration: 'bg-orange-100 text-orange-800',
}

const trustColors: Record<string, string> = {
  low: 'bg-muted text-foreground',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-red-100 text-red-800',
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  suspended: 'bg-red-100 text-red-800',
  inactive: 'bg-muted text-foreground',
}

export function AIAgentsPage() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [newAgent, setNewAgent] = useState({ name: '', description: '', agent_type: 'assistant', trust_level: 'low' })
  const [newApiKey, setNewApiKey] = useState<string | null>(null)

  const { data: agentsData, isLoading, isError, error } = useQuery({
    queryKey: ['ai-agents'],
    queryFn: () => api.get<{ data: AIAgent[]; total: number }>('/api/v1/ai-agents'),
  })

  const { data: analytics } = useQuery<AgentAnalytics>({
    queryKey: ['ai-agents-analytics'],
    queryFn: () => api.get<AgentAnalytics>('/api/v1/ai-agents/analytics'),
  })

  const { data: agentDetail } = useQuery({
    queryKey: ['ai-agent', selectedAgent],
    queryFn: () => api.get<{ data: AIAgent; credentials: AIAgentCredential[] }>(`/api/v1/ai-agents/${selectedAgent}`),
    enabled: !!selectedAgent,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newAgent) => api.post<{ data: AIAgent; api_key: string }>('/api/v1/ai-agents', data),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
      setShowCreate(false)
      setNewApiKey(resp.api_key)
      setNewAgent({ name: '', description: '', agent_type: 'assistant', trust_level: 'low' })
    },
  })

  const suspendMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ai-agents/${id}/suspend`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
    },
  })

  const activateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ai-agents/${id}/activate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/ai-agents/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
      queryClient.invalidateQueries({ queryKey: ['ai-agents-analytics'] })
      setSelectedAgent(null)
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post<{ api_key: string }>(`/api/v1/ai-agents/${id}/rotate-credentials`, {}),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['ai-agent', selectedAgent] })
      setNewApiKey(resp.api_key)
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.aiAgents.resource')} />
  }

  const agents = agentsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('pages.aiAgents.title')}</h1>
          <p className="text-muted-foreground">{t('pages.aiAgents.subtitle')}</p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.aiAgents.create')}
        </Button>
      </div>

      {newApiKey && (
        <Card className="border-yellow-300 bg-yellow-50">
          <CardContent className="pt-4">
            <p className="font-medium text-yellow-800 mb-2">
              {t('pages.aiAgents.newKeyWarning')}
            </p>
            <code className="block bg-background p-3 rounded border text-sm break-all">{newApiKey}</code>
            <Button variant="outline" className="mt-2" onClick={() => setNewApiKey(null)}>
              {t('pages.aiAgents.dismiss')}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Analytics Summary */}
      {analytics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <Card><CardContent className="pt-4 text-center">
            <Bot className="h-5 w-5 mx-auto mb-1 text-primary" />
            <p className="text-2xl font-bold">{analytics.total_agents}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.total')}</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Play className="h-5 w-5 mx-auto mb-1 text-green-600" />
            <p className="text-2xl font-bold">{analytics.active_agents}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.active')}</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Pause className="h-5 w-5 mx-auto mb-1 text-red-600" />
            <p className="text-2xl font-bold">{analytics.suspended_agents}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.suspended')}</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Key className="h-5 w-5 mx-auto mb-1 text-orange-600" />
            <p className="text-2xl font-bold">{analytics.expiring_credentials_30d}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.expiringKeys')}</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Activity className="h-5 w-5 mx-auto mb-1 text-purple-600" />
            <p className="text-2xl font-bold">{(analytics.top_agents_24h || []).reduce((s, a) => s + a.activity_count, 0)}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.actions24h')}</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Shield className="h-5 w-5 mx-auto mb-1 text-red-600" />
            <p className="text-2xl font-bold">{analytics.recent_failures_24h}</p>
            <p className="text-xs text-muted-foreground">{t('pages.aiAgents.stats.failures24h')}</p>
          </CardContent></Card>
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <Card>
          <CardHeader><CardTitle>{t('pages.aiAgents.form.title')}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.aiAgents.form.name')}</label>
              <input className="w-full border rounded px-3 py-2 mt-1" value={newAgent.name}
                onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })} placeholder={t('pages.aiAgents.form.namePlaceholder')} />
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.aiAgents.form.description')}</label>
              <input className="w-full border rounded px-3 py-2 mt-1" value={newAgent.description}
                onChange={(e) => setNewAgent({ ...newAgent, description: e.target.value })} placeholder={t('pages.aiAgents.form.descriptionPlaceholder')} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">{t('pages.aiAgents.form.type')}</label>
                <select className="w-full border rounded px-3 py-2 mt-1" value={newAgent.agent_type}
                  onChange={(e) => setNewAgent({ ...newAgent, agent_type: e.target.value })}>
                  {AGENT_TYPES.map((type) => (
                    <option key={type} value={type}>
                      {t(`pages.aiAgents.form.typeOptions.${type}`)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.aiAgents.form.trustLevel')}</label>
                <select className="w-full border rounded px-3 py-2 mt-1" value={newAgent.trust_level}
                  onChange={(e) => setNewAgent({ ...newAgent, trust_level: e.target.value })}>
                  {TRUST_LEVELS.map((level) => (
                    <option key={level} value={level}>
                      {t(`pages.aiAgents.form.trustOptions.${level}`)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={() => createMutation.mutate(newAgent)} disabled={!newAgent.name || createMutation.isPending}>
                {createMutation.isPending
                  ? t('pages.aiAgents.form.creating')
                  : t('pages.aiAgents.form.submit')}
              </Button>
              <Button variant="outline" onClick={() => setShowCreate(false)}>
                {t('common.cancel')}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent List */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>{t('pages.aiAgents.listTitle', { n: agents.length })}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="divide-y">
                {agents.map((agent) => (
                  <SelectableRow
                    key={agent.id}
                    aria-pressed={selectedAgent === agent.id}
                    className={`py-3 flex items-center justify-between hover:bg-muted px-2 rounded ${selectedAgent === agent.id ? 'bg-blue-50 dark:bg-blue-950/30' : ''}`}
                    onSelect={() => setSelectedAgent(agent.id)}>
                    <div className="flex items-center gap-3">
                      <Bot className="h-8 w-8 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{agent.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {agent.description || t('pages.aiAgents.noDescription')}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={typeColors[agent.agent_type] || 'bg-muted'}>
                        {t(`pages.aiAgents.agentTypes.${agent.agent_type}`, {
                          defaultValue: agent.agent_type,
                        })}
                      </Badge>
                      <Badge className={trustColors[agent.trust_level] || 'bg-muted'}>
                        {t('pages.aiAgents.trustBadge', {
                          level: t(`pages.aiAgents.trustLevels.${agent.trust_level}`, {
                            defaultValue: agent.trust_level,
                          }),
                        })}
                      </Badge>
                      <Badge className={statusColors[agent.status] || 'bg-muted'}>
                        {t(`pages.aiAgents.statuses.${agent.status}`, {
                          defaultValue: agent.status,
                        })}
                      </Badge>
                    </div>
                  </SelectableRow>
                ))}
                {agents.length === 0 && (
                  <p className="text-center text-muted-foreground py-8">
                    {t('pages.aiAgents.empty')}
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Agent Detail */}
        <div>
          {selectedAgent && agentDetail ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bot className="h-5 w-5" />{agentDetail.data.name}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-sm text-muted-foreground">{t('pages.aiAgents.detail.type')}</p>
                  <Badge className={typeColors[agentDetail.data.agent_type] || ''}>
                    {t(`pages.aiAgents.agentTypes.${agentDetail.data.agent_type}`, {
                      defaultValue: agentDetail.data.agent_type,
                    })}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">
                    {t('pages.aiAgents.detail.trustLevel')}
                  </p>
                  <Badge className={trustColors[agentDetail.data.trust_level] || ''}>
                    {t(`pages.aiAgents.trustLevels.${agentDetail.data.trust_level}`, {
                      defaultValue: agentDetail.data.trust_level,
                    })}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">{t('pages.aiAgents.detail.status')}</p>
                  <Badge className={statusColors[agentDetail.data.status] || ''}>
                    {t(`pages.aiAgents.statuses.${agentDetail.data.status}`, {
                      defaultValue: agentDetail.data.status,
                    })}
                  </Badge>
                </div>
                {agentDetail.data.owner_email && (
                  <div>
                    <p className="text-sm text-muted-foreground">{t('pages.aiAgents.detail.owner')}</p>
                    <p className="text-sm">{agentDetail.data.owner_email}</p>
                  </div>
                )}
                {agentDetail.data.last_active_at && (
                  <div>
                    <p className="text-sm text-muted-foreground">
                      {t('pages.aiAgents.detail.lastActive')}
                    </p>
                    <p className="text-sm flex items-center gap-1"><Clock className="h-3 w-3" />{new Date(agentDetail.data.last_active_at).toLocaleString()}</p>
                  </div>
                )}
                {agentDetail.data.allowed_scopes?.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">
                      {t('pages.aiAgents.detail.scopes')}
                    </p>
                    {/* OAuth scopes are wire values a developer requests. */}
                    <div className="flex flex-wrap gap-1">
                      {agentDetail.data.allowed_scopes.map((s) => (
                        <Badge key={s} variant="outline" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Credentials */}
                <div>
                  <p className="text-sm font-medium mb-2">{t('pages.aiAgents.detail.credentials')}</p>
                  {(agentDetail.credentials || []).map((cred) => (
                    <div key={cred.id} className="flex items-center justify-between text-sm border rounded p-2 mb-1">
                      <div>
                        <span className="font-mono">{cred.key_prefix}...</span>
                        <Badge className="ml-2" variant={cred.status === 'active' ? 'default' : 'destructive'}>
                          {t(`pages.aiAgents.credentialStatuses.${cred.status}`, {
                            defaultValue: cred.status,
                          })}
                        </Badge>
                      </div>
                      {cred.expires_at && (
                        <span className="text-xs text-muted-foreground">
                          {t('pages.aiAgents.detail.expires', {
                            date: new Date(cred.expires_at).toLocaleDateString(),
                          })}
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                {/* Actions */}
                <div className="flex flex-wrap gap-2 pt-2 border-t">
                  <ConfirmAction
                    title={t('pages.aiAgents.rotate.title')}
                    description={t('pages.aiAgents.rotate.desc')}
                    destructive
                    confirmLabel={t('pages.aiAgents.rotate.confirm')}
                    onConfirm={() => rotateMutation.mutate(selectedAgent)}
                  >
                    {(open) => (
                      <Button size="sm" variant="outline" onClick={open}>
                        <RotateCw className="h-3 w-3 mr-1" />
                        {t('pages.aiAgents.rotate.button')}
                      </Button>
                    )}
                  </ConfirmAction>
                  {agentDetail.data.status === 'active' ? (
                    <Button size="sm" variant="outline" onClick={() => suspendMutation.mutate(selectedAgent)}>
                      <Pause className="h-3 w-3 mr-1" />
                      {t('pages.aiAgents.suspend')}
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => activateMutation.mutate(selectedAgent)}>
                      <Play className="h-3 w-3 mr-1" />
                      {t('pages.aiAgents.activate')}
                    </Button>
                  )}
                  <ConfirmAction
                    title={t('pages.aiAgents.deleteDialog.title')}
                    description={t('pages.aiAgents.deleteDialog.desc')}
                    destructive
                    confirmLabel={t('common.delete')}
                    onConfirm={() => selectedAgent ? deleteMutation.mutateAsync(selectedAgent) : undefined}
                  >
                    {(open) => (
                      <Button size="sm" variant="destructive" onClick={open}>
                        <Trash2 className="h-3 w-3 mr-1" />
                        {t('common.delete')}
                      </Button>
                    )}
                  </ConfirmAction>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center text-muted-foreground">
                <Bot className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                <p>{t('pages.aiAgents.detail.selectPrompt')}</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
