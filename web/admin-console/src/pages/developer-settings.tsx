import { useState, useEffect } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Save,
  Key,
  Webhook,
  Globe,
  Gauge,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DeveloperSettings {
  api_keys: {
    max_keys_per_user: number
    default_expiry_days: number
    allowed_scopes: string[]
  }
  webhooks: {
    ip_allowlist: string[]
    max_retries: number
    retry_delay_seconds: number
  }
  cors: {
    allowed_origins: string[]
  }
  rate_limits: {
    default_rate_limit: number
    burst_limit: number
  }
}

// ApiDeveloperSettings is the flat shape the backend actually serves
// (internal/admin/developer.go). The UI models the same data nested, so we
// adapt at the query/mutation boundary.
interface ApiDeveloperSettings {
  api_key_max_per_user: number
  api_key_default_expiry: string
  api_key_allowed_scopes: string[]
  webhook_ip_allowlist: string[]
  webhook_max_retries: number
  cors_allowed_origins: string[]
  rate_limit_default: number
  sandbox_enabled: boolean
}

// "90d" <-> 90. "0"/"" -> 0 (never expires).
function expiryToDays(v: string | undefined): number {
  if (!v) return 0
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : 0
}
function daysToExpiry(days: number): string {
  return days > 0 ? `${days}d` : '0d'
}

function fromApi(a: ApiDeveloperSettings): DeveloperSettings {
  return {
    api_keys: {
      max_keys_per_user: a.api_key_max_per_user ?? 5,
      default_expiry_days: expiryToDays(a.api_key_default_expiry),
      allowed_scopes: a.api_key_allowed_scopes ?? [],
    },
    webhooks: {
      ip_allowlist: a.webhook_ip_allowlist ?? [],
      max_retries: a.webhook_max_retries ?? 3,
      retry_delay_seconds: 0, // not modeled by the backend
    },
    cors: { allowed_origins: a.cors_allowed_origins ?? [] },
    rate_limits: {
      default_rate_limit: a.rate_limit_default ?? 100,
      burst_limit: 0, // not modeled by the backend
    },
  }
}

function toApi(s: DeveloperSettings, sandboxEnabled: boolean): ApiDeveloperSettings {
  return {
    api_key_max_per_user: s.api_keys.max_keys_per_user,
    api_key_default_expiry: daysToExpiry(s.api_keys.default_expiry_days),
    api_key_allowed_scopes: s.api_keys.allowed_scopes,
    webhook_ip_allowlist: s.webhooks.ip_allowlist,
    webhook_max_retries: s.webhooks.max_retries,
    cors_allowed_origins: s.cors.allowed_origins,
    rate_limit_default: s.rate_limits.default_rate_limit,
    sandbox_enabled: sandboxEnabled,
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALL_SCOPES = [
  'read:users',
  'write:users',
  'read:groups',
  'write:groups',
  'read:applications',
  'write:applications',
  'read:audit',
  'read:governance',
  'write:governance',
  'read:provisioning',
  'write:provisioning',
] as const

// The expiry choices the API accepts. `0` means "never expires"; the labels
// resolve through the catalog at render.
const EXPIRY_OPTIONS = [
  { value: 30, key: 'd30' },
  { value: 60, key: 'd60' },
  { value: 90, key: 'd90' },
  { value: 180, key: 'd180' },
  { value: 365, key: 'd365' },
  { value: 0, key: 'never' },
] as const

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DeveloperSettingsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState<'api_keys' | 'webhooks' | 'cors' | 'rate_limits'>('api_keys')

  const { data: apiSettings, isLoading, isError, error } = useQuery({
    queryKey: ['developer-settings'],
    queryFn: () => api.get<ApiDeveloperSettings>('/api/v1/developer/settings'),
  })
  const settings = apiSettings ? fromApi(apiSettings) : undefined

  const [formData, setFormData] = useState<DeveloperSettings | null>(null)

  useEffect(() => {
    if (settings && !formData) {
      setFormData(settings)
    }
  }, [settings]) // eslint-disable-line react-hooks/exhaustive-deps

  const updateMutation = useMutation({
    mutationFn: (data: DeveloperSettings) =>
      api.put('/api/v1/developer/settings', toApi(data, apiSettings?.sandbox_enabled ?? false)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['developer-settings'] })
      toast({
        title: t('pages.developerSettings.saved'),
        description: t('pages.developerSettings.savedDesc'),
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('common.error'),
        description: error.message || t('pages.developerSettings.saveFailed'),
        variant: 'destructive',
      })
    },
  })

  const handleSave = () => {
    if (formData) {
      updateMutation.mutate(formData)
    }
  }

  // Helpers to update nested state
  const updateApiKeys = (field: keyof DeveloperSettings['api_keys'], value: number | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        api_keys: { ...formData.api_keys, [field]: value },
      })
    }
  }

  const updateWebhooks = (field: keyof DeveloperSettings['webhooks'], value: number | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        webhooks: { ...formData.webhooks, [field]: value },
      })
    }
  }

  const updateCors = (field: keyof DeveloperSettings['cors'], value: string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        cors: { ...formData.cors, [field]: value },
      })
    }
  }

  const updateRateLimits = (field: keyof DeveloperSettings['rate_limits'], value: number) => {
    if (formData) {
      setFormData({
        ...formData,
        rate_limits: { ...formData.rate_limits, [field]: value },
      })
    }
  }

  const toggleScope = (scope: string) => {
    if (!formData) return
    const current = formData.api_keys.allowed_scopes
    const next = current.includes(scope)
      ? current.filter((s) => s !== scope)
      : [...current, scope]
    updateApiKeys('allowed_scopes', next)
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.developerSettings.title')}</h1>
        <QueryError error={error} resource={t('pages.developerSettings.resource')} />
      </div>
    )
  }

  if (isLoading || !formData) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.developerSettings.title')}</h1>
        <p className="text-center py-8">{t('pages.developerSettings.loading')}</p>
      </div>
    )
  }

  const tabs = [
    { id: 'api_keys' as const, icon: Key },
    { id: 'webhooks' as const, icon: Webhook },
    { id: 'cors' as const, icon: Globe },
    { id: 'rate_limits' as const, icon: Gauge },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.developerSettings.title')}</h1>
          <p className="text-muted-foreground">{t('pages.developerSettings.subtitle')}</p>
        </div>
        <Button onClick={handleSave} disabled={updateMutation.isPending}>
          <Save className="mr-2 h-4 w-4" />
          {updateMutation.isPending
            ? t('pages.developerSettings.saving')
            : t('pages.developerSettings.save')}
        </Button>
      </div>

      <div className="flex gap-6">
        {/* Sidebar tabs */}
        <div className="w-48 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-muted text-foreground'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {t(`pages.developerSettings.tabs.${tab.id}`)}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1">
          {/* API Keys Tab */}
          {activeTab === 'api_keys' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.developerSettings.apiKeys.heading')}</CardTitle>
                  <CardDescription>{t('pages.developerSettings.apiKeys.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">{t('pages.developerSettings.apiKeys.maxKeys')}</label>
                      <Input
                        type="number"
                        min={1}
                        max={50}
                        value={formData.api_keys.max_keys_per_user}
                        onChange={(e) =>
                          updateApiKeys('max_keys_per_user', parseInt(e.target.value) || 1)
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('pages.developerSettings.apiKeys.maxKeysHint')}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">{t('pages.developerSettings.apiKeys.defaultExpiry')}</label>
                      <select
                        value={formData.api_keys.default_expiry_days}
                        onChange={(e) =>
                          updateApiKeys('default_expiry_days', parseInt(e.target.value))
                        }
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      >
                        {EXPIRY_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {t(`pages.developerSettings.apiKeys.expiry.${opt.key}`)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.developerSettings.apiKeys.scopes')}</CardTitle>
                  <CardDescription>{t('pages.developerSettings.apiKeys.scopesDesc')}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
                    {ALL_SCOPES.map((scope) => (
                      <label
                        key={scope}
                        className="flex items-center gap-2 p-2 border rounded hover:bg-muted/50 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={formData.api_keys.allowed_scopes.includes(scope)}
                          onChange={() => toggleScope(scope)}
                          className="rounded"
                        />
                        <span className="text-sm font-mono">{scope}</span>
                      </label>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Webhooks Tab */}
          {activeTab === 'webhooks' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.developerSettings.webhooks.heading')}</CardTitle>
                  <CardDescription>{t('pages.developerSettings.webhooks.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">{t('pages.developerSettings.webhooks.maxRetries')}</label>
                      <Input
                        type="number"
                        min={0}
                        max={10}
                        value={formData.webhooks.max_retries}
                        onChange={(e) =>
                          updateWebhooks('max_retries', parseInt(e.target.value) || 0)
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('pages.developerSettings.webhooks.maxRetriesHint')}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">{t('pages.developerSettings.webhooks.retryDelay')}</label>
                      <Input
                        type="number"
                        min={1}
                        max={3600}
                        value={formData.webhooks.retry_delay_seconds}
                        onChange={(e) =>
                          updateWebhooks(
                            'retry_delay_seconds',
                            parseInt(e.target.value) || 1
                          )
                        }
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('pages.developerSettings.webhooks.retryDelayHint')}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.developerSettings.webhooks.allowlist')}</CardTitle>
                  <CardDescription>{t('pages.developerSettings.webhooks.allowlistDesc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Textarea
                    className="font-mono text-sm min-h-[120px]"
                    placeholder={"10.0.0.0/8\n192.168.1.0/24\n203.0.113.50"}
                    value={(formData.webhooks.ip_allowlist || []).join('\n')}
                    onChange={(e) =>
                      updateWebhooks(
                        'ip_allowlist',
                        e.target.value
                          .split('\n')
                          .map((l) => l.trim())
                          .filter((l) => l.length > 0)
                      )
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('pages.developerSettings.webhooks.allowlistHint')}
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* CORS Tab */}
          {activeTab === 'cors' && (
            <Card>
              <CardHeader>
                <CardTitle>{t('pages.developerSettings.cors.heading')}</CardTitle>
                <CardDescription>{t('pages.developerSettings.cors.desc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">{t('pages.developerSettings.cors.origins')}</label>
                  <Textarea
                    className="font-mono text-sm min-h-[160px]"
                    placeholder={"https://app.example.com\nhttps://staging.example.com\nhttp://localhost:3000"}
                    value={(formData.cors.allowed_origins || []).join('\n')}
                    onChange={(e) =>
                      updateCors(
                        'allowed_origins',
                        e.target.value
                          .split('\n')
                          .map((l) => l.trim())
                          .filter((l) => l.length > 0)
                      )
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    <Trans
                      i18nKey="pages.developerSettings.cors.originsHint"
                      components={[<code key="0" className="bg-muted px-1 rounded" />]}
                    />
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Rate Limits Tab */}
          {activeTab === 'rate_limits' && (
            <Card>
              <CardHeader>
                <CardTitle>{t('pages.developerSettings.rateLimits.heading')}</CardTitle>
                <CardDescription>{t('pages.developerSettings.rateLimits.desc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">
                      {t('pages.developerSettings.rateLimits.defaultLimit')}
                    </label>
                    <Input
                      type="number"
                      min={1}
                      max={100000}
                      value={formData.rate_limits.default_rate_limit}
                      onChange={(e) =>
                        updateRateLimits(
                          'default_rate_limit',
                          parseInt(e.target.value) || 60
                        )
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      {t('pages.developerSettings.rateLimits.defaultLimitHint')}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">
                      {t('pages.developerSettings.rateLimits.burstLimit')}
                    </label>
                    <Input
                      type="number"
                      min={1}
                      max={10000}
                      value={formData.rate_limits.burst_limit}
                      onChange={(e) =>
                        updateRateLimits('burst_limit', parseInt(e.target.value) || 10)
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      {t('pages.developerSettings.rateLimits.burstLimitHint')}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
