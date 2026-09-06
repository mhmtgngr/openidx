import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Building, Shield, Key, Palette, X, Plus, Smartphone, Send } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Settings {
  general: {
    organization_name: string
    support_email: string
    default_language: string
    default_timezone: string
  }
  security: {
    password_policy: {
      min_length: number
      require_uppercase: boolean
      require_lowercase: boolean
      require_numbers: boolean
      require_special: boolean
      max_age: number
      history: number
    }
    session_timeout: number
    max_failed_logins: number
    lockout_duration: number
    require_mfa: boolean
    allowed_ip_ranges: string[]
    blocked_countries: string[]
    idle_timeout: number
    absolute_timeout: number
    remember_me_duration: number
    reauth_interval: number
    bind_session_to_ip: boolean
    force_logout_on_password_change: boolean
    max_concurrent_sessions: number
    concurrent_session_strategy: string
  }
  authentication: {
    allow_registration: boolean
    require_email_verify: boolean
    allowed_domains: string[]
    social_providers: string[]
    mfa_methods: string[]
  }
  branding: {
    logo_url: string
    favicon_url: string
    primary_color: string
    secondary_color: string
    custom_css: string
    login_page_title: string
    login_page_message: string
  }
}

interface SMSSettings {
  enabled: boolean
  provider: string
  message_prefix: string
  otp_length: number
  otp_expiry: number
  max_attempts: number
  credentials: Record<string, string>
}

interface ProviderField {
  key: string
  /** Key under pages.settings.sms.fields — shared by every provider that asks
   *  for the same thing, so "API Key" is translated once, not eight times. */
  labelKey: string
  sensitive: boolean
  /** Format example, deliberately not translated. */
  placeholder?: string
}

interface ProviderDef {
  id: string
  fields: ProviderField[]
}

// The provider's display name comes from pages.settings.sms.providers.<id>,
// so a gateway cannot ship with a name in one language and fields in another.
const SMS_PROVIDERS: ProviderDef[] = [
  { id: 'mock', fields: [] },
  { id: 'twilio', fields: [
    { key: 'twilio_sid', labelKey: 'accountSid', sensitive: false },
    { key: 'twilio_token', labelKey: 'authToken', sensitive: true },
    { key: 'twilio_from', labelKey: 'fromNumber', sensitive: false, placeholder: '+1234567890' },
  ]},
  { id: 'aws_sns', fields: [
    { key: 'aws_region', labelKey: 'region', sensitive: false, placeholder: 'us-east-1' },
    { key: 'aws_access_key', labelKey: 'accessKey', sensitive: false },
    { key: 'aws_secret_key', labelKey: 'secretKey', sensitive: true },
  ]},
  { id: 'netgsm', fields: [
    { key: 'netgsm_usercode', labelKey: 'userCode', sensitive: false },
    { key: 'netgsm_password', labelKey: 'password', sensitive: true },
    { key: 'netgsm_header', labelKey: 'senderHeader', sensitive: false },
  ]},
  { id: 'ileti_merkezi', fields: [
    { key: 'iletimerkezi_key', labelKey: 'apiKey', sensitive: false },
    { key: 'iletimerkezi_secret', labelKey: 'apiSecret', sensitive: true },
    { key: 'iletimerkezi_sender', labelKey: 'senderName', sensitive: false },
  ]},
  { id: 'verimor', fields: [
    { key: 'verimor_username', labelKey: 'username', sensitive: false, placeholder: '908501234567' },
    { key: 'verimor_password', labelKey: 'password', sensitive: true },
    { key: 'verimor_source_addr', labelKey: 'senderId', sensitive: false },
  ]},
  { id: 'turkcell', fields: [
    { key: 'turkcell_username', labelKey: 'username', sensitive: false },
    { key: 'turkcell_password', labelKey: 'password', sensitive: true },
    { key: 'turkcell_sender', labelKey: 'senderName', sensitive: false },
  ]},
  { id: 'vodafone', fields: [
    { key: 'vodafone_api_key', labelKey: 'apiKey', sensitive: false },
    { key: 'vodafone_secret', labelKey: 'apiSecret', sensitive: true },
    { key: 'vodafone_sender', labelKey: 'senderAddress', sensitive: false },
  ]},
  { id: 'turk_telekom', fields: [
    { key: 'turktelekom_api_key', labelKey: 'apiKey', sensitive: false },
    { key: 'turktelekom_secret', labelKey: 'apiSecret', sensitive: true },
    { key: 'turktelekom_sender', labelKey: 'senderName', sensitive: false },
  ]},
  { id: 'mutlucell', fields: [
    { key: 'mutlucell_username', labelKey: 'username', sensitive: false },
    { key: 'mutlucell_password', labelKey: 'password', sensitive: true },
    { key: 'mutlucell_api_key', labelKey: 'apiKey', sensitive: true },
    { key: 'mutlucell_sender', labelKey: 'senderName', sensitive: false },
  ]},
  { id: 'webhook', fields: [
    { key: 'webhook_url', labelKey: 'webhookUrl', sensitive: false, placeholder: 'https://...' },
    { key: 'webhook_api_key', labelKey: 'apiKey', sensitive: true },
  ]},
]

export function SettingsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'authentication' | 'sms' | 'branding'>('general')

  const { data: settings, isLoading, isError, error } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<Settings>('/api/v1/settings'),
  })

  const [formData, setFormData] = useState<Settings | null>(null)
  const [newDomain, setNewDomain] = useState('')
  const [newCountry, setNewCountry] = useState('')

  // SMS settings (separate query/state)
  const { data: smsSettingsData } = useQuery({
    queryKey: ['sms-settings'],
    queryFn: () => api.get<SMSSettings>('/api/v1/settings/sms'),
  })

  const [smsFormData, setSmsFormData] = useState<SMSSettings | null>(null)
  const [testPhone, setTestPhone] = useState('')

  // Initialize form data when settings load
  useEffect(() => {
    if (settings && !formData) {
      setFormData(settings)
    }
  }, [settings]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (smsSettingsData && !smsFormData) {
      setSmsFormData(smsSettingsData)
    }
  }, [smsSettingsData]) // eslint-disable-line react-hooks/exhaustive-deps

  const updateMutation = useMutation({
    mutationFn: (data: Settings) => api.put('/api/v1/settings', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
      toast({ title: t('pages.settings.toast.saved'), description: t('pages.settings.toast.savedDesc') })
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message || t('pages.settings.toast.saveFailed'), variant: 'destructive' })
    },
  })

  const updateSMSMutation = useMutation({
    mutationFn: (data: SMSSettings) => api.put<SMSSettings>('/api/v1/settings/sms', data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['sms-settings'] })
      setSmsFormData(data)
      toast({ title: t('pages.settings.toast.smsSaved'), description: t('pages.settings.toast.smsSavedDesc') })
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message || t('pages.settings.toast.smsSaveFailed'), variant: 'destructive' })
    },
  })

  const testSMSMutation = useMutation({
    mutationFn: (req: { phone_number: string; settings: SMSSettings }) =>
      api.post<{ success: boolean; message: string }>('/api/v1/settings/sms/test', req),
    onSuccess: () => {
      toast({ title: t('pages.settings.toast.testSent'), description: t('pages.settings.toast.testSentDesc') })
    },
    onError: (error: Error) => {
      toast({ title: t('pages.settings.toast.testFailed'), description: error.message || t('pages.settings.toast.testFailedDesc'), variant: 'destructive' })
    },
  })

  const handleSave = () => {
    if (activeTab === 'sms' && smsFormData) {
      updateSMSMutation.mutate(smsFormData)
    } else if (formData) {
      updateMutation.mutate(formData)
    }
  }

  const isSaving = activeTab === 'sms' ? updateSMSMutation.isPending : updateMutation.isPending

  const updateGeneral = (field: keyof Settings['general'], value: string) => {
    if (formData) {
      setFormData({
        ...formData,
        general: { ...formData.general, [field]: value }
      })
    }
  }

  const updateSecurity = (field: keyof Settings['security'], value: number | boolean | string) => {
    if (formData) {
      setFormData({
        ...formData,
        security: { ...formData.security, [field]: value }
      })
    }
  }

  const updatePasswordPolicy = (field: keyof Settings['security']['password_policy'], value: number | boolean) => {
    if (formData) {
      setFormData({
        ...formData,
        security: {
          ...formData.security,
          password_policy: { ...formData.security.password_policy, [field]: value }
        }
      })
    }
  }

  const updateAuthentication = (field: keyof Settings['authentication'], value: boolean | string[]) => {
    if (formData) {
      setFormData({
        ...formData,
        authentication: { ...formData.authentication, [field]: value }
      })
    }
  }

  const updateBranding = (field: keyof Settings['branding'], value: string) => {
    if (formData) {
      setFormData({
        ...formData,
        branding: { ...formData.branding, [field]: value }
      })
    }
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.settings')}</h1>
        <QueryError error={error} resource={t('pages.settings.resourceName')} />
      </div>
    )
  }

  if (isLoading || !formData) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.settings')}</h1>
        <p className="text-center py-8">{t('pages.settings.loading')}</p>
      </div>
    )
  }

  // Labels resolve from pages.settings.tabs.<id> at render.
  const tabs = [
    { id: 'general', icon: Building },
    { id: 'security', icon: Shield },
    { id: 'authentication', icon: Key },
    { id: 'sms', icon: Smartphone },
    { id: 'branding', icon: Palette },
  ] as const

  const currentProvider = SMS_PROVIDERS.find(p => p.id === smsFormData?.provider) || SMS_PROVIDERS[0]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.settings')}</h1>
          <p className="text-muted-foreground">{t('pages.settings.subtitle')}</p>
        </div>
        <Button onClick={handleSave} disabled={isSaving}>
          <Save className="mr-2 h-4 w-4" />
          {isSaving ? t('pages.settings.saving') : t('pages.settings.save')}
        </Button>
      </div>

      <div className="flex gap-6">
        <div className="w-48 space-y-1">
          {tabs.map(tab => (
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
              {t(`pages.settings.tabs.${tab.id}`)}
            </button>
          ))}
        </div>

        <div className="flex-1">
          {activeTab === 'general' && (
            <Card>
              <CardHeader>
                <CardTitle>{t('pages.settings.general.title')}</CardTitle>
                <CardDescription>{t('pages.settings.general.desc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label htmlFor="settings-org-name" className="text-sm font-medium">{t('pages.settings.general.orgName')}</label>
                    <Input id="settings-org-name"
                      value={formData.general.organization_name}
                      onChange={(e) => updateGeneral('organization_name', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="settings-support-email" className="text-sm font-medium">{t('pages.settings.general.supportEmail')}</label>
                    <Input id="settings-support-email"
                      type="email"
                      value={formData.general.support_email}
                      onChange={(e) => updateGeneral('support_email', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="settings-default-language" className="text-sm font-medium">{t('pages.settings.general.defaultLanguage')}</label>
                    <select id="settings-default-language"
                      value={formData.general.default_language}
                      onChange={(e) => updateGeneral('default_language', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="en">{t('pages.settings.general.languages.en')}</option>
                      <option value="es">{t('pages.settings.general.languages.es')}</option>
                      <option value="fr">{t('pages.settings.general.languages.fr')}</option>
                      <option value="de">{t('pages.settings.general.languages.de')}</option>
                      <option value="tr">{t('pages.settings.general.languages.tr')}</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="settings-default-timezone" className="text-sm font-medium">{t('pages.settings.general.defaultTimezone')}</label>
                    <select id="settings-default-timezone"
                      value={formData.general.default_timezone}
                      onChange={(e) => updateGeneral('default_timezone', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="UTC">{t('pages.settings.general.timezones.utc')}</option>
                      <option value="America/New_York">{t('pages.settings.general.timezones.eastern')}</option>
                      <option value="America/Chicago">{t('pages.settings.general.timezones.central')}</option>
                      <option value="America/Denver">{t('pages.settings.general.timezones.mountain')}</option>
                      <option value="America/Los_Angeles">{t('pages.settings.general.timezones.pacific')}</option>
                      <option value="Europe/Istanbul">{t('pages.settings.general.timezones.istanbul')}</option>
                      <option value="Europe/London">{t('pages.settings.general.timezones.london')}</option>
                      <option value="Europe/Berlin">{t('pages.settings.general.timezones.berlin')}</option>
                    </select>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {activeTab === 'security' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.password.title')}</CardTitle>
                  <CardDescription>{t('pages.settings.password.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label htmlFor="settings-min-length" className="text-sm font-medium">{t('pages.settings.password.minLength')}</label>
                      <Input id="settings-min-length"
                        type="number"
                        min={8}
                        max={32}
                        value={formData.security.password_policy.min_length}
                        onChange={(e) => updatePasswordPolicy('min_length', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-max-age" className="text-sm font-medium">{t('pages.settings.password.maxAge')}</label>
                      <Input id="settings-max-age"
                        type="number"
                        min={0}
                        max={365}
                        value={formData.security.password_policy.max_age}
                        onChange={(e) => updatePasswordPolicy('max_age', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-history" className="text-sm font-medium">{t('pages.settings.password.history')}</label>
                      <Input id="settings-history"
                        type="number"
                        min={0}
                        max={24}
                        value={formData.security.password_policy.history}
                        onChange={(e) => updatePasswordPolicy('history', parseInt(e.target.value))}
                      />
                    </div>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_uppercase}
                        onChange={(e) => updatePasswordPolicy('require_uppercase', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">{t('pages.settings.password.requireUppercase')}</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_lowercase}
                        onChange={(e) => updatePasswordPolicy('require_lowercase', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">{t('pages.settings.password.requireLowercase')}</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_numbers}
                        onChange={(e) => updatePasswordPolicy('require_numbers', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">{t('pages.settings.password.requireNumbers')}</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_special}
                        onChange={(e) => updatePasswordPolicy('require_special', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">{t('pages.settings.password.requireSpecial')}</span>
                    </label>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.session.title')}</CardTitle>
                  <CardDescription>{t('pages.settings.session.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label htmlFor="settings-session-timeout" className="text-sm font-medium">{t('pages.settings.session.sessionTimeout')}</label>
                      <Input id="settings-session-timeout"
                        type="number"
                        min={5}
                        max={1440}
                        value={formData.security.session_timeout}
                        onChange={(e) => updateSecurity('session_timeout', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-max-failed-logins" className="text-sm font-medium">{t('pages.settings.session.maxFailedLogins')}</label>
                      <Input id="settings-max-failed-logins"
                        type="number"
                        min={1}
                        max={20}
                        value={formData.security.max_failed_logins}
                        onChange={(e) => updateSecurity('max_failed_logins', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-lockout-duration" className="text-sm font-medium">{t('pages.settings.session.lockoutDuration')}</label>
                      <Input id="settings-lockout-duration"
                        type="number"
                        min={1}
                        max={1440}
                        value={formData.security.lockout_duration}
                        onChange={(e) => updateSecurity('lockout_duration', parseInt(e.target.value))}
                      />
                    </div>
                  </div>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={formData.security.require_mfa}
                      onChange={(e) => updateSecurity('require_mfa', e.target.checked)}
                      className="rounded"
                    />
                    <span className="text-sm font-medium">{t('pages.settings.session.requireMfa')}</span>
                  </label>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.sessionPolicies.title')}</CardTitle>
                  <CardDescription>{t('pages.settings.sessionPolicies.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label htmlFor="settings-idle-timeout" className="text-sm font-medium">{t('pages.settings.sessionPolicies.idleTimeout')}</label>
                      <Input id="settings-idle-timeout"
                        type="number"
                        min={0}
                        max={86400}
                        value={formData.security.idle_timeout ?? 1800}
                        onChange={(e) => updateSecurity('idle_timeout', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">{t('pages.settings.sessionPolicies.idleHint')}</p>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-absolute-timeout" className="text-sm font-medium">{t('pages.settings.sessionPolicies.absoluteTimeout')}</label>
                      <Input id="settings-absolute-timeout"
                        type="number"
                        min={0}
                        max={604800}
                        value={formData.security.absolute_timeout ?? 86400}
                        onChange={(e) => updateSecurity('absolute_timeout', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">{t('pages.settings.sessionPolicies.absoluteHint')}</p>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-remember-me" className="text-sm font-medium">{t('pages.settings.sessionPolicies.rememberMe')}</label>
                      <Input id="settings-remember-me"
                        type="number"
                        min={0}
                        max={7776000}
                        value={formData.security.remember_me_duration ?? 2592000}
                        onChange={(e) => updateSecurity('remember_me_duration', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">{t('pages.settings.sessionPolicies.rememberMeHint')}</p>
                    </div>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label htmlFor="settings-max-concurrent" className="text-sm font-medium">{t('pages.settings.sessionPolicies.maxConcurrent')}</label>
                      <Input id="settings-max-concurrent"
                        type="number"
                        min={0}
                        max={100}
                        value={formData.security.max_concurrent_sessions ?? 0}
                        onChange={(e) => updateSecurity('max_concurrent_sessions', parseInt(e.target.value) || 0)}
                      />
                      <p className="text-xs text-muted-foreground">{t('pages.settings.sessionPolicies.maxConcurrentHint')}</p>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-strategy" className="text-sm font-medium">{t('pages.settings.sessionPolicies.strategy')}</label>
                      <select id="settings-strategy"
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                        value={formData.security.concurrent_session_strategy ?? 'deny_new'}
                        onChange={(e) => updateSecurity('concurrent_session_strategy', e.target.value)}
                      >
                        <option value="deny_new">{t('pages.settings.sessionPolicies.strategies.deny_new')}</option>
                        <option value="terminate_oldest">{t('pages.settings.sessionPolicies.strategies.terminate_oldest')}</option>
                        <option value="prompt_user">{t('pages.settings.sessionPolicies.strategies.prompt_user')}</option>
                      </select>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.bind_session_to_ip ?? false}
                        onChange={(e) => updateSecurity('bind_session_to_ip', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">{t('pages.settings.sessionPolicies.bindToIp')}</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.force_logout_on_password_change ?? true}
                        onChange={(e) => updateSecurity('force_logout_on_password_change', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">{t('pages.settings.sessionPolicies.forceLogout')}</span>
                    </label>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.geo.title')}</CardTitle>
                  <CardDescription>{t('pages.settings.geo.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t('pages.settings.geo.blocked')}</label>
                    <div className="flex gap-2">
                      <Input
                        placeholder="e.g. CN, RU, KP"
                        value={newCountry}
                        onChange={(e) => setNewCountry(e.target.value.toUpperCase().slice(0, 2))}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            if (newCountry.length === 2 && !formData.security.blocked_countries?.includes(newCountry)) {
                              setFormData({
                                ...formData,
                                security: {
                                  ...formData.security,
                                  blocked_countries: [...(formData.security.blocked_countries || []), newCountry],
                                },
                              })
                              setNewCountry('')
                            }
                          }
                        }}
                        className="w-32"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          if (newCountry.length === 2 && !formData.security.blocked_countries?.includes(newCountry)) {
                            setFormData({
                              ...formData,
                              security: {
                                ...formData.security,
                                blocked_countries: [...(formData.security.blocked_countries || []), newCountry],
                              },
                            })
                            setNewCountry('')
                          }
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {(formData.security.blocked_countries || []).map((country) => (
                        <div
                          key={country}
                          className="flex items-center gap-1 bg-red-50 border border-red-200 px-2 py-1 rounded text-sm text-red-700"
                        >
                          <span>{country}</span>
                          <button
                            onClick={() => {
                              setFormData({
                                ...formData,
                                security: {
                                  ...formData.security,
                                  blocked_countries: formData.security.blocked_countries.filter((c) => c !== country),
                                },
                              })
                            }}
                            className="text-red-400 hover:text-red-600"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                    {(!formData.security.blocked_countries || formData.security.blocked_countries.length === 0) && (
                      <p className="text-xs text-muted-foreground">{t('pages.settings.geo.none')}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'authentication' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.auth.title')}</CardTitle>
                  <CardDescription>{t('pages.settings.auth.desc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-4">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.authentication.allow_registration}
                        onChange={(e) => updateAuthentication('allow_registration', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">{t('pages.settings.auth.allowRegistration')}</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.authentication.require_email_verify}
                        onChange={(e) => updateAuthentication('require_email_verify', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">{t('pages.settings.auth.requireEmailVerify')}</span>
                    </label>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t('pages.settings.auth.mfaMethods')}</label>
                    <div className="flex gap-4">
                      {['totp', 'webauthn', 'sms'].map(method => (
                        <label key={method} className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={formData.authentication.mfa_methods.includes(method)}
                            onChange={(e) => {
                              const methods = e.target.checked
                                ? [...formData.authentication.mfa_methods, method]
                                : formData.authentication.mfa_methods.filter(m => m !== method)
                              updateAuthentication('mfa_methods', methods)
                            }}
                            className="rounded"
                          />
                          {/* Factor identifiers (totp/webauthn/sms) are protocol
                              names, shown as-is in every language. */}
                          <span className="text-sm uppercase">{method}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.auth.domainsTitle')}</CardTitle>
                  <CardDescription>{t('pages.settings.auth.domainsDesc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                      placeholder="e.g., example.com"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          const domain = newDomain.trim().toLowerCase()
                          if (domain && !formData.authentication.allowed_domains.includes(domain)) {
                            updateAuthentication('allowed_domains', [...formData.authentication.allowed_domains, domain])
                            setNewDomain('')
                          }
                        }
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        const domain = newDomain.trim().toLowerCase()
                        if (domain && !formData.authentication.allowed_domains.includes(domain)) {
                          updateAuthentication('allowed_domains', [...formData.authentication.allowed_domains, domain])
                          setNewDomain('')
                        }
                      }}
                    >
                      <Plus className="h-4 w-4 mr-1" /> {t('common.add')}
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(formData.authentication.allowed_domains || []).length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t('pages.settings.auth.domainsNone')}</p>
                    ) : (
                      formData.authentication.allowed_domains.map(domain => (
                        <span
                          key={domain}
                          className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-sm"
                        >
                          {domain}
                          <button
                            type="button"
                            onClick={() => updateAuthentication('allowed_domains', formData.authentication.allowed_domains.filter(d => d !== domain))}
                            className="hover:text-primary"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </span>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.auth.socialTitle')}</CardTitle>
                  <CardDescription>{t('pages.settings.auth.socialDesc')}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-3 md:grid-cols-2">
                    {/* Vendor names; they read the same in every language. */}
                    {[
                      { id: 'google', label: 'Google' },
                      { id: 'github', label: 'GitHub' },
                      { id: 'microsoft', label: 'Microsoft' },
                      { id: 'apple', label: 'Apple' },
                      { id: 'facebook', label: 'Facebook' },
                    ].map(provider => (
                      <label key={provider.id} className="flex items-center gap-3 p-3 border rounded-lg hover:bg-muted cursor-pointer">
                        <input
                          type="checkbox"
                          checked={(formData.authentication.social_providers || []).includes(provider.id)}
                          onChange={(e) => {
                            const providers = e.target.checked
                              ? [...(formData.authentication.social_providers || []), provider.id]
                              : (formData.authentication.social_providers || []).filter(p => p !== provider.id)
                            updateAuthentication('social_providers', providers)
                          }}
                          className="rounded h-4 w-4"
                        />
                        <span className="text-sm font-medium">{provider.label}</span>
                      </label>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'sms' && smsFormData && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.sms.providerTitle')}</CardTitle>
                  <CardDescription>{t('pages.settings.sms.providerDesc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={smsFormData.enabled}
                      onChange={(e) => setSmsFormData({ ...smsFormData, enabled: e.target.checked })}
                      className="rounded"
                    />
                    <span className="text-sm font-medium">{t('pages.settings.sms.enable')}</span>
                  </label>

                  <div className="space-y-2">
                    <label htmlFor="settings-provider" className="text-sm font-medium">{t('pages.settings.sms.provider')}</label>
                    <select id="settings-provider"
                      value={smsFormData.provider}
                      onChange={(e) => setSmsFormData({
                        ...smsFormData,
                        provider: e.target.value,
                        credentials: {},
                      })}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      {SMS_PROVIDERS.map(p => (
                        <option key={p.id} value={p.id}>{t(`pages.settings.sms.providers.${p.id}`)}</option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t('pages.settings.sms.prefix')}</label>
                    <Input
                      value={smsFormData.message_prefix}
                      onChange={(e) => setSmsFormData({ ...smsFormData, message_prefix: e.target.value })}
                      placeholder="OpenIDX"
                    />
                    <p className="text-xs text-muted-foreground">{t('pages.settings.sms.prefixHint')}</p>
                  </div>

                  {currentProvider.fields.length > 0 && (
                    <div className="border-t pt-4 mt-4">
                      <h4 className="text-sm font-medium mb-3">
                        {t('pages.settings.sms.credentials', {
                          provider: t(`pages.settings.sms.providers.${currentProvider.id}`),
                        })}
                      </h4>
                      <div className="grid gap-4 md:grid-cols-2">
                        {currentProvider.fields.map(field => (
                          <div key={field.key} className="space-y-2">
                            <label className="text-sm font-medium">{t(`pages.settings.sms.fields.${field.labelKey}`)}</label>
                            <Input
                              type={field.sensitive ? 'password' : 'text'}
                              value={smsFormData.credentials[field.key] || ''}
                              placeholder={field.sensitive ? t('pages.settings.sms.sensitivePlaceholder') : field.placeholder || ''}
                              onChange={(e) => setSmsFormData({
                                ...smsFormData,
                                credentials: { ...smsFormData.credentials, [field.key]: e.target.value },
                              })}
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.sms.otpTitle')}</CardTitle>
                  <CardDescription>{t('pages.settings.sms.otpDesc')}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label htmlFor="settings-code-length" className="text-sm font-medium">{t('pages.settings.sms.codeLength')}</label>
                      <select id="settings-code-length"
                        value={smsFormData.otp_length}
                        onChange={(e) => setSmsFormData({ ...smsFormData, otp_length: parseInt(e.target.value) })}
                        className="w-full border rounded-md px-3 py-2"
                      >
                        <option value={4}>{t('pages.settings.sms.digits', { count: 4 })}</option>
                        <option value={6}>{t('pages.settings.sms.digits', { count: 6 })}</option>
                        <option value={8}>{t('pages.settings.sms.digits', { count: 8 })}</option>
                      </select>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-expiry" className="text-sm font-medium">{t('pages.settings.sms.expiry')}</label>
                      <Input id="settings-expiry"
                        type="number"
                        min={60}
                        max={600}
                        value={smsFormData.otp_expiry}
                        onChange={(e) => setSmsFormData({ ...smsFormData, otp_expiry: parseInt(e.target.value) || 300 })}
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('pages.settings.sms.expiryPreview', {
                          m: Math.floor(smsFormData.otp_expiry / 60),
                          s: smsFormData.otp_expiry % 60,
                        })}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="settings-max-attempts" className="text-sm font-medium">{t('pages.settings.sms.maxAttempts')}</label>
                      <Input id="settings-max-attempts"
                        type="number"
                        min={1}
                        max={10}
                        value={smsFormData.max_attempts}
                        onChange={(e) => setSmsFormData({ ...smsFormData, max_attempts: parseInt(e.target.value) || 3 })}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('pages.settings.sms.testTitle')}</CardTitle>
                  <CardDescription>{t('pages.settings.sms.testDesc')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      value={testPhone}
                      onChange={(e) => setTestPhone(e.target.value)}
                      placeholder="+905551234567"
                      className="max-w-xs"
                    />
                    <Button
                      variant="outline"
                      onClick={() => {
                        if (testPhone && smsFormData) {
                          testSMSMutation.mutate({ phone_number: testPhone, settings: smsFormData })
                        }
                      }}
                      disabled={testSMSMutation.isPending || !testPhone}
                    >
                      <Send className="mr-2 h-4 w-4" />
                      {testSMSMutation.isPending ? t('pages.settings.sms.sending') : t('pages.settings.sms.sendTest')}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t('pages.settings.sms.testHint')}
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'sms' && !smsFormData && (
            <p className="text-center py-8">{t('pages.settings.sms.loading')}</p>
          )}

          {activeTab === 'branding' && (
            <Card>
              <CardHeader>
                <CardTitle>{t('pages.settings.branding.title')}</CardTitle>
                <CardDescription>{t('pages.settings.branding.desc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-muted border border-border rounded-md p-3 text-sm">
                  {t('pages.settings.branding.tenantNote')}{' '}
                  <Link to="/tenant-management" className="text-primary hover:underline">
                    {t('pages.settings.branding.tenantLink')}
                  </Link>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t('pages.settings.branding.logoUrl')}</label>
                    <Input
                      value={formData.branding.logo_url}
                      onChange={(e) => updateBranding('logo_url', e.target.value)}
                      placeholder="https://example.com/logo.png"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">{t('pages.settings.branding.faviconUrl')}</label>
                    <Input
                      value={formData.branding.favicon_url}
                      onChange={(e) => updateBranding('favicon_url', e.target.value)}
                      placeholder="https://example.com/favicon.ico"
                    />
                  </div>
                  <div className="space-y-2">
                    <label id="settings-primary-color-label" className="text-sm font-medium">{t('pages.settings.branding.primaryColor')}</label>
                    <div className="flex gap-2">
                      <input aria-labelledby="settings-primary-color-label"
                        type="color"
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input aria-labelledby="settings-primary-color-label"
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label id="settings-secondary-color-label" className="text-sm font-medium">{t('pages.settings.branding.secondaryColor')}</label>
                    <div className="flex gap-2">
                      <input aria-labelledby="settings-secondary-color-label"
                        type="color"
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input aria-labelledby="settings-secondary-color-label"
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                      />
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <label htmlFor="settings-login-title" className="text-sm font-medium">{t('pages.settings.branding.loginTitle')}</label>
                  <Input id="settings-login-title"
                    value={formData.branding.login_page_title}
                    onChange={(e) => updateBranding('login_page_title', e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="settings-login-message" className="text-sm font-medium">{t('pages.settings.branding.loginMessage')}</label>
                  <textarea id="settings-login-message"
                    value={formData.branding.login_page_message}
                    onChange={(e) => updateBranding('login_page_message', e.target.value)}
                    className="w-full border rounded-md px-3 py-2 min-h-[80px]"
                  />
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
