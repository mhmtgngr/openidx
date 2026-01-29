import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Building, Shield, Key, Palette, X, Plus } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { api } from '../lib/api'

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

export function SettingsPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'authentication' | 'branding'>('general')

  const { data: settings, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<Settings>('/api/v1/settings'),
  })

  const [formData, setFormData] = useState<Settings | null>(null)
  const [newDomain, setNewDomain] = useState('')

  // Initialize form data when settings load
  if (settings && !formData) {
    setFormData(settings)
  }

  const updateMutation = useMutation({
    mutationFn: (data: Settings) => api.put('/api/v1/settings', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  const handleSave = () => {
    if (formData) {
      updateMutation.mutate(formData)
    }
  }

  const updateGeneral = (field: keyof Settings['general'], value: string) => {
    if (formData) {
      setFormData({
        ...formData,
        general: { ...formData.general, [field]: value }
      })
    }
  }

  const updateSecurity = (field: keyof Settings['security'], value: number | boolean) => {
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

  if (isLoading || !formData) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-center py-8">Loading settings...</p>
      </div>
    )
  }

  const tabs = [
    { id: 'general', label: 'General', icon: Building },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'authentication', label: 'Authentication', icon: Key },
    { id: 'branding', label: 'Branding', icon: Palette },
  ] as const

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">Configure system settings</p>
        </div>
        <Button onClick={handleSave} disabled={updateMutation.isPending}>
          <Save className="mr-2 h-4 w-4" />
          {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
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
                  ? 'bg-gray-100 text-gray-900'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex-1">
          {activeTab === 'general' && (
            <Card>
              <CardHeader>
                <CardTitle>General Settings</CardTitle>
                <CardDescription>Basic organization and system configuration</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Organization Name</label>
                    <Input
                      value={formData.general.organization_name}
                      onChange={(e) => updateGeneral('organization_name', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Support Email</label>
                    <Input
                      type="email"
                      value={formData.general.support_email}
                      onChange={(e) => updateGeneral('support_email', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Default Language</label>
                    <select
                      value={formData.general.default_language}
                      onChange={(e) => updateGeneral('default_language', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="en">English</option>
                      <option value="es">Spanish</option>
                      <option value="fr">French</option>
                      <option value="de">German</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Default Timezone</label>
                    <select
                      value={formData.general.default_timezone}
                      onChange={(e) => updateGeneral('default_timezone', e.target.value)}
                      className="w-full border rounded-md px-3 py-2"
                    >
                      <option value="UTC">UTC</option>
                      <option value="America/New_York">Eastern Time</option>
                      <option value="America/Chicago">Central Time</option>
                      <option value="America/Denver">Mountain Time</option>
                      <option value="America/Los_Angeles">Pacific Time</option>
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
                  <CardTitle>Password Policy</CardTitle>
                  <CardDescription>Configure password requirements</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Minimum Length</label>
                      <Input
                        type="number"
                        min={8}
                        max={32}
                        value={formData.security.password_policy.min_length}
                        onChange={(e) => updatePasswordPolicy('min_length', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Password Max Age (days)</label>
                      <Input
                        type="number"
                        min={0}
                        max={365}
                        value={formData.security.password_policy.max_age}
                        onChange={(e) => updatePasswordPolicy('max_age', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Password History</label>
                      <Input
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
                      <span className="text-sm">Require Uppercase</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_lowercase}
                        onChange={(e) => updatePasswordPolicy('require_lowercase', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Lowercase</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_numbers}
                        onChange={(e) => updatePasswordPolicy('require_numbers', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Numbers</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.security.password_policy.require_special}
                        onChange={(e) => updatePasswordPolicy('require_special', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm">Require Special Characters</span>
                    </label>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Session & Lockout</CardTitle>
                  <CardDescription>Configure session and lockout policies</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Session Timeout (minutes)</label>
                      <Input
                        type="number"
                        min={5}
                        max={1440}
                        value={formData.security.session_timeout}
                        onChange={(e) => updateSecurity('session_timeout', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Max Failed Logins</label>
                      <Input
                        type="number"
                        min={1}
                        max={20}
                        value={formData.security.max_failed_logins}
                        onChange={(e) => updateSecurity('max_failed_logins', parseInt(e.target.value))}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Lockout Duration (minutes)</label>
                      <Input
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
                    <span className="text-sm font-medium">Require MFA for all users</span>
                  </label>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'authentication' && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Authentication Settings</CardTitle>
                  <CardDescription>Configure authentication methods and restrictions</CardDescription>
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
                      <span className="text-sm font-medium">Allow Self Registration</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={formData.authentication.require_email_verify}
                        onChange={(e) => updateAuthentication('require_email_verify', e.target.checked)}
                        className="rounded"
                      />
                      <span className="text-sm font-medium">Require Email Verification</span>
                    </label>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">MFA Methods</label>
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
                          <span className="text-sm uppercase">{method}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Allowed Domains</CardTitle>
                  <CardDescription>Restrict registration to specific email domains</CardDescription>
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
                      <Plus className="h-4 w-4 mr-1" /> Add
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(formData.authentication.allowed_domains || []).length === 0 ? (
                      <p className="text-sm text-gray-500">No domain restrictions. All domains are allowed.</p>
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
                            className="hover:text-blue-600"
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
                  <CardTitle>Social Providers</CardTitle>
                  <CardDescription>Enable social login providers for user authentication</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-3 md:grid-cols-2">
                    {[
                      { id: 'google', label: 'Google' },
                      { id: 'github', label: 'GitHub' },
                      { id: 'microsoft', label: 'Microsoft' },
                      { id: 'apple', label: 'Apple' },
                      { id: 'facebook', label: 'Facebook' },
                    ].map(provider => (
                      <label key={provider.id} className="flex items-center gap-3 p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
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

          {activeTab === 'branding' && (
            <Card>
              <CardHeader>
                <CardTitle>Branding Settings</CardTitle>
                <CardDescription>Customize the look and feel of the login page</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Logo URL</label>
                    <Input
                      value={formData.branding.logo_url}
                      onChange={(e) => updateBranding('logo_url', e.target.value)}
                      placeholder="https://example.com/logo.png"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Favicon URL</label>
                    <Input
                      value={formData.branding.favicon_url}
                      onChange={(e) => updateBranding('favicon_url', e.target.value)}
                      placeholder="https://example.com/favicon.ico"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Primary Color</label>
                    <div className="flex gap-2">
                      <input
                        type="color"
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input
                        value={formData.branding.primary_color}
                        onChange={(e) => updateBranding('primary_color', e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Secondary Color</label>
                    <div className="flex gap-2">
                      <input
                        type="color"
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                        className="h-10 w-14 rounded border cursor-pointer"
                      />
                      <Input
                        value={formData.branding.secondary_color}
                        onChange={(e) => updateBranding('secondary_color', e.target.value)}
                      />
                    </div>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Login Page Title</label>
                  <Input
                    value={formData.branding.login_page_title}
                    onChange={(e) => updateBranding('login_page_title', e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Login Page Message</label>
                  <textarea
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
