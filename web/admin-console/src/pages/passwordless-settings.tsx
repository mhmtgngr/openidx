import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link2, QrCode, Mail, Shield, Settings2, Users, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface PasswordlessSettings {
  magic_link_enabled: boolean
  magic_link_expiry_minutes: number
  qr_login_enabled: boolean
  qr_session_expiry_minutes: number
  biometric_only_enabled: boolean
  allowed_domains: string[]
  require_device_trust: boolean
  max_magic_links_per_hour: number
}

interface PasswordlessStats {
  magic_links_today: number
  qr_logins_today: number
  biometric_only_users: number
  passwordless_adoption_rate: number
}

export function PasswordlessSettingsPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [testMagicLinkDialog, setTestMagicLinkDialog] = useState(false)
  const [testEmail, setTestEmail] = useState('')

  // Fetch settings
  const { data: settingsData, isLoading: settingsLoading, isError: settingsError, error: settingsErrorObj } = useQuery({
    queryKey: ['passwordless-settings'],
    queryFn: async () => {
      return api.get<{ settings: PasswordlessSettings }>('/api/v1/identity/passwordless/settings')
    }
  })

  // Fall back to an all-DISABLED posture (never a fake "enabled" one) so that
  // if the settings ever fail to load we do not paint features as turned on.
  // On a real load error we render <QueryError> below instead of any toggles.
  const settings: PasswordlessSettings = settingsData?.settings || {
    magic_link_enabled: false,
    magic_link_expiry_minutes: 15,
    qr_login_enabled: false,
    qr_session_expiry_minutes: 5,
    biometric_only_enabled: false,
    allowed_domains: [],
    require_device_trust: false,
    max_magic_links_per_hour: 5
  }

  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['passwordless-stats'],
    queryFn: async () => {
      return api.get<{ stats: PasswordlessStats }>('/api/v1/identity/passwordless/stats')
    }
  })

  const stats: PasswordlessStats = statsData?.stats || {
    magic_links_today: 0,
    qr_logins_today: 0,
    biometric_only_users: 0,
    passwordless_adoption_rate: 0
  }

  // Form state
  const [editSettings, setEditSettings] = useState<PasswordlessSettings>(settings)

  // Mutations
  const updateSettingsMutation = useMutation({
    mutationFn: (data: PasswordlessSettings) =>
      api.put('/api/v1/identity/passwordless/settings', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwordless-settings'] })
      toast({
        title: t('pages.passwordless.toasts.updatedTitle'),
        description: t('pages.passwordless.toasts.updatedDesc'),
      })
      setEditDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const sendTestMagicLinkMutation = useMutation({
    mutationFn: (email: string) =>
      api.post('/api/v1/identity/passwordless/magic-link/test', { email }),
    onSuccess: () => {
      toast({
        title: t('pages.passwordless.toasts.testSentTitle'),
        description: t('pages.passwordless.toasts.testSentDesc'),
      })
      setTestMagicLinkDialog(false)
      setTestEmail('')
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const toggleSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: keyof PasswordlessSettings; value: boolean }) =>
      api.patch('/api/v1/identity/passwordless/settings', { [key]: value }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passwordless-settings'] })
    }
  })

  const openEditDialog = () => {
    setEditSettings(settings)
    setEditDialog(true)
  }

  if (settingsLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  // Do not render any toggle state until real settings load. Surfacing the error
  // (vs. showing default-on toggles) avoids painting a fake security posture.
  if (settingsError) {
    return <QueryError error={settingsErrorObj} resource={t('pages.passwordless.resourceName')} />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('pages.passwordless.title')}</h1>
          <p className="text-muted-foreground">{t('pages.passwordless.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestMagicLinkDialog(true)}>
            <Mail className="h-4 w-4 mr-2" />
            {t('pages.passwordless.testMagicLink')}
          </Button>
          <Button onClick={openEditDialog}>
            <Settings2 className="h-4 w-4 mr-2" />
            {t('pages.passwordless.editSettings')}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.passwordless.stats.magicLinks')}</CardTitle>
            <Mail className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.magic_links_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.passwordless.stats.qrLogins')}</CardTitle>
            <QrCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.qr_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.passwordless.stats.biometricUsers')}</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.biometric_only_users}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.passwordless.stats.adoption')}</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.passwordless_adoption_rate}%</div>
          </CardContent>
        </Card>
      </div>

      {/* Feature Cards */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Magic Links */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Link2 className="h-5 w-5 text-primary" />
                <CardTitle>{t('pages.passwordless.magicLinks.title')}</CardTitle>
              </div>
              <Switch aria-label={t('pages.passwordless.magicLinks.title')}
                checked={settings.magic_link_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'magic_link_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>{t('pages.passwordless.magicLinks.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.status')}</span>
              {settings.magic_link_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />{t('pages.passwordless.enabled')}
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />{t('pages.passwordless.disabled')}
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.magicLinks.expiry')}</span>
              <span>{t('pages.passwordless.magicLinks.expiryValue', { n: settings.magic_link_expiry_minutes })}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.magicLinks.rateLimit')}</span>
              <span>{t('pages.passwordless.magicLinks.rateLimitValue', { n: settings.max_magic_links_per_hour })}</span>
            </div>
          </CardContent>
        </Card>

        {/* QR Code Login */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <QrCode className="h-5 w-5 text-purple-600" />
                <CardTitle>{t('pages.passwordless.qrLogin.title')}</CardTitle>
              </div>
              <Switch aria-label={t('pages.passwordless.qrLogin.title')}
                checked={settings.qr_login_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'qr_login_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>{t('pages.passwordless.qrLogin.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.status')}</span>
              {settings.qr_login_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />{t('pages.passwordless.enabled')}
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />{t('pages.passwordless.disabled')}
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.qrLogin.expiry')}</span>
              <span>{t('pages.passwordless.magicLinks.expiryValue', { n: settings.qr_session_expiry_minutes })}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.qrLogin.deviceTrust')}</span>
              <span>{settings.require_device_trust ? t('pages.passwordless.yes') : t('pages.passwordless.no')}</span>
            </div>
          </CardContent>
        </Card>

        {/* Biometric Only */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-green-600" />
                <CardTitle>{t('pages.passwordless.biometric.title')}</CardTitle>
              </div>
              <Switch aria-label={t('pages.passwordless.biometric.title')}
                checked={settings.biometric_only_enabled}
                onCheckedChange={(checked) =>
                  toggleSettingMutation.mutate({ key: 'biometric_only_enabled', value: checked })
                }
              />
            </div>
            <CardDescription>{t('pages.passwordless.biometric.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.status')}</span>
              {settings.biometric_only_enabled ? (
                <Badge className="bg-green-100 text-green-800">
                  <CheckCircle2 className="h-3 w-3 mr-1" />{t('pages.passwordless.enabled')}
                </Badge>
              ) : (
                <Badge variant="secondary">
                  <XCircle className="h-3 w-3 mr-1" />{t('pages.passwordless.disabled')}
                </Badge>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.biometric.enrolled')}</span>
              <span>{stats.biometric_only_users}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('pages.passwordless.biometric.requiresWebAuthn')}</span>
              <span>{t('pages.passwordless.yes')}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* How It Works */}
      <Card>
        <CardHeader>
          <CardTitle>{t('pages.passwordless.howItWorks.title')}</CardTitle>
          <CardDescription>{t('pages.passwordless.howItWorks.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-3">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-primary">
                <Link2 className="h-5 w-5" />
                <h4 className="font-medium">{t('pages.passwordless.magicLinks.title')}</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>{t('pages.passwordless.howItWorks.magic1')}</li>
                <li>{t('pages.passwordless.howItWorks.magic2')}</li>
                <li>{t('pages.passwordless.howItWorks.magic3')}</li>
                <li>{t('pages.passwordless.howItWorks.magic4')}</li>
              </ol>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-purple-600">
                <QrCode className="h-5 w-5" />
                <h4 className="font-medium">{t('pages.passwordless.qrLogin.title')}</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>{t('pages.passwordless.howItWorks.qr1')}</li>
                <li>{t('pages.passwordless.howItWorks.qr2')}</li>
                <li>{t('pages.passwordless.howItWorks.qr3')}</li>
                <li>{t('pages.passwordless.howItWorks.qr4')}</li>
              </ol>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-green-600">
                <Shield className="h-5 w-5" />
                <h4 className="font-medium">{t('pages.passwordless.biometric.title')}</h4>
              </div>
              <ol className="text-sm text-muted-foreground space-y-1 list-decimal list-inside">
                <li>{t('pages.passwordless.howItWorks.bio1')}</li>
                <li>{t('pages.passwordless.howItWorks.bio2')}</li>
                <li>{t('pages.passwordless.howItWorks.bio3')}</li>
                <li>{t('pages.passwordless.howItWorks.bio4')}</li>
              </ol>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Edit Settings Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.passwordless.editDialog.title')}</DialogTitle>
            <DialogDescription>{t('pages.passwordless.editDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="passwordless-settings-magic-expiry">{t('pages.passwordless.editDialog.magicExpiry')}</Label>
              <Input id="passwordless-settings-magic-expiry"
                type="number"
                value={editSettings.magic_link_expiry_minutes}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  magic_link_expiry_minutes: parseInt(e.target.value) || 15
                })}
                min={5}
                max={60}
              />
              <p className="text-xs text-muted-foreground">{t('pages.passwordless.editDialog.magicExpiryHint')}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="passwordless-settings-qr-expiry">{t('pages.passwordless.editDialog.qrExpiry')}</Label>
              <Input id="passwordless-settings-qr-expiry"
                type="number"
                value={editSettings.qr_session_expiry_minutes}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  qr_session_expiry_minutes: parseInt(e.target.value) || 5
                })}
                min={1}
                max={15}
              />
              <p className="text-xs text-muted-foreground">{t('pages.passwordless.editDialog.qrExpiryHint')}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="passwordless-settings-max-links">{t('pages.passwordless.editDialog.maxLinks')}</Label>
              <Input id="passwordless-settings-max-links"
                type="number"
                value={editSettings.max_magic_links_per_hour}
                onChange={(e) => setEditSettings({
                  ...editSettings,
                  max_magic_links_per_hour: parseInt(e.target.value) || 5
                })}
                min={1}
                max={20}
              />
              <p className="text-xs text-muted-foreground">{t('pages.passwordless.editDialog.maxLinksHint')}</p>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <Label htmlFor="passwordless-settings-device-trust">{t('pages.passwordless.editDialog.deviceTrust')}</Label>
                <p className="text-xs text-muted-foreground">{t('pages.passwordless.editDialog.deviceTrustHint')}</p>
              </div>
              <Switch id="passwordless-settings-device-trust"
                checked={editSettings.require_device_trust}
                onCheckedChange={(checked) => setEditSettings({
                  ...editSettings,
                  require_device_trust: checked
                })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => updateSettingsMutation.mutate(editSettings)}>
              {t('pages.passwordless.editDialog.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Test Magic Link Dialog */}
      <Dialog open={testMagicLinkDialog} onOpenChange={setTestMagicLinkDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.passwordless.testDialog.title')}</DialogTitle>
            <DialogDescription>{t('pages.passwordless.testDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.passwordless.testDialog.email')}</Label>
              <Input
                type="email"
                value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="user@example.com"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTestMagicLinkDialog(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => sendTestMagicLinkMutation.mutate(testEmail)}
              disabled={!testEmail}
            >
              <Mail className="h-4 w-4 mr-2" />
              {t('pages.passwordless.testDialog.send')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
