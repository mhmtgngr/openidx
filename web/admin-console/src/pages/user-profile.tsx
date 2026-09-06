import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Switch } from '../components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '../components/ui/alert-dialog'
import { useToast } from '../hooks/use-toast'
import { api, UserProfile, MFASetupResponse, MFAEnableResponse } from '../lib/api'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Checkbox } from '../components/ui/checkbox'
import { Shield, User, Key, Smartphone, Mail, Monitor, Phone, Globe, Trash2, Check, Plus, Copy, KeyRound, AppWindow, AlertTriangle } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'

interface MFAMethod {
  method: string
  enabled: boolean
  verified: boolean
  enrolled_at?: string
}

interface TrustedBrowser {
  id: string
  name: string
  ip_address: string
  trusted_at: string
  expires_at: string
  last_used_at?: string
  revoked: boolean
  active: boolean
}

interface MFASetup extends MFASetupResponse {
  backupCodes: string[]
}

interface Session {
  id: string
  user_id: string
  client_id: string
  ip_address: string
  user_agent: string
  started_at: string
  last_seen_at: string
  expires_at: string
}

interface PersonalAccessToken {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  status: string
  created_at: string
}

interface CreateTokenResponse {
  token: PersonalAccessToken
  raw_token: string
}

interface UserConsent {
  client_id: string
  client_name: string
  logo_uri?: string
  scopes: string[]
  authorized_at: string
  last_used_at: string
}

export function UserProfilePage() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [profileLoaded, setProfileLoaded] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<MFASetup | null>(null)
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')

  // SMS MFA state
  const [smsEnrollStep, setSmsEnrollStep] = useState<'idle' | 'enter-phone' | 'verify'>('idle')
  const [phoneNumber, setPhoneNumber] = useState('')
  const [countryCode, setCountryCode] = useState('+1')
  const [smsVerifyCode, setSmsVerifyCode] = useState('')

  // Email OTP state
  const [emailOtpEnrollStep, setEmailOtpEnrollStep] = useState<'idle' | 'verify'>('idle')
  const [emailOtpCode, setEmailOtpCode] = useState('')

  // Access Tokens state
  const [showCreateToken, setShowCreateToken] = useState(false)
  const [newTokenName, setNewTokenName] = useState('')
  const [newTokenScopes, setNewTokenScopes] = useState<string[]>([])
  const [newTokenExpiry, setNewTokenExpiry] = useState('')
  const [createdRawToken, setCreatedRawToken] = useState<string | null>(null)

  // Authorized Apps state
  const [revokeConsentClientId, setRevokeConsentClientId] = useState<string | null>(null)

  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { t } = useTranslation()

  const { data: profile, isLoading, isError, error } = useQuery({
    queryKey: ['user-profile'],
    queryFn: () => api.get<UserProfile>('/api/v1/identity/users/me'),
    select: (data) => {
      if (!profileLoaded && data) {
        setFirstName(data.firstName)
        setLastName(data.lastName)
        setEmail(data.email)
        setProfileLoaded(true)
      }
      return data
    },
  })

  const updateProfileMutation = useMutation({
    mutationFn: (updates: Partial<UserProfile>) =>
      api.put<UserProfile>('/api/v1/identity/users/me', updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      toast({ title: t('common.success'), description: t('pages.profile.toasts.profileUpdated') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.profileUpdateFailed'), variant: 'destructive' })
    },
  })

  const setupMFAMutation = useMutation({
    mutationFn: () => api.post<MFASetupResponse>('/api/v1/identity/users/me/mfa/setup'),
    onSuccess: (response) => {
      setMfaSetup({ ...response, backupCodes: [] })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.mfaSetupFailed'), variant: 'destructive' })
    },
  })

  const enableMFAMutation = useMutation({
    mutationFn: (code: string) =>
      api.post<MFAEnableResponse>('/api/v1/identity/users/me/mfa/enable', { code }),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      setMfaSetup(prev => prev ? { ...prev, backupCodes: response.backupCodes || [] } : null)
      setShowBackupCodes(true)
      toast({ title: t('common.success'), description: t('pages.profile.toasts.mfaEnabled') })
    },
    onError: (e: unknown) => {
      // Surface the backend's real reason so the user can tell "expired setup,
      // start again" apart from "wrong code, try the next one".
      const msg = e instanceof Error ? e.message : ''
      const expired = /expired|not initiated|start setup/i.test(msg)
      toast({
        title: expired ? t('pages.profile.mfa.setupExpiredTitle') : t('pages.profile.mfa.invalidVerifyTitle'),
        description: expired
          ? t('pages.profile.mfa.setupExpiredDesc')
          : t('pages.profile.mfa.invalidVerifyDesc'),
        variant: 'destructive',
      })
    },
  })

  const disableMFAMutation = useMutation({
    mutationFn: () => api.post<void>('/api/v1/identity/users/me/mfa/disable'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      toast({ title: t('common.success'), description: t('pages.profile.toasts.mfaDisabled') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.mfaDisableFailed'), variant: 'destructive' })
    },
  })

  const { data: passwordInfo } = useQuery({
    queryKey: ['password-info'],
    queryFn: () => api.get<{ source: string; is_ldap: boolean; is_azure_ad: boolean; is_directory_managed: boolean; password_changed_at?: string; password_must_change: boolean }>('/api/v1/identity/users/me/password-info'),
  })

  const changePasswordMutation = useMutation({
    mutationFn: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
      api.post<void>('/api/v1/identity/users/me/change-password', { currentPassword, newPassword }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['password-info'] })
      toast({ title: t('common.success'), description: passwordInfo?.is_ldap ? t('pages.profile.toasts.adPasswordChanged') : t('pages.profile.toasts.passwordChanged') })
    },
    onError: (error: Error & { response?: { data?: { error?: string } } }) => {
      const message = error?.response?.data?.error || t('pages.profile.toasts.passwordChangeFailed')
      toast({ title: t('common.error'), description: message, variant: 'destructive' })
    },
  })

  // Use the self-service endpoint (id derived from the JWT). The admin
  // endpoint /users/:id/sessions returns 403 for non-admins, which the old
  // code silently rendered as "No active sessions".
  const { data: sessionsResp, isLoading: sessionsLoading } = useQuery({
    queryKey: ['my-sessions'],
    queryFn: () => api.get<{ sessions: Session[] }>('/api/v1/identity/users/me/sessions'),
  })
  const sessions = sessionsResp?.sessions

  // Fetch MFA methods
  const { data: mfaMethods } = useQuery({
    queryKey: ['mfa-methods'],
    queryFn: async () => {
      const response = await api.get<{ methods: Record<string, boolean>; enabled_count: number; mfa_enabled: boolean }>('/api/v1/identity/mfa/methods')
      // Transform the map response into the MFAMethod[] format the UI expects
      const methods = response?.methods || {}
      return Object.entries(methods).map(([method, enabled]) => ({
        method,
        enabled: !!enabled,
        verified: !!enabled,
      })) as MFAMethod[]
    },
  })

  // Fetch trusted browsers
  const { data: trustedBrowsers } = useQuery({
    queryKey: ['trusted-browsers'],
    queryFn: () => api.get<TrustedBrowser[]>('/api/v1/identity/trusted-browsers'),
  })

  // SMS MFA mutations
  const enrollSMSMutation = useMutation({
    mutationFn: (data: { phone_number: string; country_code: string }) =>
      api.post('/api/v1/identity/mfa/sms/enroll', data),
    onSuccess: () => {
      setSmsEnrollStep('verify')
      toast({ title: t('pages.profile.toasts.codeSent'), description: t('pages.profile.toasts.codeSentPhone') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.codeSendFailed'), variant: 'destructive' })
    },
  })

  const verifySMSMutation = useMutation({
    mutationFn: (code: string) =>
      api.post('/api/v1/identity/mfa/sms/verify', { code }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      setSmsEnrollStep('idle')
      setPhoneNumber('')
      setSmsVerifyCode('')
      toast({ title: t('pages.profile.toasts.smsEnabled'), description: t('pages.profile.toasts.smsEnabledDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.invalidCode'), variant: 'destructive' })
    },
  })

  const deleteSMSMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/sms'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: t('pages.profile.toasts.smsDisabled'), description: t('pages.profile.toasts.smsDisabledDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.smsDisableFailed'), variant: 'destructive' })
    },
  })

  // Email OTP mutations
  const enrollEmailOTPMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/mfa/email/enroll'),
    onSuccess: () => {
      setEmailOtpEnrollStep('verify')
      toast({ title: t('pages.profile.toasts.codeSent'), description: t('pages.profile.toasts.codeSentEmail') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.codeSendFailed'), variant: 'destructive' })
    },
  })

  const verifyEmailOTPMutation = useMutation({
    mutationFn: (code: string) =>
      api.post('/api/v1/identity/mfa/email/verify', { code }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      setEmailOtpEnrollStep('idle')
      setEmailOtpCode('')
      toast({ title: t('pages.profile.toasts.emailEnabled'), description: t('pages.profile.toasts.emailEnabledDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.invalidCode'), variant: 'destructive' })
    },
  })

  const deleteEmailOTPMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/email'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: t('pages.profile.toasts.emailDisabled'), description: t('pages.profile.toasts.emailDisabledDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.emailDisableFailed'), variant: 'destructive' })
    },
  })

  // Trusted browser mutations
  const revokeBrowserMutation = useMutation({
    mutationFn: (browserId: string) =>
      api.delete(`/api/v1/identity/trusted-browsers/${browserId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: t('pages.profile.toasts.browserRevoked'), description: t('pages.profile.toasts.browserRevokedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.browserRevokeFailed'), variant: 'destructive' })
    },
  })

  const revokeAllBrowsersMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/trusted-browsers'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: t('pages.profile.toasts.allBrowsersRevoked'), description: t('pages.profile.toasts.allBrowsersRevokedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.browsersRevokeFailed'), variant: 'destructive' })
    },
  })

  // Access Tokens queries and mutations
  const { data: accessTokens, isLoading: tokensLoading } = useQuery({
    queryKey: ['access-tokens'],
    queryFn: () => api.get<PersonalAccessToken[]>('/api/v1/identity/users/me/tokens'),
  })

  const createTokenMutation = useMutation({
    mutationFn: (data: { name: string; scopes: string[]; expires_at?: string }) =>
      api.post<CreateTokenResponse>('/api/v1/identity/users/me/tokens', data),
    onSuccess: (response) => {
      setCreatedRawToken(response.raw_token)
      setShowCreateToken(false)
      setNewTokenName('')
      setNewTokenScopes([])
      setNewTokenExpiry('')
      queryClient.invalidateQueries({ queryKey: ['access-tokens'] })
      toast({ title: t('pages.profile.toasts.tokenCreated'), description: t('pages.profile.toasts.tokenCreatedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.tokenCreateFailed'), variant: 'destructive' })
    },
  })

  const revokeTokenMutation = useMutation({
    mutationFn: (tokenId: string) =>
      api.delete(`/api/v1/identity/users/me/tokens/${tokenId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-tokens'] })
      toast({ title: t('pages.profile.toasts.tokenRevoked'), description: t('pages.profile.toasts.tokenRevokedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.tokenRevokeFailed'), variant: 'destructive' })
    },
  })

  // Authorized Apps queries and mutations
  const { data: userConsents, isLoading: consentsLoading } = useQuery({
    queryKey: ['user-consents'],
    queryFn: () => api.get<UserConsent[]>('/api/v1/identity/users/me/consents'),
  })

  const revokeConsentMutation = useMutation({
    mutationFn: (clientId: string) =>
      api.delete(`/api/v1/identity/users/me/consents/${clientId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-consents'] })
      setRevokeConsentClientId(null)
      toast({ title: t('pages.profile.toasts.consentRevoked'), description: t('pages.profile.toasts.consentRevokedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.consentRevokeFailed'), variant: 'destructive' })
    },
  })

  const toggleTokenScope = (scope: string) => {
    setNewTokenScopes(prev =>
      prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]
    )
  }

  // Helper to check if a method is enabled
  const isMethodEnabled = (method: string) => {
    return mfaMethods?.some(m => m.method === method && m.enabled && m.verified)
  }

  const revokeSessionMutation = useMutation({
    mutationFn: (sessionId: string) => api.delete(`/api/v1/identity/sessions/${sessionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      toast({ title: t('pages.profile.toasts.sessionRevoked') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.sessionRevokeFailed'), variant: 'destructive' })
    },
  })

  const logoutAllMutation = useMutation({
    mutationFn: async () => {
      const token = localStorage.getItem('token')
      const response = await fetch(`${import.meta.env.VITE_OAUTH_URL || 'http://localhost:8006'}/oauth/logout-all`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      })
      if (!response.ok) {
        throw new Error('Failed to sign out everywhere')
      }
    },
    onSuccess: () => {
      toast({ title: t('pages.profile.toasts.signedOutAll'), description: t('pages.profile.toasts.signedOutAllDesc') })
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.profile.toasts.signOutAllFailed'), variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.profile.resourceName')} />
  }

  if (!profile) {
    return (
      <div className="text-center py-8">
        <p className="text-muted-foreground">{t('pages.profile.loadFailed')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">{t('nav.items.myProfile')}</h1>
          <p className="text-muted-foreground">{t('pages.profile.subtitle')}</p>
        </div>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            {t('pages.profile.tabs.profile')}
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            {t('pages.profile.tabs.security')}
          </TabsTrigger>
          <TabsTrigger value="sessions" className="flex items-center gap-2">
            <Monitor className="h-4 w-4" />
            {t('pages.profile.tabs.sessions')}
            {sessions && sessions.length > 0 && (
              <Badge variant="secondary" className="ml-1">{sessions.length}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="access-tokens" className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            {t('pages.profile.tabs.tokens')}
          </TabsTrigger>
          <TabsTrigger value="authorized-apps" className="flex items-center gap-2">
            <AppWindow className="h-4 w-4" />
            {t('pages.profile.tabs.apps')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>{t('pages.profile.personal.title')}</CardTitle>
              <CardDescription>{t('pages.profile.personal.hint')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">{t('pages.profile.personal.firstName')}</Label>
                  <Input
                    id="firstName"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">{t('pages.profile.personal.lastName')}</Label>
                  <Input
                    id="lastName"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">{t('pages.profile.personal.email')}</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  {profile.emailVerified && (
                    <Badge variant="secondary" className="flex items-center gap-1">
                      <Mail className="h-3 w-3" />
                      {t('pages.profile.personal.verified')}
                    </Badge>
                  )}
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="email-notifications"
                  checked={profile.enabled}
                  onCheckedChange={(checked) => updateProfileMutation.mutate({ enabled: checked })}
                />
                <Label htmlFor="email-notifications">{t('pages.profile.personal.accountEnabled')}</Label>
              </div>
              <Button
                onClick={() => updateProfileMutation.mutate({
                  firstName,
                  lastName,
                  email,
                })}
                disabled={updateProfileMutation.isPending}
              >
                {updateProfileMutation.isPending ? <LoadingSpinner size="sm" /> : null}
                {t('pages.profile.personal.update')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>{t('pages.profile.mfa.title')}</CardTitle>
              <CardDescription>{t('pages.profile.mfa.hint')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5" />
                  <div>
                    <p className="font-medium">{t('pages.profile.mfa.totpTitle')}</p>
                    <p className="text-sm text-muted-foreground">
                      {t('pages.profile.mfa.totpDesc')}
                    </p>
                  </div>
                </div>
                {profile.mfaEnabled ? (
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Shield className="h-3 w-3" />
                    {t('pages.profile.mfa.enabled')}
                  </Badge>
                ) : (
                  <Button onClick={() => setupMFAMutation.mutate()} variant="outline" disabled={setupMFAMutation.isPending}>
                    <Key className="h-4 w-4 mr-2" />
                    {t('pages.profile.mfa.setup')}
                  </Button>
                )}
              </div>

              {profile.mfaEnabled && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="destructive" disabled={disableMFAMutation.isPending}>
                      {t('pages.profile.mfa.disable')}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{t('pages.profile.mfa.disableTitle')}</AlertDialogTitle>
                      <AlertDialogDescription>
                        {t('pages.profile.mfa.disableDesc')}
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                      <AlertDialogAction onClick={() => disableMFAMutation.mutate()}>{t('pages.profile.mfa.disable')}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}

              {mfaSetup && (
                <Card className="border-orange-200">
                  <CardHeader>
                    <CardTitle className="text-orange-900">{t('pages.profile.mfa.setupTitle')}</CardTitle>
                    <CardDescription>{t('pages.profile.mfa.setupHint')}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex justify-center bg-background p-8 rounded-lg border">
                      <QRCodeSVG
                        value={mfaSetup.qrCodeUrl}
                        size={320}
                        level="H"
                        includeMargin={true}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label className="text-base font-semibold">{t('pages.profile.mfa.manualLabel')}</Label>
                      <div className="bg-muted p-4 rounded-lg">
                        <code className="text-sm break-all font-mono select-all cursor-pointer" onClick={(e) => {
                          const text = (e.currentTarget as HTMLElement).textContent
                          navigator.clipboard.writeText(text || '')
                        }}>
                          {mfaSetup.secret}
                        </code>
                        <p className="text-xs text-muted-foreground mt-2">{t('pages.profile.mfa.clickToCopy')}</p>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {t('pages.profile.mfa.manualHint')}
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="mfa-code">{t('pages.profile.mfa.codeLabel')}</Label>
                      <Input
                        id="mfa-code"
                        placeholder={t('pages.profile.mfa.codePlaceholder')}
                        type="text"
                        maxLength={6}
                        pattern="\d*"
                        inputMode="numeric"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        className="text-center text-2xl tracking-widest"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && mfaCode.length === 6) {
                            enableMFAMutation.mutate(mfaCode)
                          }
                        }}
                      />
                    </div>
                    <Button
                      onClick={() => {
                        if (mfaCode.length === 6) {
                          enableMFAMutation.mutate(mfaCode)
                        } else {
                          toast({
                            title: t('pages.profile.mfa.invalidCodeTitle'),
                            description: t('pages.profile.mfa.invalidCodeDesc'),
                            variant: 'destructive'
                          })
                        }
                      }}
                      className="w-full"
                      size="lg"
                      disabled={enableMFAMutation.isPending}
                    >
                      {t('pages.profile.mfa.verifyEnable')}
                    </Button>
                  </CardContent>
                </Card>
              )}

              {showBackupCodes && mfaSetup?.backupCodes && (
                <Card className="border-blue-200">
                  <CardHeader>
                    <CardTitle className="text-blue-900">{t('pages.profile.mfa.backupTitle')}</CardTitle>
                    <CardDescription>{t('pages.profile.mfa.backupHint')}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                      {mfaSetup.backupCodes.map((code, index) => (
                        <div key={index} className="bg-muted p-2 rounded text-center">
                          {code}
                        </div>
                      ))}
                    </div>
                    <Button
                      onClick={() => {
                        setShowBackupCodes(false)
                        setMfaSetup(null)
                      }}
                      className="w-full mt-4"
                    >
                      {t('pages.profile.mfa.backupSaved')}
                    </Button>
                  </CardContent>
                </Card>
              )}

              {/* SMS MFA Section */}
              <div className="border-t pt-4 mt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Phone className="h-5 w-5" />
                    <div>
                      <p className="font-medium">{t('pages.profile.sms.title')}</p>
                      <p className="text-sm text-muted-foreground">
                        {t('pages.profile.sms.desc')}
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('sms') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        {t('pages.profile.mfa.enabled')}
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">{t('pages.profile.sms.remove')}</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>{t('pages.profile.sms.removeTitle')}</AlertDialogTitle>
                            <AlertDialogDescription>
                              {t('pages.profile.sms.removeDesc')}
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteSMSMutation.mutate()}>{t('pages.profile.sms.remove')}</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => setSmsEnrollStep('enter-phone')}>
                      <Phone className="h-4 w-4 mr-2" />
                      {t('pages.profile.sms.setup')}
                    </Button>
                  )}
                </div>

                {smsEnrollStep === 'enter-phone' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">{t('pages.profile.sms.enrollTitle')}</CardTitle>
                      <CardDescription>{t('pages.profile.sms.enrollHint')}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex gap-2">
                        <div className="w-24">
                          <Label htmlFor="country-code">{t('pages.profile.sms.country')}</Label>
                          <Input
                            id="country-code"
                            value={countryCode}
                            onChange={(e) => setCountryCode(e.target.value)}
                            placeholder="+1"
                          />
                        </div>
                        <div className="flex-1">
                          <Label htmlFor="phone-number">{t('pages.profile.sms.phone')}</Label>
                          <Input
                            id="phone-number"
                            value={phoneNumber}
                            onChange={(e) => setPhoneNumber(e.target.value)}
                            placeholder="555-123-4567"
                          />
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSmsEnrollStep('idle')
                            setPhoneNumber('')
                          }}
                        >
                          {t('common.cancel')}
                        </Button>
                        <Button
                          onClick={() => enrollSMSMutation.mutate({ phone_number: phoneNumber, country_code: countryCode })}
                          disabled={enrollSMSMutation.isPending || !phoneNumber}
                        >
                          {enrollSMSMutation.isPending ? <LoadingSpinner size="sm" /> : t('pages.profile.sms.sendCode')}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {smsEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">{t('pages.profile.sms.verifyTitle')}</CardTitle>
                      <CardDescription>{t('pages.profile.sms.verifyHint')}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="sms-code">{t('pages.profile.mfa.codeLabel')}</Label>
                        <Input
                          id="sms-code"
                          value={smsVerifyCode}
                          onChange={(e) => setSmsVerifyCode(e.target.value)}
                          placeholder="000000"
                          maxLength={6}
                          className="text-center text-2xl tracking-widest"
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSmsEnrollStep('idle')
                            setSmsVerifyCode('')
                          }}
                        >
                          {t('common.cancel')}
                        </Button>
                        <Button
                          onClick={() => verifySMSMutation.mutate(smsVerifyCode)}
                          disabled={verifySMSMutation.isPending || smsVerifyCode.length !== 6}
                        >
                          {verifySMSMutation.isPending ? <LoadingSpinner size="sm" /> : t('pages.profile.sms.verifyEnable')}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>

              {/* Email OTP Section */}
              <div className="border-t pt-4 mt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Mail className="h-5 w-5" />
                    <div>
                      <p className="font-medium">{t('pages.profile.emailOtp.title')}</p>
                      <p className="text-sm text-muted-foreground">
                        {t('pages.profile.emailOtp.desc')}
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('email') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        {t('pages.profile.mfa.enabled')}
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">{t('pages.profile.sms.remove')}</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>{t('pages.profile.emailOtp.removeTitle')}</AlertDialogTitle>
                            <AlertDialogDescription>
                              {t('pages.profile.emailOtp.removeDesc')}
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteEmailOTPMutation.mutate()}>{t('pages.profile.sms.remove')}</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => enrollEmailOTPMutation.mutate()}>
                      <Mail className="h-4 w-4 mr-2" />
                      {t('pages.profile.emailOtp.setup')}
                    </Button>
                  )}
                </div>

                {emailOtpEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">{t('pages.profile.emailOtp.verifyTitle')}</CardTitle>
                      <CardDescription>{t('pages.profile.emailOtp.verifyHint', { email: profile?.email ?? '' })}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="email-otp-code">{t('pages.profile.mfa.codeLabel')}</Label>
                        <Input
                          id="email-otp-code"
                          value={emailOtpCode}
                          onChange={(e) => setEmailOtpCode(e.target.value)}
                          placeholder="000000"
                          maxLength={6}
                          className="text-center text-2xl tracking-widest"
                        />
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          onClick={() => {
                            setEmailOtpEnrollStep('idle')
                            setEmailOtpCode('')
                          }}
                        >
                          {t('common.cancel')}
                        </Button>
                        <Button
                          onClick={() => verifyEmailOTPMutation.mutate(emailOtpCode)}
                          disabled={verifyEmailOTPMutation.isPending || emailOtpCode.length !== 6}
                        >
                          {verifyEmailOTPMutation.isPending ? <LoadingSpinner size="sm" /> : t('pages.profile.sms.verifyEnable')}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Trusted Browsers Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{t('pages.profile.browsers.title')}</CardTitle>
                  <CardDescription>{t('pages.profile.browsers.hint')}</CardDescription>
                </div>
                {trustedBrowsers && trustedBrowsers.filter(b => b.active).length > 0 && (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="destructive" size="sm">
                        {t('pages.profile.browsers.revokeAll')}
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>{t('pages.profile.browsers.revokeAllTitle')}</AlertDialogTitle>
                        <AlertDialogDescription>
                          {t('pages.profile.browsers.revokeAllDesc')}
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                        <AlertDialogAction onClick={() => revokeAllBrowsersMutation.mutate()}>
                          {t('pages.profile.browsers.revokeAll')}
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!trustedBrowsers || trustedBrowsers.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p>{t('pages.profile.browsers.empty')}</p>
                  <p className="text-sm">{t('pages.profile.browsers.emptyHint')}</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {trustedBrowsers.map((browser) => (
                    <div
                      key={browser.id}
                      className={`flex items-center justify-between p-3 border rounded-lg ${
                        browser.active ? 'bg-green-50 border-green-200' : 'bg-muted border-border opacity-60'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Globe className={`h-5 w-5 ${browser.active ? 'text-green-600' : 'text-muted-foreground'}`} />
                        <div>
                          <p className="font-medium">{browser.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {browser.ip_address} • {t('pages.profile.browsers.trustedAt', { date: new Date(browser.trusted_at).toLocaleDateString() })}
                          </p>
                          {!browser.active && (
                            <Badge variant="secondary" className="mt-1">
                              {browser.revoked ? t('pages.trustedBrowsers.badges.revoked') : t('pages.trustedBrowsers.badges.expired')}
                            </Badge>
                          )}
                        </div>
                      </div>
                      {browser.active && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => revokeBrowserMutation.mutate(browser.id)}
                          disabled={revokeBrowserMutation.isPending}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t('pages.profile.password.title')}</CardTitle>
              <CardDescription>
                {passwordInfo?.is_azure_ad
                  ? t('pages.profile.password.azureManaged')
                  : passwordInfo?.is_ldap
                  ? t('pages.profile.password.ldapManaged')
                  : t('pages.profile.password.hint')}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {passwordInfo?.is_azure_ad && (
                <div className="flex items-center gap-2 p-3 bg-purple-50 dark:bg-purple-950 rounded-md text-sm text-purple-700 dark:text-purple-300">
                  <Shield className="h-4 w-4 flex-shrink-0" />
                  <span>{t('pages.profile.password.azureNote')}</span>
                </div>
              )}
              {passwordInfo?.is_ldap && (
                <div className="flex items-center gap-2 p-3 bg-blue-50 dark:bg-blue-950 rounded-md text-sm text-blue-700 dark:text-blue-300">
                  <Shield className="h-4 w-4 flex-shrink-0" />
                  <span>{t('pages.profile.password.ldapNote')}</span>
                </div>
              )}
              {!passwordInfo?.is_azure_ad && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="current-password">{t('pages.profile.password.current')}</Label>
                    <Input
                      id="current-password"
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="new-password">{t('pages.profile.password.newPassword')}</Label>
                    <Input
                      id="new-password"
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">{t('pages.profile.password.confirm')}</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                  </div>
                  <Button
                    onClick={() => {
                      if (newPassword !== confirmPassword) {
                        toast({
                          title: t('common.error'),
                          description: t('pages.profile.password.mismatch'),
                          variant: 'destructive'
                        })
                        return
                      }

                      changePasswordMutation.mutate(
                        { currentPassword, newPassword },
                        {
                          onSuccess: () => {
                            setCurrentPassword('')
                            setNewPassword('')
                            setConfirmPassword('')
                          },
                        }
                      )
                    }}
                    disabled={changePasswordMutation.isPending}
                  >
                    {passwordInfo?.is_ldap ? t('pages.profile.password.changeAd') : t('pages.profile.password.change')}
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sessions" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{t('pages.profile.sessions.title')}</CardTitle>
                  <CardDescription>{t('pages.profile.sessions.hint')}</CardDescription>
                </div>
                {sessions && sessions.length > 0 && (
                  <div className="flex items-center gap-2">
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={logoutAllMutation.isPending}
                        >
                          {t('pages.profile.sessions.signOutEverywhere')}
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>{t('pages.profile.sessions.signOutTitle')}</AlertDialogTitle>
                          <AlertDialogDescription>
                            {t('pages.profile.sessions.signOutDesc')}
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                          <AlertDialogAction onClick={() => logoutAllMutation.mutate()}>
                            {t('pages.profile.sessions.signOutEverywhere')}
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        sessions.forEach((session) => revokeSessionMutation.mutate(session.id))
                      }}
                      disabled={revokeSessionMutation.isPending}
                    >
                      {t('pages.profile.sessions.revokeAllSessions')}
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {sessionsLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !sessions || sessions.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">{t('pages.profile.sessions.empty')}</p>
                </div>
              ) : (
                <Table className="text-sm">
                    <TableHeader>
                      <TableRow className="border-b">
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.ip')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.userAgent')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.started')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.lastSeen')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.expires')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.sessions.table.actions')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sessions.map((session) => (
                        <TableRow key={session.id} className="border-b">
                          <TableCell className="py-2 px-2 font-mono text-xs">{session.ip_address}</TableCell>
                          <TableCell className="py-2 px-2 max-w-[200px] truncate" title={session.user_agent}>
                            {session.user_agent}
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.started_at).toLocaleString()}
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.last_seen_at).toLocaleString()}
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.expires_at).toLocaleString()}
                          </TableCell>
                          <TableCell className="py-2 px-2">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => revokeSessionMutation.mutate(session.id)}
                              disabled={revokeSessionMutation.isPending}
                            >
                              {t('pages.profile.sessions.revoke')}
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="access-tokens" className="space-y-4">
          {/* Created Token Banner */}
          {createdRawToken && (
            <Card className="border-amber-300 bg-amber-50">
              <CardContent className="pt-6 space-y-3">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
                  <div className="space-y-2 flex-1">
                    <p className="font-medium text-amber-900">{t('pages.profile.tokens.bannerCopy')}</p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 bg-background border border-amber-200 px-3 py-2 rounded text-sm font-mono break-all select-all">
                        {createdRawToken}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          navigator.clipboard.writeText(createdRawToken)
                          toast({ title: t('pages.profile.tokens.copied'), description: t('pages.profile.tokens.copiedDesc') })
                        }}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setCreatedRawToken(null)}
                      className="text-amber-700"
                    >
                      {t('pages.profile.tokens.dismiss')}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{t('pages.profile.tokens.title')}</CardTitle>
                  <CardDescription>{t('pages.profile.tokens.hint')}</CardDescription>
                </div>
                <Button onClick={() => setShowCreateToken(true)} disabled={showCreateToken}>
                  <Plus className="h-4 w-4 mr-2" />
                  {t('pages.profile.tokens.create')}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {/* Create Token Form */}
              {showCreateToken && (
                <Card className="mb-6 border-blue-200">
                  <CardHeader>
                    <CardTitle className="text-base">{t('pages.profile.tokens.createTitle')}</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="token-name">{t('pages.profile.tokens.nameLabel')}</Label>
                      <Input
                        id="token-name"
                        placeholder={t('pages.profile.tokens.namePlaceholder')}
                        value={newTokenName}
                        onChange={(e) => setNewTokenName(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>{t('pages.profile.tokens.scopes')}</Label>
                      <div className="flex items-center gap-6">
                        {['read', 'write', 'admin'].map((scope) => (
                          <div key={scope} className="flex items-center gap-2">
                            <Checkbox
                              id={`scope-${scope}`}
                              checked={newTokenScopes.includes(scope)}
                              onCheckedChange={() => toggleTokenScope(scope)}
                            />
                            <Label htmlFor={`scope-${scope}`} className="text-sm font-normal capitalize cursor-pointer">
                              {scope}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="token-expiry">{t('pages.profile.tokens.expiryLabel')}</Label>
                      <Input
                        id="token-expiry"
                        type="date"
                        value={newTokenExpiry}
                        onChange={(e) => setNewTokenExpiry(e.target.value)}
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setShowCreateToken(false)
                          setNewTokenName('')
                          setNewTokenScopes([])
                          setNewTokenExpiry('')
                        }}
                      >
                        {t('common.cancel')}
                      </Button>
                      <Button
                        onClick={() => {
                          if (!newTokenName.trim()) {
                            toast({ title: t('common.error'), description: t('pages.profile.tokens.nameRequired'), variant: 'destructive' })
                            return
                          }
                          if (newTokenScopes.length === 0) {
                            toast({ title: t('common.error'), description: t('pages.profile.tokens.scopeRequired'), variant: 'destructive' })
                            return
                          }
                          createTokenMutation.mutate({
                            name: newTokenName.trim(),
                            scopes: newTokenScopes,
                            ...(newTokenExpiry ? { expires_at: new Date(newTokenExpiry).toISOString() } : {}),
                          })
                        }}
                        disabled={createTokenMutation.isPending}
                      >
                        {createTokenMutation.isPending ? <LoadingSpinner size="sm" /> : null}
                        {t('pages.profile.tokens.create')}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Tokens Table */}
              {tokensLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !accessTokens || accessTokens.length === 0 ? (
                <div className="text-center py-8">
                  <KeyRound className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p className="text-muted-foreground">{t('pages.profile.tokens.empty')}</p>
                  <p className="text-sm text-muted-foreground">{t('pages.profile.tokens.emptyHint')}</p>
                </div>
              ) : (
                <Table className="text-sm">
                    <TableHeader>
                      <TableRow className="border-b">
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.name')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.prefix')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.scopes')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.created')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.lastUsed')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.expires')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.status')}</TableHead>
                        <TableHead className="text-left py-2 px-2 font-medium">{t('pages.profile.tokens.table.actions')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {accessTokens.map((token) => (
                        <TableRow key={token.id} className="border-b">
                          <TableCell className="py-2 px-2 font-medium">{token.name}</TableCell>
                          <TableCell className="py-2 px-2 font-mono text-xs">{token.key_prefix}...</TableCell>
                          <TableCell className="py-2 px-2">
                            <div className="flex flex-wrap gap-1">
                              {token.scopes.map((scope) => (
                                <Badge key={scope} variant="secondary" className="text-xs">
                                  {scope}
                                </Badge>
                              ))}
                            </div>
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {new Date(token.created_at).toLocaleDateString()}
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {token.last_used_at
                              ? new Date(token.last_used_at).toLocaleDateString()
                              : t('pages.profile.tokens.never')}
                          </TableCell>
                          <TableCell className="py-2 px-2 whitespace-nowrap">
                            {token.expires_at
                              ? new Date(token.expires_at).toLocaleDateString()
                              : t('pages.profile.tokens.never')}
                          </TableCell>
                          <TableCell className="py-2 px-2">
                            <Badge
                              variant={token.status === 'active' ? 'secondary' : 'destructive'}
                              className="text-xs"
                            >
                              {token.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="py-2 px-2">
                            {token.status === 'active' && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="destructive" size="sm">
                                    {t('pages.profile.tokens.revoke')}
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>{t('pages.profile.tokens.revokeTitle')}</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      {t('pages.profile.tokens.revokeDesc', { name: token.name })}
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                                    <AlertDialogAction onClick={() => revokeTokenMutation.mutate(token.id)}>
                                      {t('pages.profile.tokens.revokeConfirm')}
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="authorized-apps" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>{t('pages.profile.apps.title')}</CardTitle>
              <CardDescription>{t('pages.profile.apps.hint')}</CardDescription>
            </CardHeader>
            <CardContent>
              {consentsLoading ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="lg" />
                </div>
              ) : !userConsents || userConsents.length === 0 ? (
                <div className="text-center py-8">
                  <AppWindow className="h-12 w-12 mx-auto mb-3 opacity-40" />
                  <p className="text-muted-foreground">{t('pages.profile.apps.empty')}</p>
                  <p className="text-sm text-muted-foreground">
                    {t('pages.profile.apps.emptyHint')}
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {userConsents.map((consent) => (
                    <div
                      key={consent.client_id}
                      className="flex items-start justify-between p-4 border rounded-lg"
                    >
                      <div className="flex items-start gap-4">
                        {consent.logo_uri ? (
                          <img
                            src={consent.logo_uri}
                            alt={consent.client_name}
                            className="h-10 w-10 rounded-lg object-contain"
                          />
                        ) : (
                          <div className="h-10 w-10 rounded-lg bg-muted flex items-center justify-center">
                            <AppWindow className="h-5 w-5 text-muted-foreground" />
                          </div>
                        )}
                        <div className="space-y-1">
                          <p className="font-medium">{consent.client_name}</p>
                          <div className="flex flex-wrap gap-1">
                            {consent.scopes.map((scope) => (
                              <Badge key={scope} variant="secondary" className="text-xs">
                                {scope}
                              </Badge>
                            ))}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {t('pages.profile.apps.authorizedAt', { date: new Date(consent.authorized_at).toLocaleDateString() })}
                            {consent.last_used_at && (
                              <> &middot; {t('pages.profile.apps.lastUsed', { date: new Date(consent.last_used_at).toLocaleDateString() })}</>
                            )}
                          </p>
                        </div>
                      </div>
                      <AlertDialog
                        open={revokeConsentClientId === consent.client_id}
                        onOpenChange={(isOpen) => {
                          if (!isOpen) setRevokeConsentClientId(null)
                        }}
                      >
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => setRevokeConsentClientId(consent.client_id)}
                          >
                            {t('pages.profile.apps.revokeAccess')}
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>{t('pages.profile.apps.revokeTitle')}</AlertDialogTitle>
                            <AlertDialogDescription>
                              {t('pages.profile.apps.revokeDesc', { name: consent.client_name })}
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => revokeConsentMutation.mutate(consent.client_id)}
                            >
                              {t('pages.profile.apps.revokeAccess')}
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
