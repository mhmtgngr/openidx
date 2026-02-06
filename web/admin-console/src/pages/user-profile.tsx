import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Switch } from '../components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Badge } from '../components/ui/badge'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '../components/ui/alert-dialog'
import { useToast } from '../hooks/use-toast'
import { api, UserProfile, MFASetupResponse, MFAEnableResponse } from '../lib/api'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Shield, User, Key, Smartphone, Mail, Monitor, Phone, Globe, Trash2, Check } from 'lucide-react'
import QRCode from 'qrcode.react'
import { useAuth } from '../lib/auth'

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

  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { user } = useAuth()

  const { data: profile, isLoading } = useQuery({
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
      toast({ title: 'Success', description: 'Profile updated successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update profile', variant: 'destructive' })
    },
  })

  const setupMFAMutation = useMutation({
    mutationFn: () => api.post<MFASetupResponse>('/api/v1/identity/users/me/mfa/setup'),
    onSuccess: (response) => {
      setMfaSetup({ ...response, backupCodes: [] })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to setup MFA', variant: 'destructive' })
    },
  })

  const enableMFAMutation = useMutation({
    mutationFn: (code: string) =>
      api.post<MFAEnableResponse>('/api/v1/identity/users/me/mfa/enable', { code }),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      setMfaSetup(prev => prev ? { ...prev, backupCodes: response.backupCodes || [] } : null)
      setShowBackupCodes(true)
      toast({ title: 'Success', description: 'MFA enabled successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code', variant: 'destructive' })
    },
  })

  const disableMFAMutation = useMutation({
    mutationFn: () => api.post<void>('/api/v1/identity/users/me/mfa/disable'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] })
      toast({ title: 'Success', description: 'MFA disabled successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable MFA', variant: 'destructive' })
    },
  })

  const changePasswordMutation = useMutation({
    mutationFn: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
      api.post<void>('/api/v1/identity/users/me/change-password', { currentPassword, newPassword }),
    onSuccess: () => {
      toast({ title: 'Success', description: 'Password changed successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to change password', variant: 'destructive' })
    },
  })

  const { data: sessions, isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions', user?.id],
    queryFn: () => api.get<Session[]>(`/api/v1/identity/users/${user?.id}/sessions`),
    enabled: !!user?.id,
  })

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
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your phone.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
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
      toast({ title: 'SMS MFA Enabled', description: 'Your phone has been verified for SMS authentication.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  const deleteSMSMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/sms'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: 'SMS MFA Disabled', description: 'SMS authentication has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable SMS MFA.', variant: 'destructive' })
    },
  })

  // Email OTP mutations
  const enrollEmailOTPMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/mfa/email/enroll'),
    onSuccess: () => {
      setEmailOtpEnrollStep('verify')
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your email.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
    },
  })

  const verifyEmailOTPMutation = useMutation({
    mutationFn: (code: string) =>
      api.post('/api/v1/identity/mfa/email/verify', { code }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      setEmailOtpEnrollStep('idle')
      setEmailOtpCode('')
      toast({ title: 'Email OTP Enabled', description: 'Your email has been verified for OTP authentication.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  const deleteEmailOTPMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/mfa/email'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
      toast({ title: 'Email OTP Disabled', description: 'Email OTP authentication has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to disable Email OTP.', variant: 'destructive' })
    },
  })

  // Trusted browser mutations
  const revokeBrowserMutation = useMutation({
    mutationFn: (browserId: string) =>
      api.delete(`/api/v1/identity/trusted-browsers/${browserId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: 'Browser Revoked', description: 'The trusted browser has been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke browser.', variant: 'destructive' })
    },
  })

  const revokeAllBrowsersMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/trusted-browsers'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      toast({ title: 'All Browsers Revoked', description: 'All trusted browsers have been removed.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke browsers.', variant: 'destructive' })
    },
  })

  // Helper to check if a method is enabled
  const isMethodEnabled = (method: string) => {
    return mfaMethods?.some(m => m.method === method && m.enabled && m.verified)
  }

  const revokeSessionMutation = useMutation({
    mutationFn: (sessionId: string) => api.delete(`/api/v1/identity/sessions/${sessionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      toast({ title: 'Session revoked' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to revoke session', variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!profile) {
    return (
      <div className="text-center py-8">
        <p className="text-muted-foreground">Failed to load profile</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">My Profile</h1>
          <p className="text-muted-foreground">Manage your account settings and security preferences</p>
        </div>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="sessions" className="flex items-center gap-2">
            <Monitor className="h-4 w-4" />
            Sessions
            {sessions && sessions.length > 0 && (
              <Badge variant="secondary" className="ml-1">{sessions.length}</Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Personal Information</CardTitle>
              <CardDescription>Update your personal details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First Name</Label>
                  <Input
                    id="firstName"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
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
                      Verified
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
                <Label htmlFor="email-notifications">Account Enabled</Label>
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
                Update Profile
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Multi-Factor Authentication</CardTitle>
              <CardDescription>Add an extra layer of security to your account</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5" />
                  <div>
                    <p className="font-medium">Authenticator App</p>
                    <p className="text-sm text-muted-foreground">
                      Use an authenticator app to generate verification codes
                    </p>
                  </div>
                </div>
                {profile.mfaEnabled ? (
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Shield className="h-3 w-3" />
                    Enabled
                  </Badge>
                ) : (
                  <Button onClick={() => setupMFAMutation.mutate()} variant="outline" disabled={setupMFAMutation.isPending}>
                    <Key className="h-4 w-4 mr-2" />
                    Setup MFA
                  </Button>
                )}
              </div>

              {profile.mfaEnabled && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="destructive" disabled={disableMFAMutation.isPending}>
                      Disable MFA
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Disable Multi-Factor Authentication?</AlertDialogTitle>
                      <AlertDialogDescription>
                        This will remove the extra security layer from your account. Are you sure you want to continue?
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => disableMFAMutation.mutate()}>Disable MFA</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}

              {mfaSetup && (
                <Card className="border-orange-200">
                  <CardHeader>
                    <CardTitle className="text-orange-900">Setup Authenticator</CardTitle>
                    <CardDescription>Scan QR code or enter secret manually</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex justify-center bg-white p-8 rounded-lg border">
                      <QRCode
                        value={mfaSetup.qrCodeUrl}
                        size={320}
                        level="H"
                        includeMargin={true}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label className="text-base font-semibold">Or Enter Secret Manually:</Label>
                      <div className="bg-muted p-4 rounded-lg">
                        <code className="text-sm break-all font-mono select-all cursor-pointer" onClick={(e) => {
                          const text = (e.currentTarget as HTMLElement).textContent
                          navigator.clipboard.writeText(text || '')
                        }}>
                          {mfaSetup.secret}
                        </code>
                        <p className="text-xs text-muted-foreground mt-2">Click to copy</p>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        If QR code scanning fails, open your authenticator app and choose "Enter setup key" or "Manual entry", then paste this secret.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="mfa-code">Verification Code</Label>
                      <Input
                        id="mfa-code"
                        placeholder="Enter 6-digit code"
                        type="text"
                        maxLength={6}
                        pattern="\d*"
                        inputMode="numeric"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value)}
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
                            title: 'Invalid Code',
                            description: 'Please enter a 6-digit verification code',
                            variant: 'destructive'
                          })
                        }
                      }}
                      className="w-full"
                      size="lg"
                      disabled={enableMFAMutation.isPending}
                    >
                      Verify & Enable MFA
                    </Button>
                  </CardContent>
                </Card>
              )}

              {showBackupCodes && mfaSetup?.backupCodes && (
                <Card className="border-blue-200">
                  <CardHeader>
                    <CardTitle className="text-blue-900">Backup Codes</CardTitle>
                    <CardDescription>Save these codes in a safe place</CardDescription>
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
                      I've Saved My Backup Codes
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
                      <p className="font-medium">SMS Authentication</p>
                      <p className="text-sm text-muted-foreground">
                        Receive verification codes via text message
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('sms') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        Enabled
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">Remove</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove SMS Authentication?</AlertDialogTitle>
                            <AlertDialogDescription>
                              You will no longer be able to use SMS codes for authentication.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteSMSMutation.mutate()}>Remove</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => setSmsEnrollStep('enter-phone')}>
                      <Phone className="h-4 w-4 mr-2" />
                      Setup SMS
                    </Button>
                  )}
                </div>

                {smsEnrollStep === 'enter-phone' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Setup SMS Authentication</CardTitle>
                      <CardDescription>Enter your phone number to receive codes</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex gap-2">
                        <div className="w-24">
                          <Label htmlFor="country-code">Country</Label>
                          <Input
                            id="country-code"
                            value={countryCode}
                            onChange={(e) => setCountryCode(e.target.value)}
                            placeholder="+1"
                          />
                        </div>
                        <div className="flex-1">
                          <Label htmlFor="phone-number">Phone Number</Label>
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
                          Cancel
                        </Button>
                        <Button
                          onClick={() => enrollSMSMutation.mutate({ phone_number: phoneNumber, country_code: countryCode })}
                          disabled={enrollSMSMutation.isPending || !phoneNumber}
                        >
                          {enrollSMSMutation.isPending ? <LoadingSpinner size="sm" /> : 'Send Code'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {smsEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Verify Your Phone</CardTitle>
                      <CardDescription>Enter the 6-digit code sent to your phone</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="sms-code">Verification Code</Label>
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
                          Cancel
                        </Button>
                        <Button
                          onClick={() => verifySMSMutation.mutate(smsVerifyCode)}
                          disabled={verifySMSMutation.isPending || smsVerifyCode.length !== 6}
                        >
                          {verifySMSMutation.isPending ? <LoadingSpinner size="sm" /> : 'Verify & Enable'}
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
                      <p className="font-medium">Email OTP</p>
                      <p className="text-sm text-muted-foreground">
                        Receive verification codes via email
                      </p>
                    </div>
                  </div>
                  {isMethodEnabled('email') ? (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="flex items-center gap-1">
                        <Check className="h-3 w-3" />
                        Enabled
                      </Badge>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="destructive" size="sm">Remove</Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove Email OTP?</AlertDialogTitle>
                            <AlertDialogDescription>
                              You will no longer be able to use email codes for authentication.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteEmailOTPMutation.mutate()}>Remove</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  ) : (
                    <Button variant="outline" onClick={() => enrollEmailOTPMutation.mutate()}>
                      <Mail className="h-4 w-4 mr-2" />
                      Setup Email OTP
                    </Button>
                  )}
                </div>

                {emailOtpEnrollStep === 'verify' && (
                  <Card className="mt-4 border-orange-200">
                    <CardHeader>
                      <CardTitle className="text-orange-900">Verify Your Email</CardTitle>
                      <CardDescription>Enter the 6-digit code sent to {profile?.email}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="email-otp-code">Verification Code</Label>
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
                          Cancel
                        </Button>
                        <Button
                          onClick={() => verifyEmailOTPMutation.mutate(emailOtpCode)}
                          disabled={verifyEmailOTPMutation.isPending || emailOtpCode.length !== 6}
                        >
                          {verifyEmailOTPMutation.isPending ? <LoadingSpinner size="sm" /> : 'Verify & Enable'}
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
                  <CardTitle>Trusted Browsers</CardTitle>
                  <CardDescription>Browsers where MFA can be skipped</CardDescription>
                </div>
                {trustedBrowsers && trustedBrowsers.filter(b => b.active).length > 0 && (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="destructive" size="sm">
                        Revoke All
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Revoke All Trusted Browsers?</AlertDialogTitle>
                        <AlertDialogDescription>
                          You will need to complete MFA on all browsers again.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={() => revokeAllBrowsersMutation.mutate()}>
                          Revoke All
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
                  <p>No trusted browsers</p>
                  <p className="text-sm">Complete MFA and choose to trust your browser</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {trustedBrowsers.map((browser) => (
                    <div
                      key={browser.id}
                      className={`flex items-center justify-between p-3 border rounded-lg ${
                        browser.active ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200 opacity-60'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Globe className={`h-5 w-5 ${browser.active ? 'text-green-600' : 'text-gray-400'}`} />
                        <div>
                          <p className="font-medium">{browser.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {browser.ip_address} • Trusted {new Date(browser.trusted_at).toLocaleDateString()}
                          </p>
                          {!browser.active && (
                            <Badge variant="secondary" className="mt-1">
                              {browser.revoked ? 'Revoked' : 'Expired'}
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
              <CardTitle>Change Password</CardTitle>
              <CardDescription>Update your account password</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
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
                      title: 'Error',
                      description: 'Passwords do not match',
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
                Change Password
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sessions" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Active Sessions</CardTitle>
                  <CardDescription>Manage your active sessions across devices</CardDescription>
                </div>
                {sessions && sessions.length > 0 && (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => {
                      sessions.forEach((session) => revokeSessionMutation.mutate(session.id))
                    }}
                    disabled={revokeSessionMutation.isPending}
                  >
                    Revoke All Sessions
                  </Button>
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
                  <p className="text-muted-foreground">No active sessions</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-2 px-2 font-medium">IP Address</th>
                        <th className="text-left py-2 px-2 font-medium">User Agent</th>
                        <th className="text-left py-2 px-2 font-medium">Started</th>
                        <th className="text-left py-2 px-2 font-medium">Last Seen</th>
                        <th className="text-left py-2 px-2 font-medium">Expires</th>
                        <th className="text-left py-2 px-2 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map((session) => (
                        <tr key={session.id} className="border-b">
                          <td className="py-2 px-2 font-mono text-xs">{session.ip_address}</td>
                          <td className="py-2 px-2 max-w-[200px] truncate" title={session.user_agent}>
                            {session.user_agent}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.started_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.last_seen_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2 whitespace-nowrap">
                            {new Date(session.expires_at).toLocaleString()}
                          </td>
                          <td className="py-2 px-2">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => revokeSessionMutation.mutate(session.id)}
                              disabled={revokeSessionMutation.isPending}
                            >
                              Revoke
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
