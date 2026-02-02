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
import { Shield, User, Key, Smartphone, Mail, Monitor } from 'lucide-react'
import QRCode from 'qrcode.react'
import { useAuth } from '../lib/auth'

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
