import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { useToast } from '@/hooks/use-toast'
import { api, UserProfile, MFASetupResponse, MFAEnableResponse } from '@/lib/api'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Shield, User, Key, Smartphone, Mail } from 'lucide-react'
import QRCode from 'qrcode.react'

interface MFASetup extends MFASetupResponse {
  backupCodes: string[]
}

export function UserProfilePage() {
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)
  const [mfaSetup, setMfaSetup] = useState<MFASetup | null>(null)
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const { toast } = useToast()

  useEffect(() => {
    console.log('UserProfilePage rendered')
    loadUserProfile()
  }, [])

  const loadUserProfile = async () => {
    try {
      const response = await api.get<UserProfile>('/api/v1/identity/users/me')
      setProfile(response)
    } catch (error) {
      console.error('Failed to load user profile', error)
      toast({
        title: 'Error',
        description: 'Failed to load user profile',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const updateProfile = async (updates: Partial<UserProfile>) => {
    setUpdating(true)
    try {
      await api.put<UserProfile>('/api/v1/identity/users/me', updates)
      setProfile(prev => prev ? { ...prev, ...updates } : null)
      toast({
        title: 'Success',
        description: 'Profile updated successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update profile',
        variant: 'destructive'
      })
    } finally {
      setUpdating(false)
    }
  }

  const setupMFA = async () => {
    try {
      const response = await api.post<MFASetupResponse>('/api/v1/identity/users/me/mfa/setup')
      setMfaSetup({ ...response, backupCodes: [] })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to setup MFA',
        variant: 'destructive'
      })
    }
  }

  const enableMFA = async (code: string) => {
    try {
      const response = await api.post<MFAEnableResponse>('/api/v1/identity/users/me/mfa/enable', { code })
      setProfile(prev => prev ? { ...prev, mfaEnabled: true } : null)
      setMfaSetup(prev => prev ? { ...prev, backupCodes: response.backupCodes || [] } : null)
      setShowBackupCodes(true)
      toast({
        title: 'Success',
        description: 'MFA enabled successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Invalid verification code',
        variant: 'destructive'
      })
    }
  }

  const disableMFA = async () => {
    try {
      await api.post<void>('/api/v1/identity/users/me/mfa/disable')
      setProfile(prev => prev ? { ...prev, mfaEnabled: false, mfaMethods: [] } : null)
      toast({
        title: 'Success',
        description: 'MFA disabled successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to disable MFA',
        variant: 'destructive'
      })
    }
  }

  const changePassword = async (currentPassword: string, newPassword: string) => {
    try {
      await api.post<void>('/api/v1/identity/users/me/change-password', {
        currentPassword,
        newPassword
      })
      toast({
        title: 'Success',
        description: 'Password changed successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to change password',
        variant: 'destructive'
      })
    }
  }

  if (loading) {
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
                    value={profile.firstName}
                    onChange={(e) => setProfile(prev => prev ? { ...prev, firstName: e.target.value } : null)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    value={profile.lastName}
                    onChange={(e) => setProfile(prev => prev ? { ...prev, lastName: e.target.value } : null)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="email"
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile(prev => prev ? { ...prev, email: e.target.value } : null)}
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
                  onCheckedChange={(checked) => updateProfile({ enabled: checked })}
                />
                <Label htmlFor="email-notifications">Account Enabled</Label>
              </div>
              <Button
                onClick={() => updateProfile({
                  firstName: profile.firstName,
                  lastName: profile.lastName,
                  email: profile.email
                })}
                disabled={updating}
              >
                {updating ? <LoadingSpinner size="sm" /> : null}
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
                  <Button onClick={setupMFA} variant="outline">
                    <Key className="h-4 w-4 mr-2" />
                    Setup MFA
                  </Button>
                )}
              </div>

              {profile.mfaEnabled && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="destructive">
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
                      <AlertDialogAction onClick={disableMFA}>Disable MFA</AlertDialogAction>
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
                        className="text-center text-2xl tracking-widest"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const code = (e.target as HTMLInputElement).value
                            if (code.length === 6) {
                              enableMFA(code)
                            }
                          }
                        }}
                      />
                    </div>
                    <Button
                      onClick={() => {
                        const code = (document.getElementById('mfa-code') as HTMLInputElement).value
                        if (code.length === 6) {
                          enableMFA(code)
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
                <Input id="current-password" type="password" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input id="new-password" type="password" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input id="confirm-password" type="password" />
              </div>
              <Button
                onClick={() => {
                  const current = (document.getElementById('current-password') as HTMLInputElement).value
                  const newPass = (document.getElementById('new-password') as HTMLInputElement).value
                  const confirm = (document.getElementById('confirm-password') as HTMLInputElement).value

                  if (newPass !== confirm) {
                    toast({
                      title: 'Error',
                      description: 'Passwords do not match',
                      variant: 'destructive'
                    })
                    return
                  }

                  changePassword(current, newPass)
                }}
              >
                Change Password
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}