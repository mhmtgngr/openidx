import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './ui/dialog'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Card, CardContent } from './ui/card'
import { useToast } from '../hooks/use-toast'
import { api } from '../lib/api'
import { QRCodeSVG } from 'qrcode.react'
import { decodeCredentialCreationOptions, serializeAttestationResponse } from '../lib/webauthn'
import {
  Smartphone,
  Phone,
  Mail,
  Fingerprint,
  CheckCircle2,
  Copy,
  ArrowLeft,
  ArrowRight,
  Loader2,
  Shield,
} from 'lucide-react'

type MFAMethodType = 'totp' | 'sms' | 'email' | 'webauthn'
type WizardStep = 'select' | 'setup' | 'backup' | 'complete'

interface MFASetupWizardProps {
  open: boolean
  onClose: () => void
  onComplete: () => void
}

interface TOTPSetupResponse {
  secret: string
  qr_code_url: string
}

interface MFAMethodsResponse {
  methods: Record<string, boolean>
  enabled_count: number
  mfa_enabled: boolean
}

const METHOD_INFO: Record<MFAMethodType, { icon: typeof Smartphone; name: string; description: string }> = {
  totp: {
    icon: Smartphone,
    name: 'Authenticator App',
    description: 'Use an app like Google Authenticator or Authy to generate time-based codes.',
  },
  sms: {
    icon: Phone,
    name: 'SMS',
    description: 'Receive verification codes via text message to your phone.',
  },
  email: {
    icon: Mail,
    name: 'Email',
    description: 'Receive verification codes via email to your registered address.',
  },
  webauthn: {
    icon: Fingerprint,
    name: 'Passkey',
    description: 'Use a security key or biometric authentication (fingerprint, face).',
  },
}

export function MFASetupWizard({ open, onClose, onComplete }: MFASetupWizardProps) {
  const [step, setStep] = useState<WizardStep>('select')
  const [selectedMethod, setSelectedMethod] = useState<MFAMethodType | null>(null)
  const [verificationCode, setVerificationCode] = useState('')
  const [phoneNumber, setPhoneNumber] = useState('')
  const [countryCode, setCountryCode] = useState('+1')
  const [webauthnName, setWebauthnName] = useState('')
  const [totpSetup, setTotpSetup] = useState<TOTPSetupResponse | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [smsSent, setSmsSent] = useState(false)

  const { toast } = useToast()
  const queryClient = useQueryClient()

  // Fetch enrolled methods to skip already-enrolled ones
  const { data: enrolledMethods } = useQuery({
    queryKey: ['mfa-methods'],
    queryFn: () => api.get<MFAMethodsResponse>('/api/v1/identity/mfa/methods'),
    enabled: open,
  })

  const isMethodEnrolled = (method: MFAMethodType): boolean => {
    if (!enrolledMethods?.methods) return false
    return !!enrolledMethods.methods[method]
  }

  const resetState = () => {
    setStep('select')
    setSelectedMethod(null)
    setVerificationCode('')
    setPhoneNumber('')
    setCountryCode('+1')
    setWebauthnName('')
    setTotpSetup(null)
    setBackupCodes([])
    setSmsSent(false)
  }

  const handleClose = () => {
    resetState()
    onClose()
  }

  const handleComplete = () => {
    queryClient.invalidateQueries({ queryKey: ['mfa-methods'] })
    queryClient.invalidateQueries({ queryKey: ['user-profile'] })
    resetState()
    onComplete()
  }

  // TOTP setup mutation
  const totpSetupMutation = useMutation({
    mutationFn: () => api.post<TOTPSetupResponse>('/api/v1/identity/mfa/totp/setup'),
    onSuccess: (data) => {
      setTotpSetup(data)
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to initialize TOTP setup.', variant: 'destructive' })
    },
  })

  // TOTP enroll/verify mutation
  const totpEnrollMutation = useMutation({
    mutationFn: (code: string) => api.post('/api/v1/identity/mfa/totp/enroll', { code }),
    onSuccess: () => {
      toast({ title: 'Success', description: 'Authenticator app has been set up.' })
      setStep('backup')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code. Please try again.', variant: 'destructive' })
    },
  })

  // SMS enroll mutation
  const smsEnrollMutation = useMutation({
    mutationFn: (data: { phone_number: string; country_code: string }) =>
      api.post('/api/v1/identity/mfa/sms/enroll', data),
    onSuccess: () => {
      setSmsSent(true)
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your phone.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
    },
  })

  // SMS verify mutation
  const smsVerifyMutation = useMutation({
    mutationFn: (code: string) => api.post('/api/v1/identity/mfa/sms/verify', { code }),
    onSuccess: () => {
      toast({ title: 'Success', description: 'SMS authentication has been set up.' })
      setStep('backup')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  // Email enroll mutation
  const emailEnrollMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/mfa/email/enroll'),
    onSuccess: () => {
      toast({ title: 'Code Sent', description: 'A verification code has been sent to your email.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to send verification code.', variant: 'destructive' })
    },
  })

  // Email verify mutation
  const emailVerifyMutation = useMutation({
    mutationFn: (code: string) => api.post('/api/v1/identity/mfa/email/verify', { code }),
    onSuccess: () => {
      toast({ title: 'Success', description: 'Email OTP has been set up.' })
      setStep('backup')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Invalid verification code.', variant: 'destructive' })
    },
  })

  // WebAuthn registration
  const webauthnRegisterMutation = useMutation({
    mutationFn: async (name: string) => {
      // Begin registration
      const options = await api.post<{ publicKey: unknown }>(
        '/api/v1/identity/mfa/webauthn/register/begin',
        { name }
      )
      // Create credential
      const publicKeyOptions = decodeCredentialCreationOptions(
        options.publicKey as unknown as Parameters<typeof decodeCredentialCreationOptions>[0]
      )
      const credential = await navigator.credentials.create({ publicKey: publicKeyOptions })
      if (!credential) throw new Error('Failed to create credential')
      // Finish registration
      const serialized = serializeAttestationResponse(credential as PublicKeyCredential)
      await api.post('/api/v1/identity/mfa/webauthn/register/finish', JSON.parse(serialized))
      return true
    },
    onSuccess: () => {
      toast({ title: 'Success', description: 'Passkey has been registered.' })
      setStep('backup')
    },
    onError: (error) => {
      const message = error instanceof Error ? error.message : 'Failed to register passkey.'
      toast({ title: 'Error', description: message, variant: 'destructive' })
    },
  })

  // Backup codes generation
  const backupCodesMutation = useMutation({
    mutationFn: () => api.post<{ codes: string[] }>('/api/v1/identity/mfa/backup/generate'),
    onSuccess: (data) => {
      setBackupCodes(data.codes || [])
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to generate backup codes.', variant: 'destructive' })
    },
  })

  const handleSelectMethod = (method: MFAMethodType) => {
    setSelectedMethod(method)
    setStep('setup')

    // Start the setup process for the selected method
    if (method === 'totp') {
      totpSetupMutation.mutate()
    } else if (method === 'email') {
      emailEnrollMutation.mutate()
    }
  }

  const handleSetupSubmit = () => {
    if (!selectedMethod) return

    switch (selectedMethod) {
      case 'totp':
        totpEnrollMutation.mutate(verificationCode)
        break
      case 'sms':
        if (!smsSent) {
          smsEnrollMutation.mutate({ phone_number: phoneNumber, country_code: countryCode })
        } else {
          smsVerifyMutation.mutate(verificationCode)
        }
        break
      case 'email':
        emailVerifyMutation.mutate(verificationCode)
        break
      case 'webauthn':
        webauthnRegisterMutation.mutate(webauthnName || 'My Passkey')
        break
    }
  }

  const copyAllBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'))
    toast({ title: 'Copied', description: 'Backup codes copied to clipboard.' })
  }

  const isSetupLoading =
    totpSetupMutation.isPending ||
    totpEnrollMutation.isPending ||
    smsEnrollMutation.isPending ||
    smsVerifyMutation.isPending ||
    emailEnrollMutation.isPending ||
    emailVerifyMutation.isPending ||
    webauthnRegisterMutation.isPending

  const renderMethodSelection = () => {
    const availableMethods = (Object.keys(METHOD_INFO) as MFAMethodType[]).filter(
      (method) => !isMethodEnrolled(method)
    )

    if (availableMethods.length === 0) {
      return (
        <div className="text-center py-8">
          <Shield className="h-12 w-12 mx-auto mb-3 text-green-500" />
          <p className="font-medium">All MFA methods are already enrolled</p>
          <p className="text-sm text-muted-foreground mt-1">
            Your account is fully protected with all available authentication methods.
          </p>
          <Button onClick={handleClose} className="mt-4">
            Close
          </Button>
        </div>
      )
    }

    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          Choose an authentication method to add to your account.
        </p>
        <div className="grid gap-3">
          {availableMethods.map((method) => {
            const info = METHOD_INFO[method]
            const Icon = info.icon
            return (
              <Card
                key={method}
                className="cursor-pointer hover:border-primary transition-colors"
                onClick={() => handleSelectMethod(method)}
              >
                <CardContent className="flex items-center gap-4 p-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <Icon className="h-5 w-5 text-primary" />
                  </div>
                  <div className="flex-1">
                    <p className="font-medium">{info.name}</p>
                    <p className="text-sm text-muted-foreground">{info.description}</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>
    )
  }

  const renderSetup = () => {
    if (!selectedMethod) return null

    switch (selectedMethod) {
      case 'totp':
        return (
          <div className="space-y-4">
            {totpSetupMutation.isPending ? (
              <div className="flex justify-center py-8">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : totpSetup ? (
              <>
                <p className="text-sm text-muted-foreground">
                  Scan this QR code with your authenticator app, then enter the 6-digit code below.
                </p>
                <div className="flex justify-center bg-white p-6 rounded-lg border">
                  <QRCodeSVG value={totpSetup.qr_code_url} size={200} level="H" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="totp-code">Verification Code</Label>
                  <Input
                    id="totp-code"
                    placeholder="Enter 6-digit code"
                    maxLength={6}
                    inputMode="numeric"
                    pattern="\d*"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    className="text-center text-2xl tracking-widest"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && verificationCode.length === 6) {
                        handleSetupSubmit()
                      }
                    }}
                  />
                </div>
                <Button
                  onClick={handleSetupSubmit}
                  className="w-full"
                  disabled={verificationCode.length !== 6 || totpEnrollMutation.isPending}
                >
                  {totpEnrollMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Verify & Enable
                </Button>
              </>
            ) : null}
          </div>
        )

      case 'sms':
        return (
          <div className="space-y-4">
            {!smsSent ? (
              <>
                <p className="text-sm text-muted-foreground">
                  Enter your phone number to receive verification codes via SMS.
                </p>
                <div className="flex gap-2">
                  <div className="w-24">
                    <Label htmlFor="wizard-country-code">Country</Label>
                    <Input
                      id="wizard-country-code"
                      value={countryCode}
                      onChange={(e) => setCountryCode(e.target.value)}
                      placeholder="+1"
                    />
                  </div>
                  <div className="flex-1">
                    <Label htmlFor="wizard-phone">Phone Number</Label>
                    <Input
                      id="wizard-phone"
                      value={phoneNumber}
                      onChange={(e) => setPhoneNumber(e.target.value)}
                      placeholder="555-123-4567"
                    />
                  </div>
                </div>
                <Button
                  onClick={handleSetupSubmit}
                  className="w-full"
                  disabled={!phoneNumber || smsEnrollMutation.isPending}
                >
                  {smsEnrollMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Send Code
                </Button>
              </>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  Enter the 6-digit code sent to your phone.
                </p>
                <div className="space-y-2">
                  <Label htmlFor="sms-verify-code">Verification Code</Label>
                  <Input
                    id="sms-verify-code"
                    placeholder="000000"
                    maxLength={6}
                    inputMode="numeric"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    className="text-center text-2xl tracking-widest"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && verificationCode.length === 6) {
                        handleSetupSubmit()
                      }
                    }}
                  />
                </div>
                <Button
                  onClick={handleSetupSubmit}
                  className="w-full"
                  disabled={verificationCode.length !== 6 || smsVerifyMutation.isPending}
                >
                  {smsVerifyMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Verify & Enable
                </Button>
              </>
            )}
          </div>
        )

      case 'email':
        return (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              A verification code has been sent to your email address. Enter it below.
            </p>
            {emailEnrollMutation.isPending ? (
              <div className="flex justify-center py-4">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="email-verify-code">Verification Code</Label>
                  <Input
                    id="email-verify-code"
                    placeholder="000000"
                    maxLength={6}
                    inputMode="numeric"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    className="text-center text-2xl tracking-widest"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && verificationCode.length === 6) {
                        handleSetupSubmit()
                      }
                    }}
                  />
                </div>
                <Button
                  onClick={handleSetupSubmit}
                  className="w-full"
                  disabled={verificationCode.length !== 6 || emailVerifyMutation.isPending}
                >
                  {emailVerifyMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Verify & Enable
                </Button>
              </>
            )}
          </div>
        )

      case 'webauthn':
        return (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Give your passkey a name, then follow your browser's prompts to register it.
            </p>
            <div className="space-y-2">
              <Label htmlFor="webauthn-name">Passkey Name</Label>
              <Input
                id="webauthn-name"
                placeholder="e.g., MacBook Pro, YubiKey"
                value={webauthnName}
                onChange={(e) => setWebauthnName(e.target.value)}
              />
            </div>
            <Button
              onClick={handleSetupSubmit}
              className="w-full"
              disabled={webauthnRegisterMutation.isPending}
            >
              {webauthnRegisterMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Register Passkey
            </Button>
          </div>
        )

      default:
        return null
    }
  }

  const renderBackupCodes = () => {
    return (
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Backup codes can be used to access your account if you lose your authentication device.
          Save these codes in a safe place.
        </p>
        {backupCodes.length > 0 ? (
          <>
            <div className="grid grid-cols-2 gap-2">
              {backupCodes.map((code, index) => (
                <div
                  key={index}
                  className="bg-muted p-2 rounded text-center font-mono text-sm select-all"
                >
                  {code}
                </div>
              ))}
            </div>
            <Button onClick={copyAllBackupCodes} variant="outline" className="w-full">
              <Copy className="h-4 w-4 mr-2" />
              Copy All Codes
            </Button>
            <Button
              onClick={() => setStep('complete')}
              className="w-full"
            >
              I've Saved My Backup Codes
            </Button>
          </>
        ) : (
          <div className="space-y-3">
            <Button
              onClick={() => backupCodesMutation.mutate()}
              className="w-full"
              disabled={backupCodesMutation.isPending}
            >
              {backupCodesMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Generate Backup Codes
            </Button>
            <Button
              onClick={() => setStep('complete')}
              variant="outline"
              className="w-full"
            >
              Skip for Now
            </Button>
          </div>
        )}
      </div>
    )
  }

  const renderComplete = () => {
    return (
      <div className="text-center space-y-4 py-4">
        <div className="flex justify-center">
          <div className="h-16 w-16 rounded-full bg-green-100 flex items-center justify-center">
            <CheckCircle2 className="h-10 w-10 text-green-600" />
          </div>
        </div>
        <div>
          <p className="text-lg font-semibold">MFA Setup Complete</p>
          <p className="text-sm text-muted-foreground mt-1">
            {selectedMethod && METHOD_INFO[selectedMethod]
              ? `${METHOD_INFO[selectedMethod].name} has been successfully enabled on your account.`
              : 'Your new authentication method has been enabled.'}
          </p>
        </div>
        <Button onClick={handleComplete} className="w-full">
          Done
        </Button>
      </div>
    )
  }

  const getStepTitle = (): string => {
    switch (step) {
      case 'select':
        return 'Add Authentication Method'
      case 'setup':
        return selectedMethod ? `Set Up ${METHOD_INFO[selectedMethod].name}` : 'Setup'
      case 'backup':
        return 'Backup Codes'
      case 'complete':
        return 'Setup Complete'
    }
  }

  const getStepDescription = (): string => {
    switch (step) {
      case 'select':
        return 'Strengthen your account security with multi-factor authentication.'
      case 'setup':
        return 'Follow the steps below to complete the setup.'
      case 'backup':
        return 'Save backup codes for account recovery.'
      case 'complete':
        return 'Your account is now more secure.'
    }
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) handleClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{getStepTitle()}</DialogTitle>
          <DialogDescription>{getStepDescription()}</DialogDescription>
        </DialogHeader>

        {step === 'setup' && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStep('select')
              setSelectedMethod(null)
              setVerificationCode('')
              setPhoneNumber('')
              setSmsSent(false)
              setTotpSetup(null)
            }}
            className="w-fit"
            disabled={isSetupLoading}
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back
          </Button>
        )}

        {step === 'select' && renderMethodSelection()}
        {step === 'setup' && renderSetup()}
        {step === 'backup' && renderBackupCodes()}
        {step === 'complete' && renderComplete()}
      </DialogContent>
    </Dialog>
  )
}
