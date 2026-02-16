import { useEffect, useState, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, AlertCircle, Loader2, Globe, ArrowLeft, KeyRound, Smartphone, Mail, Phone, Check } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useAuth } from '../lib/auth'
import { api, baseURL, IdentityProvider } from '../lib/api'
import { getProviderIcon } from '../components/icons/social-providers'

interface MFAOption {
  method: string
  label: string
  icon: React.ReactNode
}

export function LoginPage() {
  const navigate = useNavigate()
  const { login, isAuthenticated, isLoading } = useAuth()
  const [error, setError] = useState('')
  const [identityProviders, setIdentityProviders] = useState<IdentityProvider[]>([])
  const [loadingIdPs, setLoadingIdPs] = useState(true)

  // Login form state
  const [loginSession, setLoginSession] = useState<string | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  // MFA state
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaSession, setMfaSession] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaMethods, setMfaMethods] = useState<string[]>([])
  const [selectedMfaMethod, setSelectedMfaMethod] = useState<string>('')
  const [mfaMethodSelectionStep, setMfaMethodSelectionStep] = useState(false)
  const [otpSent, setOtpSent] = useState(false)
  const mfaInputRef = useRef<HTMLInputElement>(null)

  // Trust browser state
  const [showTrustPrompt, setShowTrustPrompt] = useState(false)
  const [trustBrowser, setTrustBrowser] = useState(false)
  const [pendingRedirectUrl, setPendingRedirectUrl] = useState('')

  // Check for login_session parameter on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const session = urlParams.get('login_session')
    if (session) {
      setLoginSession(session)
      // Clear the URL parameter without reloading
      window.history.replaceState({}, '', '/login')
    }
  }, [])

  // If already authenticated, redirect to dashboard
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate])

  // Fetch Identity Providers
  useEffect(() => {
    const fetchIdPs = async () => {
      try {
        setLoadingIdPs(true)
        const data = await api.getIdentityProviders()
        setIdentityProviders(data.filter(idp => idp.enabled)) // Only show enabled IdPs
      } catch (err) {
        // Silent failure - IdPs are optional
        console.error("Failed to fetch identity providers:", err);
      } finally {
        setLoadingIdPs(false)
      }
    }
    fetchIdPs()
  }, [])

  // Check for OAuth callback parameters and handle authentication
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const hasOAuthParams = urlParams.has('code') || urlParams.has('state') || urlParams.has('session_state')

    if (hasOAuthParams && !isLoading) {
      // OAuth callback - the auth provider will handle this
      const timer = setTimeout(() => {
        if (!isAuthenticated) {
          setError('Authentication failed. Please try again.')
        }
      }, 3000)

      return () => clearTimeout(timer)
    }
  }, [isAuthenticated, isLoading])

  const handleLogin = async () => {
    setError('')
    login()
  }

  const handleSSOLogin = (idp: IdentityProvider) => {
    setError('')
    const redirectUrl = `${baseURL}/oauth/authorize?response_type=code&client_id=admin-console&redirect_uri=${window.location.origin}/login&scope=openid%20profile%20email&idp_hint=${idp.id}`
    window.location.href = redirectUrl
  }

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/oauth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
          login_session: loginSession,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error_description || 'Login failed. Please try again.')
        return
      }

      // Check if MFA is required
      if (data.mfa_required) {
        setMfaRequired(true)
        setMfaSession(data.mfa_session)
        setMfaCode('')
        setError('')

        // Check if multiple MFA methods are available
        const methods = data.mfa_methods || ['totp']
        setMfaMethods(methods)

        if (methods.length > 1) {
          // Show method selection
          setMfaMethodSelectionStep(true)
        } else {
          // Single method - proceed directly
          setSelectedMfaMethod(methods[0])
          if (methods[0] === 'sms' || methods[0] === 'email') {
            // Need to send OTP first
            sendOTP(data.mfa_session, methods[0])
          } else {
            setTimeout(() => mfaInputRef.current?.focus(), 100)
          }
        }
        return
      }

      // Redirect to the URL with the authorization code
      if (data.redirect_url) {
        window.location.href = data.redirect_url
      }
    } catch (err) {
      setError('Unable to connect to the server. Please try again.')
      console.error('Login error:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  // Send OTP for SMS/Email methods
  const sendOTP = async (session: string, method: string) => {
    try {
      const response = await fetch(`${baseURL}/oauth/mfa-send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session: session,
          method: method,
        }),
      })

      if (response.ok) {
        setOtpSent(true)
        setTimeout(() => mfaInputRef.current?.focus(), 100)
      } else {
        const data = await response.json()
        setError(data.error_description || 'Failed to send verification code.')
      }
    } catch (err) {
      setError('Unable to send verification code. Please try again.')
    }
  }

  // Select MFA method when multiple are available
  const selectMfaMethod = (method: string) => {
    setSelectedMfaMethod(method)
    setMfaMethodSelectionStep(false)
    setMfaCode('')

    if (method === 'sms' || method === 'email') {
      sendOTP(mfaSession, method)
    } else {
      setTimeout(() => mfaInputRef.current?.focus(), 100)
    }
  }

  const handleMFASubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/oauth/mfa-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session: mfaSession,
          code: mfaCode,
          method: selectedMfaMethod || 'totp',
          trust_browser: trustBrowser,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error_description || 'Invalid verification code. Please try again.')
        setMfaCode('')
        mfaInputRef.current?.focus()
        return
      }

      // Check if we should show trust browser prompt
      if (data.can_trust_browser && !trustBrowser) {
        setPendingRedirectUrl(data.redirect_url)
        setShowTrustPrompt(true)
        return
      }

      if (data.redirect_url) {
        window.location.href = data.redirect_url
      }
    } catch (err) {
      setError('Unable to connect to the server. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle trust browser decision
  const handleTrustDecision = async (trust: boolean) => {
    if (trust) {
      try {
        await fetch(`${baseURL}/api/v1/identity/trusted-browsers`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
        })
      } catch (err) {
        console.error('Failed to trust browser:', err)
      }
    }
    window.location.href = pendingRedirectUrl
  }

  const handleBackToOptions = () => {
    setLoginSession(null)
    setMfaRequired(false)
    setMfaSession('')
    setMfaCode('')
    setMfaMethods([])
    setSelectedMfaMethod('')
    setMfaMethodSelectionStep(false)
    setOtpSent(false)
    setUsername('')
    setPassword('')
    setError('')
    setShowTrustPrompt(false)
    setTrustBrowser(false)
    setPendingRedirectUrl('')
  }

  const getMfaMethodInfo = (method: string): MFAOption => {
    switch (method) {
      case 'totp':
        return { method: 'totp', label: 'Authenticator App', icon: <Smartphone className="h-5 w-5" /> }
      case 'sms':
        return { method: 'sms', label: 'SMS Code', icon: <Phone className="h-5 w-5" /> }
      case 'email':
        return { method: 'email', label: 'Email Code', icon: <Mail className="h-5 w-5" /> }
      case 'webauthn':
        return { method: 'webauthn', label: 'Security Key', icon: <KeyRound className="h-5 w-5" /> }
      default:
        return { method, label: method.toUpperCase(), icon: <Shield className="h-5 w-5" /> }
    }
  }

  // Show trust browser prompt
  if (showTrustPrompt) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center shadow-lg">
                <Check className="h-9 w-9 text-white" />
              </div>
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                Authentication Successful
              </CardTitle>
              <CardDescription className="text-base mt-2">
                Would you like to trust this browser?
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <p className="text-sm text-blue-800">
                Trusting this browser will skip MFA verification for the next 30 days on this device.
              </p>
            </div>

            <div className="space-y-3">
              <Button
                onClick={() => handleTrustDecision(true)}
                className="w-full bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700"
                size="lg"
              >
                <Check className="mr-2 h-4 w-4" />
                Trust This Browser
              </Button>

              <Button
                variant="outline"
                onClick={() => handleTrustDecision(false)}
                className="w-full"
                size="lg"
              >
                No, Don't Trust
              </Button>
            </div>
          </CardContent>

          <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 rounded-b-lg">
            <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
              <span>Privacy</span>
              <span>•</span>
              <span>Terms</span>
              <span>•</span>
              <span>Help</span>
            </div>
          </div>
        </Card>
      </div>
    )
  }

  // Show MFA method selection
  if (mfaRequired && loginSession && mfaMethodSelectionStep) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
                <Shield className="h-9 w-9 text-white" />
              </div>
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                Choose Verification Method
              </CardTitle>
              <CardDescription className="text-base mt-2">
                Select how you want to verify your identity
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="space-y-3">
            {error && (
              <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            {mfaMethods.map((method) => {
              const info = getMfaMethodInfo(method)
              return (
                <Button
                  key={method}
                  variant="outline"
                  className="w-full h-auto py-4 justify-start"
                  onClick={() => selectMfaMethod(method)}
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg text-blue-600">
                      {info.icon}
                    </div>
                    <div className="text-left">
                      <p className="font-medium">{info.label}</p>
                      <p className="text-xs text-muted-foreground">
                        {method === 'totp' && 'Enter code from your authenticator app'}
                        {method === 'sms' && 'Receive a code via text message'}
                        {method === 'email' && 'Receive a code via email'}
                        {method === 'webauthn' && 'Use your security key or biometrics'}
                      </p>
                    </div>
                  </div>
                </Button>
              )
            })}

            <Button
              type="button"
              variant="ghost"
              className="w-full mt-4"
              onClick={handleBackToOptions}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to login
            </Button>
          </CardContent>

          <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 rounded-b-lg">
            <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
              <span>Privacy</span>
              <span>•</span>
              <span>Terms</span>
              <span>•</span>
              <span>Help</span>
            </div>
          </div>
        </Card>
      </div>
    )
  }

  // Show MFA verification form
  if (mfaRequired && loginSession) {
    const methodInfo = getMfaMethodInfo(selectedMfaMethod || 'totp')

    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
                {methodInfo.icon ? (
                  <div className="text-white [&>svg]:h-9 [&>svg]:w-9">{methodInfo.icon}</div>
                ) : (
                  <KeyRound className="h-9 w-9 text-white" />
                )}
              </div>
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                {methodInfo.label}
              </CardTitle>
              <CardDescription className="text-base mt-2">
                {selectedMfaMethod === 'totp' && 'Enter the 6-digit code from your authenticator app'}
                {selectedMfaMethod === 'sms' && (otpSent ? 'Enter the code sent to your phone' : 'Sending code to your phone...')}
                {selectedMfaMethod === 'email' && (otpSent ? 'Enter the code sent to your email' : 'Sending code to your email...')}
                {!selectedMfaMethod && 'Enter the 6-digit code from your authenticator app'}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleMFASubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                  <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                  <p className="text-sm text-red-600">{error}</p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="mfa-code">Verification Code</Label>
                <Input
                  ref={mfaInputRef}
                  id="mfa-code"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  placeholder="000000"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  required
                  autoFocus
                  className="text-center text-2xl tracking-widest font-mono"
                />
              </div>

              {(selectedMfaMethod === 'sms' || selectedMfaMethod === 'email') && (
                <Button
                  type="button"
                  variant="link"
                  className="w-full text-sm"
                  onClick={() => sendOTP(mfaSession, selectedMfaMethod)}
                  disabled={isSubmitting}
                >
                  Resend Code
                </Button>
              )}

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                size="lg"
                disabled={isSubmitting || mfaCode.length !== 6}
              >
                {isSubmitting ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Verifying...
                  </span>
                ) : (
                  'Verify'
                )}
              </Button>

              {mfaMethods.length > 1 && (
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    setMfaMethodSelectionStep(true)
                    setMfaCode('')
                    setOtpSent(false)
                  }}
                >
                  Use a different method
                </Button>
              )}

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={handleBackToOptions}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to login
              </Button>
            </form>
          </CardContent>

          <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 rounded-b-lg">
            <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
              <span>Privacy</span>
              <span>•</span>
              <span>Terms</span>
              <span>•</span>
              <span>Help</span>
            </div>
          </div>
        </Card>

        <div className="absolute bottom-4 text-center w-full">
          <p className="text-sm text-gray-500">
            Powered by <span className="font-semibold text-gray-700">OpenIDX</span>
          </p>
        </div>
      </div>
    )
  }

  // Show login form when login_session is present
  if (loginSession) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
                <Shield className="h-9 w-9 text-white" />
              </div>
            </div>
            <div>
              <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                OpenIDX
              </CardTitle>
              <CardDescription className="text-base mt-2">
                Sign in with your credentials
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleCredentialsSubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                  <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                  <p className="text-sm text-red-600">{error}</p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="username">Username or Email</Label>
                <Input
                  id="username"
                  type="text"
                  placeholder="Enter your username or email"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoComplete="username"
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                size="lg"
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Signing in...
                  </span>
                ) : (
                  'Sign In'
                )}
              </Button>

              <div className="text-center">
                <Link to="/forgot-password" className="text-sm text-blue-600 hover:text-blue-800">
                  Forgot your password?
                </Link>
              </div>

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={handleBackToOptions}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to login options
              </Button>
            </form>
          </CardContent>

          <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 rounded-b-lg">
            <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
              <span>Privacy</span>
              <span>•</span>
              <span>Terms</span>
              <span>•</span>
              <span>Help</span>
            </div>
          </div>
        </Card>

        <div className="absolute bottom-4 text-center w-full">
          <p className="text-sm text-gray-500">
            Powered by <span className="font-semibold text-gray-700">OpenIDX</span>
          </p>
        </div>
      </div>
    )
  }

  // Show login options (SSO + OpenIDX button)
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
              <Shield className="h-9 w-9 text-white" />
            </div>
          </div>
          <div>
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              OpenIDX
            </CardTitle>
            <CardDescription className="text-base mt-2">
              Identity & Access Management Platform
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
              <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
              <p className="text-sm text-red-600">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            <p className="text-center text-sm text-gray-600">
              Sign in to access your OpenIDX admin console
            </p>

            {loadingIdPs ? (
              <div className="flex justify-center">
                <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
              </div>
            ) : (
              <>
                {identityProviders.map((idp) => {
                  const ProviderIcon = getProviderIcon(idp.issuer_url)
                  return (
                    <Button
                      key={idp.id}
                      onClick={() => handleSSOLogin(idp)}
                      className="w-full bg-gray-700 hover:bg-gray-800 text-white"
                      size="lg"
                      disabled={isLoading}
                    >
                      {ProviderIcon ? <ProviderIcon className="mr-2 h-4 w-4" /> : <Globe className="mr-2 h-4 w-4" />}
                      Sign in with {idp.name}
                    </Button>
                  )
                })}

                {identityProviders.length > 0 && <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
                  </div>
                </div>}

                <Button
                  onClick={handleLogin}
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                  size="lg"
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Signing in...
                    </span>
                  ) : (
                    'Sign in with OpenIDX'
                  )}
                </Button>

                <div className="text-center">
                  <Link to="/forgot-password" className="text-sm text-blue-600 hover:text-blue-800">
                    Forgot your password?
                  </Link>
                </div>
              </>
            )}
          </div>

          <div className="text-center">
            <p className="text-xs text-gray-500">
              Secured by OpenIDX authentication
            </p>
          </div>
        </CardContent>

        <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 rounded-b-lg">
          <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
            <span>Privacy</span>
            <span>•</span>
            <span>Terms</span>
            <span>•</span>
            <span>Help</span>
          </div>
        </div>
      </Card>

      {/* Footer branding */}
      <div className="absolute bottom-4 text-center w-full">
        <p className="text-sm text-gray-500">
          Powered by <span className="font-semibold text-gray-700">OpenIDX</span>
        </p>
      </div>
    </div>
  )
}
