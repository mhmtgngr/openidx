import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, Loader2, Globe, ArrowLeft } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useAuth } from '../lib/auth'
import { api, baseURL, IdentityProvider } from '../lib/api'

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

  const { authProvider } = useAuth()

  const handleLogin = () => {
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

  const handleBackToOptions = () => {
    setLoginSession(null)
    setUsername('')
    setPassword('')
    setError('')
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
                {identityProviders.map((idp) => (
                  <Button
                    key={idp.id}
                    onClick={() => handleSSOLogin(idp)}
                    className="w-full bg-gray-700 hover:bg-gray-800 text-white"
                    size="lg"
                    disabled={isLoading}
                  >
                    <Globe className="mr-2 h-4 w-4" />
                    Sign in with {idp.name}
                  </Button>
                ))}

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
                    authProvider === 'openidx' ? 'Sign in with OpenIDX' : 'Sign in with Keycloak'
                  )}
                </Button>
              </>
            )}
          </div>

          <div className="text-center">
            <p className="text-xs text-gray-500">
              Secured by {authProvider === 'openidx' ? 'OpenIDX' : 'Keycloak'} authentication
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
