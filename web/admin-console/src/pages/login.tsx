import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, Loader2, Globe } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { useAuth } from '../lib/auth'
import { api, baseURL, IdentityProvider } from '../lib/api'
import { useToast } from '../hooks/use-toast'

export function LoginPage() {
  const navigate = useNavigate()
  const { login, isAuthenticated, isLoading } = useAuth()
  const [error, setError] = useState('')
  const [identityProviders, setIdentityProviders] = useState<IdentityProvider[]>([])
  const [loadingIdPs, setLoadingIdPs] = useState(true)
  const { toast } = useToast()

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
        toast({
          title: "Error",
          description: "Failed to load external identity providers.",
          variant: "destructive",
        });
        console.error("Failed to fetch identity providers:", err);
      } finally {
        setLoadingIdPs(false)
      }
    }
    fetchIdPs()
  }, [toast])

  // Check for OAuth callback parameters and handle authentication
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const hasOAuthParams = urlParams.has('code') || urlParams.has('state') || urlParams.has('session_state')

    if (hasOAuthParams && !isLoading) {
      // OAuth callback - Keycloak will handle this automatically via the auth provider
      // Just wait for authentication state to update
      const timer = setTimeout(() => {
        if (!isAuthenticated) {
          setError('Authentication failed. Please try again.')
        }
      }, 3000)

      return () => clearTimeout(timer)
    }
  }, [isAuthenticated, isLoading])

  const handleKeycloakLogin = () => {
    setError('')
    login() // This is the existing Keycloak login
  }

  const handleSSOLogin = (idp: IdentityProvider) => {
    setError('')
    // Construct the redirect URL to our OAuth service's authorize endpoint
    // with idp_hint set to the external IdP's ID
    const redirectUrl = `${baseURL}/oauth/authorize?response_type=code&client_id=admin-console&redirect_uri=${window.location.origin}/login&scope=openid%20profile%20email&idp_hint=${idp.id}`
    window.location.href = redirectUrl
  }

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
                  onClick={handleKeycloakLogin}
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
                    'Sign in with Keycloak'
                  )}
                </Button>
              </>
            )}
          </div>

          <div className="text-center">
            <p className="text-xs text-gray-500">
              Secured by Keycloak authentication
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
