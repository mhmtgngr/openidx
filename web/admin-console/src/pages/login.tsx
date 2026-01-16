import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'

export function LoginPage() {
  const { isAuthenticated, login, isLoading } = useAuth()
  const navigate = useNavigate()

  // Check if this is an OAuth callback (has code param)
  const isOAuthCallback = window.location.search.includes('code=')

  useEffect(() => {
    // Wait for auth initialization to complete
    if (isLoading) {
      console.log('[Login] Auth still loading, waiting...')
      return
    }

    // Once loading is complete and user is authenticated, redirect to dashboard
    if (isAuthenticated) {
      console.log('[Login] User authenticated, redirecting to dashboard')
      // Clean up any OAuth params from URL before redirecting
      if (window.location.search) {
        window.history.replaceState({}, '', '/login')
      }
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, isLoading, navigate])

  // Show a simple loading state during OAuth callback processing
  if (isOAuthCallback && isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <Shield className="h-12 w-12 text-blue-600 animate-pulse" />
            </div>
            <CardTitle className="text-2xl">Signing you in...</CardTitle>
            <CardDescription>
              Please wait while we complete the authentication.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-600" />
          </div>
          <CardTitle className="text-2xl">Welcome to OpenIDX</CardTitle>
          <CardDescription>
            Sign in to access the admin console
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            className="w-full"
            size="lg"
            onClick={login}
            disabled={isLoading}
          >
            {isLoading ? 'Loading...' : 'Sign in with SSO'}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
