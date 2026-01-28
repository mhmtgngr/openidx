import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import Keycloak from 'keycloak-js'
import { setAuthInitializing } from './api'

interface User {
  id: string
  email: string
  name: string
  roles: string[]
}

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  user: User | null
  token: string | null
  login: () => void
  logout: () => void
  hasRole: (role: string) => boolean
  authProvider: string
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

// Determine auth provider from environment
const AUTH_PROVIDER = import.meta.env.VITE_AUTH_PROVIDER || 'keycloak'
export const OAUTH_URL = import.meta.env.VITE_OAUTH_URL || 'http://localhost:8006'
export const OAUTH_CLIENT_ID = import.meta.env.VITE_OAUTH_CLIENT_ID || 'admin-console'

// Keycloak instance (only used if AUTH_PROVIDER is 'keycloak')
const keycloak = AUTH_PROVIDER === 'keycloak' ? new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL || 'http://localhost:8180',
  realm: import.meta.env.VITE_KEYCLOAK_REALM || 'openidx',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'admin-console',
}) : null

// Prevent multiple initializations
let authInitialized = false
let authInitPromise: Promise<boolean> | null = null

// Helper to parse JWT token
function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const base64Url = token.split('.')[1]
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return JSON.parse(jsonPayload)
  } catch {
    return null
  }
}

// Generate PKCE code verifier and challenge
function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)

  useEffect(() => {
    if (AUTH_PROVIDER === 'openidx') {
      initOpenIDXAuth()
    } else {
      initKeycloakAuth()
    }
  }, [])

  // OpenIDX OAuth authentication
  const initOpenIDXAuth = async () => {
    console.log('[Auth] Initializing OpenIDX OAuth')

    const url = new URL(window.location.href)
    const code = url.searchParams.get('code')
    const storedToken = localStorage.getItem('token')
    const refreshToken = localStorage.getItem('refresh_token')

    // Check if we have a code from OAuth callback
    if (code) {
      console.log('[Auth] Processing OAuth callback')
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier')

      try {
        const tokenResponse = await fetch(`${OAUTH_URL}/oauth/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: OAUTH_CLIENT_ID,
            code: code,
            redirect_uri: window.location.origin + '/login',
            code_verifier: codeVerifier || '',
          }),
        })

        if (tokenResponse.ok) {
          const tokens = await tokenResponse.json()
          localStorage.setItem('token', tokens.access_token)
          if (tokens.refresh_token) {
            localStorage.setItem('refresh_token', tokens.refresh_token)
          }
          sessionStorage.removeItem('pkce_code_verifier')

          // Clean URL
          url.searchParams.delete('code')
          url.searchParams.delete('state')
          window.history.replaceState({}, '', url.pathname)

          // Set auth state
          const parsed = parseJwt(tokens.access_token)
          if (parsed) {
            setUser({
              id: (parsed.sub as string) || '',
              email: (parsed.email as string) || '',
              name: (parsed.name as string) || (parsed.preferred_username as string) || '',
              roles: (parsed.roles as string[]) || [],
            })
            setToken(tokens.access_token)
            setIsAuthenticated(true)
          }
        } else {
          console.error('[Auth] Token exchange failed')
          localStorage.removeItem('token')
          localStorage.removeItem('refresh_token')
        }
      } catch (error) {
        console.error('[Auth] Token exchange error:', error)
      }

      setAuthInitializing(false)
      setIsLoading(false)
      return
    }

    // Check for existing token
    if (storedToken) {
      const parsed = parseJwt(storedToken)
      if (parsed) {
        const exp = (parsed.exp as number) * 1000
        if (exp > Date.now()) {
          console.log('[Auth] Valid token found', parsed)

          // Check if token has roles field
          const roles = parsed.roles as string[] | undefined
          if (!roles || roles.length === 0) {
            console.warn('[Auth] Token missing roles - logging out to re-authenticate')
            localStorage.removeItem('token')
            localStorage.removeItem('refresh_token')
            setAuthInitializing(false)
            setIsLoading(false)
            return
          }

          setUser({
            id: (parsed.sub as string) || '',
            email: (parsed.email as string) || '',
            name: (parsed.name as string) || (parsed.preferred_username as string) || '',
            roles: roles,
          })
          setToken(storedToken)
          setIsAuthenticated(true)
          setAuthInitializing(false)
          setIsLoading(false)

          // Setup token refresh
          setupTokenRefresh()
          return
        } else if (refreshToken) {
          // Token expired, try to refresh
          const refreshed = await refreshAccessToken(refreshToken)
          if (refreshed) {
            setAuthInitializing(false)
            setIsLoading(false)
            return
          }
        }
      }
      // Invalid token
      localStorage.removeItem('token')
      localStorage.removeItem('refresh_token')
    }

    console.log('[Auth] Not authenticated')
    setAuthInitializing(false)
    setIsLoading(false)
  }

  const refreshAccessToken = async (refreshToken: string): Promise<boolean> => {
    try {
      const response = await fetch(`${OAUTH_URL}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: OAUTH_CLIENT_ID,
          refresh_token: refreshToken,
        }),
      })

      if (response.ok) {
        const tokens = await response.json()
        localStorage.setItem('token', tokens.access_token)
        if (tokens.refresh_token) {
          localStorage.setItem('refresh_token', tokens.refresh_token)
        }

        const parsed = parseJwt(tokens.access_token)
        if (parsed) {
          setUser({
            id: (parsed.sub as string) || '',
            email: (parsed.email as string) || '',
            name: (parsed.name as string) || (parsed.preferred_username as string) || '',
            roles: (parsed.roles as string[]) || [],
          })
          setToken(tokens.access_token)
          setIsAuthenticated(true)
          return true
        }
      }
    } catch (error) {
      console.error('[Auth] Token refresh failed:', error)
    }

    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    setIsAuthenticated(false)
    setUser(null)
    setToken(null)
    return false
  }

  const setupTokenRefresh = () => {
    const refreshInterval = setInterval(async () => {
      const refreshToken = localStorage.getItem('refresh_token')
      const currentToken = localStorage.getItem('token')

      if (currentToken && refreshToken) {
        const parsed = parseJwt(currentToken)
        if (parsed) {
          const exp = (parsed.exp as number) * 1000
          // Refresh if token expires in less than 60 seconds
          if (exp - Date.now() < 60000) {
            await refreshAccessToken(refreshToken)
          }
        }
      }
    }, 30000)

    return () => clearInterval(refreshInterval)
  }

  // Keycloak authentication (existing implementation)
  const initKeycloakAuth = async () => {
    if (!keycloak) return

    if (authInitialized) {
      console.log('[Auth] Keycloak already initialized, syncing state')
      setIsAuthenticated(keycloak.authenticated || false)
      if (keycloak.authenticated && keycloak.tokenParsed) {
        setUser({
          id: keycloak.tokenParsed.sub || '',
          email: keycloak.tokenParsed.email || '',
          name: keycloak.tokenParsed.name || keycloak.tokenParsed.preferred_username || '',
          roles: keycloak.tokenParsed.realm_access?.roles || [],
        })
        setToken(keycloak.token || null)
      }
      setAuthInitializing(false)
      setIsLoading(false)
      return
    }

    if (authInitPromise) {
      console.log('[Auth] Keycloak init in progress, waiting...')
      await authInitPromise
      setIsAuthenticated(keycloak.authenticated || false)
      if (keycloak.authenticated && keycloak.tokenParsed) {
        setUser({
          id: keycloak.tokenParsed.sub || '',
          email: keycloak.tokenParsed.email || '',
          name: keycloak.tokenParsed.name || keycloak.tokenParsed.preferred_username || '',
          roles: keycloak.tokenParsed.realm_access?.roles || [],
        })
        setToken(keycloak.token || null)
      }
      setAuthInitializing(false)
      setIsLoading(false)
      return
    }

    console.log('[Auth] Initializing Keycloak')

    const url = new URL(window.location.href)
    const hasOAuthParams = url.searchParams.has('code') || url.searchParams.has('state')

    authInitPromise = keycloak.init({
      onLoad: 'check-sso',
      checkLoginIframe: false,
      enableLogging: true,
    })

    try {
      const authenticated = await authInitPromise
      authInitialized = true
      console.log('[Auth] Keycloak init complete, authenticated:', authenticated)

      setIsAuthenticated(authenticated)
      if (authenticated && keycloak.tokenParsed) {
        setUser({
          id: keycloak.tokenParsed.sub || '',
          email: keycloak.tokenParsed.email || '',
          name: keycloak.tokenParsed.name || keycloak.tokenParsed.preferred_username || '',
          roles: keycloak.tokenParsed.realm_access?.roles || [],
        })
        setToken(keycloak.token || null)
        if (keycloak.token) {
          localStorage.setItem('token', keycloak.token)
        }
        if (hasOAuthParams) {
          url.searchParams.delete('code')
          url.searchParams.delete('state')
          url.searchParams.delete('session_state')
          window.history.replaceState({}, '', url.pathname + (url.search || ''))
        }
      } else {
        localStorage.removeItem('token')
      }
      setAuthInitializing(false)
      setIsLoading(false)
    } catch (error) {
      console.error('[Auth] Keycloak init failed:', error)
      authInitialized = true
      setAuthInitializing(false)
      setIsLoading(false)
    }

    // Keycloak token refresh
    const refreshInterval = setInterval(() => {
      if (keycloak.authenticated) {
        keycloak.updateToken(60)
          .then((refreshed) => {
            if (refreshed && keycloak.token) {
              setToken(keycloak.token)
              localStorage.setItem('token', keycloak.token)
            }
          })
          .catch(() => {
            console.error('[Auth] Token refresh failed, logging out')
            setIsAuthenticated(false)
            setUser(null)
            setToken(null)
            localStorage.removeItem('token')
            keycloak.logout({ redirectUri: window.location.origin + '/login' })
          })
      }
    }, 30000)

    return () => clearInterval(refreshInterval)
  }

  const login = async () => {
    if (AUTH_PROVIDER === 'openidx') {
      // OpenIDX OAuth login with PKCE
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)
      sessionStorage.setItem('pkce_code_verifier', codeVerifier)

      const authUrl = new URL(`${OAUTH_URL}/oauth/authorize`)
      authUrl.searchParams.set('response_type', 'code')
      authUrl.searchParams.set('client_id', OAUTH_CLIENT_ID)
      authUrl.searchParams.set('redirect_uri', window.location.origin + '/login')
      authUrl.searchParams.set('scope', 'openid profile email')
      authUrl.searchParams.set('code_challenge', codeChallenge)
      authUrl.searchParams.set('code_challenge_method', 'S256')

      window.location.href = authUrl.toString()
    } else if (keycloak) {
      keycloak.login({
        redirectUri: window.location.origin + '/login',
      })
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    sessionStorage.removeItem('pkce_code_verifier')

    if (AUTH_PROVIDER === 'openidx') {
      // For OpenIDX, just clear state and redirect to login
      setIsAuthenticated(false)
      setUser(null)
      setToken(null)
      window.location.href = window.location.origin + '/login'
    } else if (keycloak) {
      keycloak.logout({ redirectUri: window.location.origin })
    }
  }

  const hasRole = (role: string) => {
    return user?.roles.includes(role) || false
  }

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isLoading,
        user,
        token,
        login,
        logout,
        hasRole,
        authProvider: AUTH_PROVIDER,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Export PKCE functions for use in login component
export { generateCodeVerifier, generateCodeChallenge }
