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
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL || 'http://localhost:8180',
  realm: import.meta.env.VITE_KEYCLOAK_REALM || 'openidx',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'admin-console',
})

// Prevent multiple initializations (React StrictMode, etc.)
let keycloakInitialized = false
let keycloakInitPromise: Promise<boolean> | null = null

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)

  useEffect(() => {
    const initKeycloak = async () => {
      // If already initialized, just sync state from keycloak instance
      if (keycloakInitialized) {
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

      // If initialization is in progress, wait for it
      if (keycloakInitPromise) {
        console.log('[Auth] Keycloak init in progress, waiting...')
        await keycloakInitPromise
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

      console.log('[Auth] Initializing Keycloak, URL:', window.location.href)

      // Clean OAuth params from URL BEFORE init to prevent Keycloak from re-processing them
      const url = new URL(window.location.href)
      const hasOAuthParams = url.searchParams.has('code') || url.searchParams.has('state')

      keycloakInitPromise = keycloak.init({
        onLoad: 'check-sso',
        checkLoginIframe: false,
        enableLogging: true,
        silentCheckSsoRedirectUri: undefined,
      })

      try {
        const authenticated = await keycloakInitPromise
        keycloakInitialized = true
        console.log('[Auth] Keycloak init complete, authenticated:', authenticated)

        setIsAuthenticated(authenticated)
        if (authenticated && keycloak.tokenParsed) {
          console.log('[Auth] User authenticated:', keycloak.tokenParsed.preferred_username)
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
          // Clean up OAuth callback parameters from URL
          if (hasOAuthParams) {
            url.searchParams.delete('code')
            url.searchParams.delete('state')
            url.searchParams.delete('session_state')
            window.history.replaceState({}, '', url.pathname + (url.search || ''))
          }
        } else {
          console.log('[Auth] Not authenticated')
          localStorage.removeItem('token')
        }
        setAuthInitializing(false)
        setIsLoading(false)
      } catch (error) {
        console.error('[Auth] Keycloak init failed:', error)
        keycloakInitialized = true // Mark as initialized even on failure to prevent retries
        setAuthInitializing(false)
        setIsLoading(false)
      }
    }

    initKeycloak()

    // Token refresh
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
            // Token refresh failed - session is invalid, clear state and redirect to login
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
  }, [])

  const login = () => {
    // Redirect back to login page after Keycloak auth - the login page will then
    // redirect to dashboard once auth state is confirmed. This prevents the OAuth
    // callback from landing on a protected route before auth is processed.
    keycloak.login({
      redirectUri: window.location.origin + '/login',
    })
  }

  const logout = () => {
    localStorage.removeItem('token')
    keycloak.logout({ redirectUri: window.location.origin })
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
