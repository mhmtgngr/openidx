import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'

// API response types
export interface ApiError {
  code: string
  message: string
  status?: number
  details?: unknown
}

export interface ApiResponse<T> {
  data: T
  error?: ApiError
}

// Token storage.
//
// IMPORTANT: these keys MUST match what the auth context (lib/auth.tsx) actually
// writes at login — it stores the access token under 'token' and the refresh
// token under 'refresh_token'. This client historically used different keys
// ('openidx_access_token' / 'openidx_refresh_token'), which meant that if any
// page wired this client it would read an empty token and 401 on every request.
// Keep these aligned with auth.tsx.
const TOKEN_KEY = 'token'
const REFRESH_TOKEN_KEY = 'refresh_token'

export const getToken = (): string | null => {
  return localStorage.getItem(TOKEN_KEY)
}

export const setToken = (token: string): void => {
  localStorage.setItem(TOKEN_KEY, token)
}

export const removeToken = (): void => {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
}

// Create axios instance
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor - add auth token
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = getToken()
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  },
)

// Response interceptor - handle errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<ApiError>) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    // Handle 401 - unauthorized
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      // Try to refresh token
      const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
      if (refreshToken) {
        try {
          // Refresh via the OAuth token endpoint (form-encoded, grant_type=
          // refresh_token) — the same path the auth context uses. The previous
          // '/api/v1/identity/refresh' route does NOT exist on the backend, so
          // every refresh here 404'd and logged the user out. The oauth issuer
          // base may differ from the API base, so target it explicitly.
          const oauthBase = import.meta.env.VITE_OAUTH_URL || import.meta.env.VITE_API_URL || ''
          const clientId = import.meta.env.VITE_OAUTH_CLIENT_ID || 'admin-console'
          const response = await axios.post(
            `${oauthBase}/oauth/token`,
            new URLSearchParams({
              grant_type: 'refresh_token',
              client_id: clientId,
              refresh_token: refreshToken,
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
          )

          const { access_token, refresh_token } = response.data
          setToken(access_token)
          if (refresh_token) {
            localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token)
          }

          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${access_token}`
          }

          return apiClient(originalRequest)
        } catch {
          // Refresh failed, clear tokens and redirect to login
          removeToken()
          window.location.href = '/login'
          return Promise.reject(error)
        }
      } else {
        // No refresh token, redirect to login
        removeToken()
        window.location.href = '/login'
      }
    }

    // Extract error message
    const errorMessage = error.response?.data?.message || error.message || 'An error occurred'

    return Promise.reject({
      message: errorMessage,
      code: error.response?.data?.code || 'UNKNOWN_ERROR',
      status: error.response?.status,
      details: error.response?.data?.details,
    })
  },
)

export default apiClient
