import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'

// API response types
export interface ApiError {
  code: string
  message: string
  details?: unknown
}

export interface ApiResponse<T> {
  data: T
  error?: ApiError
}

// Token storage
const TOKEN_KEY = 'openidx_access_token'
const REFRESH_TOKEN_KEY = 'openidx_refresh_token'

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
          const response = await axios.post('/api/v1/identity/refresh', {
            refresh_token: refreshToken,
          })

          const { access_token } = response.data
          setToken(access_token)

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
