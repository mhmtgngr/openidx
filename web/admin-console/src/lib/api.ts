import axios, { AxiosError, AxiosRequestConfig } from 'axios'

export interface UserProfile {
  id: string
  username: string
  email: string
  firstName: string
  lastName: string
  enabled: boolean
  emailVerified: boolean
  createdAt: string
  mfaEnabled: boolean
  mfaMethods: string[]
}

export interface MFASetupResponse {
  secret: string
  qrCodeUrl: string
}

export interface MFAEnableResponse {
  status: string
  backupCodes: string[]
}

export interface IdentityProvider {
  id: string;
  name: string;
  provider_type: 'oidc' | 'saml';
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RuleCondition {
  field: string
  operator: string
  value: string
}

export interface RuleAction {
  type: string
  target: string
  parameters?: Record<string, unknown>
}

export interface ProvisioningRule {
  id: string
  name: string
  description: string
  trigger: string
  conditions: RuleCondition[]
  actions: RuleAction[]
  enabled: boolean
  priority: number
  created_at: string
  updated_at: string
}

export const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

const axiosInstance = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Exported for auth.tsx to signal when auth init is complete (kept for potential future use)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const setAuthInitializing = (_value: boolean) => {
  // Currently not used - 401 handling moved to auth context
}

// Response interceptor for error handling
axiosInstance.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Log 401 errors but don't auto-redirect - let the auth context handle session state
      // This prevents redirect loops when the backend rejects tokens during auth flow
      console.warn('[API] 401 Unauthorized:', error.config?.url)
    }
    return Promise.reject(error)
  }
)

export const api = {
  get: async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.get<T>(url, config)
    return response.data
  },

  getWithHeaders: async <T>(url: string, config?: AxiosRequestConfig): Promise<{ data: T; headers: Record<string, string> }> => {
    const response = await axiosInstance.get<T>(url, config)
    const headers: Record<string, string> = {}
    if (response.headers) {
      Object.entries(response.headers).forEach(([key, value]) => {
        if (typeof value === 'string') headers[key] = value
      })
    }
    return { data: response.data, headers }
  },

  post: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.post<T>(url, data, config)
    return response.data
  },

  put: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.put<T>(url, data, config)
    return response.data
  },

  patch: async <T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.patch<T>(url, data, config)
    return response.data
  },

  delete: async <T>(url: string, config?: AxiosRequestConfig): Promise<T> => {
    const response = await axiosInstance.delete<T>(url, config)
    return response.data
  },

  // Identity Providers API
  getIdentityProviders: async (): Promise<IdentityProvider[]> => {
    const response = await api.get<IdentityProvider[]>('/api/v1/identity/providers');
    return response;
  },

  createIdentityProvider: async (data: Omit<IdentityProvider, 'id' | 'created_at' | 'updated_at'>): Promise<IdentityProvider> => {
    const response = await api.post<IdentityProvider>('/api/v1/identity/providers', data);
    return response;
  },

  getIdentityProvider: async (id: string): Promise<IdentityProvider> => {
    const response = await api.get<IdentityProvider>(`/api/v1/identity/providers/${id}`);
    return response;
  },

  updateIdentityProvider: async (id: string, data: Partial<IdentityProvider>): Promise<IdentityProvider> => {
    const response = await api.put<IdentityProvider>(`/api/v1/identity/providers/${id}`, data);
    return response;
  },

  deleteIdentityProvider: async (id: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/providers/${id}`);
  },

  // Provisioning Rules API
  getProvisioningRules: async (): Promise<ProvisioningRule[]> => {
    return api.get<ProvisioningRule[]>('/api/v1/provisioning/rules')
  },

  createProvisioningRule: async (data: Omit<ProvisioningRule, 'id' | 'created_at' | 'updated_at'>): Promise<ProvisioningRule> => {
    return api.post<ProvisioningRule>('/api/v1/provisioning/rules', data)
  },

  updateProvisioningRule: async (id: string, data: Partial<ProvisioningRule>): Promise<ProvisioningRule> => {
    return api.put<ProvisioningRule>(`/api/v1/provisioning/rules/${id}`, data)
  },

  deleteProvisioningRule: async (id: string): Promise<void> => {
    await api.delete<void>(`/api/v1/provisioning/rules/${id}`)
  },

  postFormData: async <T>(url: string, formData: FormData): Promise<T> => {
    const response = await axiosInstance.post<T>(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return response.data
  },
}

export default axiosInstance
