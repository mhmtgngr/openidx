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

// Get API base URL based on environment
const getAPIBaseURL = (): string => {
  const envURL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL
  if (envURL) {
    return envURL
  }

  // In production, use the current origin
  if (import.meta.env.PROD && window.location.origin !== 'http://localhost:3000') {
    return window.location.origin
  }

  return 'http://localhost:8005'
}

export const baseURL = getAPIBaseURL()

// Get OAuth URL based on environment
// Export as function for use in auth.tsx
export function getOAuthURL(): string {
  return import.meta.env.VITE_OAUTH_URL || baseURL
}

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

  // WebAuthn API
  getWebAuthnCredentials: async (): Promise<WebAuthnCredential[]> => {
    return api.get<WebAuthnCredential[]>('/api/v1/identity/mfa/webauthn/credentials')
  },

  beginWebAuthnRegistration: async (): Promise<unknown> => {
    return api.post<unknown>('/api/v1/identity/mfa/webauthn/register/begin')
  },

  finishWebAuthnRegistration: async (data: unknown): Promise<WebAuthnCredential> => {
    return api.post<WebAuthnCredential>('/api/v1/identity/mfa/webauthn/register/finish', data)
  },

  deleteWebAuthnCredential: async (credentialId: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/mfa/webauthn/credentials/${credentialId}`)
  },

  // Push MFA API
  getPushDevices: async (): Promise<PushMFADevice[]> => {
    return api.get<PushMFADevice[]>('/api/v1/identity/mfa/push/devices')
  },

  registerPushDevice: async (data: PushMFAEnrollment): Promise<PushMFADevice> => {
    return api.post<PushMFADevice>('/api/v1/identity/mfa/push/devices', data)
  },

  deletePushDevice: async (deviceId: string): Promise<void> => {
    await api.delete<void>(`/api/v1/identity/mfa/push/devices/${deviceId}`)
  },

  // Audit stream WebSocket helpers
  createAuditStreamConnection: (options: {
    token?: string
    onMessage: (event: MessageEvent) => void
    onOpen?: () => void
    onError?: (error: Event) => void
    onClose?: (event: CloseEvent) => void
  }) => {
    const apiBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''
    let wsUrl: string

    if (apiBase) {
      // Convert HTTP to WebSocket protocol
      wsUrl = apiBase.replace(/^https?:\/\//, window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    } else {
      // Default to current origin with WebSocket protocol
      wsUrl = window.location.protocol === 'https:'
        ? `wss://${window.location.host}`
        : `ws://${window.location.host}`
    }

    wsUrl = `${wsUrl}/api/v1/audit/stream`

    // Note: Origin header cannot be set manually in browser WebSocket API
    // The browser automatically sets it based on the current page origin
    // Origin validation happens server-side
    const protocols = []
    if (options.token) {
      // Use subprotocol for token (common pattern)
      protocols.push(`access_token_${options.token}`)
    }

    const ws = new WebSocket(wsUrl, protocols)

    ws.onopen = options.onOpen ?? null
    ws.onmessage = options.onMessage
    ws.onerror = options.onError ?? null
    ws.onclose = options.onClose ?? null

    return ws
  },

  getWebSocketUrl: (): string => {
    const apiBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''

    if (apiBase) {
      return apiBase.replace(/^https?:\/\//, window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    }

    return window.location.protocol === 'https:'
      ? `wss://${window.location.host}`
      : `ws://${window.location.host}`
  },
}

// WebAuthn types
export interface WebAuthnCredential {
  id: string
  user_id: string
  credential_id: string
  name: string
  aaguid: string
  sign_count: number
  created_at: string
  last_used_at?: string
}

// Push MFA types
export interface PushMFADevice {
  id: string
  user_id: string
  device_name: string
  platform: string
  device_model: string
  enabled: boolean
  trusted: boolean
  created_at: string
  last_used_at?: string
}

export interface PushMFAEnrollment {
  device_token: string
  platform: 'ios' | 'android' | 'web'
  device_name: string
  device_model?: string
}

export default axiosInstance
