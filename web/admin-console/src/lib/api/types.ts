// User types
export interface User {
  id: string
  email: string
  username: string
  first_name?: string
  last_name?: string
  display_name?: string
  status: 'active' | 'inactive' | 'suspended' | 'pending'
  created_at: string
  updated_at: string
  last_login?: string
}

export interface CreateUserRequest {
  email: string
  username: string
  first_name?: string
  last_name?: string
  password: string
}

export interface UpdateUserRequest {
  email?: string
  username?: string
  first_name?: string
  last_name?: string
  status?: User['status']
}

export interface UserSession {
  id: string
  user_id: string
  ip_address: string
  user_agent: string
  created_at: string
  expires_at: string
  last_active: string
}

// Pagination types
export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface ListParams {
  page?: number
  per_page?: number
  search?: string
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

// Access Review types
export interface AccessReview {
  id: string
  title: string
  description?: string
  status: 'pending' | 'approved' | 'denied' | 'expired'
  reviewer_id: string
  requester_id: string
  created_at: string
  due_date?: string
  completed_at?: string
}

export interface AccessReviewItem {
  id: string
  review_id: string
  resource_type: string
  resource_id: string
  resource_name: string
  requested_by: string
  requested_at: string
  status: 'pending' | 'approved' | 'denied'
  decision_reason?: string
  decided_at?: string
}

export interface SubmitDecisionRequest {
  decision: 'approve' | 'deny'
  reason?: string
}

// Policy types
export interface Policy {
  id: string
  name: string
  description?: string
  type: 'rbac' | 'abac' | 'custom'
  status: 'active' | 'inactive'
  rules: PolicyRule[]
  created_at: string
  updated_at: string
  created_by: string
}

export interface PolicyRule {
  id: string
  effect: 'allow' | 'deny'
  actions: string[]
  resources: string[]
  conditions?: Record<string, unknown>
}

export interface CreatePolicyRequest {
  name: string
  description?: string
  type: Policy['type']
  rules: Omit<PolicyRule, 'id'>[]
}

// Audit types
export interface AuditEvent {
  id: string
  timestamp: string
  actor_id: string
  actor_type: 'user' | 'service' | 'system'
  action: string
  resource_type: string
  resource_id: string
  outcome: 'success' | 'failure' | 'partial'
  ip_address?: string
  details?: Record<string, unknown>
}

export interface AuditQuery {
  start_date?: string
  end_date?: string
  actor_id?: string
  action?: string
  resource_type?: string
  resource_id?: string
  outcome?: AuditEvent['outcome']
  page?: number
  per_page?: number
}

export interface ComplianceReport {
  id: string
  type: string
  period_start: string
  period_end: string
  status: 'pending' | 'completed' | 'failed'
  created_at: string
  completed_at?: string
  download_url?: string
}

// Dashboard types
export interface DashboardStats {
  total_users: number
  active_sessions: number
  pending_reviews: number
  active_policies: number
  recent_events: AuditEvent[]
}

// Settings types
export interface SystemSettings {
  site_name: string
  site_url: string
  session_timeout_minutes: number
  max_login_attempts: number
  password_min_length: number
  password_require_uppercase: boolean
  password_require_lowercase: boolean
  password_require_numbers: boolean
  password_require_symbols: boolean
  mfa_enabled: boolean
  mfa_method: 'totp' | 'sms' | 'email' | 'none'
}

// Application types
export interface Application {
  id: string
  name: string
  description?: string
  client_id: string
  redirect_uris: string[]
  grant_types: string[]
  status: 'active' | 'inactive'
  created_at: string
  updated_at: string
}
