import { useQuery } from '@tanstack/react-query'
import { api } from './api'

// GET /api/v1/security-posture (admin-api): which authorization controls are
// open, what each would have refused this week, and the days left in a
// declared observe window. Production startup refuses open controls outside
// such a window, so an administrator who sees this banner is mid-rollout.
export interface EnforcementGate {
  name: string
  mode: 'off' | 'observe' | 'enforce' | string
  enforcing: boolean
  meaning?: string
  observe_action?: string
  would_deny_7d: number
}

export interface EnforcementPosture {
  environment: string
  fully_enforcing: boolean
  observe_until?: string
  observe_days_left?: number
  window_status?: string
  gates: EnforcementGate[]
  env_lines: string[]
}

export function useEnforcementPosture(enabled = true) {
  return useQuery({
    queryKey: ['security-posture'],
    queryFn: () => api.get<EnforcementPosture>('/api/v1/security-posture'),
    enabled,
    staleTime: 60_000,
  })
}
