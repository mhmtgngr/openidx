import { apiClient } from './client'
import type {
  AuditEvent,
  AuditQuery,
  ComplianceReport,
  PaginatedResponse,
} from './types'

export const auditApi = {
  // Audit events
  async queryEvents(params: AuditQuery): Promise<PaginatedResponse<AuditEvent>> {
    const response = await apiClient.get<PaginatedResponse<AuditEvent>>('/api/v1/audit/events', {
      params,
    })
    return response.data
  },

  async getEvent(id: string): Promise<AuditEvent> {
    const response = await apiClient.get<AuditEvent>(`/api/v1/audit/events/${id}`)
    return response.data
  },

  // Statistics
  async getStatistics(): Promise<{
    total_events: number
    events_by_action: Record<string, number>
    events_by_outcome: Record<string, number>
    events_by_actor: Array<{ actor_id: string; count: number }>
  }> {
    const response = await apiClient.get('/api/v1/audit/statistics')
    return response.data
  },

  // Compliance reports
  async createReport(params: {
    type: string
    period_start: string
    period_end: string
  }): Promise<ComplianceReport> {
    const response = await apiClient.post<ComplianceReport>('/api/v1/audit/reports', params)
    return response.data
  },

  async getReports(): Promise<ComplianceReport[]> {
    const response = await apiClient.get<ComplianceReport[]>('/api/v1/audit/reports')
    return response.data
  },

  async getReport(id: string): Promise<ComplianceReport> {
    const response = await apiClient.get<ComplianceReport>(`/api/v1/audit/reports/${id}`)
    return response.data
  },

  async exportEvents(params: AuditQuery & { format: 'csv' | 'json' }): Promise<Blob> {
    const response = await apiClient.get('/api/v1/audit/events/export', {
      params,
      responseType: 'blob',
    })
    return response.data
  },
}
