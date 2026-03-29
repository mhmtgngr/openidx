import { describe, it, expect, vi, beforeEach } from 'vitest'
import { auditApi } from './audit'
import { ApiError } from './client'

// Mock the apiClient
vi.mock('./client', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
  },
  ApiError: class extends Error {
    code: string
    status?: number
    details?: unknown
    constructor(message: string, code: string, status?: number) {
      super(message)
      this.name = 'ApiError'
      this.code = code
      this.status = status
    }
  },
}))

import { apiClient } from './client'

describe('Audit API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('queryEvents', () => {
    it('should query audit events successfully', async () => {
      const mockResponse = {
        data: {
          data: [
            {
              id: 'evt-123',
              timestamp: '2025-02-28T12:00:00Z',
              actor_id: 'user-123',
              actor_type: 'user',
              action: 'user.login',
              resource_type: 'session',
              resource_id: 'sess-456',
              outcome: 'success',
            },
          ],
          total: 1,
          page: 1,
          per_page: 50,
        },
      }

      vi.mocked(apiClient.get).mockResolvedValue(mockResponse)

      const params = {
        actor_id: 'user-123',
        limit: 10,
      }

      const result = await auditApi.queryEvents(params)

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events', {
        params,
      })
      expect(result).toEqual(mockResponse.data)
    })

    it('should handle API errors', async () => {
      const mockError: ApiError = {
        code: 'UNAUTHORIZED',
        message: 'Unauthorized access',
        status: 401,
      }

      vi.mocked(apiClient.get).mockRejectedValue(mockError)

      await expect(
        auditApi.queryEvents({})
      ).rejects.toEqual(mockError)
    })
  })

  describe('getEvent', () => {
    it('should get a single audit event', async () => {
      const mockEvent = {
        id: 'evt-123',
        timestamp: '2025-02-28T12:00:00Z',
        actor_id: 'user-123',
        actor_type: 'user',
        action: 'user.login',
        resource_type: 'session',
        resource_id: 'sess-456',
        outcome: 'success',
        ip_address: '192.168.1.100',
        details: {
          browser: 'Chrome',
          os: 'Windows',
        },
      }

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockEvent })

      const result = await auditApi.getEvent('evt-123')

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events/evt-123')
      expect(result).toEqual(mockEvent)
    })

    it('should handle 404 for non-existent event', async () => {
      const mockError: ApiError = {
        code: 'NOT_FOUND',
        message: 'Event not found',
        status: 404,
      }

      vi.mocked(apiClient.get).mockRejectedValue(mockError)

      await expect(
        auditApi.getEvent('non-existent')
      ).rejects.toEqual(mockError)
    })
  })

  describe('getStatistics', () => {
    it('should get audit statistics', async () => {
      const mockStats = {
        total_events: 12345,
        events_by_action: {
          'user.login': 5432,
          'user.logout': 4321,
          'user.create': 1234,
          'user.delete': 567,
        },
        events_by_outcome: {
          success: 11000,
          failure: 1345,
        },
        events_by_actor: [
          { actor_id: 'user-123', count: 234 },
          { actor_id: 'user-456', count: 123 },
        ],
      }

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockStats })

      const result = await auditApi.getStatistics()

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/statistics')
      expect(result).toEqual(mockStats)
    })
  })

  describe('createReport', () => {
    it('should create a compliance report', async () => {
      const mockReport = {
        id: 'report-123',
        type: 'SOX',
        period_start: '2025-01-01T00:00:00Z',
        period_end: '2025-01-31T23:59:59Z',
        status: 'pending',
        created_at: '2025-02-28T12:00:00Z',
      }

      vi.mocked(apiClient.post).mockResolvedValue({ data: mockReport })

      const params = {
        type: 'SOX',
        period_start: '2025-01-01T00:00:00Z',
        period_end: '2025-01-31T23:59:59Z',
      }

      const result = await auditApi.createReport(params)

      expect(apiClient.post).toHaveBeenCalledWith('/api/v1/audit/reports', params)
      expect(result).toEqual(mockReport)
    })
  })

  describe('getReports', () => {
    it('should get all compliance reports', async () => {
      const mockReports = [
        {
          id: 'report-123',
          type: 'SOX',
          period_start: '2025-01-01T00:00:00Z',
          period_end: '2025-01-31T23:59:59Z',
          status: 'completed',
          created_at: '2025-02-28T12:00:00Z',
        },
        {
          id: 'report-456',
          type: 'SOC2',
          period_start: '2025-02-01T00:00:00Z',
          period_end: '2025-02-28T23:59:59Z',
          status: 'pending',
          created_at: '2025-02-28T13:00:00Z',
        },
      ]

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockReports })

      const result = await auditApi.getReports()

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/reports')
      expect(result).toEqual(mockReports)
    })
  })

  describe('getReport', () => {
    it('should get a single compliance report', async () => {
      const mockReport = {
        id: 'report-123',
        type: 'SOX',
        period_start: '2025-01-01T00:00:00Z',
        period_end: '2025-01-31T23:59:59Z',
        status: 'completed',
        created_at: '2025-02-28T12:00:00Z',
        completed_at: '2025-02-28T12:05:00Z',
        file_url: 'https://example.com/reports/report-123.pdf',
        event_count: 12345,
      }

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockReport })

      const result = await auditApi.getReport('report-123')

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/reports/report-123')
      expect(result).toEqual(mockReport)
    })
  })

  describe('exportEvents', () => {
    it('should export events as CSV', async () => {
      const mockBlob = new Blob(['csv,data'], { type: 'text/csv' })

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockBlob })

      const params = {
        format: 'csv' as const,
        actor_id: 'user-123',
      }

      const result = await auditApi.exportEvents(params)

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events/export', {
        params,
        responseType: 'blob',
      })
      expect(result).toEqual(mockBlob)
    })

    it('should export events as JSON', async () => {
      const mockBlob = new Blob(['{"events":[]}'], {
        type: 'application/json',
      })

      vi.mocked(apiClient.get).mockResolvedValue({ data: mockBlob })

      const params = {
        format: 'json' as const,
        limit: 1000,
      }

      const result = await auditApi.exportEvents(params)

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events/export', {
        params,
        responseType: 'blob',
      })
      expect(result).toEqual(mockBlob)
    })
  })

  describe('Error Handling', () => {
    it('should handle network errors', async () => {
      const mockError: ApiError = {
        code: 'NETWORK_ERROR',
        message: 'Network request failed',
      }

      vi.mocked(apiClient.get).mockRejectedValue(mockError)

      await expect(
        auditApi.queryEvents({})
      ).rejects.toEqual(mockError)
    })

    it('should handle rate limiting errors', async () => {
      const mockError: ApiError = {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        status: 429,
      }

      vi.mocked(apiClient.get).mockRejectedValue(mockError)

      await expect(
        auditApi.queryEvents({})
      ).rejects.toEqual(mockError)
    })

    it('should handle server errors', async () => {
      const mockError: ApiError = {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected error occurred',
        status: 500,
      }

      vi.mocked(apiClient.get).mockRejectedValue(mockError)

      await expect(
        auditApi.queryEvents({})
      ).rejects.toEqual(mockError)
    })
  })

  describe('Query Parameters', () => {
    it('should pass query parameters correctly', async () => {
      vi.mocked(apiClient.get).mockResolvedValue({ data: { data: [], total: 0 } })

      const params = {
        actor_id: 'user-123',
        action: 'user.login',
        outcome: 'success' as const,
        limit: 50,
        offset: 0,
      }

      await auditApi.queryEvents(params)

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events', {
        params,
      })
    })

    it('should handle empty query parameters', async () => {
      vi.mocked(apiClient.get).mockResolvedValue({ data: { data: [], total: 0 } })

      await auditApi.queryEvents({})

      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/audit/events', {
        params: {},
      })
    })
  })
})
