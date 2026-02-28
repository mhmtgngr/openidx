import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useAuditStreamStore } from './audit-stream'

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  url: string
  protocols: string[] | undefined
  readyState: number = MockWebSocket.CONNECTING
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null

  constructor(url: string, protocols?: string[]) {
    this.url = url
    this.protocols = protocols

    // Simulate async connection
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN
      if (this.onopen) {
        this.onopen(new Event('open'))
      }
    }, 0)
  }

  send(data: string): void {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open')
    }
  }

  close(code?: number, reason?: string): void {
    this.readyState = MockWebSocket.CLOSED
    if (this.onclose) {
      const event = new CloseEvent('close', {
        code: code ?? 1000,
        reason: reason ?? '',
        wasClean: true,
      })
      this.onclose(event)
    }
  }

  // Helper methods for testing
  simulateMessage(data: unknown): void {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data }))
    }
  }

  simulateError(): void {
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }
}

// Mock global WebSocket
vi.stubGlobal('WebSocket', MockWebSocket)

// Mock window.location
const mockLocation = {
  origin: 'https://example.com',
  href: 'https://example.com/',
  protocol: 'https:',
  hostname: 'example.com',
  port: '',
  pathname: '/',
  search: '',
  hash: '',
}

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
})

describe('Audit Stream Store', () => {
  beforeEach(() => {
    // Reset store state before each test
    const { result } = renderHook(() => useAuditStreamStore())
    act(() => {
      result.current.disconnect()
      result.current.clearEvents()
      result.current.clearError()
      result.current.setAllowedOrigins([]) // Reset allowed origins
      result.current.setCurrentOrigin(mockLocation.origin) // Reset to mocked origin
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      expect(result.current.connectionState).toBe('disconnected')
      expect(result.current.connectionError).toBeNull()
      expect(result.current.isConnected).toBe(false)
      expect(result.current.allowedOrigins).toEqual([])
      expect(result.current.currentOrigin).toBe('https://example.com')
      expect(result.current.events).toEqual([])
      expect(result.current.maxEvents).toBe(500)
    })
  })

  describe('Connection Management', () => {
    it('should connect to WebSocket', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // State should transition to connecting first
      expect(result.current.connectionState).toBe('connecting')

      // Then to connected after WebSocket opens
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      expect(result.current.connectionState).toBe('connected')
      expect(result.current.isConnected).toBe(true)
      expect(result.current.connectionError).toBeNull()
    })

    it('should disconnect from WebSocket', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      act(() => {
        result.current.disconnect()
      })

      expect(result.current.connectionState).toBe('disconnected')
      expect(result.current.isConnected).toBe(false)
    })

    it('should not connect if already connected', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const wsSpy = vi.spyOn(global, 'WebSocket')

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should only create one WebSocket instance
      expect(wsSpy).toHaveBeenCalledTimes(1)
    })

    it('should not connect if already connecting', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const wsSpy = vi.spyOn(global, 'WebSocket')

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Immediately try to connect again
      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should only create one WebSocket instance
      expect(wsSpy).toHaveBeenCalledTimes(1)
    })
  })

  describe('Origin Validation', () => {
    it('should reject connection when origin not in allowed list', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setAllowedOrigins(['https://allowed.example.com'])
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should immediately reject
      expect(result.current.connectionState).toBe('origin_rejected')
      expect(result.current.connectionError).toEqual({
        code: 'ORIGIN_NOT_ALLOWED',
        message: 'Origin https://example.com is not in the allowed origins list',
        origin: 'https://example.com',
      })
    })

    it('should allow connection when origin is in allowed list', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setAllowedOrigins(['https://example.com'])
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should proceed to connecting
      expect(result.current.connectionState).toBe('connecting')
    })

    it('should allow connection when allowed origins is empty', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setAllowedOrigins([])
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should proceed to connecting (no validation)
      expect(result.current.connectionState).toBe('connecting')
    })
  })

  describe('Event Handling', () => {
    it('should receive and store audit events', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        // Get the WebSocket instance and simulate a message
        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.simulateMessage({
            type: 'audit_event',
            event: {
              id: 'evt-123',
              timestamp: '2025-02-28T12:00:00Z',
              actor_id: 'user-123',
              actor_type: 'user',
              action: 'user.login',
              resource_type: 'session',
              resource_id: 'sess-456',
              outcome: 'success',
            },
          })
        }
      })

      expect(result.current.events).toHaveLength(1)
      expect(result.current.events[0]).toMatchObject({
        id: 'evt-123',
        actor_id: 'user-123',
        action: 'user.login',
      })
    })

    it('should limit events to maxEvents', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      // Set a smaller max for testing
      act(() => {
        ;(result.current as unknown as { maxEvents: number }).maxEvents = 5
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          // Add more events than maxEvents
          for (let i = 0; i < 10; i++) {
            ws.simulateMessage({
              type: 'audit_event',
              event: {
                id: `evt-${i}`,
                timestamp: '2025-02-28T12:00:00Z',
                actor_id: 'user-123',
                actor_type: 'user',
                action: 'test.action',
                resource_type: 'test',
                resource_id: `test-${i}`,
                outcome: 'success',
              },
            })
          }
        }
      })

      // Should only keep the last 5 events
      expect(result.current.events.length).toBeLessThanOrEqual(5)
    })

    it('should update allowed origins from config message', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.simulateMessage({
            type: 'config',
            allowedOrigins: ['https://example.com', 'https://app.example.com'],
          })
        }
      })

      expect(result.current.allowedOrigins).toEqual([
        'https://example.com',
        'https://app.example.com',
      ])
    })

    it('should handle error messages', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.simulateMessage({
            type: 'error',
            code: 'AUTH_FAILED',
            message: 'Authentication failed',
          })
        }
      })

      expect(result.current.connectionState).toBe('error')
      expect(result.current.connectionError).toEqual({
        code: 'AUTH_FAILED',
        message: 'Authentication failed',
      })
    })
  })

  describe('Error Handling', () => {
    it('should handle WebSocket errors', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.simulateError()
        }
      })

      expect(result.current.connectionState).toBe('error')
      expect(result.current.connectionError).toEqual({
        code: 'WS_CONNECTION_ERROR',
        message: 'WebSocket connection error',
      })
    })

    it('should handle connection close with error code', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.close(1008, 'Policy violation')
        }
      })

      expect(result.current.connectionState).toBe('error')
      expect(result.current.connectionError).toEqual({
        code: 'WS_CLOSE_1008',
        message: 'Policy violation - origin may not be allowed',
      })
    })

    it('should handle non-JSON messages gracefully', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          // This should not throw
          ws.simulateMessage('plain text message')
        }
      })

      // Should still be connected
      expect(result.current.connectionState).toBe('connected')
    })
  })

  describe('State Management', () => {
    it('should set connection state', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setConnectionState('connecting')
      })

      expect(result.current.connectionState).toBe('connecting')
    })

    it('should set connection error', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const error = {
        code: 'TEST_ERROR',
        message: 'Test error message',
      }

      act(() => {
        result.current.setConnectionError(error)
      })

      expect(result.current.connectionError).toEqual(error)
    })

    it('should clear connection error', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setConnectionError({
          code: 'TEST_ERROR',
          message: 'Test error',
        })
      })

      act(() => {
        result.current.clearError()
      })

      expect(result.current.connectionError).toBeNull()
    })

    it('should set allowed origins', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const origins = ['https://example.com', 'https://app.example.com']

      act(() => {
        result.current.setAllowedOrigins(origins)
      })

      expect(result.current.allowedOrigins).toEqual(origins)
    })

    it('should add event', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const event = {
        id: 'evt-123',
        timestamp: '2025-02-28T12:00:00Z',
        actor_id: 'user-123',
        actor_type: 'user' as const,
        action: 'test.action',
        resource_type: 'test',
        resource_id: 'test-123',
        outcome: 'success' as const,
      }

      act(() => {
        result.current.addEvent(event)
      })

      expect(result.current.events).toHaveLength(1)
      expect(result.current.events[0]).toEqual(event)
    })

    it('should clear events', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.addEvent({
          id: 'evt-1',
          timestamp: '2025-02-28T12:00:00Z',
          actor_id: 'user-1',
          actor_type: 'user',
          action: 'test.action',
          resource_type: 'test',
          resource_id: 'test-1',
          outcome: 'success',
        })
      })

      expect(result.current.events).toHaveLength(1)

      act(() => {
        result.current.clearEvents()
      })

      expect(result.current.events).toHaveLength(0)
    })
  })

  describe('Token Authentication', () => {
    it('should include token as subprotocol', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const wsSpy = vi.spyOn(global, 'WebSocket')

      act(() => {
        result.current.connect('wss://example.com/audit/stream', 'test-token-123')
      })

      expect(wsSpy).toHaveBeenCalledWith(
        'wss://example.com/audit/stream',
        ['access_token_test-token-123']
      )
    })

    it('should connect without token when not provided', () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const wsSpy = vi.spyOn(global, 'WebSocket')

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      expect(wsSpy).toHaveBeenCalledWith('wss://example.com/audit/stream', [])
    })
  })

  describe('Close Code Messages', () => {
    it('should provide meaningful error message for close code 1006', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.close(1006)
        }
      })

      expect(result.current.connectionError?.message).toBe(
        'Connection closed abnormally'
      )
    })

    it('should provide meaningful error message for close code 1000', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))

        const ws = (result.current as unknown as { _ws: MockWebSocket })._ws as MockWebSocket
        if (ws) {
          ws.close(1000, 'Normal closure')
        }
      })

      // Should not set error for normal closure
      expect(result.current.connectionState).toBe('disconnected')
    })
  })
})
