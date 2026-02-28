import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

// Mock window.location before importing the store
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

// Track WebSocket instances for testing
let mockWebSocketInstances: any[] = []

// Create a proper MockWebSocket class
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

    // Track this instance
    mockWebSocketInstances.push(this)

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

// Use vi.stubGlobal to mock WebSocket
vi.stubGlobal('WebSocket', MockWebSocket)

// Import store AFTER WebSocket is mocked
import { useAuditStreamStore } from './audit-stream'

describe('Audit Stream Store', () => {
  beforeEach(() => {
    // Clear WebSocket instances
    mockWebSocketInstances = []

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
    // Clean up WebSocket instances
    mockWebSocketInstances.forEach(ws => {
      try {
        ws.close()
      } catch {
        // Ignore
      }
    })
    mockWebSocketInstances = []
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

    it('should not connect if already connected', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const initialCount = mockWebSocketInstances.length

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Wait for async connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      // Should only create one WebSocket instance
      // (Note: The connection is rejected because it's already connecting/connected)
      expect(mockWebSocketInstances.length).toBe(initialCount + 1)
    })

    it('should not connect if already connecting', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const initialCount = mockWebSocketInstances.length

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Immediately try to connect again
      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Wait for async connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      // Should only create one WebSocket instance
      expect(mockWebSocketInstances.length).toBe(initialCount + 1)
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

    it('should allow connection when origin is in allowed list', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setAllowedOrigins(['https://example.com'])
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should proceed to connecting
      expect(result.current.connectionState).toBe('connecting')

      // Wait for connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      expect(result.current.connectionState).toBe('connected')
    })

    it('should allow connection when allowed origins is empty', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      act(() => {
        result.current.setAllowedOrigins([])
      })

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Should proceed to connecting (no validation)
      expect(result.current.connectionState).toBe('connecting')

      // Wait for connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      expect(result.current.connectionState).toBe('connected')
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
        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onmessage) {
          // Send JSON string like real WebSocket
          ws.onmessage(new MessageEvent('message', {
            data: JSON.stringify({
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
          }))
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onmessage) {
          // Add more events than maxEvents
          for (let i = 0; i < 10; i++) {
            ws.onmessage(new MessageEvent('message', {
              data: JSON.stringify({
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
            }))
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

        // Get the WebSocket instance and send a config message
        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onmessage) {
          // Send JSON string like real WebSocket
          ws.onmessage(new MessageEvent('message', {
            data: JSON.stringify({
              type: 'config',
              allowedOrigins: ['https://example.com', 'https://app.example.com'],
            })
          }))
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

        // Get the WebSocket instance and send an error message
        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onmessage) {
          // Send JSON string like real WebSocket
          ws.onmessage(new MessageEvent('message', {
            data: JSON.stringify({
              type: 'error',
              code: 'AUTH_FAILED',
              message: 'Authentication failed',
            })
          }))
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onerror) {
          ws.onerror(new Event('error'))
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onclose) {
          ws.onclose(new CloseEvent('close', { code: 1008, reason: 'Policy violation', wasClean: true }))
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onmessage) {
          // This should not throw - plain text message
          ws.onmessage(new MessageEvent('message', { data: 'plain text message' }))
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
    it('should include token as subprotocol', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const initialCount = mockWebSocketInstances.length

      act(() => {
        result.current.connect('wss://example.com/audit/stream', 'test-token-123')
      })

      // Wait for connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      // Check that WebSocket was created with the token protocol
      expect(mockWebSocketInstances.length).toBe(initialCount + 1)
      const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
      expect(ws.protocols).toEqual(['access_token_test-token-123'])
    })

    it('should connect without token when not provided', async () => {
      const { result } = renderHook(() => useAuditStreamStore())

      const initialCount = mockWebSocketInstances.length

      act(() => {
        result.current.connect('wss://example.com/audit/stream')
      })

      // Wait for connection
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
      })

      // Check that WebSocket was created without protocols
      expect(mockWebSocketInstances.length).toBe(initialCount + 1)
      const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
      // When no token, protocols array is empty
      expect(ws.protocols).toEqual([])
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onclose) {
          ws.onclose(new CloseEvent('close', { code: 1006, reason: '', wasClean: false }))
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

        const ws = mockWebSocketInstances[mockWebSocketInstances.length - 1]
        if (ws && ws.onclose) {
          ws.onclose(new CloseEvent('close', { code: 1000, reason: 'Normal closure', wasClean: true }))
        }
      })

      // Should not set error for normal closure
      expect(result.current.connectionState).toBe('disconnected')
    })
  })
})
