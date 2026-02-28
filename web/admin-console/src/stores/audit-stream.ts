import { create } from 'zustand'

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

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'error'
  | 'origin_rejected'

export interface ConnectionError {
  code: string
  message: string
  origin?: string
}

interface AuditStreamState {
  // Connection state
  connectionState: ConnectionState
  connectionError: ConnectionError | null
  isConnected: boolean
  allowedOrigins: string[]
  currentOrigin: string

  // Data
  events: AuditEvent[]
  maxEvents: number

  // WebSocket instance (non-serializable)
  _ws: WebSocket | null

  // Actions
  connect: (url: string, token?: string) => void
  disconnect: () => void
  setConnectionState: (state: ConnectionState) => void
  setConnectionError: (error: ConnectionError | null) => void
  addEvent: (event: AuditEvent) => void
  clearEvents: () => void
  setAllowedOrigins: (origins: string[]) => void
  clearError: () => void
}

export const useAuditStreamStore = create<AuditStreamState>((set, get) => ({
    // Initial state
    connectionState: 'disconnected',
    connectionError: null,
    isConnected: false,
    allowedOrigins: [],
    currentOrigin: typeof window !== 'undefined' ? window.location.origin : '',
    events: [],
    maxEvents: 500, // Keep last 500 events in memory
    _ws: null,

    // Actions
    connect: (url: string, token?: string) => {
      const state = get()
      if (state.isConnected || state.connectionState === 'connecting') {
        return
      }

      set({ connectionState: 'connecting', connectionError: null })

      try {
        // Validate origin before connecting
        const currentOrigin = state.currentOrigin
        const allowedOrigins = state.allowedOrigins

        // In production, if allowed origins is configured and current origin is not in the list,
        // we should not attempt connection
        if (allowedOrigins.length > 0 && !allowedOrigins.includes(currentOrigin)) {
          set({
            connectionState: 'origin_rejected',
            connectionError: {
              code: 'ORIGIN_NOT_ALLOWED',
              message: `Origin ${currentOrigin} is not in the allowed origins list`,
              origin: currentOrigin,
            },
          })
          return
        }

        // Create WebSocket connection
        const protocols = []
        if (token) {
          // Use subprotocol for token (common pattern)
          protocols.push(`access_token_${token}`)
        }

        // Create WebSocket connection
        const ws = new WebSocket(url, protocols)

        ws.onopen = () => {
          set({ connectionState: 'connected', isConnected: true })
        }

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.type === 'audit_event' || data.event) {
              const auditEvent: AuditEvent = data.event || data
              set((state) => {
                const newEvents = [auditEvent, ...state.events]
                return {
                  events: newEvents.slice(0, state.maxEvents),
                }
              })
            } else if (data.type === 'config') {
              // Update allowed origins from server config
              if (data.allowedOrigins) {
                set({ allowedOrigins: data.allowedOrigins })
              }
            } else if (data.type === 'error') {
              set({
                connectionState: 'error',
                connectionError: {
                  code: data.code || 'WS_ERROR',
                  message: data.message || 'WebSocket error',
                },
              })
            }
          } catch {
            // Ignore non-JSON messages
          }
        }

        ws.onerror = () => {
          set({
            connectionState: 'error',
            connectionError: {
              code: 'WS_CONNECTION_ERROR',
              message: 'WebSocket connection error',
            },
          })
        }

        ws.onclose = (event) => {
          set({
            connectionState: 'disconnected',
            isConnected: false,
          })

          // If connection was closed with an error code, log it
          if (event.code !== 1000) {
            const errorMessage = {
              1002: 'Protocol error - check WebSocket subprotocol',
              1003: 'Unsupported data type',
              1006: 'Connection closed abnormally',
              1007: 'Invalid message format',
              1008: 'Policy violation - origin may not be allowed',
              1010: 'Missing required extension',
              1011: 'Internal server error',
            }[event.code] || `Connection closed with code ${event.code}`

            set({
              connectionState: 'error',
              connectionError: {
                code: `WS_CLOSE_${event.code}`,
                message: errorMessage,
              },
            })
          }
        }

        // Store WebSocket instance for cleanup
        set({ _ws: ws })
      } catch (error) {
        set({
          connectionState: 'error',
          connectionError: {
            code: 'WS_INIT_ERROR',
            message: error instanceof Error ? error.message : 'Failed to initialize WebSocket',
          },
        })
      }
    },

    disconnect: () => {
      const ws = get()._ws
      if (ws) {
        ws.close(1000, 'User disconnected')
      }
      set({
        _ws: null,
        connectionState: 'disconnected',
        isConnected: false,
        connectionError: null,
      })
    },

    setConnectionState: (state) => {
      set({ connectionState: state })
    },

    setConnectionError: (error) => {
      set({ connectionError: error })
    },

    addEvent: (event) => {
      set((state) => {
        const newEvents = [event, ...state.events]
        return {
          events: newEvents.slice(0, state.maxEvents),
        }
      })
    },

    clearEvents: () => {
      set({ events: [] })
    },

    setAllowedOrigins: (origins) => {
      set({ allowedOrigins: origins })
    },

    clearError: () => {
      set({ connectionError: null })
    },
  })
)
