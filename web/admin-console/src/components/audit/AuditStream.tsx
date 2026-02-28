import { useEffect, useRef } from 'react'
import { useAuditStreamStore, type ConnectionState } from '../../stores/audit-stream'
import { Badge } from '../ui/badge'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { LoadingSpinner } from '../ui/loading-spinner'
import { AlertCircle, CheckCircle, Plug, Unplug, RefreshCw, Shield, XCircle } from 'lucide-react'

interface AuditStreamProps {
  /** WebSocket URL for the audit stream endpoint */
  wsUrl?: string
  /** Optional auth token for WebSocket connection */
  token?: string
  /** Whether to auto-connect on mount */
  autoConnect?: boolean
  /** Event handlers */
  onStateChange?: (state: ConnectionState) => void
  onError?: (error: { code: string; message: string }) => void
}

const CONNECTION_STATUS_CONFIG: Record<
  ConnectionState,
  {
    label: string
    color: string
    icon: React.ReactNode
    description: string
  }
> = {
  disconnected: {
    label: 'Disconnected',
    color: 'secondary',
    icon: <Unplug className="h-4 w-4" />,
    description: 'Not connected to audit stream',
  },
  connecting: {
    label: 'Connecting',
    color: 'secondary',
    icon: <RefreshCw className="h-4 w-4 animate-spin" />,
    description: 'Establishing connection...',
  },
  connected: {
    label: 'Connected',
    color: 'default',
    icon: <CheckCircle className="h-4 w-4 text-green-600" />,
    description: 'Receiving audit events in real-time',
  },
  error: {
    label: 'Connection Error',
    color: 'destructive',
    icon: <XCircle className="h-4 w-4" />,
    description: 'Failed to connect to audit stream',
  },
  origin_rejected: {
    label: 'Origin Not Allowed',
    color: 'destructive',
    icon: <Shield className="h-4 w-4" />,
    description: 'Your origin is not authorized to connect',
  },
}

export function AuditStream({
  wsUrl,
  token,
  autoConnect = false,
  onStateChange,
  onError,
}: AuditStreamProps) {
  const {
    connectionState,
    connectionError,
    isConnected,
    allowedOrigins,
    currentOrigin,
    connect,
    disconnect,
    clearError,
  } = useAuditStreamStore()

  const prevConnectionState = useRef<ConnectionState>('disconnected')
  const wsUrlRef = useRef<string>(
    wsUrl || `${getWebSocketBaseUrl()}/api/v1/audit/stream`
  )

  // Update ref when wsUrl changes
  useEffect(() => {
    if (wsUrl) {
      wsUrlRef.current = wsUrl
    }
  }, [wsUrl])

  // Notify parent of state changes
  useEffect(() => {
    if (prevConnectionState.current !== connectionState) {
      onStateChange?.(connectionState)
      prevConnectionState.current = connectionState
    }

    if (connectionState === 'error' || connectionState === 'origin_rejected') {
      onError?.(connectionError || { code: 'UNKNOWN', message: 'Unknown error' })
    }
  }, [connectionState, connectionError, onStateChange, onError])

  // Auto-connect on mount if enabled
  useEffect(() => {
    if (autoConnect) {
      handleConnect()
    }

    return () => {
      // Cleanup on unmount
      disconnect()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Get WebSocket base URL from environment
  function getWebSocketBaseUrl(): string {
    const apiBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''

    if (apiBase) {
      // Convert HTTP to WebSocket protocol
      return apiBase.replace(/^https?:\/\//, window.location.protocol === 'https:' ? 'wss://' : 'ws://')
    }

    // Default to current origin with WebSocket protocol
    return window.location.protocol === 'https:'
      ? `wss://${window.location.host}`
      : `ws://${window.location.host}`
  }

  function handleConnect() {
    // Get token from localStorage if not provided
    const authToken = token || localStorage.getItem('token') || undefined
    connect(wsUrlRef.current, authToken)
  }

  function handleDisconnect() {
    disconnect()
  }

  function handleRetry() {
    clearError()
    handleConnect()
  }

  const statusConfig = CONNECTION_STATUS_CONFIG[connectionState]

  return (
    <Card className="border-l-4 border-l-[var(--color)]" style={{ '--color': getStatusColor(connectionState) } as React.CSSProperties}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            {statusConfig.icon}
            Audit Stream Connection
          </CardTitle>
          <Badge variant={statusConfig.color as 'default' | 'secondary' | 'destructive'}>
            {statusConfig.label}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">{statusConfig.description}</p>

        {/* Origin Information */}
        {(connectionState === 'origin_rejected' || connectionState === 'connected' || allowedOrigins.length > 0) && (
          <div className="space-y-2 rounded bg-muted/50 p-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Current Origin:</span>
              <code className="text-xs font-mono bg-background px-2 py-0.5 rounded">
                {currentOrigin}
              </code>
            </div>
            {allowedOrigins.length > 0 && (
              <div className="flex items-start justify-between text-xs">
                <span className="text-muted-foreground">Allowed Origins:</span>
                <div className="flex flex-col gap-1 items-end">
                  {allowedOrigins.slice(0, 3).map((origin) => (
                    <code key={origin} className="text-xs font-mono bg-background px-2 py-0.5 rounded">
                      {origin}
                    </code>
                  ))}
                  {allowedOrigins.length > 3 && (
                    <span className="text-xs text-muted-foreground">
                      +{allowedOrigins.length - 3} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Connection Error Details */}
        {connectionError && (
          <div className="flex items-start gap-2 rounded bg-destructive/10 p-3 border border-destructive/20">
            <AlertCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
            <div className="flex-1 space-y-1">
              <p className="text-sm font-medium text-destructive">
                {connectionError.message}
              </p>
              {connectionError.code && (
                <p className="text-xs text-muted-foreground">
                  Error code: <code className="bg-background px-1 rounded">{connectionError.code}</code>
                </p>
              )}
              {connectionError.origin && (
                <p className="text-xs text-muted-foreground">
                  Rejected origin: <code className="bg-background px-1 rounded">{connectionError.origin}</code>
                </p>
              )}
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {!isConnected ? (
            <Button
              size="sm"
              onClick={handleRetry}
              disabled={connectionState === 'connecting'}
              className="w-full sm:w-auto"
            >
              {connectionState === 'connecting' ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Connecting...
                </>
              ) : (
                <>
                  <Plug className="mr-2 h-4 w-4" />
                  Connect
                </>
              )}
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              onClick={handleDisconnect}
              className="w-full sm:w-auto"
            >
              <Unplug className="mr-2 h-4 w-4" />
              Disconnect
            </Button>
          )}

          {connectionState === 'error' || connectionState === 'origin_rejected' ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={handleRetry}
              className="w-full sm:w-auto"
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          ) : null}
        </div>

        {/* Security Notice */}
        {connectionState === 'origin_rejected' && (
          <div className="rounded bg-blue-50 dark:bg-blue-950/20 p-3 border border-blue-200 dark:border-blue-800">
            <div className="flex items-start gap-2">
              <Shield className="h-4 w-4 text-blue-600 dark:text-blue-400 mt-0.5 shrink-0" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-blue-900 dark:text-blue-100">
                  Origin Validation Enabled
                </p>
                <p className="text-xs text-blue-700 dark:text-blue-300">
                  The audit service requires origin validation for security. Contact your administrator
                  to add <code className="bg-background px-1 rounded">{currentOrigin}</code> to the allowed origins list.
                </p>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function getStatusColor(state: ConnectionState): string {
  switch (state) {
    case 'connected':
      return '#22c55e' // green
    case 'connecting':
      return '#f59e0b' // amber
    case 'error':
    case 'origin_rejected':
      return '#ef4444' // red
    default:
      return '#6b7280' // gray
  }
}
