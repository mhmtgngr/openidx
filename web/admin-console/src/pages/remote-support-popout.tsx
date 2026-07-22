import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { baseURL } from '../lib/api'
import { RelayRenderer } from '../components/remote-support/relay-renderer'

/**
 * RemoteSupportPopout is a standalone, chrome-less window for a single relay
 * session. It's opened via window.open from the main remote-support page so an
 * operator can pull the live screen into its own window (or move it to a second
 * monitor) and go fullscreen, without the admin console sidebar/dialog around
 * it. Only the relay transport supports this (plain WebSocket, reconstructable
 * from a URL); WebRTC needs the original offer/answer exchange and can't be
 * re-opened standalone.
 *
 * Query params: ?session=<id>&ws=<wsPath>&mode=<interactive|view>
 */
export function RemoteSupportPopout() {
  const [params] = useSearchParams()
  const wsPath = params.get('ws') || ''
  const mode = (params.get('mode') === 'view' ? 'view' : 'interactive') as
    | 'interactive'
    | 'view'
  const sessionId = params.get('session') || ''

  const wsUrl = useMemo(
    () => (wsPath ? baseURL.replace(/^http/, 'ws') + wsPath : ''),
    [wsPath],
  )

  if (!wsUrl) {
    return (
      <div className="flex h-screen items-center justify-center bg-black text-white/80">
        Missing session parameters.
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black p-3">
      <RelayRenderer
        wsUrl={wsUrl}
        mode={mode}
        autoFullscreen
        onEnd={() => {
          // The popout can't end the server-side session (that lives in the
          // opener's mutation); just close the window. The opener's End button
          // remains the authoritative teardown.
          window.close()
        }}
      />
      <p className="mt-2 text-center text-xs text-white/50">
        Pop-out viewer · session {sessionId.slice(0, 8)} · closing this window
        stops viewing but leaves the session running (end it from the console).
      </p>
    </div>
  )
}
