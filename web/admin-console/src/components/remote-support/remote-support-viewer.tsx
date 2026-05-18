import { useEffect, useRef, useState } from 'react'
import { Button } from '../ui/button'
import { Badge } from '../ui/badge'
import { Square, WifiOff } from 'lucide-react'

/**
 * Admin-side WebRTC peer for a remote-support session.
 *
 * Wiring:
 *   - Opens the admin WebSocket on mount; receives offer / ICE from the
 *     device side via the in-memory broker.
 *   - Builds an RTCPeerConnection, plays the inbound video track on a
 *     <video> element.
 *   - In interactive mode, creates a data channel ("openidx-input") and
 *     forwards pointer / keyboard events as InputEventMessage payloads.
 *
 * Token auth: the WebSocket URL is opened on the admin side, where the
 * APISIX layer already attaches the OAuth Bearer. The agent side
 * authenticates with its own headers (handled server-side).
 */

interface Props {
  wsUrl: string
  mode: 'interactive' | 'view'
  iceServers: RTCIceServer[]
  onClose: () => void
  onEnd: () => void
}

type ConnState = 'connecting' | 'awaiting-offer' | 'negotiating' | 'streaming' | 'closed' | 'error'

export function RemoteSupportViewer({ wsUrl, mode, iceServers, onClose: _onClose, onEnd }: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const overlayRef = useRef<HTMLDivElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const pcRef = useRef<RTCPeerConnection | null>(null)
  const inputChannelRef = useRef<RTCDataChannel | null>(null)
  const [state, setState] = useState<ConnState>('connecting')
  const [errorMessage, setErrorMessage] = useState<string>('')

  useEffect(() => {
    const ws = openSignalingSocket(wsUrl)
    wsRef.current = ws

    const pc = new RTCPeerConnection({ iceServers })
    pcRef.current = pc

    pc.ontrack = (e) => {
      if (videoRef.current) {
        videoRef.current.srcObject = e.streams[0] ?? new MediaStream([e.track])
        setState('streaming')
      }
    }
    pc.onicecandidate = (e) => {
      if (e.candidate && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'ice',
          payload: {
            candidate: e.candidate.candidate,
            sdp_mid: e.candidate.sdpMid,
            sdp_m_line_index: e.candidate.sdpMLineIndex,
          },
        }))
      }
    }
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
        setState('error')
        setErrorMessage(`peer connection ${pc.connectionState}`)
      }
    }
    if (mode === 'interactive') {
      // The agent side creates the channel and we receive it via ondatachannel;
      // we also create our own as a fallback so input flows regardless of
      // which side wins the implicit race.
      const ch = pc.createDataChannel('openidx-input', { ordered: true })
      inputChannelRef.current = ch
      ch.onopen = () => { /* ready to send */ }
    }
    pc.ondatachannel = (e) => {
      if (e.channel.label === 'openidx-input') {
        inputChannelRef.current = e.channel
      }
    }

    ws.onopen = () => setState('awaiting-offer')
    ws.onclose = () => {
      if (state !== 'closed') {
        setState('error')
        setErrorMessage('signaling channel closed')
      }
    }
    ws.onerror = () => {
      setState('error')
      setErrorMessage('signaling error')
    }
    ws.onmessage = async (ev) => {
      const envelope = parseEnvelope(ev.data)
      if (!envelope) return
      if (envelope.type === 'sdp') {
        const { sdp, type } = envelope.payload as { sdp: string; type: string }
        setState('negotiating')
        if (type === 'offer') {
          await pc.setRemoteDescription({ type: 'offer', sdp })
          const answer = await pc.createAnswer()
          await pc.setLocalDescription(answer)
          ws.send(JSON.stringify({
            type: 'sdp',
            payload: { sdp: answer.sdp ?? '', type: 'answer' },
          }))
        } else if (type === 'answer') {
          await pc.setRemoteDescription({ type: 'answer', sdp })
        }
      } else if (envelope.type === 'ice') {
        const ice = envelope.payload as { candidate: string; sdp_mid?: string; sdp_m_line_index?: number }
        try {
          await pc.addIceCandidate({
            candidate: ice.candidate,
            sdpMid: ice.sdp_mid,
            sdpMLineIndex: ice.sdp_m_line_index,
          })
        } catch (err) {
          console.warn('addIceCandidate failed', err)
        }
      }
    }

    return () => {
      try { ws.close() } catch {}
      try { pc.close() } catch {}
      setState('closed')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsUrl])

  function sendInput(event: Record<string, unknown>) {
    const ch = inputChannelRef.current
    if (!ch || ch.readyState !== 'open') return
    ch.send(JSON.stringify(event))
  }

  /**
   * Translate a pointer event on the overlay to normalized device-screen
   * coordinates. The Android side scales these to the actual screen size,
   * so we pass through fractional x/y in the 0..1 range plus the absolute
   * dimensions of the overlay so the device can interpret pixel offsets if
   * it prefers.
   */
  function pointerCoords(e: React.PointerEvent<HTMLDivElement>) {
    const rect = overlayRef.current?.getBoundingClientRect()
    if (!rect) return { x: 0, y: 0 }
    return {
      x: ((e.clientX - rect.left) / rect.width) * 1000,
      y: ((e.clientY - rect.top) / rect.height) * 1000,
    }
  }

  const pointerDownAt = useRef<{ x: number; y: number; t: number } | null>(null)

  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    const { x, y } = pointerCoords(e)
    pointerDownAt.current = { x, y, t: Date.now() }
  }
  function onPointerUp(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive' || !pointerDownAt.current) return
    const { x, y } = pointerCoords(e)
    const start = pointerDownAt.current
    const dx = x - start.x
    const dy = y - start.y
    const dist = Math.hypot(dx, dy)
    const duration = Date.now() - start.t
    if (dist < 20) {
      sendInput({ event: 'tap', x, y, duration_ms: Math.max(50, duration) })
    } else {
      sendInput({
        event: 'swipe',
        x: start.x, y: start.y, x_end: x, y_end: y,
        duration_ms: Math.max(100, duration),
      })
    }
    pointerDownAt.current = null
  }
  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    if (e.key === 'Escape') {
      sendInput({ event: 'global_action', action: 'back' })
      e.preventDefault()
      return
    }
    if (e.key === 'Home') {
      sendInput({ event: 'global_action', action: 'home' })
      e.preventDefault()
      return
    }
    // Named keys that need to land in the focused text field: forward
    // as 'key' events. Regular character keys are handled separately
    // through the dedicated text input below so we don't try to
    // single-character-spam over the data channel on every keystroke.
    if (e.key === 'Backspace') {
      sendInput({ event: 'key', key_name: 'backspace' })
      e.preventDefault()
      return
    }
    if (e.key === 'Enter') {
      sendInput({ event: 'key', key_name: 'enter' })
      e.preventDefault()
      return
    }
    if (e.key === 'Tab') {
      sendInput({ event: 'key', key_name: 'tab' })
      e.preventDefault()
      return
    }
  }

  // Text-input state — kept separate from the overlay so the admin can
  // compose a longer string and commit it as one message instead of one
  // keystroke per data-channel frame.
  const [pendingText, setPendingText] = useState('')

  function sendPendingText() {
    if (!pendingText) return
    sendInput({ event: 'text', text: pendingText })
    setPendingText('')
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <ConnectionStatus state={state} message={errorMessage} />
        <div className="flex items-center gap-2">
          {mode === 'interactive' && (
            <>
              <Button variant="outline" size="sm" onClick={() => sendInput({ event: 'global_action', action: 'back' })}>
                Back
              </Button>
              <Button variant="outline" size="sm" onClick={() => sendInput({ event: 'global_action', action: 'home' })}>
                Home
              </Button>
              <Button variant="outline" size="sm" onClick={() => sendInput({ event: 'global_action', action: 'recents' })}>
                Recents
              </Button>
            </>
          )}
          <Button variant="destructive" size="sm" onClick={onEnd}>
            <Square className="mr-1 h-3 w-3" /> End session
          </Button>
        </div>
      </div>

      <div
        ref={overlayRef}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onKeyDown={onKeyDown}
        className="relative bg-black rounded-md aspect-video overflow-hidden focus:outline-none focus:ring-2 focus:ring-primary"
      >
        <video
          ref={videoRef}
          autoPlay
          playsInline
          muted
          className="absolute inset-0 h-full w-full object-contain"
        />
        {state !== 'streaming' && (
          <div className="absolute inset-0 flex items-center justify-center text-white/80 text-sm">
            <Placeholder state={state} message={errorMessage} />
          </div>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {mode === 'interactive'
          ? 'Tap = single press · drag = swipe · Esc = back · Home = home · Backspace / Enter / Tab pass through.'
          : 'View-only — input is disabled for this session.'}
      </p>

      {mode === 'interactive' && (
        <div className="flex items-center gap-2 pt-1">
          <input
            type="text"
            value={pendingText}
            onChange={(e) => setPendingText(e.target.value)}
            onKeyDown={(e) => {
              // Send on Enter; consume so the overlay's onKeyDown doesn't
              // also fire an 'enter' key event for the same press.
              if (e.key === 'Enter') {
                e.preventDefault()
                sendPendingText()
              }
            }}
            placeholder="Type and press Enter to inject into the focused field…"
            className="flex-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
            disabled={state !== 'streaming'}
          />
          <Button
            variant="outline"
            size="sm"
            onClick={sendPendingText}
            disabled={!pendingText || state !== 'streaming'}
          >
            Send text
          </Button>
        </div>
      )}
    </div>
  )
}

function ConnectionStatus({ state, message }: { state: ConnState; message: string }) {
  const variant = state === 'streaming' ? 'success'
    : state === 'error' ? 'destructive'
    : 'secondary'
  const label = state === 'streaming' ? 'streaming'
    : state === 'connecting' ? 'connecting'
    : state === 'awaiting-offer' ? 'waiting for device'
    : state === 'negotiating' ? 'negotiating'
    : state === 'closed' ? 'closed'
    : `error${message ? `: ${message}` : ''}`
  return <Badge variant={variant as any}>{label}</Badge>
}

function Placeholder({ state, message }: { state: ConnState; message: string }) {
  if (state === 'error') {
    return (
      <div className="flex items-center gap-2">
        <WifiOff className="h-4 w-4" />
        <span>{message || 'connection failed'}</span>
      </div>
    )
  }
  return <span>{stateLabel(state)}</span>
}

function stateLabel(state: ConnState) {
  switch (state) {
    case 'connecting': return 'Connecting to signaling…'
    case 'awaiting-offer': return 'Waiting for the device to accept the consent prompt…'
    case 'negotiating': return 'Negotiating WebRTC peer…'
    case 'closed': return 'Session closed'
    default: return state
  }
}

function parseEnvelope(raw: unknown): { type: string; payload?: unknown } | null {
  if (typeof raw !== 'string') return null
  try {
    const obj = JSON.parse(raw)
    if (obj && typeof obj === 'object' && typeof obj.type === 'string') return obj
  } catch { /* ignore */ }
  return null
}

function openSignalingSocket(url: string): WebSocket {
  // Attach the OAuth bearer via subprotocol so the browser supplies it on
  // upgrade. The server broker doesn't read it, but APISIX upstream might.
  const token = localStorage.getItem('token')
  try {
    return token ? new WebSocket(url, [`bearer.${token}`]) : new WebSocket(url)
  } catch {
    return new WebSocket(url)
  }
}
