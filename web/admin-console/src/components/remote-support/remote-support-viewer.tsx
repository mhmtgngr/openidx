import { useEffect, useRef, useState } from 'react'
import { Button } from '../ui/button'
import { Badge } from '../ui/badge'
import { Circle, Square, WifiOff } from 'lucide-react'
import { api } from '../../lib/api'

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
  /** Session UUID — used to address /recording/chunk + /recording/finalize. */
  sessionId: string
  /** When true, MediaRecorder captures the inbound stream and chunks
   *  upload to the server every [recordingTimesliceMs] ms. */
  recordingEnabled: boolean
  /** Optional override; defaults to 5 s. */
  recordingTimesliceMs?: number
  onClose: () => void
  onEnd: () => void
}

type ConnState = 'connecting' | 'awaiting-offer' | 'negotiating' | 'streaming' | 'closed' | 'error'
type RecState = 'off' | 'arming' | 'recording' | 'finalizing' | 'failed'

export function RemoteSupportViewer({
  wsUrl,
  mode,
  iceServers,
  sessionId,
  recordingEnabled,
  recordingTimesliceMs = 5000,
  onClose: _onClose,
  onEnd,
}: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null)
  const overlayRef = useRef<HTMLDivElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const pcRef = useRef<RTCPeerConnection | null>(null)
  const inputChannelRef = useRef<RTCDataChannel | null>(null)
  const recorderRef = useRef<MediaRecorder | null>(null)
  const chunkIndexRef = useRef<number>(0)
  const recordedStreamRef = useRef<MediaStream | null>(null)
  const [state, setState] = useState<ConnState>('connecting')
  const [errorMessage, setErrorMessage] = useState<string>('')
  const [recState, setRecState] = useState<RecState>('off')

  useEffect(() => {
    const ws = openSignalingSocket(wsUrl)
    wsRef.current = ws

    const pc = new RTCPeerConnection({ iceServers })
    pcRef.current = pc

    pc.ontrack = (e) => {
      const stream = e.streams[0] ?? new MediaStream([e.track])
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        setState('streaming')
      }
      recordedStreamRef.current = stream
      if (recordingEnabled && !recorderRef.current) {
        try { startMediaRecorder(stream) }
        catch (err) {
          console.warn('MediaRecorder start failed', err)
          setRecState('failed')
        }
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
      try { stopRecording() } catch {}
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
   * Pick a MediaRecorder codec the browser actually supports. Chromium
   * picks `video/webm;codecs=vp8,opus` by default but Safari only
   * understands `video/mp4` flavors. We probe in order and bail out if
   * nothing matches.
   */
  function preferredRecorderMime(): string | null {
    if (typeof MediaRecorder === 'undefined') return null
    const candidates = [
      'video/webm;codecs=vp8',
      'video/webm;codecs=vp9',
      'video/webm',
      'video/mp4',
    ]
    return candidates.find((m) => MediaRecorder.isTypeSupported(m)) ?? null
  }

  function startMediaRecorder(stream: MediaStream) {
    const mime = preferredRecorderMime()
    if (!mime) {
      setRecState('failed')
      return
    }
    setRecState('arming')
    chunkIndexRef.current = 0
    const recorder = new MediaRecorder(stream, { mimeType: mime })
    recorderRef.current = recorder

    recorder.ondataavailable = async (ev) => {
      if (!ev.data || ev.data.size === 0) return
      const index = chunkIndexRef.current++
      try {
        await uploadChunk(ev.data, index)
      } catch (err) {
        console.warn('recording chunk upload failed', { index, err })
      }
    }
    recorder.onstart = () => setRecState('recording')
    recorder.onerror = (ev: Event) => {
      console.warn('MediaRecorder error', ev)
      setRecState('failed')
    }
    recorder.onstop = async () => {
      setRecState('finalizing')
      try {
        await api.post(`/api/v1/access/remote-support/sessions/${sessionId}/recording/finalize`)
        setRecState('off')
      } catch (err) {
        console.warn('finalize failed', err)
        setRecState('failed')
      }
    }
    recorder.start(recordingTimesliceMs)
  }

  async function uploadChunk(blob: Blob, index: number) {
    // axios doesn't handle raw octet-stream uploads as well as fetch does
    // here, so use fetch directly with the same Bearer header the api
    // client attaches. baseURL = window.location.origin in dev / prod.
    const token = localStorage.getItem('token')
    const url = `/api/v1/access/remote-support/sessions/${sessionId}/recording/chunk`
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Chunk-Index': String(index),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: blob,
    })
    if (!resp.ok) throw new Error(`chunk upload ${resp.status}`)
  }

  function stopRecording() {
    const rec = recorderRef.current
    if (rec && rec.state !== 'inactive') {
      rec.stop() // triggers final ondataavailable + onstop → finalize
    }
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
  // Clipboard-push state. Distinct from pendingText: the device's
  // ClipboardManager.setPrimaryClip path is "paste this somewhere
  // later", not "type this into the focused field now".
  const [pendingClipboard, setPendingClipboard] = useState('')

  function sendPendingText() {
    if (!pendingText) return
    sendInput({ event: 'text', text: pendingText })
    setPendingText('')
  }

  function sendPendingClipboard() {
    if (!pendingClipboard) return
    sendInput({ event: 'clipboard', text: pendingClipboard })
    setPendingClipboard('')
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ConnectionStatus state={state} message={errorMessage} />
          {recordingEnabled && <RecordingIndicator state={recState} />}
        </div>
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
        <div className="space-y-2 pt-1">
          <div className="flex items-center gap-2">
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

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={pendingClipboard}
              onChange={(e) => setPendingClipboard(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  sendPendingClipboard()
                }
              }}
              placeholder="Push to device clipboard (user pastes wherever they need it)…"
              className="flex-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
              disabled={state !== 'streaming'}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={sendPendingClipboard}
              disabled={!pendingClipboard || state !== 'streaming'}
            >
              Push clipboard
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function RecordingIndicator({ state }: { state: RecState }) {
  if (state === 'off') return null
  const label = state === 'recording' ? 'recording'
    : state === 'finalizing' ? 'finalizing recording…'
    : state === 'arming' ? 'recording (arming)'
    : state === 'failed' ? 'recording failed'
    : state
  const variant = state === 'recording' ? 'destructive'
    : state === 'failed' ? 'destructive'
    : 'secondary'
  return (
    <Badge variant={variant as any} className="gap-1">
      <Circle className="h-3 w-3 fill-current" /> {label}
    </Badge>
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
