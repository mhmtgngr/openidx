import { useEffect, useRef, useState } from 'react'
import { Button } from '../ui/button'
import { Maximize, Square, WifiOff } from 'lucide-react'

/**
 * RelayRenderer is the admin-side view for a remote-support session whose
 * transport is "relay": the device streams VP8 frames as binary WebSocket
 * messages through the broker (no WebRTC/STUN — full-Ziti capable). We decode
 * them with WebCodecs VideoDecoder(VP8) onto a canvas, and send input as text
 * JSON on the same socket. Requires a Chromium-based browser (WebCodecs VP8);
 * the WebRTC path remains the cross-browser fallback.
 */
interface Props {
  wsUrl: string
  mode: 'interactive' | 'view'
  onEnd: () => void
}

type RelayState = 'connecting' | 'streaming' | 'error' | 'closed'

// A 1-byte header precedes each VP8 frame: bit0 = keyframe.
const RELAY_FLAG_KEYFRAME = 0x01

export function RelayRenderer({ wsUrl, mode, onEnd }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const overlayRef = useRef<HTMLDivElement | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const decoderRef = useRef<VideoDecoder | null>(null)
  const controlActiveRef = useRef<boolean>(mode === 'interactive')
  const gotKeyRef = useRef(false)
  const [state, setState] = useState<RelayState>('connecting')
  const [errorMessage, setErrorMessage] = useState('')
  const [controlActive, setControlActive] = useState(mode === 'interactive')

  useEffect(() => {
    if (typeof VideoDecoder === 'undefined') {
      setState('error')
      setErrorMessage('This browser lacks WebCodecs VP8 (use Chrome/Edge, or switch the session to WebRTC).')
      return
    }

    const ws = new WebSocket(wsUrl, tokenSubprotocols())
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    // WebCodecs VP8 decoder -> canvas.
    const decoder = new VideoDecoder({
      output: (frame) => {
        const c = canvasRef.current
        if (c) {
          if (c.width !== frame.displayWidth || c.height !== frame.displayHeight) {
            c.width = frame.displayWidth
            c.height = frame.displayHeight
          }
          const ctx = c.getContext('2d')
          if (ctx) ctx.drawImage(frame, 0, 0)
          setState('streaming')
        }
        frame.close()
      },
      error: (e) => {
        // Decode errors usually mean we started mid-stream without a keyframe;
        // request one and keep going.
        console.warn('relay decode error', e)
        requestKeyframe()
      },
    })
    decoder.configure({ codec: 'vp8' })
    decoderRef.current = decoder

    ws.onopen = () => {
      if (controlActiveRef.current) sendJSON({ event: 'control_state', active: true })
      requestKeyframe()
    }
    ws.onclose = () => setState((p) => (p === 'closed' ? p : 'error'))
    ws.onerror = () => setState((p) => (p === 'closed' ? p : 'error'))
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') return // control text (unused inbound)
      const buf = new Uint8Array(ev.data as ArrayBuffer)
      if (buf.length < 2) return
      const isKey = (buf[0] & RELAY_FLAG_KEYFRAME) !== 0
      const payload = buf.subarray(1)
      // Wait for the first keyframe before feeding delta frames to the decoder.
      if (!gotKeyRef.current) {
        if (!isKey) return
        gotKeyRef.current = true
      }
      try {
        decoder.decode(
          new EncodedVideoChunk({
            type: isKey ? 'key' : 'delta',
            timestamp: performance.now() * 1000,
            data: payload,
          }),
        )
      } catch (err) {
        console.warn('relay decode threw', err)
      }
    }

    return () => {
      try { ws.close() } catch { /* already closed */ }
      try { decoder.close() } catch { /* already closed */ }
      setState('closed')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsUrl])

  function sendJSON(obj: Record<string, unknown>) {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(obj)) } catch { /* not open */ }
    }
  }

  function requestKeyframe() {
    gotKeyRef.current = false
    sendJSON({ event: 'request_keyframe' })
  }

  function sendInput(ev: Record<string, unknown>) {
    if (!controlActiveRef.current) return
    sendJSON(ev)
  }

  // Map a pointer event to the device's 0..1000 coordinate space, accounting for
  // the canvas's letterbox inside the overlay (object-contain).
  function coords(e: React.PointerEvent<HTMLDivElement>) {
    const rect = overlayRef.current?.getBoundingClientRect()
    const c = canvasRef.current
    if (!rect || !c || c.width === 0 || c.height === 0) return { x: 0, y: 0 }
    const videoAR = c.width / c.height
    const boxAR = rect.width / rect.height
    let cw = rect.width, ch = rect.height, cx = rect.left, cy = rect.top
    if (videoAR > boxAR) { cw = rect.width; ch = rect.width / videoAR; cy = rect.top + (rect.height - ch) / 2 }
    else { ch = rect.height; cw = rect.height * videoAR; cx = rect.left + (rect.width - cw) / 2 }
    const clamp = (v: number) => Math.max(0, Math.min(1, v))
    return { x: clamp((e.clientX - cx) / cw) * 1000, y: clamp((e.clientY - cy) / ch) * 1000 }
  }

  const downAt = useRef<{ x: number; y: number; t: number } | null>(null)
  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    e.currentTarget.focus()
    downAt.current = { ...coords(e), t: Date.now() }
  }
  function onPointerUp(e: React.PointerEvent<HTMLDivElement>) {
    if (mode !== 'interactive' || !downAt.current) return
    const p = coords(e)
    const s = downAt.current
    const dist = Math.hypot(p.x - s.x, p.y - s.y)
    const dur = Date.now() - s.t
    if (dist < 20) sendInput({ event: 'tap', x: p.x, y: p.y, duration_ms: Math.max(50, dur) })
    else sendInput({ event: 'swipe', x: s.x, y: s.y, x2: p.x, y2: p.y, duration_ms: Math.max(100, dur) })
    downAt.current = null
  }
  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (mode !== 'interactive') return
    if (e.key === 'Escape') { sendInput({ event: 'global_action', action: 'back' }); e.preventDefault() }
  }

  function toggleControl() {
    setControlActive((prev) => {
      const next = !prev
      controlActiveRef.current = next
      sendJSON({ event: 'control_state', active: next })
      return next
    })
  }

  function enterFullscreen() {
    overlayRef.current?.requestFullscreen?.().then(() => overlayRef.current?.focus()).catch(() => {})
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {state === 'streaming' ? 'Live (relay / Ziti)' : state === 'connecting' ? 'Connecting…' : state === 'error' ? (errorMessage || 'Disconnected') : 'Closed'}
        </div>
        <div className="flex items-center gap-2">
          {mode === 'interactive' && (
            <>
              <Button variant={controlActive ? 'default' : 'outline'} size="sm" onClick={toggleControl}>
                {controlActive ? 'Release control' : 'Take control'}
              </Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'back' })}>Back</Button>
              <Button variant="outline" size="sm" disabled={!controlActive} onClick={() => sendInput({ event: 'global_action', action: 'home' })}>Home</Button>
            </>
          )}
          <Button variant="outline" size="sm" onClick={enterFullscreen}><Maximize className="mr-1 h-3 w-3" /> Fullscreen</Button>
          <Button variant="destructive" size="sm" onClick={onEnd}><Square className="mr-1 h-3 w-3" /> End session</Button>
        </div>
      </div>
      <div
        ref={overlayRef}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onKeyDown={onKeyDown}
        onClick={(e) => e.stopPropagation()}
        style={{ touchAction: 'none' }}
        className="relative bg-black rounded-md aspect-video overflow-hidden flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-primary cursor-crosshair fullscreen:aspect-auto fullscreen:h-screen fullscreen:w-screen fullscreen:rounded-none"
      >
        <canvas ref={canvasRef} className="max-h-full max-w-full object-contain pointer-events-none" />
        {state !== 'streaming' && (
          <div className="absolute inset-0 flex items-center justify-center text-white/80 text-sm">
            {state === 'error' ? (
              <span className="flex items-center gap-2"><WifiOff className="h-4 w-4" /> {errorMessage || 'Disconnected'}</span>
            ) : state === 'connecting' ? 'Connecting…' : 'Closed'}
          </div>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        Relay transport (full Ziti): media + control flow through the broker, no P2P/STUN. Click = tap, drag = swipe, Esc = back.
      </p>
    </div>
  )
}

// tokenSubprotocols mirrors the WebRTC viewer: browsers can't set an Auth header
// on a WebSocket, so the OAuth bearer rides as a subprotocol.
function tokenSubprotocols(): string[] {
  const token = localStorage.getItem('token')
  return token ? [`bearer.${token}`] : []
}
