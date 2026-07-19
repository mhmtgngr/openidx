import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { baseURL } from '../../lib/api'

/**
 * Clientless in-browser SSH terminal (the "wasm-ssh" renderer).
 *
 * Opens a WebSocket to the access-service relay
 *   GET /api/v1/access/pam/entries/:id/ws?proto=ssh
 * and bridges an xterm.js terminal to it: keystrokes/resize -> server, server
 * output (binary frames) -> terminal. No client is installed; the browser tab
 * is the SSH client. The OAuth token is carried as the `bearer.<jwt>`
 * WebSocket subprotocol (browsers can't set an Authorization header on a WS).
 *
 * The connection reaches the target over the Ziti overlay when the entry is in
 * ziti reach mode (zero inbound target exposure); the server enforces the same
 * PAM permission + approval gate as the guacamole launch before the socket is
 * upgraded, so an unauthorized user never reaches the target.
 */
interface Props {
  entryId: string
  entryName: string
  onClose: () => void
}

type ConnState = 'connecting' | 'connected' | 'closed' | 'error'

export function TerminalSession({ entryId, entryName, onClose }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [state, setState] = useState<ConnState>('connecting')
  const [errorMsg, setErrorMsg] = useState('')

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      theme: { background: '#0b0e14' },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    if (containerRef.current) {
      term.open(containerRef.current)
      try {
        fit.fit()
      } catch {
        /* container not measured yet */
      }
    }

    // Build ws(s):// URL from the API base. The token rides as a subprotocol.
    const httpBase = baseURL || window.location.origin
    const wsBase = httpBase.replace(/^http/, 'ws')
    const url = `${wsBase}/api/v1/access/pam/entries/${entryId}/ws?proto=ssh`
    const token = localStorage.getItem('token')
    const ws = token
      ? new WebSocket(url, [`bearer.${token}`])
      : new WebSocket(url)
    ws.binaryType = 'arraybuffer'

    const sendResize = () => {
      try {
        fit.fit()
      } catch {
        /* ignore */
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
      }
    }

    ws.onopen = () => {
      setState('connected')
      term.focus()
      sendResize()
    }
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data))
      } else if (typeof ev.data === 'string') {
        term.write(ev.data)
      }
    }
    ws.onerror = () => {
      setState('error')
      setErrorMsg('Connection failed. You may not have permission, or the target is unreachable.')
    }
    ws.onclose = (ev) => {
      setState((s) => (s === 'error' ? s : 'closed'))
      if (ev.code !== 1000 && ev.code !== 1005) {
        term.write(`\r\n\x1b[31m[session closed: ${ev.reason || ev.code}]\x1b[0m\r\n`)
      }
    }

    // Terminal keystrokes -> server (binary keeps control bytes intact).
    const dataSub = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data))
      }
    })
    const resizeSub = term.onResize(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
      }
    })
    window.addEventListener('resize', sendResize)

    return () => {
      window.removeEventListener('resize', sendResize)
      dataSub.dispose()
      resizeSub.dispose()
      try {
        ws.close(1000, 'client closed')
      } catch {
        /* ignore */
      }
      term.dispose()
    }
  }, [entryId])

  return (
    <div className="flex flex-col h-full min-h-[420px]">
      <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/40">
        <div className="flex items-center gap-2 text-sm">
          <span className="font-medium">SSH — {entryName}</span>
          <span
            className={
              state === 'connected'
                ? 'text-green-600'
                : state === 'error'
                  ? 'text-red-600'
                  : 'text-muted-foreground'
            }
          >
            ● {state}
          </span>
        </div>
        <button
          className="text-sm px-3 py-1 rounded-md border hover:bg-muted"
          onClick={onClose}
        >
          Close
        </button>
      </div>
      {state === 'error' && (
        <div className="px-3 py-2 text-sm text-red-600 bg-red-50 border-b">{errorMsg}</div>
      )}
      <div ref={containerRef} className="flex-1 min-h-[380px] bg-[#0b0e14] p-2" />
    </div>
  )
}
