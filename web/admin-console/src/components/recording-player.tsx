import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import Guacamole from 'guacamole-common-js'
import { Pause, Play } from 'lucide-react'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { LoadingSpinner } from './ui/loading-spinner'
import { api } from '../lib/api'
import { formatRecordingTime } from '../lib/recording-time'
import { blobTunnel } from '../lib/recording-tunnel'

// RecordingPlayer plays a guacd session recording in the browser with
// guacamole-common-js's SessionRecording (Apache-2.0). The recording is
// fetched once, through the API client (so the admin's session authorises
// it and the server audits the download), as a Blob the player parses; it is
// never written anywhere and is dropped when the dialog closes.
//
// url is the admin-only download route: /api/v1/access/pam/sessions/:id/recording
// for an entry session, /api/v1/access/guacamole/sessions/:id/recording for a
// route session.

type State = 'loading' | 'ready' | 'error'

export function RecordingPlayer({ url, title, onClose }: { url: string; title: string; onClose: () => void }) {
  const { t } = useTranslation()
  const host = useRef<HTMLDivElement>(null)
  const rec = useRef<Guacamole.SessionRecording | null>(null)
  const [state, setState] = useState<State>('loading')
  const [error, setError] = useState('')
  const [playing, setPlaying] = useState(false)
  const [position, setPosition] = useState(0)
  const [duration, setDuration] = useState(0)

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setInterval> | undefined
    api.get<Blob>(url, { responseType: 'blob' })
      .then((blob) => {
        if (cancelled) return
        const r = new Guacamole.SessionRecording(blobTunnel(blob))
        rec.current = r
        const display = r.getDisplay()
        const el = display.getElement()
        host.current?.replaceChildren(el)
        const fit = () => {
          const w = host.current?.clientWidth ?? 0
          if (w && display.getWidth()) display.scale(Math.min(1, w / display.getWidth()))
        }
        display.onresize = fit
        r.onprogress = (d: number) => setDuration(d)
        r.onload = () => { setDuration(r.getDuration()); setState('ready') }
        r.onerror = (msg: string) => { setError(msg); setState('error') }
        r.onplay = () => setPlaying(true)
        r.onpause = () => setPlaying(false)
        r.onseek = (p: number) => setPosition(p)
        r.connect()
        timer = setInterval(() => setPosition(r.getPosition()), 250)
      })
      .catch((e: unknown) => {
        if (cancelled) return
        const status = (e as { response?: { status?: number } }).response?.status
        setError(status === 410 ? t('pages.guacSessions.player.purged') : t('pages.guacSessions.player.loadFailed'))
        setState('error')
      })
    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
      const r = rec.current
      rec.current = null
      if (r) {
        r.pause()
        r.abort()
        r.disconnect()
      }
    }
  }, [url, t])

  const toggle = () => {
    const r = rec.current
    if (!r) return
    if (r.isPlaying()) r.pause()
    else r.play()
  }

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        {state === 'loading' && (
          <div className="py-12 flex justify-center"><LoadingSpinner /></div>
        )}
        {state === 'error' && (
          <p role="alert" className="text-sm text-destructive">{error}</p>
        )}
        <div ref={host} data-testid="recording-display" className="w-full overflow-hidden bg-black" />
        {state === 'ready' && (
          <div className="flex items-center gap-3">
            <Button size="sm" variant="outline" onClick={toggle}
              aria-label={playing ? t('pages.guacSessions.player.pause') : t('pages.guacSessions.player.play')}>
              {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>
            <input
              type="range"
              className="flex-1"
              min={0}
              max={duration}
              value={Math.min(position, duration)}
              aria-label={t('pages.guacSessions.player.seek')}
              onChange={(e) => rec.current?.seek(Number(e.target.value))}
            />
            <span className="text-xs tabular-nums text-muted-foreground">
              {formatRecordingTime(position)} / {formatRecordingTime(duration)}
            </span>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
