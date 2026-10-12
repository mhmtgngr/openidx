import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download } from 'lucide-react'
import { Button } from '../ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog'
import { LoadingSpinner } from '../ui/loading-spinner'
import { fetchRecording, saveRecording } from '../../lib/remote-support-recording'

/**
 * Plays a remote-support session's recording in the console. Every recording
 * is served as WebM (a vendor session's remuxed from the broker's IVF), so a
 * plain <video> plays it. It is fetched as a blob, because the endpoint wants
 * the Authorization header, and played from an object URL -- which also makes
 * it seekable without the server answering ranges. The same blob backs
 * Download.
 */

export function RecordingPlayer({ sessionId, onClose }: { sessionId: string; onClose: () => void }) {
  const { t } = useTranslation()
  const [blob, setBlob] = useState<Blob | null>(null)
  const [src, setSrc] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let live = true
    let objectUrl: string | null = null
    fetchRecording(sessionId).then(
      (b) => {
        if (!live) return
        objectUrl = URL.createObjectURL(b)
        setBlob(b)
        setSrc(objectUrl)
      },
      () => { if (live) setFailed(true) },
    )
    return () => {
      live = false
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [sessionId])

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle>{t('pages.remoteSupport.player.title', { id: sessionId.slice(0, 8) })}</DialogTitle>
          <DialogDescription>{t('pages.remoteSupport.player.description')}</DialogDescription>
        </DialogHeader>
        {failed ? (
          <p role="alert" className="text-sm text-destructive">{t('pages.remoteSupport.player.failed')}</p>
        ) : src ? (
          <video data-testid="recording-video" src={src} controls autoPlay className="w-full max-h-[70vh] bg-black rounded" />
        ) : (
          <div className="py-12 flex justify-center" aria-label={t('pages.remoteSupport.player.loading')}><LoadingSpinner /></div>
        )}
        {blob && (
          <div className="flex justify-end">
            <Button variant="outline" size="sm" onClick={() => saveRecording(sessionId, blob)}>
              <Download className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.player.download')}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
