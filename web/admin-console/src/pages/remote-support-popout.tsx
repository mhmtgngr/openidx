import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const wsPath = params.get('ws') || ''
  // Fail safe. `interactive` is remote INPUT INJECTION into someone's
  // desktop -- keyboard and mouse -- so it is granted only when the URL asks
  // for it by that name. A missing mode, a typo, a link truncated in a chat
  // window: all view-only. The opener (pages/remote-support.tsx) always sends
  // the session's own mode, so no legitimate flow changes; what changes is
  // what a malformed URL gets.
  const mode: 'interactive' | 'view' =
    params.get('mode') === 'interactive' ? 'interactive' : 'view'
  const sessionId = params.get('session') || ''

  const wsUrl = useMemo(
    () => (wsPath ? baseURL.replace(/^http/, 'ws') + wsPath : ''),
    [wsPath],
  )

  if (!wsUrl) {
    return (
      <div className="flex h-screen items-center justify-center bg-black text-white/80">
        {t('pages.remoteSupportPopout.missingParams')}
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
        {t('pages.remoteSupportPopout.footnote', {
          session: sessionId.slice(0, 8),
        })}
      </p>
    </div>
  )
}
