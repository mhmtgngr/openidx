import { useCallback, useState, type ReactNode } from 'react'
import { PamSessionNotice, type NoticeEntry } from '../components/pam-session-notice'
import { shouldShowNotice } from '../lib/pam-clarity'

/**
 * useSessionNotice wraps a connect action: `guard(entry, run)` runs at once
 * when no notice is due, otherwise after the user presses Continue.
 */
export function useSessionNotice(): { guard: (entry: NoticeEntry, run: () => void) => void; notice: ReactNode } {
  const [pending, setPending] = useState<{ entry: NoticeEntry; run: () => void } | null>(null)
  const guard = useCallback((entry: NoticeEntry, run: () => void) => {
    if (shouldShowNotice(entry.id, entry)) setPending({ entry, run })
    else run()
  }, [])
  const notice = (
    <PamSessionNotice
      entry={pending?.entry ?? null}
      onCancel={() => setPending(null)}
      onContinue={() => { const p = pending; setPending(null); p?.run() }}
    />
  )
  return { guard, notice }
}
