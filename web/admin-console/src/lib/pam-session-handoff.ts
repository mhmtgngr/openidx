import type { PamConnectResult } from './api'

/**
 * Opening a brokered PAM session, in the one place that decides how.
 *
 * There are two launchers — the Connections page and the Quick links section —
 * and they used to disagree about the same URL. The Connections page opens a
 * chrome-less `/pam-session` wrapper and hands the connect URL off through a
 * single-use localStorage entry, for two reasons it states in its own comment:
 * the URL carries a bearer token, so it must not reach the address bar or
 * browser history; and on failure the user must see OpenIDX messaging rather
 * than Guacamole's home/connection-manager. Quick links called
 * `window.open(url)` with the raw URL, which does neither.
 *
 * Nothing about a quick link makes those reasons weaker — it is the same token
 * and the same broker — so both now come through here.
 */

const HANDOFF_PREFIX = 'pam-session:'

/** An unguessable key for the single-use handoff entry. */
function randomHandoffKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Open `res`'s session in its own wrapper window. Returns false when the result
 * carries no URL, so the caller can say "nothing to launch" in its own words.
 *
 * `overlay` is derived here rather than by each caller, because it decides
 * which failure card the window shows: an overlay launch that never connects
 * means the OpenIDX client is not running on this machine — the URL resolves
 * only for a member of the overlay — and the generic card's guesses ("may be
 * temporary", "you may not have access") are both wrong for it. A launch whose
 * reach mode is absent or anything but ziti keeps the generic card.
 */
export function openPamSessionWindow(res: PamConnectResult, title: string): boolean {
  const url = res.connect_url || res.url
  if (!url) return false

  const key = randomHandoffKey()
  try {
    localStorage.setItem(
      HANDOFF_PREFIX + key,
      JSON.stringify({ url, title, overlay: res.reach_mode === 'ziti' }),
    )
  } catch {
    // Private mode / quota. The window will find no handoff and show its
    // "expired" card, which is the right outcome: better than opening the raw
    // token-bearing URL as a fallback.
  }
  window.open('/pam-session?k=' + key, '_blank')
  return true
}
