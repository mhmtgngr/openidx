import { useEffect, useRef } from 'react'

// THE CHALLENGE THE LOGIN DOOR ASKS FOR, RENDERED.
//
// internal/botgate refuses a login with 403 challenge_required once an account
// name has collected enough failed attempts from anywhere, or when the edge
// scores the caller as automated. Until now the refusal was the end of it: the
// response said "complete the verification challenge" and the page had nothing
// to render, so the person read an instruction with no way to follow it. This
// is that way.
//
// The site key arrives WITH the refusal (see challengeRefusal in
// internal/oauth), not from build-time configuration, and the server sends one
// only when it can also verify the answer. So this component is mounted
// exactly when solving it can actually let someone in, and an install with no
// Turnstile configured never reaches it.
//
// Turnstile's explicit-render API is used rather than the implicit one: the
// widget has to appear on a form that is already on screen, after a failed
// submit, not at page load.

type TurnstileAPI = {
  render: (
    container: HTMLElement,
    options: { sitekey: string; callback: (token: string) => void; 'error-callback'?: () => void },
  ) => string
  remove?: (widgetId: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileAPI
  }
}

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
const SCRIPT_ID = 'cf-turnstile-api'

export function TurnstileChallenge({
  siteKey,
  onSolved,
  onError,
}: {
  siteKey: string
  onSolved: (token: string) => void
  onError?: () => void
}) {
  const container = useRef<HTMLDivElement>(null)
  // The callbacks live in refs so re-rendering the parent -- which happens on
  // every keystroke in the form behind this widget -- does not tear the widget
  // down and build it again, losing the challenge the person is solving.
  const solved = useRef(onSolved)
  const failed = useRef(onError)
  // Assigned in an effect rather than during render: a ref written while
  // rendering is the "cannot access refs during render" rule, and the deps-free
  // effect is the latest-ref pattern this needs -- it runs after every render,
  // so the widget's callbacks are never one render stale.
  useEffect(() => {
    solved.current = onSolved
    failed.current = onError
  })

  useEffect(() => {
    let widgetId: string | undefined
    let cancelled = false

    const renderWidget = () => {
      if (cancelled || !container.current || !window.turnstile) return
      widgetId = window.turnstile.render(container.current, {
        sitekey: siteKey,
        callback: (token: string) => solved.current(token),
        'error-callback': () => failed.current?.(),
      })
    }

    if (window.turnstile) {
      renderWidget()
    } else {
      // One script tag per document, however many times this mounts.
      let script = document.getElementById(SCRIPT_ID) as HTMLScriptElement | null
      if (!script) {
        script = document.createElement('script')
        script.id = SCRIPT_ID
        script.src = SCRIPT_SRC
        script.async = true
        script.defer = true
        document.head.appendChild(script)
      }
      script.addEventListener('load', renderWidget)
      script.addEventListener('error', () => failed.current?.())
    }

    return () => {
      cancelled = true
      if (widgetId && window.turnstile?.remove) {
        window.turnstile.remove(widgetId)
      }
    }
  }, [siteKey])

  return <div ref={container} data-testid="turnstile-challenge" />
}
