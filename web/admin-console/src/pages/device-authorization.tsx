import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Monitor, CheckCircle2, XCircle, AlertTriangle, Clock } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { OAUTH_URL } from '../lib/auth'

/**
 * Device authorization (RFC 8628) — the page the user opens on a phone or
 * laptop after a TV app, CLI or kiosk shows them a code.
 *
 * Without this page the grant is only reachable by hand-crafting requests to
 * /oauth/device/lookup and /oauth/device/decision, which is not a flow any
 * actual user can complete.
 */

interface DeviceCodeInfo {
  user_code: string
  client_id: string
  client_name: string
  scope: string
  state: string
  expires_in: number
}

// The server accepts any casing and separators; normalizing here too means the
// button enables when the code *looks* complete rather than only when it was
// typed in the one shape the screen happened to show.
function normalizeUserCode(input: string): string {
  return input.toUpperCase().replace(/[-\s_]/g, '')
}

const USER_CODE_LENGTH = 8

// The device endpoints live on the OAuth service, which is a different origin
// from the admin API the shared `api` client is bound to. Calling them through
// that client would send these requests to the wrong service entirely, so they
// go direct — same shape as the other OAuth call in the console (logout-all).
async function oauthFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = localStorage.getItem('token')
  return fetch(`${OAUTH_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  })
}

/** Human-readable scope list; an empty scope means the client asked for none. */
function describeScopes(scope: string): string[] {
  return scope.split(' ').map((s) => s.trim()).filter(Boolean)
}

export function DeviceAuthorizationPage() {
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()
  // verification_uri_complete puts the code in the query string so a device
  // that can render a QR code spares the user the typing entirely.
  const prefilled = searchParams.get('user_code') ?? ''

  const [code, setCode] = useState(prefilled)
  const [info, setInfo] = useState<DeviceCodeInfo | null>(null)
  const [lookupError, setLookupError] = useState<string | null>(null)
  const [looking, setLooking] = useState(false)
  const [deciding, setDeciding] = useState(false)
  const [outcome, setOutcome] = useState<'approved' | 'denied' | null>(null)
  const [decideError, setDecideError] = useState<string | null>(null)

  const normalized = normalizeUserCode(code)
  const complete = normalized.length === USER_CODE_LENGTH

  async function lookup(userCode: string) {
    setLooking(true)
    setLookupError(null)
    setInfo(null)
    try {
      const res = await oauthFetch(
        `/oauth/device/lookup?user_code=${encodeURIComponent(userCode)}`,
      )
      if (!res.ok) {
        // The server answers identically for "no such code" and "expired" so
        // this page cannot be used to probe which codes exist; the message says
        // the same thing rather than inventing a distinction the API refuses to
        // make.
        setLookupError(
          res.status === 404
            ? t('pages.deviceAuthorization.lookupNotFound')
            : t('pages.deviceAuthorization.lookupFailed'),
        )
        return
      }
      setInfo((await res.json()) as DeviceCodeInfo)
    } catch {
      setLookupError(t('pages.deviceAuthorization.lookupFailed'))
    } finally {
      setLooking(false)
    }
  }

  // Auto-look-up a prefilled code so the QR path lands straight on the
  // confirmation rather than on an already-filled form the user must submit.
  useEffect(() => {
    const initial = normalizeUserCode(prefilled)
    if (initial.length === USER_CODE_LENGTH) {
      void lookup(initial)
    }
    // Runs once for the value the page was opened with.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function decide(approve: boolean) {
    if (!info) return
    setDeciding(true)
    setDecideError(null)
    try {
      const res = await oauthFetch('/oauth/device/decision', {
        method: 'POST',
        body: JSON.stringify({ user_code: info.user_code, approve }),
      })
      if (!res.ok) {
        setDecideError(
          res.status === 404
            ? t('pages.deviceAuthorization.decideExpired')
            : t('pages.deviceAuthorization.decideFailed'),
        )
        return
      }
      setOutcome(approve ? 'approved' : 'denied')
    } catch {
      setDecideError(t('pages.deviceAuthorization.decideFailed'))
    } finally {
      setDeciding(false)
    }
  }

  if (outcome) {
    return (
      <div className="mx-auto max-w-lg py-10">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {outcome === 'approved' ? (
                <CheckCircle2 className="h-5 w-5 text-green-600" />
              ) : (
                <XCircle className="h-5 w-5 text-red-600" />
              )}
              {outcome === 'approved'
                ? t('pages.deviceAuthorization.approvedTitle')
                : t('pages.deviceAuthorization.deniedTitle')}
            </CardTitle>
            <CardDescription>
              {outcome === 'approved'
                ? t('pages.deviceAuthorization.approvedBody')
                : t('pages.deviceAuthorization.deniedBody')}
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-lg py-10">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5" />
            {t('pages.deviceAuthorization.title')}
          </CardTitle>
          <CardDescription>
            {t('pages.deviceAuthorization.subtitle')}
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {!info && (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                if (complete) void lookup(normalized)
              }}
              className="space-y-4"
            >
              <div className="space-y-2">
                <label htmlFor="user_code" className="text-sm font-medium">
                  {t('pages.deviceAuthorization.codeLabel')}
                </label>
                {/* The placeholder is a sample of the shape a code takes,
                    not prose, so it stays as the device shows it.
                    This input sets no background or border colour of its own,
                    so the browser's default white box stayed while the text
                    came from the theme: 1.05:1 in dark mode -- you could not
                    see the code you were typing. It now carries the same
                    bg-transparent/border-input treatment as the shared Input. */}
                <input
                  id="user_code"
                  name="user_code"
                  autoFocus
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  placeholder="ACDE-FGHJ"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-center font-mono text-2xl tracking-widest uppercase placeholder:text-muted-foreground"
                />
                <p className="text-xs text-muted-foreground">
                  {t('pages.deviceAuthorization.codeHint')}
                </p>
              </div>

              {lookupError && (
                <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{lookupError}</span>
                </div>
              )}

              <Button type="submit" disabled={!complete || looking} className="w-full">
                {looking ? <LoadingSpinner /> : t('pages.deviceAuthorization.continue')}
              </Button>
            </form>
          )}

          {info && (
            <div className="space-y-6">
              <div className="rounded-md border p-4">
                <p className="text-sm text-muted-foreground">
                  {t('pages.deviceAuthorization.aboutToGive')}
                </p>
                {/* The client's own registered name. */}
                <p className="mt-1 text-lg font-semibold">{info.client_name}</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  {t('pages.deviceAuthorization.accessToAccount')}
                </p>

                <div className="mt-4 flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">{t('pages.deviceAuthorization.code')}</span>
                  <code className="font-mono tracking-widest">{info.user_code}</code>
                </div>

                {describeScopes(info.scope).length > 0 && (
                  <div className="mt-4">
                    <p className="text-sm text-muted-foreground">
                      {t('pages.deviceAuthorization.asking')}
                    </p>
                    {/* OAuth scope names, as the client requested them. */}
                    <div className="mt-2 flex flex-wrap gap-2">
                      {describeScopes(info.scope).map((s) => (
                        <Badge key={s} variant="secondary">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {info.expires_in > 0 && (
                  <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="h-3.5 w-3.5" />
                    {t('pages.deviceAuthorization.expiresIn', {
                      count: Math.max(1, Math.round(info.expires_in / 60)),
                    })}
                  </p>
                )}
              </div>

              <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{t('pages.deviceAuthorization.warning')}</span>
              </div>

              {decideError && (
                <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{decideError}</span>
                </div>
              )}

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  className="flex-1"
                  disabled={deciding}
                  onClick={() => void decide(false)}
                >
                  {t('pages.deviceAuthorization.deny')}
                </Button>
                <Button className="flex-1" disabled={deciding} onClick={() => void decide(true)}>
                  {deciding ? <LoadingSpinner /> : t('pages.deviceAuthorization.allow')}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
