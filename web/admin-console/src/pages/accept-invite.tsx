import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { QRCodeSVG } from 'qrcode.react'
import { Shield, ArrowLeft, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { baseURL } from '../lib/api'
import { AuthCardFooter, PoweredBy } from '../components/auth-card-footer'

// The page an invitation email links to (/accept-invite?token=...). The token
// is the credential for both calls, so the page is public:
//
//   1. POST /invitations/:token/accept creates the account. An internal
//      invitation is finished here.
//   2. An external (vendor) invitation answers with an authenticator secret
//      instead: the account exists but cannot sign in until
//      POST /invitations/:token/mfa receives a valid code from it (invariant
//      I4 of the third-party access framework).

type Step = { kind: 'form' } | { kind: 'mfa'; secret: string; otpauthURL: string } | { kind: 'done'; external: boolean }

export function AcceptInvitePage() {
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [step, setStep] = useState<Step>({ kind: 'form' })
  const [form, setForm] = useState({ username: '', first_name: '', last_name: '', password: '', confirm: '' })
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const post = async (path: string, body: unknown) => {
    const response = await fetch(`${baseURL}/api/v1/identity/invitations/${encodeURIComponent(token)}/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await response.json().catch(() => ({}))
    return { ok: response.ok, data }
  }

  const accept = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (form.password !== form.confirm) {
      setError(t('pages.acceptInvite.mismatch'))
      return
    }
    setBusy(true)
    try {
      const { ok, data } = await post('accept', {
        username: form.username.trim(),
        password: form.password,
        first_name: form.first_name.trim(),
        last_name: form.last_name.trim(),
      })
      if (!ok) {
        setError(data.error || t('pages.acceptInvite.failed'))
      } else if (data.mfa?.secret) {
        setStep({ kind: 'mfa', secret: data.mfa.secret, otpauthURL: data.mfa.otpauth_url || '' })
      } else {
        setStep({ kind: 'done', external: false })
      }
    } catch {
      setError(t('pages.acceptInvite.offline'))
    } finally {
      setBusy(false)
    }
  }

  const confirmFactor = async (e: React.FormEvent) => {
    e.preventDefault()
    if (step.kind !== 'mfa') return
    setError('')
    setBusy(true)
    try {
      const { ok, data } = await post('mfa', { secret: step.secret, code: code.trim() })
      if (ok) {
        setStep({ kind: 'done', external: true })
      } else {
        setError(data.error || t('pages.acceptInvite.codeFailed'))
      }
    } catch {
      setError(t('pages.acceptInvite.offline'))
    } finally {
      setBusy(false)
    }
  }

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }))

  const banner = error && (
    <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md" role="alert">
      <AlertCircle className="h-4 w-4 text-red-700 flex-shrink-0" />
      {/* Either one of this page's own messages or the API's. */}
      <p className="text-sm text-red-700">{error}</p>
    </div>
  )

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
              <Shield className="h-9 w-9 text-white" />
            </div>
          </div>
          <div>
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              OpenIDX
            </CardTitle>
            <CardDescription className="text-base mt-2">{t('pages.acceptInvite.title')}</CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          {!token ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                <AlertCircle className="h-4 w-4 text-red-700 flex-shrink-0" />
                <p className="text-sm text-red-700">{t('pages.acceptInvite.invalidToken')}</p>
              </div>
              <BackToLogin label={t('pages.acceptInvite.backToLogin')} />
            </div>
          ) : step.kind === 'done' ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle className="h-4 w-4 text-green-600 flex-shrink-0" />
                <p className="text-sm text-green-700">
                  {step.external ? t('pages.acceptInvite.doneExternal') : t('pages.acceptInvite.done')}
                </p>
              </div>
              <Link to="/login">
                <Button className="w-full" size="lg">{t('pages.acceptInvite.goToLogin')}</Button>
              </Link>
            </div>
          ) : step.kind === 'mfa' ? (
            <form onSubmit={confirmFactor} className="space-y-4">
              <p className="text-sm text-muted-foreground">{t('pages.acceptInvite.mfaIntro')}</p>
              {step.otpauthURL && (
                <div className="flex justify-center rounded-md border bg-background p-4">
                  <QRCodeSVG value={step.otpauthURL} size={176} includeMargin aria-label={t('pages.acceptInvite.qrLabel')} />
                </div>
              )}
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">{t('pages.acceptInvite.secretLabel')}</p>
                <code className="block break-all rounded bg-muted px-2 py-1 text-sm" data-testid="totp-secret">{step.secret}</code>
              </div>
              {banner}
              <div className="space-y-2">
                <Label htmlFor="invite-code">{t('pages.acceptInvite.code')}</Label>
                <Input
                  id="invite-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                  autoFocus
                />
              </div>
              <Button type="submit" className="w-full" size="lg" disabled={busy || code.trim() === ''}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : t('pages.acceptInvite.activate')}
              </Button>
            </form>
          ) : (
            <form onSubmit={accept} className="space-y-4">
              {banner}
              <div className="space-y-2">
                <Label htmlFor="invite-username">{t('pages.acceptInvite.username')}</Label>
                <Input id="invite-username" value={form.username} onChange={set('username')} required autoFocus autoComplete="username" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor="invite-first-name">{t('pages.acceptInvite.firstName')}</Label>
                  <Input id="invite-first-name" value={form.first_name} onChange={set('first_name')} autoComplete="given-name" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="invite-last-name">{t('pages.acceptInvite.lastName')}</Label>
                  <Input id="invite-last-name" value={form.last_name} onChange={set('last_name')} autoComplete="family-name" />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-password">{t('pages.acceptInvite.password')}</Label>
                <Input id="invite-password" type="password" value={form.password} onChange={set('password')} required autoComplete="new-password" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-confirm">{t('pages.acceptInvite.confirmPassword')}</Label>
                <Input id="invite-confirm" type="password" value={form.confirm} onChange={set('confirm')} required autoComplete="new-password" />
              </div>
              <Button type="submit" className="w-full" size="lg" disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : t('pages.acceptInvite.submit')}
              </Button>
              <BackToLogin label={t('pages.acceptInvite.backToLogin')} />
            </form>
          )}
        </CardContent>

        <AuthCardFooter />
      </Card>

      <div className="absolute bottom-4 text-center w-full">
        <PoweredBy />
      </div>
    </div>
  )
}

function BackToLogin({ label }: { label: string }) {
  return (
    <Link to="/login">
      <Button type="button" variant="ghost" className="w-full">
        <ArrowLeft className="mr-2 h-4 w-4" />
        {label}
      </Button>
    </Link>
  )
}
