import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { QRCodeSVG } from 'qrcode.react'
import { AlertCircle, KeyRound, Loader2, Smartphone } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { baseURL } from '../lib/api'
import {
  decodeCredentialCreationOptions,
  serializeAttestationResponse,
  type PublicKeyCredentialCreationOptionsJSON,
} from '../lib/webauthn'

// The completion answer of POST /oauth/mfa/enroll/*/finish: the same shape as
// any other completed sign-in, plus the backup codes minted with the factor.
export interface InlineEnrollResult {
  redirect_url?: string
  consent_required?: boolean
  consent_session?: string
  backup_codes?: string[]
  error_description?: string
}

interface Props {
  enrollSession: string
  methods: string[]
  onDone: (result: InlineEnrollResult) => void
}

// MfaInlineEnroll is the login page's "add a sign-in method" step, reached
// when an MFA policy refuses a sign-in for want of a method the person has not
// added (internal/oauth/mfa_enroll_inline.go). It sets up an authenticator app
// (the QR and code the profile's MFA section shows) or a passkey against the
// enroll_session, and the server issues the code once the factor is stored.
export function MfaInlineEnroll({ enrollSession, methods, onDone }: Props) {
  const { t } = useTranslation()
  const canTotp = methods.includes('totp')
  const canPasskey = methods.includes('webauthn')
  const [mode, setMode] = useState<'totp' | 'webauthn'>(canTotp ? 'totp' : 'webauthn')
  const [totp, setTotp] = useState<{ qr: string; key: string } | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [result, setResult] = useState<InlineEnrollResult | null>(null)
  const started = useRef(false)

  const post = async (path: string, body: Record<string, unknown>) => {
    const response = await fetch(`${baseURL}/oauth/mfa/enroll/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enroll_session: enrollSession, ...body }),
    })
    const data = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(data.error_description || t('login.enroll.failed'))
    return data
  }

  const finished = (data: InlineEnrollResult) => {
    if (data.backup_codes && data.backup_codes.length > 0) {
      setBackupCodes(data.backup_codes)
      setResult(data)
      return
    }
    onDone(data)
  }

  useEffect(() => {
    if (mode !== 'totp' || totp || started.current) return
    started.current = true
    setBusy(true)
    post('totp/begin', {})
      .then((data) => setTotp({ qr: data.qr_code_url, key: data.manual_key }))
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(false))
    // post is recreated each render; the ref keeps this to one call.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, totp])

  const submitTotp = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      finished(await post('totp/finish', { code: code.trim() }))
    } catch (err) {
      setError((err as Error).message)
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  const registerPasskey = async () => {
    setError('')
    setBusy(true)
    try {
      const begin = await post('webauthn/begin', {})
      const options = decodeCredentialCreationOptions(
        (begin as { publicKey: PublicKeyCredentialCreationOptionsJSON }).publicKey,
      )
      const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null
      if (!credential) throw new Error(t('login.errors.webauthnCancelled'))
      finished(
        await post('webauthn/finish', {
          credential: JSON.parse(serializeAttestationResponse(credential)),
          name: t('login.enroll.passkeyName'),
        }),
      )
    } catch (err) {
      setError((err as Error).message || t('login.enroll.failed'))
    } finally {
      setBusy(false)
    }
  }

  if (backupCodes && result) {
    return (
      <div className="space-y-4">
        <p className="text-sm font-medium">{t('login.enroll.backupTitle')}</p>
        <p className="text-sm text-muted-foreground">{t('login.enroll.backupHint')}</p>
        <ul className="grid grid-cols-2 gap-2 rounded-lg bg-muted p-4 font-mono text-sm" aria-label={t('login.enroll.backupTitle')}>
          {backupCodes.map((c) => (
            <li key={c} className="select-all">{c}</li>
          ))}
        </ul>
        <Button type="button" className="w-full" onClick={() => onDone(result)}>
          {t('login.enroll.continue')}
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-sm">{t('login.enroll.intro')}</p>
      {error && (
        <div role="alert" className="flex items-center gap-2 rounded-md bg-red-50 p-3 text-sm text-red-700">
          <AlertCircle className="h-4 w-4" />
          <span>{error}</span>
        </div>
      )}
      {mode === 'totp' && canTotp && (
        <form onSubmit={submitTotp} className="space-y-4">
          <p className="text-sm text-muted-foreground">{t('login.enroll.totpHint')}</p>
          {totp ? (
            <>
              <div className="flex justify-center rounded-lg border bg-background p-4">
                <QRCodeSVG value={totp.qr} size={200} level="H" includeMargin aria-label={t('login.enroll.qrLabel')} />
              </div>
              <div className="space-y-1">
                <Label>{t('login.enroll.manualLabel')}</Label>
                <code className="block break-all rounded bg-muted p-2 font-mono text-xs select-all">{totp.key}</code>
              </div>
              <div className="space-y-2">
                <Label htmlFor="enroll-code">{t('login.enroll.codeLabel')}</Label>
                <Input
                  id="enroll-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                />
              </div>
              <Button type="submit" className="w-full" disabled={busy || code.length !== 6}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : t('login.enroll.verify')}
              </Button>
            </>
          ) : (
            <div className="flex justify-center p-6">
              {busy && <Loader2 className="h-6 w-6 animate-spin" aria-label={t('login.enroll.loading')} />}
            </div>
          )}
        </form>
      )}
      {mode === 'webauthn' && canPasskey && (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">{t('login.enroll.passkeyHint')}</p>
          <Button type="button" className="w-full" disabled={busy} onClick={registerPasskey}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <><KeyRound className="mr-2 h-4 w-4" />{t('login.enroll.registerPasskey')}</>}
          </Button>
        </div>
      )}
      {canTotp && canPasskey && (
        <Button
          type="button"
          variant="outline"
          className="w-full"
          onClick={() => { setError(''); setMode(mode === 'totp' ? 'webauthn' : 'totp') }}
        >
          {mode === 'totp'
            ? <><KeyRound className="mr-2 h-4 w-4" />{t('login.enroll.usePasskey')}</>
            : <><Smartphone className="mr-2 h-4 w-4" />{t('login.enroll.useApp')}</>}
        </Button>
      )}
    </div>
  )
}
