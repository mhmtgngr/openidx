import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyRound, Plus, Trash2, Loader2, AlertCircle, Shield } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useToast } from '../hooks/use-toast'
import { api, WebAuthnCredential } from '../lib/api'
import {
  decodeCredentialCreationOptions,
  serializeAttestationResponse,
} from '../lib/webauthn'

export function SecurityKeysPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([])
  const [loading, setLoading] = useState(true)
  const [registering, setRegistering] = useState(false)
  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchCredentials = async () => {
    try {
      setLoading(true)
      const data = await api.getWebAuthnCredentials()
      setCredentials(data || [])
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.securityKeys.toasts.loadFailed'),
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCredentials()
  }, [])

  const handleRegister = async () => {
    if (!keyName.trim()) return

    try {
      setRegistering(true)

      // Step 1: Begin registration (get options from server)
      const beginResponse = await api.beginWebAuthnRegistration()
      const options = decodeCredentialCreationOptions(
        (beginResponse as { publicKey: Parameters<typeof decodeCredentialCreationOptions>[0] }).publicKey
      )

      // Step 2: Create credential via browser API
      const credential = await navigator.credentials.create({ publicKey: options }) as PublicKeyCredential
      if (!credential) {
        throw new Error(t('pages.securityKeys.toasts.cancelled'))
      }

      // Step 3: Send credential to server
      const attestationJSON = serializeAttestationResponse(credential)
      await api.finishWebAuthnRegistration(JSON.parse(attestationJSON))

      toast({ title: t('common.success'), description: t('pages.securityKeys.toasts.registered') })
      setShowRegisterForm(false)
      setKeyName('')
      fetchCredentials()
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('pages.securityKeys.toasts.registerFailed')
      toast({ title: t('common.error'), description: message, variant: 'destructive' })
    } finally {
      setRegistering(false)
    }
  }

  const handleDelete = async (credentialId: string) => {
    try {
      setDeleting(credentialId)
      await api.deleteWebAuthnCredential(credentialId)
      toast({ title: t('common.success'), description: t('pages.securityKeys.toasts.removed') })
      setCredentials(credentials.filter(c => c.id !== credentialId))
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.securityKeys.toasts.removeFailed'),
        variant: 'destructive',
      })
    } finally {
      setDeleting(null)
    }
  }

  const isWebAuthnSupported = typeof window !== 'undefined' && window.PublicKeyCredential !== undefined

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.securityKeys')}</h1>
          <p className="text-muted-foreground">{t('pages.securityKeys.subtitle')}</p>
        </div>
        {isWebAuthnSupported && (
          <Button onClick={() => setShowRegisterForm(true)} disabled={showRegisterForm}>
            <Plus className="mr-2 h-4 w-4" /> {t('pages.securityKeys.register')}
          </Button>
        )}
      </div>

      {!isWebAuthnSupported && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-yellow-600" />
              <p className="text-sm text-yellow-800">{t('pages.securityKeys.unsupported')}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {showRegisterForm && (
        <Card>
          <CardHeader>
            <CardTitle>{t('pages.securityKeys.registerCard.title')}</CardTitle>
            <CardDescription>{t('pages.securityKeys.registerCard.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1 space-y-2">
                <Label htmlFor="key-name">{t('pages.securityKeys.registerCard.keyName')}</Label>
                <Input
                  id="key-name"
                  placeholder={t('pages.securityKeys.registerCard.keyNamePlaceholder')}
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  disabled={registering}
                />
              </div>
              <Button onClick={handleRegister} disabled={registering || !keyName.trim()}>
                {registering ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('pages.securityKeys.registerCard.waiting')}
                  </span>
                ) : (
                  t('pages.securityKeys.registerCard.submit')
                )}
              </Button>
              <Button variant="outline" onClick={() => { setShowRegisterForm(false); setKeyName('') }} disabled={registering}>
                {t('common.cancel')}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            {t('pages.securityKeys.listTitle')}
          </CardTitle>
          <CardDescription>
            {t('pages.securityKeys.count', { count: credentials.length })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : credentials.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">{t('pages.securityKeys.empty')}</p>
              <p className="text-sm text-muted-foreground mt-1">{t('pages.securityKeys.emptyHint')}</p>
            </div>
          ) : (
            <div className="space-y-3">
              {credentials.map((cred) => (
                <div
                  key={cred.id}
                  className="flex items-center justify-between p-4 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg">
                      <KeyRound className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium">{cred.name || t('pages.securityKeys.fallbackName')}</p>
                      <p className="text-sm text-muted-foreground">
                        {t('pages.securityKeys.registered', {
                          date: new Date(cred.created_at).toLocaleDateString(undefined),
                        })}
                        {cred.last_used_at && (
                          <>
                            {' '}
                            &middot;{' '}
                            {t('pages.securityKeys.lastUsed', {
                              date: new Date(cred.last_used_at).toLocaleDateString(undefined),
                            })}
                          </>
                        )}
                        {cred.sign_count > 0 && (
                          <> &middot; {t('pages.securityKeys.usedTimes', { n: cred.sign_count })}</>
                        )}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    onClick={() => handleDelete(cred.id)}
                    disabled={deleting === cred.id}
                  >
                    {deleting === cred.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
