import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Ban, KeyRound, Mail, MessageSquare, Smartphone, Trash2, Fingerprint, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { ConfirmAction } from './confirm-action'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// An administrator's view of one user's sign-in methods.
//
// Built after an administrator was locked out: their only second factor was
// push to a phone that no longer existed, and nothing in the console showed
// that the phone had not been heard from in months. Every factor is listed
// here, push devices with when each was last seen, and each can be removed
// (or, for a push device, disabled) from this card.

type PushStatus = 'active' | 'stale' | 'disabled' | 'switched_off'

export interface SignInPushDevice {
  id: string
  device_name: string
  platform: string
  device_model?: string
  app_version?: string
  status: PushStatus
  agent_linked: boolean
  created_at: string
  last_used_at?: string
  last_seen_at?: string
  disabled_at?: string
  disabled_reason?: string
}

export interface SignInMethods {
  user_id: string
  stale_after_days: number
  totp: { enabled: boolean; enrolled_at?: string; last_used_at?: string } | null
  webauthn: { id: string; name: string; backup_eligible: boolean; created_at: string; last_used_at?: string }[]
  push_devices: SignInPushDevice[]
  backup_codes_remaining: number
  email: { enabled: boolean; address: string; last_used_at?: string } | null
  sms: { enabled: boolean; verified: boolean; phone_last4: string; last_used_at?: string } | null
  summary: { usable_factors: number; only_stale_push: boolean }
}

const statusClass: Record<PushStatus, string> = {
  active: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  stale: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
  disabled: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  switched_off: 'bg-muted text-muted-foreground',
}

function formatDate(value?: string): string | null {
  if (!value) return null
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return null
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function SignInMethodsCard({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const base = `/api/v1/identity/users/${encodeURIComponent(userId)}/sign-in-methods`
  const key = ['user-sign-in-methods', userId]

  const { data, isLoading, error } = useQuery({
    queryKey: key,
    // Normalised so a partial answer (an older server) renders as "nothing
    // there" rather than throwing.
    queryFn: async (): Promise<SignInMethods> => {
      const r = (await api.get<Partial<SignInMethods>>(base)) ?? {}
      return {
        user_id: r.user_id ?? userId,
        stale_after_days: r.stale_after_days ?? 30,
        totp: r.totp ?? null,
        webauthn: r.webauthn ?? [],
        push_devices: r.push_devices ?? [],
        backup_codes_remaining: r.backup_codes_remaining ?? 0,
        email: r.email ?? null,
        sms: r.sms ?? null,
        summary: r.summary ?? { usable_factors: 0, only_stale_push: false },
      }
    },
    enabled: !!userId,
  })

  const onDone = (message: string) => {
    toast({ title: message })
    queryClient.invalidateQueries({ queryKey: key })
  }
  const onFail = () =>
    toast({ title: t('components.signInMethods.actionFailed'), variant: 'destructive' })

  const remove = useMutation({
    mutationFn: ({ method, id }: { method: string; id?: string }) =>
      api.delete(id ? `${base}/${method}/${encodeURIComponent(id)}` : `${base}/${method}`),
    onSuccess: () => onDone(t('components.signInMethods.removed')),
    onError: onFail,
  })
  const disable = useMutation({
    mutationFn: (id: string) => api.post(`${base}/push/${encodeURIComponent(id)}/disable`),
    onSuccess: () => onDone(t('components.signInMethods.disabledToast')),
    onError: onFail,
  })
  const busy = remove.isPending || disable.isPending

  const removeButton = (method: string, label: string, id?: string) => (
    <ConfirmAction
      title={t('components.signInMethods.removeTitle', { method: label })}
      description={t('components.signInMethods.removeDesc')}
      destructive
      confirmLabel={t('components.signInMethods.remove')}
      onConfirm={() => remove.mutateAsync({ method, id })}
    >
      {(open) => (
        <Button
          variant="outline"
          size="sm"
          className="shrink-0 text-red-600 hover:text-red-700"
          disabled={busy}
          onClick={open}
          aria-label={t('components.signInMethods.removeAria', { method: label })}
        >
          <Trash2 className="mr-1 h-3.5 w-3.5" />
          {t('components.signInMethods.remove')}
        </Button>
      )}
    </ConfirmAction>
  )

  const row = (icon: ReactNode, title: string, detail: ReactNode, actions?: ReactNode, key?: string) => (
    <li key={key ?? title} className="flex items-center justify-between gap-3 rounded-md border p-3">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 text-muted-foreground">{icon}</span>
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{title}</p>
          <div className="text-xs text-muted-foreground">{detail}</div>
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </li>
  )

  const never = t('components.signInMethods.never')

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <ShieldCheck className="h-5 w-5" />
          {t('components.signInMethods.title')}
        </CardTitle>
        <CardDescription>{t('components.signInMethods.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
        ) : error || !data ? (
          <QueryError error={error} resource={t('components.signInMethods.resource')} />
        ) : (
          <>
            {data.summary.only_stale_push && (
              <div role="alert" className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950/40">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" />
                <p className="text-sm text-amber-800 dark:text-amber-300">
                  {t('components.signInMethods.onlyStalePush', { days: data.stale_after_days })}
                </p>
              </div>
            )}
            <ul className="space-y-2">
              {data.totp &&
                row(
                  <KeyRound className="h-4 w-4" />,
                  t('components.signInMethods.totp'),
                  <>
                    {data.totp.enabled ? t('components.signInMethods.enabled') : t('components.signInMethods.off')}
                    {' · '}
                    {t('components.signInMethods.lastUsed', { when: formatDate(data.totp.last_used_at) ?? never })}
                  </>,
                  removeButton('totp', t('components.signInMethods.totp')),
                  'totp',
                )}
              {data.webauthn.map((k) =>
                row(
                  <Fingerprint className="h-4 w-4" />,
                  k.name || t('components.signInMethods.securityKey'),
                  <>
                    {t('components.signInMethods.added', { when: formatDate(k.created_at) ?? never })}
                    {' · '}
                    {t('components.signInMethods.lastUsed', { when: formatDate(k.last_used_at) ?? never })}
                  </>,
                  removeButton('webauthn', k.name || t('components.signInMethods.securityKey'), k.id),
                  `webauthn-${k.id}`,
                ),
              )}
              {data.push_devices.map((d) =>
                row(
                  <Smartphone className="h-4 w-4" />,
                  d.device_name || t('components.signInMethods.pushDevice'),
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span>{d.platform}{d.device_model ? ` · ${d.device_model}` : ''}</span>
                    <span>{t('components.signInMethods.lastSeen', { when: formatDate(d.last_seen_at) ?? never })}</span>
                    <Badge className={statusClass[d.status] ?? statusClass.switched_off}>
                      {t(`components.signInMethods.status.${d.status}`)}
                    </Badge>
                    {d.status === 'disabled' && d.disabled_reason && (
                      <span>{t(`components.signInMethods.disabledReason.${d.disabled_reason === 'admin' ? 'admin' : 'stale'}`)}</span>
                    )}
                  </span>,
                  <>
                    {(d.status === 'active' || d.status === 'stale') && (
                      <ConfirmAction
                        title={t('components.signInMethods.disableTitle', { name: d.device_name || t('components.signInMethods.pushDevice') })}
                        description={t('components.signInMethods.disableDesc')}
                        confirmLabel={t('components.signInMethods.disable')}
                        onConfirm={() => disable.mutateAsync(d.id)}
                      >
                        {(open) => (
                          <Button variant="outline" size="sm" disabled={busy} onClick={open}
                            aria-label={t('components.signInMethods.disableAria', { name: d.device_name || t('components.signInMethods.pushDevice') })}>
                            <Ban className="mr-1 h-3.5 w-3.5" />
                            {t('components.signInMethods.disable')}
                          </Button>
                        )}
                      </ConfirmAction>
                    )}
                    {removeButton('push', d.device_name || t('components.signInMethods.pushDevice'), d.id)}
                  </>,
                  `push-${d.id}`,
                ),
              )}
              {data.email &&
                row(
                  <Mail className="h-4 w-4" />,
                  t('components.signInMethods.email'),
                  <>
                    {data.email.address}
                    {' · '}
                    {data.email.enabled ? t('components.signInMethods.enabled') : t('components.signInMethods.off')}
                  </>,
                  removeButton('email', t('components.signInMethods.email')),
                  'email',
                )}
              {data.sms &&
                row(
                  <MessageSquare className="h-4 w-4" />,
                  t('components.signInMethods.sms'),
                  <>
                    {t('components.signInMethods.phoneEnding', { last4: data.sms.phone_last4 })}
                    {' · '}
                    {data.sms.enabled && data.sms.verified ? t('components.signInMethods.enabled') : t('components.signInMethods.off')}
                  </>,
                  removeButton('sms', t('components.signInMethods.sms')),
                  'sms',
                )}
              {row(
                <KeyRound className="h-4 w-4" />,
                t('components.signInMethods.backupCodes'),
                t('components.signInMethods.backupRemaining', { count: data.backup_codes_remaining }),
                data.backup_codes_remaining > 0
                  ? removeButton('backup_codes', t('components.signInMethods.backupCodes'))
                  : undefined,
                'backup',
              )}
            </ul>
            {!data.totp && data.webauthn.length === 0 && data.push_devices.length === 0 && !data.email && !data.sms && (
              <p className="text-sm text-muted-foreground">{t('components.signInMethods.none')}</p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
