import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RotateCw } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { api } from '../lib/api'
import { isPlatformAdminRequired } from '../lib/platform-admin'
import { useToast } from '../hooks/use-toast'

export interface EAMKey {
  kid: string
  not_before: string
  not_after: string
  active: boolean
  created_at: string
}

export interface EAMStatus {
  enabled: boolean
  issuer: string
  discovery_url: string
  jwks_url: string
  authorize_url: string
  client_id: string
  tenant_ids: string[]
  require_strong_factors: boolean
  keys: EAMKey[]
  verifications_24h: number
  verifications_failed_24h: number
}

// keyStates mirrors the server's rule: the newest key whose not_before has
// passed signs; a newer one rotated in waits (published so Entra caches it
// first); older ones stay published until their certificate expires.
export function keyStates(keys: EAMKey[], now: number): Record<string, 'signing' | 'pending' | 'retired'> {
  const out: Record<string, 'signing' | 'pending' | 'retired'> = {}
  const sorted = [...keys].sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime())
  let signing = false
  for (const k of sorted) {
    if (new Date(k.not_before).getTime() > now) out[k.kid] = 'pending'
    else if (!signing) {
      out[k.kid] = 'signing'
      signing = true
    } else out[k.kid] = 'retired'
  }
  return out
}

export function EntraEAMCard() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['eam-status'],
    queryFn: () => api.get<EAMStatus>('/api/v1/oauth/eam/status'),
    retry: false,
  })
  const rotate = useMutation({
    mutationFn: () => api.post<EAMKey>('/api/v1/oauth/eam/keys/rotate'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['eam-status'] })
      toast({ title: t('pages.settings.eam.rotated'), variant: 'success' })
    },
    onError: () => toast({ title: t('pages.settings.eam.rotateFailed'), variant: 'destructive' }),
  })

  const states = keyStates(data?.keys ?? [], Date.now())
  return (
    <Card data-testid="entra-eam-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {t('pages.settings.eam.title')}
          {data && (
            <Badge variant={data.enabled ? 'default' : 'secondary'}>
              {data.enabled ? t('pages.settings.eam.on') : t('pages.settings.eam.off')}
            </Badge>
          )}
        </CardTitle>
        <CardDescription>{t('pages.settings.eam.desc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading && <p className="text-sm text-muted-foreground">{t('common.loading')}</p>}
        {isError && (
          <p className="text-sm text-muted-foreground">
            {isPlatformAdminRequired(error) ? t('pages.settings.eam.platformOnly') : t('pages.settings.eam.loadFailed')}
          </p>
        )}
        {data && (
          <>
            {!data.enabled && <p className="text-sm text-muted-foreground">{t('pages.settings.eam.offHint')}</p>}
            <dl className="grid gap-2 text-sm md:grid-cols-[12rem_1fr]">
              <dt className="font-medium">{t('pages.settings.eam.issuer')}</dt>
              <dd className="break-all font-mono">{data.issuer}</dd>
              <dt className="font-medium">{t('pages.settings.eam.discovery')}</dt>
              <dd className="break-all font-mono">{data.discovery_url}</dd>
              <dt className="font-medium">{t('pages.settings.eam.jwks')}</dt>
              <dd className="break-all font-mono">{data.jwks_url}</dd>
              <dt className="font-medium">{t('pages.settings.eam.replyUrl')}</dt>
              <dd className="break-all font-mono">{data.authorize_url}</dd>
              <dt className="font-medium">{t('pages.settings.eam.clientId')}</dt>
              <dd className="break-all font-mono">{data.client_id || '—'}</dd>
              <dt className="font-medium">{t('pages.settings.eam.tenants')}</dt>
              <dd className="font-mono">
                {data.tenant_ids.length ? data.tenant_ids.join(', ') : t('pages.settings.eam.noTenants')}
              </dd>
              <dt className="font-medium">{t('pages.settings.eam.factors')}</dt>
              <dd>{data.require_strong_factors ? t('pages.settings.eam.strongOnly') : t('pages.settings.eam.anyFactor')}</dd>
              <dt className="font-medium">{t('pages.settings.eam.last24h')}</dt>
              <dd data-testid="eam-count">
                {t('pages.settings.eam.counts', { ok: data.verifications_24h, failed: data.verifications_failed_24h })}
              </dd>
            </dl>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-medium">{t('pages.settings.eam.keys')}</h4>
                <Button size="sm" variant="outline" onClick={() => rotate.mutate()} disabled={rotate.isPending || !data.enabled}>
                  <RotateCw className="mr-2 h-4 w-4" />
                  {t('pages.settings.eam.rotate')}
                </Button>
              </div>
              {data.keys.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t('pages.settings.eam.noKeys')}</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {data.keys.map((k) => {
                    const st = states[k.kid]
                    return (
                      <li key={k.kid} className="flex flex-wrap items-center gap-2">
                        <span className="font-mono">{k.kid}</span>
                        <Badge variant={st === 'signing' ? 'default' : 'secondary'}>{t(`pages.settings.eam.key_${st}`)}</Badge>
                        <span className="text-xs text-muted-foreground">
                          {new Date(k.not_before).toLocaleString()} → {new Date(k.not_after).toLocaleDateString()}
                        </span>
                      </li>
                    )
                  })}
                </ul>
              )}
              <p className="text-xs text-muted-foreground">{t('pages.settings.eam.rotateHint')}</p>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
