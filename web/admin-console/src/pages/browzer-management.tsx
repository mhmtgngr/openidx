import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Globe, RefreshCw, Shield, Server, Clock,
  AlertTriangle, CheckCircle, FileKey, ExternalLink,
} from 'lucide-react'
import { api } from '../lib/api'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface BrowZerTarget {
  vhost: string
  service: string
  path: string
  scheme: string
}

interface BrowZerDomainConfig {
  domain: string
  cert_type: string
  cert_subject: string
  cert_issuer: string
  cert_not_before: string
  cert_not_after: string
  cert_fingerprint: string
  cert_san: string[]
  custom_cert_uploaded_at: string | null
  previous_domain: string | null
  domain_changed_at: string | null
}

interface BrowZerManagementStatus {
  browzer_enabled: boolean
  domain: string
  bootstrapper_url: string
  cert_type: string
  cert_subject: string
  cert_issuer: string
  cert_not_after: string
  cert_fingerprint: string
  cert_san: string[]
  cert_days_left: number
  targets_count: number
  targets: BrowZerTarget[]
  domain_config: BrowZerDomainConfig | null
}

export function BrowZerManagementPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [newDomain, setNewDomain] = useState('')

  const { data: status, isLoading, isError, error } = useQuery<BrowZerManagementStatus>({
    queryKey: ['browzer-management'],
    queryFn: () => api.get('/api/v1/access/ziti/browzer/management'),
    refetchInterval: 10000,
  })

  const domainMutation = useMutation({
    mutationFn: (domain: string) => api.put('/api/v1/access/ziti/browzer/domain', { domain }),
    onSuccess: () => {
      toast({
        title: t('pages.browzerManagement.toast.domainChanged'),
        description: t('pages.browzerManagement.toast.domainChangedDesc'),
      })
      queryClient.invalidateQueries({ queryKey: ['browzer-management'] })
      setNewDomain('')
    },
    onError: (err: Error) => {
      toast({ title: t('pages.browzerManagement.toast.domainFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const restartMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/restart'),
    onSuccess: () => {
      toast({
        title: t('pages.browzerManagement.toast.restartTriggered'),
        description: t('pages.browzerManagement.toast.restartTriggeredDesc'),
      })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.browzerManagement.toast.restartFailed'), description: err.message, variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.browzerManagement.resourceName')} />

  const certExpiringSoon = status && status.cert_days_left > 0 && status.cert_days_left <= 30

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('pages.browzerManagement.title')}</h1>
          <p className="text-muted-foreground">
            {t('pages.browzerManagement.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {status?.browzer_enabled ? (
            <Badge variant="default" className="gap-1">
              <CheckCircle className="h-3 w-3" /> {t('pages.browzerManagement.enabled')}
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">{t('pages.browzerManagement.disabled')}</Badge>
          )}
        </div>
      </div>

      {/* Status Banner */}
      {certExpiringSoon && (
        <div className="flex items-center gap-2 rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500" />
          <span className="text-sm">
            {t('pages.browzerManagement.certExpiring')}{' '}
            <strong>{t('pages.browzerManagement.certExpiringDays', { count: status?.cert_days_left ?? 0 })}</strong>.{' '}
            {t(
              status?.cert_type === 'self_signed'
                ? 'pages.browzerManagement.certAdviceSelfSigned'
                : 'pages.browzerManagement.certAdviceRenew',
            )}
          </span>
        </div>
      )}

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">{t('pages.browzerManagement.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="certificates">{t('pages.browzerManagement.tabs.certificates')}</TabsTrigger>
          <TabsTrigger value="domain">{t('pages.browzerManagement.tabs.domain')}</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {/* Status Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.overview.status')}</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.browzer')}</span>
                    <Badge variant={status?.browzer_enabled ? 'default' : 'secondary'}>
                      {t(status?.browzer_enabled ? 'pages.browzerManagement.enabled' : 'pages.browzerManagement.disabled')}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.domain')}</span>
                    <span className="font-mono text-xs">{status?.domain}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.url')}</span>
                    <a href={status?.bootstrapper_url} target="_blank" rel="noopener noreferrer"
                       className="font-mono text-xs text-blue-500 hover:underline">
                      {status?.bootstrapper_url}
                    </a>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Certificate Summary Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.overview.certificate')}</CardTitle>
                <FileKey className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.type')}</span>
                    <Badge variant={status?.cert_type === 'custom' ? 'default' : 'outline'}>
                      {t(status?.cert_type === 'custom' ? 'pages.browzerManagement.overview.caSigned' : 'pages.browzerManagement.overview.selfSigned')}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.issuer')}</span>
                    <span className="text-xs truncate max-w-[180px]">{status?.cert_issuer || t('pages.browzerManagement.overview.notAvailable')}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('pages.browzerManagement.overview.expires')}</span>
                    <span className={`text-xs ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                      {status?.cert_not_after ? new Date(status.cert_not_after).toLocaleDateString() : t('pages.browzerManagement.overview.notAvailable')}
                      {status?.cert_days_left !== undefined && status.cert_days_left > 0
                        ? ` ${t('pages.browzerManagement.overview.daysLeft', { n: status.cert_days_left })}`
                        : ''}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Targets Card */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.overview.targets')}</CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{status?.targets_count ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">{t('pages.browzerManagement.overview.targetsSub')}</p>
                {status?.targets && status.targets.length > 0 && (
                  <div className="mt-3 space-y-1">
                    {status.targets.map((t, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <Globe className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono">{t.vhost}</span>
                        <span className="text-muted-foreground">{t.service}</span>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.overview.actions')}</CardTitle>
            </CardHeader>
            <CardContent>
              <Button
                onClick={() => restartMutation.mutate()}
                disabled={restartMutation.isPending}
                variant="outline"
                className="gap-2"
              >
                <RefreshCw className={`h-4 w-4 ${restartMutation.isPending ? 'animate-spin' : ''}`} />
                {t('pages.browzerManagement.overview.restart')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Certificates Tab */}
        <TabsContent value="certificates" className="space-y-4">
          {/* Certificate Summary */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.certificates.title')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.browzerManagement.overview.type')}</p>
                  <Badge variant={status?.cert_type === 'custom' ? 'default' : 'outline'}>
                    {t(status?.cert_type === 'custom' ? 'pages.browzerManagement.overview.caSigned' : 'pages.browzerManagement.overview.selfSigned')}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.browzerManagement.overview.issuer')}</p>
                  <p className="text-sm truncate">{status?.cert_issuer || t('pages.browzerManagement.overview.notAvailable')}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.browzerManagement.overview.expires')}</p>
                  <p className={`text-sm ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                    {status?.cert_not_after ? new Date(status.cert_not_after).toLocaleDateString() : t('pages.browzerManagement.overview.notAvailable')}
                    {status?.cert_days_left !== undefined && status.cert_days_left > 0
                      ? ` ${t('pages.browzerManagement.overview.daysLeft', { n: status.cert_days_left })}`
                      : ''}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.browzerManagement.certificates.subject')}</p>
                  <p className="text-sm font-mono truncate">{status?.cert_subject || t('pages.browzerManagement.overview.notAvailable')}</p>
                </div>
              </div>
              <div className="mt-4 pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-3">
                  {t('pages.browzerManagement.certificates.centralNote')}
                </p>
                <Button
                  onClick={() => navigate('/certificates')}
                  className="gap-2"
                >
                  <FileKey className="h-4 w-4" />
                  {t('pages.browzerManagement.certificates.manage')}
                  <ExternalLink className="h-3 w-3" />
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Domain Tab */}
        <TabsContent value="domain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.domain.current')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-muted-foreground" />
                <span className="text-lg font-mono">{status?.domain}</span>
                {status?.domain_config?.previous_domain && (
                  <span className="text-xs text-muted-foreground">
                    {t('pages.browzerManagement.domain.previously', { domain: status.domain_config.previous_domain })}
                  </span>
                )}
              </div>
              {status?.domain_config?.domain_changed_at && (
                <p className="text-xs text-muted-foreground mt-2">
                  <Clock className="h-3 w-3 inline mr-1" />
                  {t('pages.browzerManagement.domain.lastChanged', { when: new Date(status.domain_config.domain_changed_at).toLocaleString() })}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.browzerManagement.domain.change')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                {t('pages.browzerManagement.domain.changeNote')}
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder={t('pages.browzerManagement.domain.placeholder')}
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="max-w-sm font-mono"
                />
                <Button
                  onClick={() => {
                    if (newDomain.trim()) domainMutation.mutate(newDomain.trim())
                  }}
                  disabled={domainMutation.isPending || !newDomain.trim()}
                  className="gap-2"
                >
                  <Globe className={`h-4 w-4 ${domainMutation.isPending ? 'animate-spin' : ''}`} />
                  {t('pages.browzerManagement.domain.save')}
                </Button>
              </div>

              <div className="rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4 space-y-2">
                <p className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  {t('pages.browzerManagement.domain.cascadeTitle')}
                </p>
                <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                  <li>{t('pages.browzerManagement.domain.cascade1')}</li>
                  <li>{t('pages.browzerManagement.domain.cascade2')}</li>
                  <li>{t('pages.browzerManagement.domain.cascade3')}</li>
                  <li>{t('pages.browzerManagement.domain.cascade4')}</li>
                  <li>{t('pages.browzerManagement.domain.cascade5')}</li>
                </ul>
              </div>
            </CardContent>
          </Card>

          {/* Post-change instructions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                {t('pages.browzerManagement.domain.afterTitle')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-2">
                {t('pages.browzerManagement.domain.afterNote')}
              </p>
              <pre className="bg-muted p-3 rounded text-xs font-mono">
docker restart openidx-oauth-tls-proxy openidx-ziti-controller-proxy openidx-ziti-router
              </pre>
              <p className="text-sm text-muted-foreground mt-2">
                {t('pages.browzerManagement.domain.afterAuto')}
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
