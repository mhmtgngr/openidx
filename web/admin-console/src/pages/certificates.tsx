import { useRef } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload, RefreshCw, Server, Clock,
  AlertTriangle, Trash2, Lock, Unlock,
} from 'lucide-react'
import { api } from '../lib/api'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'

interface PlatformCertConsumer {
  name: string
  port: number
  protocol: string
  status: string
  description: string
  restart_hint: string
}

interface PlatformCertInfo {
  cert_type: string
  subject: string
  issuer: string
  not_before: string
  not_after: string
  days_left: number
  fingerprint: string
  sans: string[]
  serial_number: string
  uploaded_at: string | null
  consumers: PlatformCertConsumer[]
}

interface APISIXSSLConfig {
  enabled: boolean
  last_updated: string
  cert_fingerprint: string
}

interface CertExpiryAlert {
  source: string
  name: string
  days_left: number
  severity: string
  not_after: string
}

interface PlatformCertHealthStatus {
  platform: PlatformCertInfo | null
  apisix: APISIXSSLConfig | null
  expiry_alerts: CertExpiryAlert[]
}

interface ZitiCertificate {
  id: string
  name: string
  cert_type: string
  subject: string
  issuer: string
  fingerprint: string
  not_before: string
  not_after: string
  auto_renew: boolean
  status: string
  days_until_expiry: number
}

export function CertificatesPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const certFileRef = useRef<HTMLInputElement>(null)
  const keyFileRef = useRef<HTMLInputElement>(null)

  const { data: certStatus, isLoading, isError, error } = useQuery<PlatformCertHealthStatus>({
    queryKey: ['certificates-status'],
    queryFn: () => api.get('/api/v1/access/certificates/status'),
    refetchInterval: 15000,
  })

  const { data: zitiCertsRaw } = useQuery({
    queryKey: ['ziti-certificates'],
    queryFn: () => api.get('/api/v1/access/ziti/certificates'),
  })
  const zitiCerts: ZitiCertificate[] = Array.isArray(zitiCertsRaw) ? zitiCertsRaw : []

  const uploadMutation = useMutation({
    mutationFn: async () => {
      const certInput = certFileRef.current
      const keyInput = keyFileRef.current
      if (!certInput?.files?.[0] || !keyInput?.files?.[0]) {
        throw new Error(t('pages.certificates.platform.selectBoth'))
      }
      const formData = new FormData()
      formData.append('cert', certInput.files[0])
      formData.append('key', keyInput.files[0])
      return api.postFormData('/api/v1/access/certificates/platform', formData)
    },
    onSuccess: () => {
      toast({
        title: t('pages.certificates.platform.uploaded'),
        description: t('pages.certificates.platform.uploadedDesc'),
      })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
      if (certFileRef.current) certFileRef.current.value = ''
      if (keyFileRef.current) keyFileRef.current.value = ''
    },
    onError: (err: Error) => {
      toast({ title: t('pages.certificates.platform.uploadFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const revertMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/access/certificates/platform'),
    onSuccess: () => {
      toast({ title: t('pages.certificates.platform.reverted') })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.certificates.platform.revertFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const enableApisixMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/certificates/apisix/enable'),
    onSuccess: () => {
      toast({
        title: t('pages.certificates.apisix.enabledToast'),
        description: t('pages.certificates.apisix.enabledToastDesc'),
      })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.certificates.apisix.enableFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const disableApisixMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/certificates/apisix/disable'),
    onSuccess: () => {
      toast({ title: t('pages.certificates.apisix.disabledToast') })
      queryClient.invalidateQueries({ queryKey: ['certificates-status'] })
    },
    onError: (err: Error) => {
      toast({ title: t('pages.certificates.apisix.disableFailed'), description: err.message, variant: 'destructive' })
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/certificates/${id}/rotate`, {}),
    onSuccess: () => {
      toast({ title: t('pages.certificates.ziti.rotated') })
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates'] })
    },
    onError: () => {
      toast({ title: t('pages.certificates.ziti.rotateFailed'), variant: 'destructive' })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.certificates.resource')} />

  const platform = certStatus?.platform
  const apisix = certStatus?.apisix
  const alerts = certStatus?.expiry_alerts || []
  const certExpiringSoon = platform && platform.days_left > 0 && platform.days_left <= 30

  const expiryBadge = (days: number) => {
    const variant: 'default' | 'destructive' | 'secondary' =
      days < 7 ? 'destructive' : days <= 30 ? 'secondary' : 'default'
    const label =
      days <= 0
        ? t('pages.certificates.expired')
        : t('pages.certificates.daysRemaining', { n: days })
    return <Badge variant={variant}>{label}</Badge>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('pages.certificates.title')}</h1>
        <p className="text-muted-foreground">{t('pages.certificates.subtitle')}</p>
      </div>

      {/* Expiry Alert Banner */}
      {alerts.length > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-4">
          <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0" />
          <div>
            {alerts.map((alert, i) => (
              <p key={i} className="text-sm">
                <Trans
                  i18nKey="pages.certificates.expiryAlert"
                  values={{ name: alert.name, days: alert.days_left }}
                  components={[<strong key="0" />, <strong key="1" />]}
                />
                {alert.severity === 'critical' && t('pages.certificates.actionRequired')}
              </p>
            ))}
          </div>
        </div>
      )}

      <Tabs defaultValue="platform">
        <TabsList>
          <TabsTrigger value="platform">{t('pages.certificates.tabs.platform')}</TabsTrigger>
          <TabsTrigger value="apisix">{t('pages.certificates.tabs.apisix')}</TabsTrigger>
          <TabsTrigger value="ziti">{t('pages.certificates.tabs.ziti')}</TabsTrigger>
        </TabsList>

        {/* Platform TLS Tab */}
        <TabsContent value="platform" className="space-y-4">
          {/* Certificate Details */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.certificates.platform.heading')}</CardTitle>
              <Badge variant={platform?.cert_type === 'custom' ? 'default' : 'outline'}>
                {platform?.cert_type === 'custom'
                  ? t('pages.certificates.platform.caSigned')
                  : t('pages.certificates.platform.selfSigned')}
              </Badge>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.subject')}</p>
                  <p className="text-sm font-mono">{platform?.subject || t('pages.certificates.na')}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.issuer')}</p>
                  <p className="text-sm font-mono">{platform?.issuer || t('pages.certificates.na')}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.validFrom')}</p>
                  <p className="text-sm">
                    {platform?.not_before
                      ? new Date(platform.not_before).toLocaleDateString()
                      : t('pages.certificates.na')}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.expires')}</p>
                  <p className={`text-sm ${certExpiringSoon ? 'text-yellow-500 font-semibold' : ''}`}>
                    {!platform?.not_after
                      ? t('pages.certificates.na')
                      : platform.days_left > 0
                        ? t('pages.certificates.platform.expiryWithDays', {
                            date: new Date(platform.not_after).toLocaleDateString(),
                            n: platform.days_left,
                          })
                        : new Date(platform.not_after).toLocaleDateString()}
                  </p>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.sans')}</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {platform?.sans?.length ? platform.sans.map((san, i) => (
                      <Badge key={i} variant="outline" className="text-xs font-mono">{san}</Badge>
                    )) : <span className="text-sm text-muted-foreground">{t('pages.certificates.none')}</span>}
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.platform.fingerprint')}</p>
                  <p className="text-xs font-mono break-all">{platform?.fingerprint || t('pages.certificates.na')}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Consumers */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.certificates.platform.consumers')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {platform?.consumers?.map((consumer, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-lg border p-3">
                    <Server className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{consumer.name}</span>
                        <Badge variant={consumer.status === 'active' ? 'default' : 'secondary'} className="text-[10px] px-1.5 py-0">
                          {consumer.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{consumer.description}</p>
                      <p className="text-xs font-mono text-muted-foreground mt-1">
                        {consumer.protocol} :{consumer.port}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Upload Custom Certificate */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.certificates.platform.upload')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">{t('pages.certificates.platform.uploadDesc')}</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="text-sm font-medium mb-1 block">{t('pages.certificates.platform.certFile')}</label>
                  <Input ref={certFileRef} type="file" accept=".pem,.crt,.cer" />
                </div>
                <div>
                  <label className="text-sm font-medium mb-1 block">{t('pages.certificates.platform.keyFile')}</label>
                  <Input ref={keyFileRef} type="file" accept=".pem,.key" />
                </div>
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => uploadMutation.mutate()}
                  disabled={uploadMutation.isPending}
                  className="gap-2"
                >
                  <Upload className={`h-4 w-4 ${uploadMutation.isPending ? 'animate-spin' : ''}`} />
                  {t('pages.certificates.platform.uploadButton')}
                </Button>
                {platform?.cert_type === 'custom' && (
                  <ConfirmAction
                    title={t('pages.certificates.platform.revertTitle')}
                    description={t('pages.certificates.platform.revertDesc')}
                    destructive
                    requireReason
                    confirmLabel={t('pages.certificates.platform.revertConfirm')}
                    onConfirm={() => revertMutation.mutateAsync()}
                  >
                    {(open) => (
                      <Button
                        onClick={open}
                        disabled={revertMutation.isPending}
                        variant="outline"
                        className="gap-2"
                      >
                        <Trash2 className="h-4 w-4" />
                        {t('pages.certificates.platform.revertConfirm')}
                      </Button>
                    )}
                  </ConfirmAction>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Post-change instructions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                {t('pages.certificates.platform.afterChanges')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-2">
                {t('pages.certificates.platform.afterChangesDesc')}
              </p>
              <pre className="bg-muted p-3 rounded text-xs font-mono">
docker restart openidx-oauth-tls-proxy openidx-ziti-controller-proxy openidx-ziti-router
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Gateway Tab */}
        <TabsContent value="apisix" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.certificates.apisix.heading')}</CardTitle>
              {apisix?.enabled ? (
                <Badge variant="default" className="gap-1">
                  <Lock className="h-3 w-3" /> {t('pages.certificates.apisix.enabled')}
                </Badge>
              ) : (
                <Badge variant="secondary" className="gap-1">
                  <Unlock className="h-3 w-3" /> {t('pages.certificates.apisix.disabled')}
                </Badge>
              )}
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.apisix.httpEndpoint')}</p>
                  <p className="text-sm font-mono">http://localhost:8088</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{t('pages.certificates.apisix.httpsEndpoint')}</p>
                  <p className={`text-sm font-mono ${apisix?.enabled ? '' : 'text-muted-foreground'}`}>
                    {apisix?.enabled ? 'https://localhost:8443' : t('pages.certificates.apisix.notConfigured')}
                  </p>
                </div>
                {apisix?.last_updated && (
                  <div className="sm:col-span-2">
                    <p className="text-xs text-muted-foreground">{t('pages.certificates.apisix.lastUpdated')}</p>
                    <p className="text-sm">
                      <Clock className="h-3 w-3 inline mr-1" />
                      {new Date(apisix.last_updated).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                {apisix?.enabled ? (
                  <Button
                    onClick={() => disableApisixMutation.mutate()}
                    disabled={disableApisixMutation.isPending}
                    variant="outline"
                    className="gap-2"
                  >
                    <Unlock className="h-4 w-4" />
                    {t('pages.certificates.apisix.disableHttps')}
                  </Button>
                ) : (
                  <Button
                    onClick={() => enableApisixMutation.mutate()}
                    disabled={enableApisixMutation.isPending}
                    className="gap-2"
                  >
                    <Lock className={`h-4 w-4 ${enableApisixMutation.isPending ? 'animate-spin' : ''}`} />
                    {t('pages.certificates.apisix.enableHttps')}
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.certificates.apisix.howItWorks')}</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="text-sm text-muted-foreground space-y-2 list-disc list-inside">
                <li>{t('pages.certificates.apisix.how1')}</li>
                <li>{t('pages.certificates.apisix.how2')}</li>
                <li>
                  <Trans
                    i18nKey="pages.certificates.apisix.how3"
                    components={[<span key="0" className="font-mono" />]}
                  />
                </li>
                <li>
                  <Trans
                    i18nKey="pages.certificates.apisix.how4"
                    components={[<span key="0" className="font-mono" />]}
                  />
                </li>
                <li>{t('pages.certificates.apisix.how5')}</li>
              </ul>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Ziti Certificates Tab */}
        <TabsContent value="ziti" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">{t('pages.certificates.ziti.heading')}</CardTitle>
            </CardHeader>
            <CardContent>
              {!zitiCerts || zitiCerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('pages.certificates.ziti.empty')}</p>
              ) : (
                <div className="space-y-3">
                  {/* Expiry alerts */}
                  {zitiCerts.filter(c => c.days_until_expiry <= 30 && c.days_until_expiry > 0).length > 0 && (
                    <div className="p-3 rounded-lg border border-yellow-500/50 bg-yellow-500/10">
                      <div className="flex items-center gap-2 mb-1">
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                        <span className="text-sm font-medium">{t('pages.certificates.ziti.expiringSoon')}</span>
                      </div>
                      {zitiCerts
                        .filter(c => c.days_until_expiry <= 30 && c.days_until_expiry > 0)
                        .map(cert => (
                          <div key={cert.id} className="flex items-center justify-between text-sm mt-1">
                            <span>
                              {t('pages.certificates.ziti.expiringRow', {
                                name: cert.name,
                                n: cert.days_until_expiry,
                              })}
                            </span>
                            <ConfirmAction
                              title={t('pages.certificates.ziti.rotateTitle')}
                              description={t('pages.certificates.ziti.rotateDesc')}
                              destructive
                              confirmLabel={t('pages.certificates.ziti.rotate')}
                              onConfirm={() => rotateMutation.mutate(cert.id)}
                            >
                              {(open) => (
                                <Button variant="outline" size="sm" onClick={open}>
                                  {t('pages.certificates.ziti.rotate')}
                                </Button>
                              )}
                            </ConfirmAction>
                          </div>
                        ))}
                    </div>
                  )}

                  {/* Cert list */}
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-b bg-muted/50">
                          <TableHead className="p-2 text-left text-xs font-medium text-muted-foreground">{t('pages.certificates.ziti.colName')}</TableHead>
                          <TableHead className="p-2 text-left text-xs font-medium text-muted-foreground">{t('pages.certificates.ziti.colType')}</TableHead>
                          <TableHead className="p-2 text-left text-xs font-medium text-muted-foreground">{t('pages.certificates.ziti.colSubject')}</TableHead>
                          <TableHead className="p-2 text-left text-xs font-medium text-muted-foreground">{t('pages.certificates.ziti.colExpiry')}</TableHead>
                          <TableHead className="p-2 text-left text-xs font-medium text-muted-foreground">{t('pages.certificates.ziti.colAutoRenew')}</TableHead>
                          <TableHead className="p-2 w-[80px]"></TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {zitiCerts.map(cert => (
                          <TableRow key={cert.id} className="border-b hover:bg-muted/50">
                            <TableCell className="p-2 text-sm font-medium">{cert.name}</TableCell>
                            <TableCell className="p-2"><Badge variant="outline" className="text-xs">{cert.cert_type}</Badge></TableCell>
                            <TableCell className="p-2 text-sm text-muted-foreground truncate max-w-[200px]">{cert.subject}</TableCell>
                            <TableCell className="p-2">{expiryBadge(cert.days_until_expiry)}</TableCell>
                            <TableCell className="p-2">
                              <Badge variant={cert.auto_renew ? 'default' : 'secondary'} className="text-xs">
                                {cert.auto_renew
                                  ? t('pages.certificates.ziti.yes')
                                  : t('pages.certificates.ziti.no')}
                              </Badge>
                            </TableCell>
                            <TableCell className="p-2">
                              <ConfirmAction
                                title={t('pages.certificates.ziti.rotateTitle')}
                                description={t('pages.certificates.ziti.rotateDesc')}
                                destructive
                                confirmLabel={t('pages.certificates.ziti.rotate')}
                                onConfirm={() => rotateMutation.mutate(cert.id)}
                              >
                                {(open) => (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={open}
                                    disabled={rotateMutation.isPending}
                                    className="gap-1 text-xs"
                                  >
                                    <RefreshCw className="h-3 w-3" /> {t('pages.certificates.ziti.rotate')}
                                  </Button>
                                )}
                              </ConfirmAction>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
