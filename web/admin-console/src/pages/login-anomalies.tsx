import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Activity, ShieldAlert, Users, BarChart3, Clock, Globe, Monitor } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'

interface LoginAnomaly {
  id: string
  user_id: string
  username: string
  ip_address: string
  user_agent: string
  location: string
  risk_score: number
  success: boolean
  auth_methods: string[]
  created_at: string
}

interface RiskOverview {
  avg_risk_score: number
  high_risk_count: number
  total_logins_7d: number
  risk_distribution: {
    low: number
    medium: number
    high: number
    critical: number
  }
}

interface UserRiskProfile {
  user_id: string
  username: string
  baseline: {
    typical_login_hours: number[]
    typical_countries: string[]
    typical_ips: string[]
    avg_risk_score: number
    login_count: number
  }
  recent_logins: LoginAnomaly[]
}

const riskScoreBadge = (score: number) => {
  if (score >= 90) return { labelKey: 'critical', className: 'bg-red-100 text-red-800' }
  if (score >= 70) return { labelKey: 'high', className: 'bg-orange-100 text-orange-800' }
  if (score >= 30) return { labelKey: 'medium', className: 'bg-yellow-100 text-yellow-800' }
  return { labelKey: 'low', className: 'bg-green-100 text-green-800' }
}

const avgScoreColor = (score: number) => {
  if (score >= 70) return 'text-red-600'
  if (score >= 30) return 'text-yellow-600'
  return 'text-green-600'
}

export default function LoginAnomalies() {
  const { t } = useTranslation()
  const [days, setDays] = useState('7')
  const [minScore, setMinScore] = useState('50')
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['risk-overview'],
    queryFn: () => api.get<RiskOverview>('/api/v1/risk/overview'),
  })

  const { data: anomaliesData, isLoading: anomaliesLoading, isError: anomaliesError, error: anomaliesErrorObj } = useQuery({
    queryKey: ['risk-anomalies', days, minScore],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('days', days)
      params.set('min_score', minScore)
      params.set('page', '1')
      params.set('page_size', '20')
      const raw = await api.get<{ anomalies: LoginAnomaly[]; total: number; page: number; page_size: number }>(
        `/api/v1/risk/anomalies?${params.toString()}`
      )
      return {
        ...raw,
        anomalies: (raw?.anomalies ?? []).map(a => ({
          ...a,
          risk_score: a?.risk_score ?? 0,
          auth_methods: a?.auth_methods ?? [],
        })),
      }
    },
  })
  const anomalies = anomaliesData?.anomalies || []

  const { data: userProfile, isLoading: profileLoading } = useQuery({
    queryKey: ['risk-user-profile', selectedUserId],
    queryFn: async () => {
      const raw = await api.get<UserRiskProfile>(`/api/v1/risk/user-profile/${selectedUserId}`)
      return {
        ...raw,
        baseline: {
          typical_login_hours: raw?.baseline?.typical_login_hours ?? [],
          typical_countries: raw?.baseline?.typical_countries ?? [],
          typical_ips: raw?.baseline?.typical_ips ?? [],
          avg_risk_score: raw?.baseline?.avg_risk_score ?? 0,
          login_count: raw?.baseline?.login_count ?? 0,
        },
        recent_logins: (raw?.recent_logins ?? []).map(l => ({
          ...l,
          risk_score: l?.risk_score ?? 0,
        })),
      }
    },
    enabled: !!selectedUserId,
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.loginAnomalies')}</h1>
        <p className="text-muted-foreground">{t('pages.loginAnomalies.subtitle')}</p>
      </div>

      {/* Summary Cards */}
      {overviewLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">{t('pages.loginAnomalies.overviewLoading')}</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.loginAnomalies.stats.avgRisk')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${avgScoreColor(overview?.avg_risk_score || 0)}`}>
                {overview?.avg_risk_score?.toFixed(1) || '0.0'}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.loginAnomalies.stats.highRisk7d')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{overview?.high_risk_count || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.loginAnomalies.stats.total7d')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{overview?.total_logins_7d || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{t('pages.loginAnomalies.stats.distribution')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge className="bg-green-100 text-green-800">
                  {t('pages.loginAnomalies.distribution.low', { n: overview?.risk_distribution?.low || 0 })}
                </Badge>
                <Badge className="bg-yellow-100 text-yellow-800">
                  {t('pages.loginAnomalies.distribution.medium', { n: overview?.risk_distribution?.medium || 0 })}
                </Badge>
                <Badge className="bg-orange-100 text-orange-800">
                  {t('pages.loginAnomalies.distribution.high', { n: overview?.risk_distribution?.high || 0 })}
                </Badge>
                <Badge className="bg-red-100 text-red-800">
                  {t('pages.loginAnomalies.distribution.critical', { n: overview?.risk_distribution?.critical || 0 })}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filter Bar */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <label htmlFor="anomaly-days" className="text-sm font-medium">{t('pages.loginAnomalies.filters.days')}</label>
              <Select value={days} onValueChange={setDays}>
                <SelectTrigger id="anomaly-days" className="w-[120px]">
                  <SelectValue placeholder={t('pages.loginAnomalies.filters.daysPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {[1, 3, 7, 14, 30].map((d) => (
                    <SelectItem key={d} value={String(d)}>
                      {t('pages.loginAnomalies.filters.day', { count: d })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <label htmlFor="anomaly-min-score" className="text-sm font-medium">{t('pages.loginAnomalies.filters.minScore')}</label>
              <Select value={minScore} onValueChange={setMinScore}>
                <SelectTrigger id="anomaly-min-score" className="w-[120px]">
                  <SelectValue placeholder={t('pages.loginAnomalies.filters.minScorePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {[0, 30, 50, 70, 90].map((s) => (
                    <SelectItem key={s} value={String(s)}>
                      {t('pages.loginAnomalies.filters.scorePlus', { n: s })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent Anomalies Table */}
      <Card>
        <CardHeader>
          <CardTitle>{t('pages.loginAnomalies.recent.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          {anomaliesLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.loginAnomalies.recent.loading')}</p>
            </div>
          ) : anomaliesError ? (
            <QueryError error={anomaliesErrorObj} resource={t('pages.loginAnomalies.resourceName')} />
          ) : anomalies.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Activity className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.loginAnomalies.recent.empty')}</p>
              <p className="text-sm">{t('pages.loginAnomalies.recent.emptyHint')}</p>
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.loginAnomalies.table.user')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.ip')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.location')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.riskScore')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.authMethods')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.time')}</TableHead>
                    <TableHead>{t('pages.loginAnomalies.table.status')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {anomalies.map(a => {
                    const risk = riskScoreBadge(a.risk_score)
                    return (
                      <TableRow key={a.id} className="cursor-pointer" onClick={() => setSelectedUserId(a.user_id)}>
                        <TableCell className="font-medium">{a.username}</TableCell>
                        <TableCell className="font-mono text-sm">{a.ip_address}</TableCell>
                        <TableCell>{a.location}</TableCell>
                        <TableCell>
                          <Badge className={risk.className}>
                            {t('pages.loginAnomalies.scoreBadge', {
                              score: a.risk_score,
                              label: t(`pages.loginAnomalies.levels.${risk.labelKey}`),
                            })}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {a.auth_methods.map(m => (
                              <Badge key={m} variant="outline">{m}</Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(a.created_at)}</TableCell>
                        <TableCell>
                          {a.success ? (
                            <Badge className="bg-green-100 text-green-800">{t('pages.loginAnomalies.success')}</Badge>
                          ) : (
                            <Badge className="bg-red-100 text-red-800">{t('pages.loginAnomalies.failed')}</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* User Risk Profile Dialog */}
      <Dialog open={!!selectedUserId} onOpenChange={open => !open && setSelectedUserId(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {t('pages.loginAnomalies.profile.title', {
                username: userProfile?.username || t('pages.loginAnomalies.profile.loadingName'),
              })}
            </DialogTitle>
          </DialogHeader>
          {profileLoading ? (
            <div className="flex flex-col items-center justify-center py-8">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.loginAnomalies.profile.loading')}</p>
            </div>
          ) : userProfile ? (
            <div className="space-y-6">
              {/* Baseline Info */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold">{t('pages.loginAnomalies.profile.baseline')}</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-start gap-2">
                    <Clock className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{t('pages.loginAnomalies.profile.typicalHours')}</p>
                      <p className="text-muted-foreground">
                        {userProfile.baseline.typical_login_hours.length > 0
                          ? userProfile.baseline.typical_login_hours.map(h => `${h}:00`).join(', ')
                          : t('pages.loginAnomalies.profile.noData')}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Globe className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{t('pages.loginAnomalies.profile.typicalCountries')}</p>
                      <p className="text-muted-foreground">
                        {userProfile.baseline.typical_countries.length > 0
                          ? userProfile.baseline.typical_countries.join(', ')
                          : t('pages.loginAnomalies.profile.noData')}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Monitor className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{t('pages.loginAnomalies.profile.typicalIps')}</p>
                      <p className="text-muted-foreground font-mono text-xs">
                        {userProfile.baseline.typical_ips.length > 0
                          ? userProfile.baseline.typical_ips.join(', ')
                          : t('pages.loginAnomalies.profile.noData')}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <BarChart3 className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{t('pages.loginAnomalies.profile.avgRisk')}</p>
                      <p className={avgScoreColor(userProfile.baseline.avg_risk_score)}>
                        {userProfile.baseline.avg_risk_score.toFixed(1)}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Users className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">{t('pages.loginAnomalies.profile.totalLogins')}</span>
                  <span className="text-muted-foreground">{userProfile.baseline.login_count}</span>
                </div>
              </div>

              {/* Recent Logins */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold">{t('pages.loginAnomalies.profile.recentLogins')}</h3>
                {userProfile.recent_logins.length === 0 ? (
                  <p className="text-sm text-muted-foreground">{t('pages.loginAnomalies.profile.noRecent')}</p>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('pages.loginAnomalies.profile.table.ip')}</TableHead>
                          <TableHead>{t('pages.loginAnomalies.profile.table.location')}</TableHead>
                          <TableHead>{t('pages.loginAnomalies.profile.table.risk')}</TableHead>
                          <TableHead>{t('pages.loginAnomalies.profile.table.status')}</TableHead>
                          <TableHead>{t('pages.loginAnomalies.profile.table.time')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {userProfile.recent_logins.map(login => {
                          const risk = riskScoreBadge(login.risk_score)
                          return (
                            <TableRow key={login.id}>
                              <TableCell className="font-mono text-sm">{login.ip_address}</TableCell>
                              <TableCell>{login.location}</TableCell>
                              <TableCell>
                                <Badge className={risk.className}>{login.risk_score}</Badge>
                              </TableCell>
                              <TableCell>
                                {login.success ? (
                                  <Badge className="bg-green-100 text-green-800">{t('pages.loginAnomalies.success')}</Badge>
                                ) : (
                                  <Badge className="bg-red-100 text-red-800">{t('pages.loginAnomalies.failed')}</Badge>
                                )}
                              </TableCell>
                              <TableCell className="text-sm text-muted-foreground">{formatDate(login.created_at)}</TableCell>
                            </TableRow>
                          )
                        })}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.loginAnomalies.profile.unavailable')}</p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
