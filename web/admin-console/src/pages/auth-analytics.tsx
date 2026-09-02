import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Activity, ShieldCheck, Users, KeyRound, Globe, Clock, XCircle, TrendingUp, TrendingDown,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'
import { api } from '../lib/api'

interface AuthDashboard {
  period: string
  total_logins: number
  successful_logins: number
  failed_logins: number
  mfa_usage_count: number
  active_users: number
  login_methods: Array<{
    method: string
    count: number
    percentage: number
  }>
  geo_top_countries: Array<{
    country: string
    count: number
    failed: number
  }>
  hourly_activity: Array<{
    hour: number
    count: number
  }>
  recent_failed_logins: Array<{
    user_id: string
    email: string
    source_ip: string
    reason: string
    timestamp: string
  }>
}

const PERIODS = ['24h', '7d', '30d', '90d'] as const
const periodKeys: Record<string, string> = {
  '24h': 'h24',
  '7d': 'd7',
  '30d': 'd30',
  '90d': 'd90',
}

export function AuthAnalyticsPage() {
  const { t } = useTranslation()
  const [period, setPeriod] = useState('7d')

  const { data, isLoading, isError, error } = useQuery<{ dashboard: AuthDashboard }>({
    queryKey: ['auth-analytics', period],
    queryFn: async () => {
      const res = await api.get<{ dashboard: AuthDashboard }>(
        `/api/v1/analytics/auth-dashboard?period=${period}`
      )
      const d = res.dashboard
      if (!d) return { dashboard: d }
      return {
        dashboard: {
          period: d.period ?? '',
          total_logins: d.total_logins ?? 0,
          successful_logins: d.successful_logins ?? 0,
          failed_logins: d.failed_logins ?? 0,
          mfa_usage_count: d.mfa_usage_count ?? 0,
          active_users: d.active_users ?? 0,
          login_methods: (d.login_methods ?? []).map((m) => ({
            method: m.method ?? '',
            count: m.count ?? 0,
            percentage: m.percentage ?? 0,
          })),
          geo_top_countries: (d.geo_top_countries ?? []).map((g) => ({
            country: g.country ?? '',
            count: g.count ?? 0,
            failed: g.failed ?? 0,
          })),
          hourly_activity: (d.hourly_activity ?? []).map((h) => ({
            hour: h.hour ?? 0,
            count: h.count ?? 0,
          })),
          recent_failed_logins: (d.recent_failed_logins ?? []).map((l) => ({
            user_id: l.user_id ?? '',
            email: l.email ?? '',
            source_ip: l.source_ip ?? '',
            reason: l.reason ?? '',
            timestamp: l.timestamp ?? '',
          })),
        },
      }
    },
  })

  const dashboard = data?.dashboard

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) return <QueryError error={error} resource={t('pages.authAnalytics.resourceName')} />

  if (!dashboard) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        {t('pages.authAnalytics.noData')}
      </div>
    )
  }

  const successRate =
    dashboard.total_logins > 0
      ? ((dashboard.successful_logins / dashboard.total_logins) * 100).toFixed(1)
      : '0.0'

  const mfaRate =
    dashboard.total_logins > 0
      ? ((dashboard.mfa_usage_count / dashboard.total_logins) * 100).toFixed(1)
      : '0.0'

  const maxHourly = Math.max(...(dashboard.hourly_activity?.map((h) => h.count) || [1]))
  const maxMethodCount = Math.max(...(dashboard.login_methods?.map((m) => m.count) || [1]))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('pages.authAnalytics.title')}</h1>
          <p className="text-muted-foreground">{t('pages.authAnalytics.subtitle')}</p>
        </div>
        <Select value={period} onValueChange={setPeriod}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PERIODS.map((value) => (
              <SelectItem key={value} value={value}>
                {t(`common.periods.${periodKeys[value]}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <RelatedLinks links={[{ to: '/login-analytics', label: t('nav.items.loginAnalytics') }]} />

      {/* Stat Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.authAnalytics.stats.totalLogins')}</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {dashboard.total_logins.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {t('pages.authAnalytics.stats.totalLoginsHint', {
                success: dashboard.successful_logins.toLocaleString(),
                failed: dashboard.failed_logins.toLocaleString(),
              })}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.authAnalytics.stats.successRate')}</CardTitle>
            {parseFloat(successRate) >= 95 ? (
              <TrendingUp className="h-4 w-4 text-green-600" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-600" />
            )}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{successRate}%</div>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  parseFloat(successRate) >= 95
                    ? 'bg-green-500'
                    : parseFloat(successRate) >= 80
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                }`}
                style={{ width: `${successRate}%` }}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.authAnalytics.stats.mfaRate')}</CardTitle>
            <ShieldCheck className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{mfaRate}%</div>
            <p className="text-xs text-muted-foreground mt-1">
              {t('pages.authAnalytics.stats.mfaHint', {
                n: dashboard.mfa_usage_count.toLocaleString(),
              })}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.authAnalytics.stats.activeUsers')}</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {dashboard.active_users.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {t('pages.authAnalytics.stats.activeUsersHint')}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Login Method Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5" />
              {t('pages.authAnalytics.methods.title')}
            </CardTitle>
            <CardDescription>{t('pages.authAnalytics.methods.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {dashboard.login_methods?.length > 0 ? (
                dashboard.login_methods.map((method) => (
                  <div key={method.method} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="capitalize font-medium">{method.method.replace(/_/g, ' ')}</span>
                      <span className="text-muted-foreground">
                        {method.count.toLocaleString()} ({method.percentage.toFixed(1)}%)
                      </span>
                    </div>
                    <div className="h-3 bg-muted rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full transition-all"
                        style={{ width: `${maxMethodCount > 0 ? (method.count / maxMethodCount) * 100 : 0}%` }}
                      />
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-center text-muted-foreground py-4">{t('pages.authAnalytics.methods.empty')}</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Geographic Top 5 Countries */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              {t('pages.authAnalytics.geo.title')}
            </CardTitle>
            <CardDescription>{t('pages.authAnalytics.geo.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {dashboard.geo_top_countries?.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.authAnalytics.geo.table.country')}</TableHead>
                    <TableHead className="text-right">{t('pages.authAnalytics.geo.table.logins')}</TableHead>
                    <TableHead className="text-right">{t('pages.authAnalytics.geo.table.failed')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {dashboard.geo_top_countries.slice(0, 5).map((geo, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-medium">{geo.country}</TableCell>
                      <TableCell className="text-right">
                        {geo.count.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        {geo.failed > 0 ? (
                          <Badge className="bg-red-100 text-red-800 hover:bg-red-100">
                            {geo.failed}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-center text-muted-foreground py-4">{t('pages.authAnalytics.geo.empty')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Hourly Activity and Recent Failed */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Hourly Activity Pattern */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              {t('pages.authAnalytics.hourly.title')}
            </CardTitle>
            <CardDescription>{t('pages.authAnalytics.hourly.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-40">
              {dashboard.hourly_activity?.map((hour) => {
                const height = maxHourly > 0 ? (hour.count / maxHourly) * 100 : 0
                return (
                  <div
                    key={hour.hour}
                    className="flex-1 flex flex-col items-center"
                    title={t('pages.authAnalytics.hourly.tooltip', {
                      hour: hour.hour,
                      count: hour.count,
                    })}
                  >
                    <div
                      className="w-full bg-blue-500 rounded-t transition-all hover:bg-primary"
                      style={{
                        height: `${height}%`,
                        minHeight: hour.count > 0 ? '4px' : '0',
                      }}
                    />
                    {hour.hour % 3 === 0 && (
                      <span className="text-[10px] text-muted-foreground mt-1">
                        {hour.hour.toString().padStart(2, '0')}
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
            <p className="text-xs text-muted-foreground text-center mt-3">
              {t('pages.authAnalytics.hourly.axis')}
            </p>
          </CardContent>
        </Card>

        {/* Recent Failed Logins */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-500" />
              {t('pages.authAnalytics.failed.title')}
            </CardTitle>
            <CardDescription>{t('pages.authAnalytics.failed.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            {dashboard.recent_failed_logins?.length > 0 ? (
              <div className="space-y-2">
                {dashboard.recent_failed_logins.slice(0, 10).map((login, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-2 border rounded-md text-sm"
                  >
                    <div className="min-w-0">
                      <p className="font-medium truncate" title={login.email}>
                        {login.email}
                      </p>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span>{login.source_ip}</span>
                        <Badge variant="outline" className="text-xs">
                          {login.reason}
                        </Badge>
                      </div>
                    </div>
                    <span className="text-xs text-muted-foreground whitespace-nowrap ml-2">
                      {new Date(login.timestamp).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-center text-muted-foreground py-4">
                {t('pages.authAnalytics.failed.empty')}
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
