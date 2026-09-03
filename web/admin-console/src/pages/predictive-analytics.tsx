import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { UserLink } from '../components/user-link'
import { TrendingUp, TrendingDown, Minus, Users, Activity, Shield, Server, UserX, BarChart3 } from 'lucide-react'

interface DailyMetric {
  date: string
  value: number
}

interface DailyFloat {
  date: string
  value: number
}

interface ChurnRiskUser {
  user_id: string
  username: string
  last_login: string
  login_freq_change_pct: number
  risk_score: number
}

interface PredictionSummary {
  login_forecast: {
    historical: DailyMetric[]
    predicted: DailyMetric[]
    trend: string
    avg_daily: number
  }
  risk_forecast: {
    historical: DailyFloat[]
    predicted: DailyFloat[]
    trend: string
    current_avg: number
  }
  capacity_forecast: {
    peak_concurrent_sessions: number
    avg_concurrent_sessions: number
    peak_hour: number
    peak_day_of_week: string
    session_growth_rate_pct: number
    recommended_capacity: number
    license_utilization_pct: number
  }
  account_growth: {
    current_users: number
    growth_rate_monthly_pct: number
    projected_30d: number
    projected_90d: number
    historical: DailyMetric[]
  }
  churn_risk_users: ChurnRiskUser[]
}

const trendIcons: Record<string, React.ReactNode> = {
  increasing: <TrendingUp className="h-4 w-4 text-green-600" />,
  decreasing: <TrendingDown className="h-4 w-4 text-red-600" />,
  stable: <Minus className="h-4 w-4 text-muted-foreground" />,
  insufficient_data: <Minus className="h-4 w-4 text-muted-foreground" />,
}

const trendColors: Record<string, string> = {
  increasing: 'text-green-600',
  decreasing: 'text-red-600',
  stable: 'text-muted-foreground',
  insufficient_data: 'text-muted-foreground',
}

function MiniChart({ data, color = 'bg-blue-500', height = 64 }: { data: { value: number }[]; color?: string; height?: number }) {
  if (!data || data.length === 0) return null
  const maxVal = Math.max(...data.map((d) => d.value), 1)
  return (
    <div className="flex items-end gap-px" style={{ height }}>
      {data.map((d, i) => (
        <div key={i} className={`flex-1 rounded-t ${color}`} style={{ height: `${(d.value / maxVal) * 100}%`, minHeight: 2 }} />
      ))}
    </div>
  )
}

function ForecastChart({ historical, predicted }: { historical: DailyMetric[]; predicted: DailyMetric[] | null }) {
  const { t } = useTranslation()
  const all = [...(historical || []), ...(predicted || [])]
  if (all.length === 0) return null
  const maxVal = Math.max(...all.map((d) => d.value), 1)
  const histLen = historical?.length || 0
  return (
    <div className="flex items-end gap-px h-24">
      {all.map((d, i) => {
        const isPredicted = i >= histLen
        const color = isPredicted ? 'bg-blue-300 border-2 border-dashed border-blue-400' : 'bg-blue-500'
        return (
          <div
            key={i}
            className="flex-1 flex flex-col items-center"
            title={
              t('pages.predictiveAnalytics.chart.pointTooltip', {
                date: d.date,
                value: d.value,
              }) +
              (isPredicted ? t('pages.predictiveAnalytics.chart.predictedSuffix') : '')
            }
          >
            <div className={`w-full rounded-t ${color}`} style={{ height: `${(d.value / maxVal) * 100}%`, minHeight: 2 }} />
          </div>
        )
      })}
    </div>
  )
}

export function PredictiveAnalyticsPage() {
  const { t } = useTranslation()
  const { data: predictions, isLoading, isError, error } = useQuery<PredictionSummary>({
    queryKey: ['predictions-summary'],
    queryFn: async () => {
      const res = await api.get<PredictionSummary>('/api/v1/analytics/predictions')
      const normDaily = (arr: DailyMetric[] | null | undefined): DailyMetric[] =>
        (arr ?? []).map((d) => ({ date: d?.date ?? '', value: d?.value ?? 0 }))
      return {
        login_forecast: {
          historical: normDaily(res.login_forecast?.historical),
          predicted: normDaily(res.login_forecast?.predicted),
          trend: res.login_forecast?.trend ?? '',
          avg_daily: res.login_forecast?.avg_daily ?? 0,
        },
        risk_forecast: {
          historical: normDaily(res.risk_forecast?.historical),
          predicted: normDaily(res.risk_forecast?.predicted),
          trend: res.risk_forecast?.trend ?? '',
          current_avg: res.risk_forecast?.current_avg ?? 0,
        },
        capacity_forecast: {
          peak_concurrent_sessions: res.capacity_forecast?.peak_concurrent_sessions ?? 0,
          avg_concurrent_sessions: res.capacity_forecast?.avg_concurrent_sessions ?? 0,
          peak_hour: res.capacity_forecast?.peak_hour ?? 0,
          peak_day_of_week: res.capacity_forecast?.peak_day_of_week ?? '',
          session_growth_rate_pct: res.capacity_forecast?.session_growth_rate_pct ?? 0,
          recommended_capacity: res.capacity_forecast?.recommended_capacity ?? 0,
          license_utilization_pct: res.capacity_forecast?.license_utilization_pct ?? 0,
        },
        account_growth: {
          current_users: res.account_growth?.current_users ?? 0,
          growth_rate_monthly_pct: res.account_growth?.growth_rate_monthly_pct ?? 0,
          projected_30d: res.account_growth?.projected_30d ?? 0,
          projected_90d: res.account_growth?.projected_90d ?? 0,
          historical: normDaily(res.account_growth?.historical),
        },
        churn_risk_users: (res.churn_risk_users ?? []).map((u) => ({
          user_id: u?.user_id ?? '',
          username: u?.username ?? '',
          last_login: u?.last_login ?? '',
          login_freq_change_pct: u?.login_freq_change_pct ?? 0,
          risk_score: u?.risk_score ?? 0,
        })),
      }
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.predictiveAnalytics.resource')} />
  }

  if (!predictions) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        {t('pages.predictiveAnalytics.empty')}
      </div>
    )
  }

  const lf = predictions.login_forecast
  const rf = predictions.risk_forecast
  const cf = predictions.capacity_forecast
  const ag = predictions.account_growth
  const churn = predictions.churn_risk_users || []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('pages.predictiveAnalytics.title')}</h1>
        <p className="text-muted-foreground">{t('pages.predictiveAnalytics.subtitle')}</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Activity className="h-5 w-5 text-primary" />
              {lf?.trend && trendIcons[lf.trend]}
            </div>
            <p className="text-2xl font-bold">{lf?.avg_daily?.toFixed(0) || 0}</p>
            <p className="text-xs text-muted-foreground">
              {t('pages.predictiveAnalytics.cards.avgDailyLogins')}
            </p>
            <p className={`text-xs mt-1 ${trendColors[lf?.trend || ''] || ''}`}>
              {lf?.trend
                ? t(`pages.predictiveAnalytics.trends.${lf.trend}`, {
                    defaultValue: lf.trend.replace(/_/g, ' '),
                  })
                : t('pages.predictiveAnalytics.notAvailable')}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Shield className="h-5 w-5 text-orange-600" />
              {rf?.trend && trendIcons[rf.trend]}
            </div>
            <p className="text-2xl font-bold">{rf?.current_avg?.toFixed(1) || 0}</p>
            <p className="text-xs text-muted-foreground">
              {t('pages.predictiveAnalytics.cards.avgRiskScore')}
            </p>
            <p className={`text-xs mt-1 ${trendColors[rf?.trend || ''] || ''}`}>
              {rf?.trend
                ? t(`pages.predictiveAnalytics.trends.${rf.trend}`, {
                    defaultValue: rf.trend.replace(/_/g, ' '),
                  })
                : t('pages.predictiveAnalytics.notAvailable')}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Users className="h-5 w-5 text-green-600" />
              <Badge variant="outline" className="text-xs">
                {t('pages.predictiveAnalytics.cards.monthlyGrowth', {
                  n: ag?.growth_rate_monthly_pct?.toFixed(1) || 0,
                })}
              </Badge>
            </div>
            <p className="text-2xl font-bold">{ag?.current_users?.toLocaleString() || 0}</p>
            <p className="text-xs text-muted-foreground">
              {t('pages.predictiveAnalytics.cards.activeUsers')}
            </p>
            <p className="text-xs text-green-600 mt-1">
              {t('pages.predictiveAnalytics.cards.projected30d', {
                n: ag?.projected_30d?.toLocaleString(),
              })}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-2">
              <Server className="h-5 w-5 text-purple-600" />
            </div>
            <p className="text-2xl font-bold">{cf?.peak_concurrent_sessions || 0}</p>
            <p className="text-xs text-muted-foreground">
              {t('pages.predictiveAnalytics.cards.peakSessions')}
            </p>
            <p className="text-xs mt-1">
              {t('pages.predictiveAnalytics.cards.capacityHint', {
                n: cf?.recommended_capacity || 0,
              })}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Login Forecast */}
      {lf && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><BarChart3 className="h-5 w-5" />
            {t('pages.predictiveAnalytics.loginForecast.title')}
          </CardTitle></CardHeader>
          <CardContent>
            <ForecastChart historical={lf.historical} predicted={lf.predicted} />
            <div className="flex justify-between text-xs text-muted-foreground mt-2">
              <span>
                {t('pages.predictiveAnalytics.loginForecast.historical', {
                  count: lf.historical?.length || 0,
                })}
              </span>
              <span className="border-l-2 border-dashed border-blue-400 pl-2">
                {t('pages.predictiveAnalytics.loginForecast.predicted', {
                  count: lf.predicted?.length || 0,
                })}
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Risk Forecast */}
      {rf && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5" />
            {t('pages.predictiveAnalytics.riskForecast.title')}
          </CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-end gap-px h-24">
              {[...(rf.historical || []), ...(rf.predicted || [])].map((d, i) => {
                const isPredicted = i >= (rf.historical?.length || 0)
                const val = d.value
                const color = val > 50 ? (isPredicted ? 'bg-red-300' : 'bg-red-500') : val > 25 ? (isPredicted ? 'bg-yellow-300' : 'bg-yellow-500') : (isPredicted ? 'bg-green-300' : 'bg-green-500')
                return (
                  <div
                    key={i}
                    className="flex-1"
                    title={
                      t('pages.predictiveAnalytics.chart.pointTooltip', {
                        date: d.date,
                        value: val.toFixed(1),
                      }) +
                      (isPredicted
                        ? t('pages.predictiveAnalytics.chart.predictedSuffix')
                        : '')
                    }
                  >
                    <div className={`w-full rounded-t ${color}`} style={{ height: `${Math.min(val, 100)}%`, minHeight: 2 }} />
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Capacity Planning */}
        {cf && (
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2"><Server className="h-5 w-5" />
              {t('pages.predictiveAnalytics.capacity.title')}
            </CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between text-sm">
                <span>{t('pages.predictiveAnalytics.capacity.peakConcurrent')}</span>
                <span className="font-medium">{cf.peak_concurrent_sessions}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span>{t('pages.predictiveAnalytics.capacity.avgConcurrent')}</span>
                <span className="font-medium">{cf.avg_concurrent_sessions}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span>{t('pages.predictiveAnalytics.capacity.peakHour')}</span>
                <span className="font-medium">
                  {t('pages.predictiveAnalytics.capacity.peakHourValue', {
                    hour: cf.peak_hour,
                  })}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span>{t('pages.predictiveAnalytics.capacity.peakDay')}</span>
                {/* The weekday name is composed by the forecaster. */}
                <span className="font-medium">{cf.peak_day_of_week}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span>{t('pages.predictiveAnalytics.capacity.licenseUtilization')}</span>
                <span className="font-medium">{cf.license_utilization_pct?.toFixed(1)}%</span>
              </div>
              <div className="flex justify-between text-sm border-t pt-2">
                <span className="font-medium">
                  {t('pages.predictiveAnalytics.capacity.recommended')}
                </span>
                <Badge>
                  {t('pages.predictiveAnalytics.capacity.recommendedValue', {
                    count: cf.recommended_capacity,
                  })}
                </Badge>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Churn Risk */}
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><UserX className="h-5 w-5" />
            {t('pages.predictiveAnalytics.churn.title', { n: churn.length })}
          </CardTitle></CardHeader>
          <CardContent>
            {churn.length > 0 ? (
              <div className="divide-y">
                {churn.map((u) => (
                  <div key={u.user_id} className="py-2 flex items-center justify-between">
                    <UserLink
                      userId={u.user_id}
                      name={u.username}
                      subtitle={t('pages.predictiveAnalytics.churn.lastLogin', {
                        date: u.last_login,
                      })}
                      className="text-sm"
                    />
                    <div className="text-right">
                      <Badge variant={u.risk_score > 0.7 ? 'destructive' : 'secondary'}>
                        {t('pages.predictiveAnalytics.churn.risk', {
                          pct: (u.risk_score * 100).toFixed(0),
                        })}
                      </Badge>
                      <p className="text-xs text-red-600 mt-0.5">
                        {t('pages.predictiveAnalytics.churn.loginDrop', {
                          pct: u.login_freq_change_pct?.toFixed(0),
                        })}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-center text-muted-foreground py-4">
                {t('pages.predictiveAnalytics.churn.empty')}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Account Growth */}
      {ag && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Users className="h-5 w-5" />
            {t('pages.predictiveAnalytics.growth.title')}
          </CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <p className="text-2xl font-bold">{ag.current_users.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">
                  {t('pages.predictiveAnalytics.growth.current')}
                </p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-primary">{ag.projected_30d.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">
                  {t('pages.predictiveAnalytics.growth.projected30')}
                </p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-purple-600">{ag.projected_90d.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">
                  {t('pages.predictiveAnalytics.growth.projected90')}
                </p>
              </div>
            </div>
            {ag.historical?.length > 0 && <MiniChart data={ag.historical} color="bg-green-500" height={48} />}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
