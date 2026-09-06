import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Users, UserCheck, UserPlus, Layers, Shield, Key, Fingerprint,
  Smartphone, Link2, Globe, ArrowUpRight,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface UsageData {
  dau: number
  wau: number
  mau: number
  total_users: number
  total_groups: number
  total_apps: number
  new_registrations: Array<{
    date: string
    count: number
  }>
}

interface FeatureAdoption {
  features: Array<{
    name: string
    category: string
    total_users: number
    adopted_users: number
    adoption_percentage: number
  }>
}

const featureIcons: Record<string, React.ReactNode> = {
  totp: <Key className="h-4 w-4" />,
  webauthn: <Fingerprint className="h-4 w-4" />,
  sms: <Smartphone className="h-4 w-4" />,
  passkey: <Fingerprint className="h-4 w-4" />,
  magic_link: <Link2 className="h-4 w-4" />,
  api_keys: <Key className="h-4 w-4" />,
  social_login: <Globe className="h-4 w-4" />,
}

function featureColor(percentage: number): string {
  if (percentage >= 75) return 'bg-green-500'
  if (percentage >= 50) return 'bg-blue-500'
  if (percentage >= 25) return 'bg-yellow-500'
  return 'bg-gray-400'
}

export function UsageAnalyticsPage() {
  const { t } = useTranslation()
  const {
    data: usageData,
    isLoading: usageLoading,
    isError: usageError,
    error: usageErrorObj,
  } = useQuery<{ usage: UsageData }>({
    queryKey: ['usage-analytics'],
    // Normalize: the analytics endpoints can omit numeric fields per row (a Go
    // zero/absent value serializes to null or is dropped), and the cards call
    // .toLocaleString()/.toFixed() on them, which crashed the page with "Cannot
    // read properties of undefined (reading 'toLocaleString')". Default every
    // rendered field so the typed shape holds at runtime, not just in TS.
    queryFn: async () => {
      const res = await api.get<{ usage: UsageData }>('/api/v1/analytics/usage')
      const u = res.usage
      return {
        usage: {
          ...u,
          new_registrations: (u?.new_registrations ?? []).map((r) => ({
            date: r.date ?? '',
            count: r.count ?? 0,
          })),
        },
      }
    },
  })

  const { data: adoptionData, isLoading: adoptionLoading } = useQuery<{ adoption: FeatureAdoption }>({
    queryKey: ['feature-adoption'],
    queryFn: async () => {
      const res = await api.get<{ adoption: FeatureAdoption }>(
        '/api/v1/analytics/feature-adoption'
      )
      return {
        adoption: {
          features: (res.adoption?.features ?? []).map((f) => ({
            name: f.name ?? '',
            category: f.category ?? '',
            total_users: f.total_users ?? 0,
            adopted_users: f.adopted_users ?? 0,
            adoption_percentage: f.adoption_percentage ?? 0,
          })),
        },
      }
    },
  })

  const usage = usageData?.usage
  const adoption = adoptionData?.adoption

  const isLoading = usageLoading || adoptionLoading

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  // The primary usage query drives the whole dashboard; a 401/403 here must not
  // fall through to an all-zeros "no usage" view.
  if (usageError) {
    return <QueryError error={usageErrorObj} resource={t('pages.usageAnalytics.resource')} />
  }

  const maxRegistration = Math.max(
    ...(usage?.new_registrations?.map((r) => r.count) || [1])
  )
  // Hoisted because the summary line needs the raw number for the plural
  // rule and the locale-formatted string for the sentence's own slot.
  const registrationTotal = (usage?.new_registrations ?? []).reduce(
    (sum, d) => sum + d.count,
    0,
  )

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">
          {t('nav.items.usageAnalytics')}
        </h1>
        <p className="text-muted-foreground">{t('pages.usageAnalytics.subtitle')}</p>
      </div>

      {/* Active User Stats */}
      <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.dau')}</CardTitle>
            <UserCheck className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.dau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.dauHint')}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.wau')}</CardTitle>
            <UserCheck className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.wau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.wauHint')}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.mau')}</CardTitle>
            <UserCheck className="h-4 w-4 text-purple-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.mau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.mauHint')}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.totalUsers')}</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_users ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.totalUsersHint')}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.totalGroups')}</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_groups ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.totalGroupsHint')}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('pages.usageAnalytics.cards.totalApps')}</CardTitle>
            <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_apps ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages.usageAnalytics.cards.totalAppsHint')}</p>
          </CardContent>
        </Card>
      </div>

      {/* Feature Adoption */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            {t('pages.usageAnalytics.adoption.title')}
          </CardTitle>
          <CardDescription>{t('pages.usageAnalytics.adoption.desc')}</CardDescription>
        </CardHeader>
        <CardContent>
          {adoption?.features && adoption.features.length > 0 ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {adoption.features.map((feature) => (
                <div
                  key={feature.name}
                  className="p-4 border rounded-lg space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {featureIcons[feature.name.toLowerCase()] || (
                        <Shield className="h-4 w-4" />
                      )}
                      <span className="font-medium">
                        {t(`pages.usageAnalytics.features.${feature.name.toLowerCase()}`, {
                          defaultValue: feature.name.replace(/_/g, ' '),
                        })}
                      </span>
                    </div>
                    {/* The category is the server's own grouping string. */}
                    <Badge variant="outline" className="text-xs">
                      {feature.category}
                    </Badge>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">
                        {t('pages.usageAnalytics.adoption.ofUsers', {
                          adopted: feature.adopted_users.toLocaleString(),
                          total: feature.total_users.toLocaleString(),
                        })}
                      </span>
                      <span className="font-medium">
                        {feature.adoption_percentage.toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${featureColor(feature.adoption_percentage)}`}
                        style={{ width: `${feature.adoption_percentage}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-muted-foreground py-6">
              {t('pages.usageAnalytics.adoption.empty')}
            </p>
          )}
        </CardContent>
      </Card>

      {/* New User Registrations Trend.
        The API Usage card that shared this row read /analytics/api-usage,
        which read api_usage_metrics -- a table nothing has ever written a row
        to, with three of the column names it asked for absent from the schema
        besides. It reported 0 requests, 0% errors and 0 ms latency on every
        install. Endpoint volume, latency and status codes are measured by the
        Prometheus middleware every service mounts and are on /metrics for the
        Prometheus and Grafana this repo ships; migration v176 drops the table
        and the endpoint goes with it. */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserPlus className="h-5 w-5" />
            {t('pages.usageAnalytics.registrations.title')}
          </CardTitle>
          <CardDescription>{t('pages.usageAnalytics.registrations.desc')}</CardDescription>
        </CardHeader>
        <CardContent>
          {usage?.new_registrations && usage.new_registrations.length > 0 ? (
            <>
              <div className="flex items-end gap-1 h-40">
                {usage.new_registrations.map((day) => {
                  const height =
                    maxRegistration > 0
                      ? (day.count / maxRegistration) * 100
                      : 0
                  return (
                    <div
                      key={day.date}
                      className="flex-1 flex flex-col items-center"
                      title={t('pages.usageAnalytics.registrations.dayTooltip', {
                        date: day.date,
                        count: day.count,
                      })}
                    >
                      <div
                        className="w-full bg-emerald-500 rounded-t transition-all hover:bg-emerald-600"
                        style={{
                          height: `${height}%`,
                          minHeight: day.count > 0 ? '4px' : '0',
                        }}
                      />
                    </div>
                  )
                })}
              </div>
              <div className="flex justify-between text-xs text-muted-foreground mt-2">
                <span>
                  {usage.new_registrations[0]?.date.slice(5)}
                </span>
                <span>
                  {usage.new_registrations[usage.new_registrations.length - 1]?.date.slice(5)}
                </span>
              </div>
              <p className="text-xs text-muted-foreground text-center mt-1">
                {t('pages.usageAnalytics.registrations.total', {
                  count: registrationTotal,
                  formatted: registrationTotal.toLocaleString(),
                })}
              </p>
            </>
          ) : (
            <p className="text-center text-muted-foreground py-6">
              {t('pages.usageAnalytics.registrations.empty')}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
