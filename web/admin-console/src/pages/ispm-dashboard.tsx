import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'
import { AlertTriangle, Eye, Wrench, TrendingUp, RefreshCw, X, CheckCircle } from 'lucide-react'

interface PostureScore {
  overall_score: number
  category_scores: Record<string, number>
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  snapshot_date: string
  details: Record<string, number>
}

interface PostureFinding {
  id: string
  check_type: string
  severity: string
  category: string
  title: string
  description: string
  affected_entity_type: string
  affected_entity_id: string
  affected_entity_name: string
  status: string
  remediation_action: string
  created_at: string
}

interface PostureRule {
  id: string
  name: string
  description: string
  category: string
  check_type: string
  enabled: boolean
  severity: string
  thresholds: Record<string, number>
  /**
   * Whether the scan engine has code for this check_type. A rule row can
   * exist for a check that never runs (the pre-v138 seed shipped six), and
   * rendering that as Enabled/Disabled would put a live-looking toggle on
   * something the scan ignores.
   */
  implemented: boolean
}

/**
 * The severities the scanner assigns, worst first. The summary card labels
 * them in title case and a finding's own badge in lowercase; both shapes
 * resolve off this one list, so they cannot come to mean different sets.
 */
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

const categoryColors: Record<string, string> = {
  authentication: 'text-primary',
  authorization: 'text-purple-600',
  accounts: 'text-green-600',
  compliance: 'text-orange-600',
}

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-green-600' : score >= 60 ? 'text-yellow-600' : 'text-red-600'
  const bgColor = score >= 80 ? 'bg-green-100' : score >= 60 ? 'bg-yellow-100' : 'bg-red-100'
  return (
    <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full ${bgColor}`}>
      <span className={`text-3xl font-bold ${color}`}>{score}</span>
    </div>
  )
}

function CategoryScore({ name, score }: { name: string; score: number }) {
  const { t } = useTranslation()
  const color = score >= 80 ? 'bg-green-500' : score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm">
        <span className="capitalize">
          {t(`pages.ispm.categories.${name}`, { defaultValue: name })}
        </span>
        <span className="font-medium">{score}%</span>
      </div>
      <div className="h-2 bg-muted rounded-full">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

export function ISPMDashboardPage() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()

  const { data: score, isLoading, isError, error } = useQuery<PostureScore>({
    queryKey: ['ispm-score'],
    queryFn: () => api.get<PostureScore>('/api/v1/ispm/score'),
  })

  const { data: findingsData } = useQuery({
    queryKey: ['ispm-findings'],
    queryFn: () => api.get<{ data: PostureFinding[] }>('/api/v1/ispm/findings'),
  })

  const { data: rulesData } = useQuery({
    queryKey: ['ispm-rules'],
    queryFn: () => api.get<{ data: PostureRule[] }>('/api/v1/ispm/rules'),
  })

  const { data: trendsData } = useQuery({
    queryKey: ['ispm-trends'],
    queryFn: () => api.get<{ data: Array<{ date: string; overall_score: number; total_findings: number }> }>('/api/v1/ispm/trends'),
  })

  const scanMutation = useMutation({
    mutationFn: () => api.post('/api/v1/ispm/scan', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
    },
  })

  const dismissMutation = useMutation({
    // The reason is stored on the finding for whoever reviews it later, so
    // it is sent as written rather than in the operator's current language.
    mutationFn: (id: string) => api.post(`/api/v1/ispm/findings/${id}/dismiss`, { reason: 'False positive' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
    },
  })

  const remediateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ispm/findings/${id}/remediate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.ispm.resource')} />
  }

  const findings = findingsData?.data || []
  const rules = rulesData?.data || []
  const trends = trendsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('pages.ispm.title')}</h1>
          <p className="text-muted-foreground">{t('pages.ispm.subtitle')}</p>
        </div>
        <Button onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
          <RefreshCw className={`h-4 w-4 mr-2 ${scanMutation.isPending ? 'animate-spin' : ''}`} />
          {scanMutation.isPending ? t('pages.ispm.scanning') : t('pages.ispm.scan')}
        </Button>
      </div>

      <RelatedLinks links={[{ to: '/zero-trust', label: t('nav.items.zeroTrustAccess') }]} />

      {/* Score Overview */}
      {score && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="md:col-span-1">
            <CardContent className="pt-6 text-center">
              <ScoreGauge score={score.overall_score} />
              <p className="mt-3 font-medium">{t('pages.ispm.overallScore')}</p>
              <p className="text-sm text-muted-foreground">{score.snapshot_date}</p>
            </CardContent>
          </Card>
          <Card className="md:col-span-1">
            <CardHeader>
              <CardTitle className="text-base">{t('pages.ispm.categoryBreakdown')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {Object.entries(score.category_scores).map(([cat, val]) => (
                <CategoryScore key={cat} name={cat} score={val} />
              ))}
            </CardContent>
          </Card>
          <Card className="md:col-span-1">
            <CardHeader>
              <CardTitle className="text-base">{t('pages.ispm.openFindings')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {SEVERITIES.map((s) => (
                  <div key={s} className="flex justify-between items-center">
                    <Badge className={severityColors[s]}>
                      {t(`pages.ispm.severityLabels.${s}`)}
                    </Badge>
                    <span className="font-bold text-lg">{score[`${s}_findings`]}</span>
                  </div>
                ))}
                <div className="border-t pt-2 flex justify-between items-center">
                  <span className="font-medium">{t('pages.ispm.total')}</span>
                  <span className="font-bold text-xl">{score.total_findings}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Trend Chart */}
      {trends.length > 1 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              {t('pages.ispm.trend')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {trends.slice(-30).reverse().map((point, i) => {
                const color = point.overall_score >= 80 ? 'bg-green-500' : point.overall_score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                return (
                  <div key={i} className="flex-1 flex flex-col items-center" title={`${point.date}: ${point.overall_score}`}>
                    <div className={`w-full rounded-t ${color}`} style={{ height: `${point.overall_score}%` }} />
                  </div>
                )
              })}
            </div>
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>{trends.length > 0 ? trends[trends.length - 1]?.date : ''}</span>
              <span>{trends.length > 0 ? trends[0]?.date : ''}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5" />
            {t('pages.ispm.findings.title', { n: findings.length })}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="divide-y">
            {findings.map((f) => (
              <div key={f.id} className="py-3 flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className={severityColors[f.severity] || ''}>
                      {t(`pages.ispm.severities.${f.severity}`, { defaultValue: f.severity })}
                    </Badge>
                    <Badge variant="outline" className={categoryColors[f.category] || ''}>
                      {t(`pages.ispm.categories.${f.category}`, { defaultValue: f.category })}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{new Date(f.created_at).toLocaleDateString()}</span>
                  </div>
                  {/* Title, description and entity name are the scanner's own. */}
                  <p className="font-medium text-sm">{f.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{f.description}</p>
                  {f.affected_entity_name && (
                    <p className="text-xs mt-1">
                      <Trans
                        i18nKey="pages.ispm.findings.affected"
                        values={{
                          name: f.affected_entity_name,
                          type: f.affected_entity_type,
                        }}
                        components={[<span key="0" className="font-medium" />]}
                      />
                    </p>
                  )}
                </div>
                <div className="flex gap-1 ml-4">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => remediateMutation.mutate(f.id)}
                    title={t('pages.ispm.findings.remediate')}
                  >
                    <Wrench className="h-3 w-3" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => dismissMutation.mutate(f.id)}
                    title={t('pages.ispm.findings.dismiss')}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
            {findings.length === 0 && (
              <div className="py-8 text-center text-muted-foreground">
                <CheckCircle className="h-8 w-8 mx-auto mb-2 text-green-500" />
                <p>{t('pages.ispm.findings.empty')}</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Rules Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            {t('pages.ispm.rules.title', { n: rules.length })}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="divide-y">
            {rules.map((r) => (
              <div key={r.id} className="py-3 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-sm">{r.name}</p>
                    <Badge className={severityColors[r.severity] || ''} variant="outline">
                      {t(`pages.ispm.severities.${r.severity}`, { defaultValue: r.severity })}
                    </Badge>
                    <Badge variant="outline" className={categoryColors[r.category] || ''}>
                      {t(`pages.ispm.categories.${r.category}`, { defaultValue: r.category })}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{r.description}</p>
                </div>
                {r.implemented ? (
                  <Badge variant={r.enabled ? 'default' : 'secondary'}>
                    {r.enabled ? t('pages.ispm.rules.enabled') : t('pages.ispm.rules.disabled')}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground">
                    {t('pages.ispm.rules.notImplemented')}
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
