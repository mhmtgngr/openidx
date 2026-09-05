import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  ShieldCheck,
  KeyRound,
  ClipboardCheck,
  AlertTriangle,
  UserX,
  UserMinus,
  Target,
  TrendingUp,
  ShieldAlert,
  ExternalLink,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useNavigate } from 'react-router-dom'

/**
 * The weights the backend scorer applies, in the order the card lists
 * them. Keeping them here rather than in the catalogs means the number
 * lives in one place and a locale only ever writes the wording around it.
 */
const SCORE_WEIGHTS = [
  { key: 'mfa', weight: 25 },
  { key: 'password', weight: 20 },
  { key: 'reviews', weight: 15 },
  { key: 'policy', weight: 15 },
  { key: 'accounts', weight: 10 },
  { key: 'campaignCoverage', weight: 10 },
  { key: 'campaignProgress', weight: 5 },
] as const

interface CompliancePosture {
  mfa_adoption_rate: number
  password_compliance_rate: number
  open_reviews_count: number
  overdue_reviews_count: number
  dormant_accounts_count: number
  disabled_accounts_count: number
  active_campaigns_count: number
  campaign_completion_rate: number
  policy_violations_count: number
  overall_score: number
}

function ScoreGauge({ score }: { score: number }) {
  const { t } = useTranslation()
  const getColor = (s: number) => {
    if (s >= 80) return 'text-green-600'
    if (s >= 60) return 'text-yellow-600'
    if (s >= 40) return 'text-orange-600'
    return 'text-red-600'
  }

  const getBgColor = (s: number) => {
    if (s >= 80) return 'bg-green-100'
    if (s >= 60) return 'bg-yellow-100'
    if (s >= 40) return 'bg-orange-100'
    return 'bg-red-100'
  }

  // Returns the catalog key rather than a label, so the tier re-resolves
  // when the operator switches language.
  const getTierKey = (s: number) => {
    if (s >= 80) return 'excellent'
    if (s >= 60) return 'good'
    if (s >= 40) return 'needsImprovement'
    return 'critical'
  }

  return (
    <div className="flex flex-col items-center justify-center py-6">
      <div className={`relative w-40 h-40 rounded-full ${getBgColor(score)} flex items-center justify-center`}>
        <div className="bg-background rounded-full w-28 h-28 flex flex-col items-center justify-center shadow-inner">
          <span className={`text-4xl font-bold ${getColor(score)}`}>{score}</span>
          <span className="text-xs text-muted-foreground mt-1">/ 100</span>
        </div>
      </div>
      <Badge className={`mt-4 ${getBgColor(score)} ${getColor(score)} border-0`}>
        {t(`pages.complianceDashboard.tiers.${getTierKey(score)}`)}
      </Badge>
    </div>
  )
}

function MetricCard({
  title,
  value,
  icon: Icon,
  subtitle,
  color,
  action,
  onAction,
}: {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  subtitle?: string
  color: string
  action?: string
  onAction?: () => void
}) {
  const bgColor = {
    green: 'bg-green-100',
    yellow: 'bg-yellow-100',
    orange: 'bg-orange-100',
    red: 'bg-red-100',
    blue: 'bg-blue-100',
    purple: 'bg-purple-100',
    gray: 'bg-muted',
  }[color] || 'bg-muted'

  const iconColor = {
    green: 'text-green-700',
    yellow: 'text-yellow-700',
    orange: 'text-orange-700',
    red: 'text-red-700',
    blue: 'text-blue-700',
    purple: 'text-purple-700',
    gray: 'text-foreground',
  }[color] || 'text-foreground'

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={`h-10 w-10 rounded-lg ${bgColor} flex items-center justify-center`}>
              <Icon className={`h-5 w-5 ${iconColor}`} />
            </div>
            <div>
              <p className="text-2xl font-bold">{typeof value === 'number' ? (Number.isInteger(value) ? value : value.toFixed(1) + '%') : value}</p>
              <p className="text-sm text-muted-foreground">{title}</p>
              {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
            </div>
          </div>
          {action && onAction && (
            <Button variant="ghost" size="sm" onClick={onAction} className="text-xs">
              {action} <ExternalLink className="h-3 w-3 ml-1" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function ComplianceDashboardPage() {
  const navigate = useNavigate()
  const { t } = useTranslation()

  const { data: posture, isLoading, isError, error } = useQuery({
    queryKey: ['compliance-posture'],
    queryFn: async () => {
      const raw = await api.get<Partial<CompliancePosture>>('/api/v1/compliance-posture')
      // Normalize every field to a number so rendering (comparisons,
      // toFixed) never sees null/undefined from an incomplete backend
      // response and blanks the page via the error boundary.
      const r = raw ?? {}
      const normalized: CompliancePosture = {
        mfa_adoption_rate: r.mfa_adoption_rate ?? 0,
        password_compliance_rate: r.password_compliance_rate ?? 0,
        open_reviews_count: r.open_reviews_count ?? 0,
        overdue_reviews_count: r.overdue_reviews_count ?? 0,
        dormant_accounts_count: r.dormant_accounts_count ?? 0,
        disabled_accounts_count: r.disabled_accounts_count ?? 0,
        active_campaigns_count: r.active_campaigns_count ?? 0,
        campaign_completion_rate: r.campaign_completion_rate ?? 0,
        policy_violations_count: r.policy_violations_count ?? 0,
        overall_score: r.overall_score ?? 0,
      }
      return normalized
    },
    refetchInterval: 60000,
  })

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-24">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-muted-foreground">
          {t('pages.complianceDashboard.loading')}
        </p>
      </div>
    )
  }

  // Surface load/permission errors instead of falling back to an all-zeros
  // posture, which would render a fully-populated dashboard showing 0% for a
  // 403 and read as "perfectly compliant".
  if (isError) {
    return <QueryError error={error} resource={t('pages.complianceDashboard.resource')} />
  }

  const p = posture || {
    mfa_adoption_rate: 0,
    password_compliance_rate: 0,
    open_reviews_count: 0,
    overdue_reviews_count: 0,
    dormant_accounts_count: 0,
    disabled_accounts_count: 0,
    active_campaigns_count: 0,
    campaign_completion_rate: 0,
    policy_violations_count: 0,
    overall_score: 0,
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          {t('nav.items.compliancePosture')}
        </h1>
        <p className="text-muted-foreground">{t('pages.complianceDashboard.subtitle')}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Score Gauge */}
        <Card className="lg:row-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              {t('pages.complianceDashboard.overallScore')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScoreGauge score={p.overall_score} />
            <div className="mt-4 space-y-2 text-sm text-muted-foreground">
              <p>{t('pages.complianceDashboard.weightsIntro')}</p>
              <ul className="space-y-1 ml-4 list-disc">
                {SCORE_WEIGHTS.map((w) => (
                  <li key={w.key}>
                    {t('pages.complianceDashboard.weightLine', {
                      label: t(`pages.complianceDashboard.weights.${w.key}`),
                      weight: w.weight,
                    })}
                  </li>
                ))}
              </ul>
            </div>
          </CardContent>
        </Card>

        {/* Authentication Metrics */}
        <MetricCard
          title={t('pages.complianceDashboard.cards.mfaAdoption')}
          value={p.mfa_adoption_rate}
          icon={KeyRound}
          subtitle={t('pages.complianceDashboard.cards.mfaAdoptionSub')}
          color={p.mfa_adoption_rate >= 80 ? 'green' : p.mfa_adoption_rate >= 50 ? 'yellow' : 'red'}
          action={t('pages.complianceDashboard.actions.viewUsers')}
          onAction={() => navigate('/users')}
        />

        <MetricCard
          title={t('pages.complianceDashboard.cards.passwordCompliance')}
          value={p.password_compliance_rate}
          icon={ShieldCheck}
          subtitle={t('pages.complianceDashboard.cards.passwordComplianceSub')}
          color={p.password_compliance_rate >= 80 ? 'green' : p.password_compliance_rate >= 50 ? 'yellow' : 'red'}
        />

        {/* Review Metrics */}
        <MetricCard
          title={t('pages.complianceDashboard.cards.openReviews')}
          value={p.open_reviews_count}
          icon={ClipboardCheck}
          subtitle={t('pages.complianceDashboard.cards.openReviewsSub')}
          color={p.open_reviews_count === 0 ? 'green' : 'blue'}
          action={t('pages.complianceDashboard.actions.viewReviews')}
          onAction={() => navigate('/access-reviews')}
        />

        <MetricCard
          title={t('pages.complianceDashboard.cards.overdueReviews')}
          value={p.overdue_reviews_count}
          icon={AlertTriangle}
          subtitle={t('pages.complianceDashboard.cards.overdueReviewsSub')}
          color={p.overdue_reviews_count === 0 ? 'green' : 'red'}
          action={t('pages.complianceDashboard.actions.viewReviews')}
          onAction={() => navigate('/access-reviews')}
        />
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title={t('pages.complianceDashboard.cards.dormantAccounts')}
          value={p.dormant_accounts_count}
          icon={UserX}
          subtitle={t('pages.complianceDashboard.cards.dormantAccountsSub')}
          color={p.dormant_accounts_count === 0 ? 'green' : p.dormant_accounts_count < 5 ? 'yellow' : 'orange'}
          action={t('pages.complianceDashboard.actions.viewUsers')}
          onAction={() => navigate('/users')}
        />

        <MetricCard
          title={t('pages.complianceDashboard.cards.disabledAccounts')}
          value={p.disabled_accounts_count}
          icon={UserMinus}
          subtitle={t('pages.complianceDashboard.cards.disabledAccountsSub')}
          color="gray"
        />

        <MetricCard
          title={t('pages.complianceDashboard.cards.activeCampaigns')}
          value={p.active_campaigns_count}
          icon={Target}
          subtitle={t('pages.complianceDashboard.cards.activeCampaignsSub')}
          color={p.active_campaigns_count > 0 ? 'purple' : 'gray'}
          action={t('pages.complianceDashboard.actions.viewCampaigns')}
          onAction={() => navigate('/certification-campaigns')}
        />

        <MetricCard
          title={t('pages.complianceDashboard.cards.campaignCompletion')}
          value={p.campaign_completion_rate}
          icon={TrendingUp}
          subtitle={t('pages.complianceDashboard.cards.campaignCompletionSub')}
          color={p.campaign_completion_rate >= 80 ? 'green' : p.campaign_completion_rate >= 50 ? 'yellow' : 'orange'}
        />
      </div>

      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-3">
            <div className={`h-10 w-10 rounded-lg ${p.policy_violations_count === 0 ? 'bg-green-100' : 'bg-red-100'} flex items-center justify-center`}>
              <ShieldAlert className={`h-5 w-5 ${p.policy_violations_count === 0 ? 'text-green-700' : 'text-red-700'}`} />
            </div>
            <div className="flex-1">
              <p className="text-2xl font-bold">{p.policy_violations_count}</p>
              <p className="text-sm text-muted-foreground">
                {t('pages.complianceDashboard.violations')}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate('/policies')}>
              {t('pages.complianceDashboard.actions.viewPolicies')}{' '}
              <ExternalLink className="h-3 w-3 ml-1" />
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
