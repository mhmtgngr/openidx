import type { ReactNode } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Briefcase, CalendarClock, Globe, GitPullRequest, Monitor, UserCircle } from 'lucide-react'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { TableSkeleton } from '../components/ui/skeleton'
import { QueryError } from '../components/query-error'
import { useAuth } from '../lib/auth'
import { roleLevel, ROLE_LEVELS } from '../lib/roles'
import { useVendorSelf, type MyVendorEngagement } from '../lib/external-access'

// The vendor portal: what an external (vendor) user sees first. Their work
// (engagements: what each covers and until when), who sponsors them, when
// their account ends, and the three things they can do: reach what an
// engagement covers (My Apps & Network), ask for access, look after their
// own account. Everything here is read from GET /api/v1/access/my/vendor; the
// access itself is enforced where it is used.

const formatDateTime = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

const targetIcon = { application: Globe, pam_entry: Monitor, device: Monitor } as const

export function VendorPortalPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const staff = roleLevel(user?.roles ?? []) >= ROLE_LEVELS.operator
  const { data, isLoading, isError, error } = useVendorSelf(!staff)

  if (staff) return <Navigate to="/dashboard" replace />
  if (isLoading) return <TableSkeleton rows={3} cols={3} />
  if (isError || !data) return <QueryError error={error} resource={t('pages.vendorPortal.resourceName')} />
  if (!data.external) return <Navigate to="/dashboard" replace />

  const engagements = data.engagements ?? []
  const running = engagements.filter((e) => e.state === 'running')
  const scheduled = engagements.filter((e) => e.state === 'scheduled')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.vendorPortal.title', { vendor: data.vendor?.name ?? '' })}</h1>
        <p className="text-muted-foreground">{t('pages.vendorPortal.subtitle')}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.vendorPortal.sponsor')}</CardDescription>
            <CardTitle className="text-lg">{data.sponsor?.name || '—'}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground break-all">{data.sponsor?.email}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.vendorPortal.accountEnds')}</CardDescription>
            <CardTitle className="text-lg">{formatDateTime(data.account_expires_at)}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {t(`pages.externalUsers.status.${data.account_status}`, { defaultValue: data.account_status ?? '' })}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.vendorPortal.workMode')}</CardDescription>
            <CardTitle className="text-lg">
              {data.vendor?.require_engagement ? t('pages.vendorPortal.engagementsOnly') : t('pages.vendorPortal.grantsAndEngagements')}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {data.vendor?.require_engagement ? t('pages.vendorPortal.engagementsOnlyHint') : t('pages.vendorPortal.grantsHint')}
          </CardContent>
        </Card>
      </div>

      <div className="flex flex-wrap gap-2">
        <QuickLink to="/my-network" icon={<Globe className="mr-2 h-4 w-4" />} label={t('pages.vendorPortal.reach')} primary />
        <QuickLink to="/access-requests" icon={<GitPullRequest className="mr-2 h-4 w-4" />} label={t('pages.vendorPortal.request')} />
        <QuickLink to="/profile" icon={<UserCircle className="mr-2 h-4 w-4" />} label={t('pages.vendorPortal.profile')} />
      </div>

      <section className="space-y-3">
        <h2 className="text-xl font-semibold">{t('pages.vendorPortal.running')}</h2>
        {running.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-10 text-muted-foreground text-center gap-2">
              <Briefcase className="h-10 w-10 text-muted-foreground/40" />
              <p className="font-medium">{t('pages.vendorPortal.noRunning')}</p>
              <p className="text-sm">{t('pages.vendorPortal.noRunningHint', { sponsor: data.sponsor?.name || t('pages.vendorPortal.yourSponsor') })}</p>
            </CardContent>
          </Card>
        ) : (
          running.map((e) => <EngagementCard key={e.id} engagement={e} />)
        )}
      </section>

      {scheduled.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-xl font-semibold">{t('pages.vendorPortal.scheduled')}</h2>
          {scheduled.map((e) => <EngagementCard key={e.id} engagement={e} />)}
        </section>
      )}
    </div>
  )
}

function QuickLink({ to, icon, label, primary }: { to: string; icon: ReactNode; label: string; primary?: boolean }) {
  return (
    <Button asChild variant={primary ? 'default' : 'outline'}>
      <Link to={to}>{icon}{label}</Link>
    </Button>
  )
}

function EngagementCard({ engagement: e }: { engagement: MyVendorEngagement }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="text-lg">{e.title}</CardTitle>
            <CardDescription>
              {[e.ticket_ref, e.sponsor_name && t('pages.externalUsers.engagements.sponsoredBy', { name: e.sponsor_name })].filter(Boolean).join(' · ')}
            </CardDescription>
          </div>
          <div className="text-right text-sm">
            <Badge className={e.state === 'running' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'}>
              {t(`pages.externalUsers.engagements.state.${e.state}`)}
            </Badge>
            <p className="mt-1 flex items-center justify-end gap-1 text-muted-foreground">
              <CalendarClock className="h-4 w-4" />
              {e.state === 'running'
                ? t('pages.vendorPortal.until', { date: formatDateTime(e.ends_at) })
                : t('pages.vendorPortal.from', { start: formatDateTime(e.starts_at), end: formatDateTime(e.ends_at) })}
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        {e.purpose && <p className="text-sm text-muted-foreground whitespace-pre-wrap">{e.purpose}</p>}
        <ul className="grid gap-1 sm:grid-cols-2">
          {e.targets.map((x) => {
            const Icon = targetIcon[x.target_type] ?? Monitor
            return (
              <li key={`${x.target_type}:${x.target_id}`} className="flex items-center gap-2 text-sm">
                <Icon className="h-4 w-4 text-muted-foreground" />
                <span>{x.name}</span>
                <Badge variant="outline">{t(`pages.externalUsers.engagements.types.${x.target_type}`)}</Badge>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
