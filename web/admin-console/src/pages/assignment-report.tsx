import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface ReportEntry {
  user_id: string
  username: string
  application_id: string
  application_name: string
  enforcement_point: string
  reason: string
}

interface AssignmentEntry {
  user_id: string
  username: string
  application_id: string
  application_name: string
}

interface IdentitylessUser {
  user_id: string
  username: string
}

interface Report {
  entries: ReportEntry[]
  // What assignment grants today. DB-only, so it stays correct even when the
  // reach half could not be computed.
  assignments?: AssignmentEntry[]
  // The users with no Ziti identity, themselves. The page asks the operator to
  // check whether any of them should have been enrolled, so it has to name
  // them; summary.users_without_identity counts the same list.
  users_without_identity?: IdentitylessUser[]
  // Where the reachability half came from. "controller" = live data, the
  // answer can be trusted. "unavailable" = the Ziti controller could not be
  // read, so the report cannot say who would lose access; it deliberately does
  // NOT fall back to the local policy mirror, which the reconciler never
  // writes and which therefore reads as "nobody loses anything" no matter what
  // the truth is. Anything else (including a missing field) is treated as
  // untrustworthy for the same reason.
  reachability_source?: string
  reachability_error?: string
  summary: {
    users: number
    applications: number
    would_deny: number
    // Users whose evaluation failed and were therefore excluded from the diff
    // entirely, rather than being scored as either a loss or a keep. This is
    // the go/no-go signal underneath the headline: a report that could not
    // evaluate part of the org must never look identical to a clean one, or an
    // operator could flip ACCESS_ASSIGNMENT_ENFORCE believing nothing breaks
    // when the truth is simply "we don't know" for some users.
    incomplete_users: number
    // The denominator. users_evaluated is how many users the report actually
    // scored; users_total is how many the organization has. They diverge when
    // users have no synced Ziti identity, which is precisely the case where an
    // unevaluated org would otherwise be indistinguishable from a clean one.
    users_evaluated?: number
    users_total?: number
    // How much of that gap is explained by users with no Ziti identity at all.
    // Such a user has no Ziti reach and therefore no Ziti reach to lose, so
    // they do not make the report incomplete — but the operator must be able to
    // see the number and decide whether a given user SHOULD have had an
    // identity. We surface it; we fold it into neither "safe" nor "incomplete".
    users_without_identity?: number
    // How many application-backed routes this report did NOT model. The reach
    // half covers the Ziti overlay only, but the same flag also gates the
    // reverse proxy for every application-backed route, including routes with
    // no Ziti service. Without this number a clean headline speaks for an
    // enforcement surface nobody measured.
    routes_outside_reach_model?: number
    // The go/no-go, computed server-side so every consumer reads one rule
    // instead of re-deriving it from four fields. True only when reach came
    // from the live controller, no user was skipped, and at least one user was
    // actually evaluated. A missing field is not a true one: fail closed.
    evaluation_complete?: boolean
  }
}

export function AssignmentReportPage() {
  const { t } = useTranslation()
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['assignment-report'],
    queryFn: () => api.get<Report>('/api/v1/access/assignment-report'),
  })

  if (isError) return <QueryError error={error} resource={t('pages.assignmentReport.resource')} />

  const entries = data?.entries ?? []
  const summary = data?.summary
  const incompleteUsers = summary?.incomplete_users ?? 0
  const assignments = data?.assignments ?? []
  // Trust the reach half only when the server says it came from the live
  // controller. Fail closed on anything else.
  const fromController = data?.reachability_source === 'controller'
  // Two counts in one sentence: each is pluralized on its own and dropped
  // into the line, so neither language has to write "user(s)".
  const wouldLose = t('pages.assignmentReport.wouldLose', {
    users: t('pages.assignmentReport.userCount', { count: summary?.users ?? 0 }),
    applications: t('pages.assignmentReport.applicationCount', {
      count: summary?.applications ?? 0,
    }),
  })

  // The denominator. A response that omits the counts is not a response
  // reporting zeros: it simply did not say how much of the org it covered, and
  // the page must say that rather than assert "0 of 0".
  const countsReported =
    summary?.users_evaluated !== undefined && summary?.users_total !== undefined
  const usersEvaluated = summary?.users_evaluated ?? 0
  const usersTotal = summary?.users_total ?? 0
  const usersWithoutIdentity = summary?.users_without_identity ?? 0
  const identitylessUsers = data?.users_without_identity ?? []
  const routesOutside = summary?.routes_outside_reach_model

  // The go/no-go comes from the server, which computes it once for every
  // consumer. Re-deriving it here is what let a zero-user org read as clean.
  // Anything but an explicit true — including a missing field — fails closed.
  const complete = summary?.evaluation_complete === true
  const headline = isLoading
    ? t('pages.assignmentReport.checking')
    : !fromController
      ? t('pages.assignmentReport.reachUnavailable')
      : !complete
        ? entries.length === 0
          ? t('pages.assignmentReport.reportIncomplete')
          : wouldLose
        : entries.length === 0
          ? // Scoped deliberately. This report models overlay reach; the same
            // flag also enforces at the reverse proxy, which this page never
            // looked at. The headline may only speak for what was measured.
            t('pages.assignmentReport.safe')
          : wouldLose

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">{t('nav.items.assignmentReport')}</h1>
        <p className="text-sm text-muted-foreground">
          {t('pages.assignmentReport.subtitle')}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{headline}</CardTitle>
          {/* Shown ALWAYS, not only when the counts look odd: the headline is
              about the overlay, and every reader has to know what it leaves
              out. The proxy half is a follow-up, not something this page can
              silently imply it covered. */}
          {!isLoading && (
            <p className="text-sm text-muted-foreground">
              {t('pages.assignmentReport.overlayOnly')}
              {routesOutside !== undefined && (
                <>
                  {' '}
                  <span className="font-medium">
                    {t('pages.assignmentReport.routesOutside', { count: routesOutside })}
                  </span>
                </>
              )}
            </p>
          )}
          {!isLoading && !fromController && (
            <div
              role="alert"
              className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm"
            >
              <p className="font-medium text-destructive">
                {t('pages.assignmentReport.controllerUnavailable')}
              </p>
              {/* The controller's own error text. */}
              {data?.reachability_error && (
                <p className="mt-1 text-muted-foreground">{data.reachability_error}</p>
              )}
            </div>
          )}
          {!isLoading && fromController && incompleteUsers > 0 && (
            <p className="text-sm font-medium text-amber-600">
              {/* The leading connective is part of the sentence, so each
                  form is its own key rather than a prefix glued on. */}
              {entries.length === 0
                ? t('pages.assignmentReport.incompleteBut', { count: incompleteUsers })
                : t('pages.assignmentReport.incomplete', { count: incompleteUsers })}
            </p>
          )}
          {/* Informational, not alarming, and shown even beside a clean
              headline: these users have no Ziti reach to lose, but an operator
              must still be able to see how many there are and judge whether any
              of them should have had an identity. */}
          {!isLoading && fromController && usersWithoutIdentity > 0 && (
            <p className="text-sm text-muted-foreground">
              {/* The subject agrees with the total, the rest of the sentence
                  with how many lack an identity, so the subject is composed
                  first and the sentence pluralizes around it. */}
              {t('pages.assignmentReport.identityless', {
                count: usersWithoutIdentity,
                subject: t('pages.assignmentReport.identitylessSubject', {
                  count: usersTotal,
                  n: usersWithoutIdentity,
                }),
              })}
            </p>
          )}
          {!isLoading && fromController && countsReported && usersTotal === 0 && (
            <p className="text-sm font-medium text-amber-600">
              {t('pages.assignmentReport.noUsers')}
            </p>
          )}
          {!isLoading && fromController && !countsReported && (
            <p className="text-sm font-medium text-amber-600">
              {t('pages.assignmentReport.countsMissing')}
            </p>
          )}
        </CardHeader>
        <CardContent>
          {!isLoading && (
            <p className="text-sm text-muted-foreground">
              {countsReported
                ? t('pages.assignmentReport.evaluated', {
                    count: usersTotal,
                    n: usersEvaluated,
                  })
                : t('pages.assignmentReport.countsMissingBody')}
            </p>
          )}
          {!isLoading && !fromController && (
            <p className="text-sm text-muted-foreground">
              {t('pages.assignmentReport.grants', { count: assignments.length })}
            </p>
          )}
          {/* F2: the line above asks the operator to adjudicate these users, so
              the page has to name them rather than hand over a count. */}
          {!isLoading && fromController && identitylessUsers.length > 0 && (
            <div className="mt-3">
              <p className="text-sm font-medium">
                {t('pages.assignmentReport.identitylessTitle')}
              </p>
              <ul className="mt-1 text-sm text-muted-foreground">
                {identitylessUsers.map((u) => (
                  <li key={u.user_id}>{u.username || u.user_id}</li>
                ))}
              </ul>
            </div>
          )}
          {entries.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.assignmentReport.colUser')}</TableHead>
                  <TableHead>{t('pages.assignmentReport.colApplication')}</TableHead>
                  <TableHead>{t('pages.assignmentReport.colEnforcedAt')}</TableHead>
                  <TableHead>{t('pages.assignmentReport.colWhy')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e) => (
                  <TableRow key={`${e.user_id}-${e.application_id}`}>
                    <TableCell>{e.username || e.user_id}</TableCell>
                    <TableCell>{e.application_name || e.application_id}</TableCell>
                    {/* Enforcement point and reason are composed server-side. */}
                    <TableCell>{e.enforcement_point}</TableCell>
                    <TableCell className="text-muted-foreground">{e.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
