import { useQuery } from '@tanstack/react-query'
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

interface Report {
  entries: ReportEntry[]
  // What assignment grants today. DB-only, so it stays correct even when the
  // reach half could not be computed.
  assignments?: AssignmentEntry[]
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
  }
}

export function AssignmentReportPage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['assignment-report'],
    queryFn: () => api.get<Report>('/api/v1/access/assignment-report'),
  })

  if (isError) return <QueryError error={error} resource="the assignment report" />

  const entries = data?.entries ?? []
  const summary = data?.summary
  const incompleteUsers = summary?.incomplete_users ?? 0
  const assignments = data?.assignments ?? []
  // Trust the reach half only when the server says it came from the live
  // controller. Fail closed on anything else.
  const fromController = data?.reachability_source === 'controller'
  const wouldLose = `${summary?.users ?? 0} user(s) would lose access to ${summary?.applications ?? 0} application(s)`

  // The denominator. Missing fields count as zero evaluated, i.e. fail closed:
  // a server that does not tell us how much of the org it covered has not
  // earned the reassuring headline either.
  const usersEvaluated = summary?.users_evaluated ?? 0
  const usersTotal = summary?.users_total ?? 0
  const notEvaluated = Math.max(usersTotal - usersEvaluated, 0)
  // Evaluating nobody is not a clean result — an org whose Ziti sync has never
  // run would otherwise render "safe to enforce" over an evaluation of no one.
  const evaluatedEveryone = usersEvaluated > 0 && notEvaluated === 0

  // The reassuring headline is reserved for the one case that earns it: live
  // controller data, every user evaluated, nothing lost.
  const complete = fromController && evaluatedEveryone && incompleteUsers === 0
  const headline = isLoading
    ? 'Checking…'
    : !fromController
      ? 'Reachability unavailable'
      : !complete
        ? entries.length === 0
          ? 'Report incomplete — some users could not be evaluated'
          : wouldLose
        : entries.length === 0
          ? 'No one would lose access — safe to enforce'
          : wouldLose

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Assignment report</h1>
        <p className="text-sm text-muted-foreground">
          Who would lose access when ACCESS_ASSIGNMENT_ENFORCE is turned on.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{headline}</CardTitle>
          {!isLoading && !fromController && (
            <div
              role="alert"
              className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm"
            >
              <p className="font-medium text-destructive">
                Could not read the Ziti controller, so this report cannot tell you who would lose
                access. Do not enable enforcement based on this page.
              </p>
              {data?.reachability_error && (
                <p className="mt-1 text-muted-foreground">{data.reachability_error}</p>
              )}
            </div>
          )}
          {!isLoading && fromController && incompleteUsers > 0 && (
            <p className="text-sm font-medium text-amber-600">
              {entries.length === 0 ? 'But ' : ''}
              {incompleteUsers} user{incompleteUsers === 1 ? '' : 's'} could not be evaluated and{' '}
              {incompleteUsers === 1 ? 'is' : 'are'} excluded from this report. Treat this report as
              incomplete until that count is zero.
            </p>
          )}
          {!isLoading && fromController && notEvaluated > 0 && (
            <p className="text-sm font-medium text-amber-600">
              {notEvaluated} of {usersTotal} user{usersTotal === 1 ? '' : 's'} in this organization
              could not be evaluated because they have no synced Ziti identity. Their reach is
              unknown, so this report does not cover them.
            </p>
          )}
          {!isLoading && fromController && usersTotal === 0 && (
            <p className="text-sm font-medium text-amber-600">
              No users were found in this organization, so nothing was evaluated. An empty
              evaluation is not evidence that enforcement is safe.
            </p>
          )}
        </CardHeader>
        <CardContent>
          {!isLoading && (
            <p className="text-sm text-muted-foreground">
              Evaluated {usersEvaluated} of {usersTotal} user{usersTotal === 1 ? '' : 's'} in this
              organization.
            </p>
          )}
          {!isLoading && !fromController && (
            <p className="text-sm text-muted-foreground">
              Assignment currently grants {assignments.length} user–application pair
              {assignments.length === 1 ? '' : 's'} in this organization. That half of the report is
              read from the database and is still accurate; only the "who can reach what today" half
              is missing.
            </p>
          )}
          {entries.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Application</TableHead>
                  <TableHead>Enforced at</TableHead>
                  <TableHead>Why</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e) => (
                  <TableRow key={`${e.user_id}-${e.application_id}`}>
                    <TableCell>{e.username || e.user_id}</TableCell>
                    <TableCell>{e.application_name || e.application_id}</TableCell>
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
