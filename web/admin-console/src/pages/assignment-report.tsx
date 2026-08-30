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
    ? 'Checking…'
    : !fromController
      ? 'Reachability unavailable'
      : !complete
        ? entries.length === 0
          ? 'Report incomplete — some users could not be evaluated'
          : wouldLose
        : entries.length === 0
          ? // Scoped deliberately. This report models overlay reach; the same
            // flag also enforces at the reverse proxy, which this page never
            // looked at. The headline may only speak for what was measured.
            'No one would lose Ziti overlay reach — safe to enforce for the overlay'
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
          {/* Shown ALWAYS, not only when the counts look odd: the headline is
              about the overlay, and every reader has to know what it leaves
              out. The proxy half is a follow-up, not something this page can
              silently imply it covered. */}
          {!isLoading && (
            <p className="text-sm text-muted-foreground">
              This report models Ziti overlay reach only. Assignment enforcement also applies at
              the reverse proxy for every application-backed route, including routes with no Ziti
              service, and to users with no Ziti identity. Those are not measured here.
              {routesOutside !== undefined && (
                <>
                  {' '}
                  <span className="font-medium">
                    {routesOutside} application-backed route{routesOutside === 1 ? '' : 's'}{' '}
                    {routesOutside === 1 ? 'is' : 'are'} enforced at the proxy and{' '}
                    {routesOutside === 1 ? 'is' : 'are'} not covered by this report.
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
          {/* Informational, not alarming, and shown even beside a clean
              headline: these users have no Ziti reach to lose, but an operator
              must still be able to see how many there are and judge whether any
              of them should have had an identity. */}
          {!isLoading && fromController && usersWithoutIdentity > 0 && (
            <p className="text-sm text-muted-foreground">
              {usersWithoutIdentity} of {usersTotal} user{usersTotal === 1 ? '' : 's'} in this
              organization {usersWithoutIdentity === 1 ? 'has' : 'have'} no Ziti identity, so{' '}
              {usersWithoutIdentity === 1 ? 'that user has' : 'those users have'} no Ziti reach to
              lose and {usersWithoutIdentity === 1 ? 'was' : 'were'} not evaluated. Check that none
              of them should have been enrolled.
            </p>
          )}
          {!isLoading && fromController && countsReported && usersTotal === 0 && (
            <p className="text-sm font-medium text-amber-600">
              No users were found in this organization, so nothing was evaluated. An empty
              evaluation is not evidence that enforcement is safe.
            </p>
          )}
          {!isLoading && fromController && !countsReported && (
            <p className="text-sm font-medium text-amber-600">
              This response did not carry the user counts, so how much of the organization was
              evaluated is unknown. Do not read it as a clean result.
            </p>
          )}
        </CardHeader>
        <CardContent>
          {!isLoading && (
            <p className="text-sm text-muted-foreground">
              {countsReported
                ? `Evaluated ${usersEvaluated} of ${usersTotal} user${usersTotal === 1 ? '' : 's'} in this organization.`
                : 'User counts not reported by the server, so this report cannot say how much of the organization it covered.'}
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
          {/* F2: the line above asks the operator to adjudicate these users, so
              the page has to name them rather than hand over a count. */}
          {!isLoading && fromController && identitylessUsers.length > 0 && (
            <div className="mt-3">
              <p className="text-sm font-medium">Users with no Ziti identity</p>
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
