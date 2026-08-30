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

interface Report {
  entries: ReportEntry[]
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

  const headline = isLoading
    ? 'Checking…'
    : entries.length === 0
      ? 'No one would lose access — safe to enforce'
      : `${summary?.users ?? 0} user(s) would lose access to ${summary?.applications ?? 0} application(s)`

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
          {!isLoading && incompleteUsers > 0 && (
            <p className="text-sm font-medium text-amber-600">
              {entries.length === 0 ? 'But ' : ''}
              {incompleteUsers} user{incompleteUsers === 1 ? '' : 's'} could not be evaluated and{' '}
              {incompleteUsers === 1 ? 'is' : 'are'} excluded from this report. Treat this report as
              incomplete until that count is zero.
            </p>
          )}
        </CardHeader>
        <CardContent>
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
