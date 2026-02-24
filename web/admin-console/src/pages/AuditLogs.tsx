import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download, Search, Filter } from 'lucide-react'
import { auditApi } from '@/lib/api/audit'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { formatDateTime } from '@/lib/utils/date'
import type { AuditEvent } from '@/lib/api/types'

const outcomeColors: Record<AuditEvent['outcome'], 'success' | 'destructive' | 'warning'> = {
  success: 'success',
  failure: 'destructive',
  partial: 'warning',
}

export function AuditLogs() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [outcomeFilter, setOutcomeFilter] = useState<AuditEvent['outcome'] | 'all'>('all')
  const [exportFormat, setExportFormat] = useState<'csv' | 'json'>('csv')

  const { data, isLoading } = useQuery({
    queryKey: ['audit-events', page, search, actionFilter, outcomeFilter],
    queryFn: () =>
      auditApi.queryEvents({
        page,
        per_page: 50,
        action: actionFilter === 'all' ? undefined : actionFilter,
        outcome: outcomeFilter === 'all' ? undefined : outcomeFilter,
      }),
  })

  const handleExport = async () => {
    try {
      const blob = await auditApi.exportEvents({
        page,
        per_page: 50,
        action: actionFilter === 'all' ? undefined : actionFilter,
        outcome: outcomeFilter === 'all' ? undefined : outcomeFilter,
        format: exportFormat,
      })

      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-logs-${new Date().toISOString()}.${exportFormat}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Export failed:', error)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Audit Logs</h1>
          <p className="text-muted-foreground">
            Query and export system audit events
          </p>
        </div>
        <Button onClick={handleExport}>
          <Download className="h-4 w-4 mr-2" />
          Export
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="space-y-4">
            <CardTitle>Event Filters</CardTitle>
            <div className="flex flex-wrap items-center gap-4">
              <div className="relative flex-1 min-w-64">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by resource ID..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8"
                />
              </div>
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <Select value={actionFilter} onValueChange={setActionFilter}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="Filter by action" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Actions</SelectItem>
                    <SelectItem value="user.login">Login</SelectItem>
                    <SelectItem value="user.logout">Logout</SelectItem>
                    <SelectItem value="user.create">Create User</SelectItem>
                    <SelectItem value="user.update">Update User</SelectItem>
                    <SelectItem value="user.delete">Delete User</SelectItem>
                    <SelectItem value="policy.create">Create Policy</SelectItem>
                    <SelectItem value="policy.update">Update Policy</SelectItem>
                    <SelectItem value="policy.delete">Delete Policy</SelectItem>
                    <SelectItem value="access.decide">Access Decision</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={outcomeFilter} onValueChange={(v: any) => setOutcomeFilter(v)}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Filter by outcome" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Outcomes</SelectItem>
                    <SelectItem value="success">Success</SelectItem>
                    <SelectItem value="failure">Failure</SelectItem>
                    <SelectItem value="partial">Partial</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-2 ml-auto">
                <Label htmlFor="format">Format:</Label>
                <Select value={exportFormat} onValueChange={(v: any) => setExportFormat(v)}>
                  <SelectTrigger id="format" className="w-24">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="csv">CSV</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>IP Address</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data?.data.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell className="font-mono text-sm">
                        {formatDateTime(event.timestamp)}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-medium">{event.actor_id}</span>
                          <Badge variant="outline" className="w-fit text-xs">
                            {event.actor_type}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>{event.action}</TableCell>
                      <TableCell>
                        <div className="flex flex-col">
                          <span>{event.resource_type}</span>
                          <span className="text-xs text-muted-foreground font-mono">
                            {event.resource_id}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={outcomeColors[event.outcome]}>
                          {event.outcome}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {event.ip_address || '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {data && data.total_pages > 1 && (
                <div className="flex items-center justify-between mt-4">
                  <span className="text-sm text-muted-foreground">
                    Showing {data.data.length} of {data.total} events
                  </span>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                    >
                      Previous
                    </Button>
                    <span className="text-sm text-muted-foreground">
                      Page {page} of {data.total_pages}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => p + 1)}
                      disabled={page >= data.total_pages}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
