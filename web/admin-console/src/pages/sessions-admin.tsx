import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Monitor, MonitorSmartphone, Trash2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Session {
  id: string
  user_id: string
  username: string
  email: string
  client_id: string
  ip_address?: string
  user_agent?: string
  device_name?: string
  location?: string
  device_type?: string
  started_at: string
  last_seen_at: string
  expires_at: string
  revoked: boolean
  revoked_at?: string
  revoke_reason?: string
}

export function SessionsAdminPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [userIdFilter, setUserIdFilter] = useState('')
  const [activeOnly, setActiveOnly] = useState(true)
  const [revokeTarget, setRevokeTarget] = useState<Session | null>(null)
  const [revokeReason, setRevokeReason] = useState('')
  const [bulkRevokeUser, setBulkRevokeUser] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['admin-sessions', userIdFilter, activeOnly],
    queryFn: () => {
      const params = new URLSearchParams()
      params.set('active_only', String(activeOnly))
      if (userIdFilter) params.set('user_id', userIdFilter)
      return api.get<{ sessions: Session[]; total: number }>(`/api/v1/sessions?${params.toString()}`)
    },
  })
  const sessions = data?.sessions || []
  const total = data?.total || 0

  const revokeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.delete(`/api/v1/sessions/${id}`, { data: { reason } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-sessions'] })
      toast({ title: 'Session revoked' })
      setRevokeTarget(null)
      setRevokeReason('')
    },
    onError: () => toast({ title: 'Failed to revoke session', variant: 'destructive' }),
  })

  const bulkRevokeMutation = useMutation({
    mutationFn: ({ userId, reason }: { userId: string; reason: string }) =>
      api.delete(`/api/v1/users/${userId}/sessions`, { data: { reason } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-sessions'] })
      toast({ title: 'All user sessions revoked' })
      setBulkRevokeUser(null)
      setRevokeReason('')
    },
    onError: () => toast({ title: 'Failed to revoke sessions', variant: 'destructive' }),
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Session Management</h1>
        <p className="text-muted-foreground">View and manage active user sessions</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <CardTitle className="flex items-center gap-2"><Monitor className="h-5 w-5" />Sessions ({total})</CardTitle>
            <Input placeholder="Filter by user ID..." className="max-w-xs" value={userIdFilter}
              onChange={e => setUserIdFilter(e.target.value)} />
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={activeOnly} onChange={e => setActiveOnly(e.target.checked)} />
              Active only
            </label>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading sessions...</p>
            </div>
          ) : sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <MonitorSmartphone className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No active sessions</p>
              <p className="text-sm">User sessions will appear here when users log in</p>
            </div>
          ) : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>User</TableHead><TableHead>Device</TableHead><TableHead>Location</TableHead>
                <TableHead>IP Address</TableHead><TableHead>Started</TableHead><TableHead>Last Active</TableHead>
                <TableHead>Status</TableHead><TableHead>Actions</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {sessions.map(s => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium">{s.username}</div>
                        <div className="text-xs text-muted-foreground">{s.email}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">{s.device_name || '-'}</div>
                      {s.device_type && <div className="text-xs text-muted-foreground">{s.device_type}</div>}
                    </TableCell>
                    <TableCell className="text-sm">{s.location || '-'}</TableCell>
                    <TableCell className="font-mono text-sm">{s.ip_address || '-'}</TableCell>
                    <TableCell className="text-sm">{formatDate(s.started_at)}</TableCell>
                    <TableCell className="text-sm">{formatDate(s.last_seen_at)}</TableCell>
                    <TableCell>
                      {s.revoked ? (
                        <Badge variant="secondary">Revoked</Badge>
                      ) : new Date(s.expires_at) < new Date() ? (
                        <Badge variant="secondary">Expired</Badge>
                      ) : (
                        <Badge className="bg-green-100 text-green-800">Active</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {!s.revoked && new Date(s.expires_at) > new Date() && (
                          <Button variant="ghost" size="sm" onClick={() => setRevokeTarget(s)}>
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </Button>
                        )}
                        <Button variant="outline" size="sm" onClick={() => { setBulkRevokeUser(s.user_id); setRevokeReason('') }}>
                          Revoke All
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Revoke Single Session */}
      <Dialog open={!!revokeTarget} onOpenChange={open => !open && setRevokeTarget(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Revoke Session</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">
            Revoke session for {revokeTarget?.username} from {revokeTarget?.ip_address || 'unknown IP'}?
          </p>
          <div>
            <label className="text-sm font-medium">Reason</label>
            <Input placeholder="Reason for revocation" value={revokeReason}
              onChange={e => setRevokeReason(e.target.value)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeTarget(null)}>Cancel</Button>
            <Button variant="destructive" disabled={revokeMutation.isPending}
              onClick={() => revokeTarget && revokeMutation.mutate({ id: revokeTarget.id, reason: revokeReason })}>
              Revoke
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Revoke */}
      <Dialog open={!!bulkRevokeUser} onOpenChange={open => !open && setBulkRevokeUser(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>Revoke All User Sessions</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">This will revoke all active sessions for this user.</p>
          <div>
            <label className="text-sm font-medium">Reason</label>
            <Input placeholder="Reason for revocation" value={revokeReason}
              onChange={e => setRevokeReason(e.target.value)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkRevokeUser(null)}>Cancel</Button>
            <Button variant="destructive" disabled={bulkRevokeMutation.isPending}
              onClick={() => bulkRevokeUser && bulkRevokeMutation.mutate({ userId: bulkRevokeUser, reason: revokeReason })}>
              Revoke All Sessions
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
