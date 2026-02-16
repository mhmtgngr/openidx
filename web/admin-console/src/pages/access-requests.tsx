import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { GitPullRequest, Plus, Clock, CheckCircle, XCircle, Ban, Timer } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AccessRequest {
  id: string
  requester_id: string
  requester_name: string
  resource_name: string
  resource_type: string
  status: string
  priority: string
  justification: string
  expires_at?: string
  created_at: string
  updated_at: string
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    approved: 'bg-green-100 text-green-800',
    fulfilled: 'bg-green-100 text-green-800',
    denied: 'bg-red-100 text-red-800',
    cancelled: 'bg-gray-100 text-gray-800',
    expired: 'bg-orange-100 text-orange-800',
  }
  return map[status] || 'bg-gray-100 text-gray-800'
}

const DURATION_OPTIONS = [
  { value: '', label: 'Permanent' },
  { value: '4h', label: '4 hours' },
  { value: '8h', label: '8 hours' },
  { value: '1d', label: '1 day' },
  { value: '3d', label: '3 days' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
]

export function AccessRequestsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('my-requests')
  const [createOpen, setCreateOpen] = useState(false)
  const [approvalOpen, setApprovalOpen] = useState(false)
  const [approvalAction, setApprovalAction] = useState<'approve' | 'deny'>('approve')
  const [selectedRequest, setSelectedRequest] = useState<AccessRequest | null>(null)
  const [comments, setComments] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const [newReq, setNewReq] = useState({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '' })

  const { data: myRequestsData, isLoading: myLoading } = useQuery({
    queryKey: ['my-requests'],
    queryFn: () => api.get<{ requests: AccessRequest[] }>('/api/v1/governance/requests?requester_id=me'),
  })
  const myRequests = myRequestsData?.requests || []

  const { data: pendingData, isLoading: pendingLoading } = useQuery({
    queryKey: ['my-approvals'],
    queryFn: () => api.get<{ pending_approvals: AccessRequest[] }>('/api/v1/governance/my-approvals'),
  })
  const pendingApprovals = pendingData?.pending_approvals || []

  const { data: allData, isLoading: allLoading } = useQuery({
    queryKey: ['all-requests', statusFilter],
    queryFn: () => {
      const params = statusFilter !== 'all' ? `?status=${statusFilter}` : ''
      return api.get<{ requests: AccessRequest[] }>(`/api/v1/governance/requests${params}`)
    },
  })
  const allRequests = allData?.requests || []

  const createMutation = useMutation({
    mutationFn: (data: typeof newReq) => {
      const payload = { ...data, duration: data.duration === 'permanent' ? '' : data.duration }
      return api.post('/api/v1/governance/requests', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Access request submitted' })
      setCreateOpen(false)
      setNewReq({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '' })
    },
    onError: () => toast({ title: 'Failed to submit request', variant: 'destructive' }),
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      toast({ title: 'Request cancelled' })
    },
  })

  const approveMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/approve`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Request approved' })
      setApprovalOpen(false)
    },
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/deny`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Request denied' })
      setApprovalOpen(false)
    },
  })

  const formatDate = (d: string) => new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

  const openApproval = (req: AccessRequest, action: 'approve' | 'deny') => {
    setSelectedRequest(req)
    setApprovalAction(action)
    setComments('')
    setApprovalOpen(true)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Access Requests</h1>
          <p className="text-muted-foreground">Request access to resources and manage approvals</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Request Access
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="my-requests"><GitPullRequest className="mr-2 h-4 w-4" />My Requests</TabsTrigger>
          <TabsTrigger value="pending-approvals">
            <Clock className="mr-2 h-4 w-4" />Pending Approvals
            {pendingApprovals.length > 0 && <Badge variant="secondary" className="ml-1">{pendingApprovals.length}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="all-requests">All Requests</TabsTrigger>
        </TabsList>

        <TabsContent value="my-requests">
          <Card>
            <CardHeader><CardTitle>My Access Requests</CardTitle></CardHeader>
            <CardContent>
              {myLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               myRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">No requests found</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Resource</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead>
                    <TableHead>Priority</TableHead><TableHead>Created</TableHead><TableHead>Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {myRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600" title={`Expires ${new Date(r.expires_at).toLocaleString()}`}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          {r.status === 'pending' && (
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="outline" size="sm"><Ban className="h-3 w-3 mr-1" />Cancel</Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>Cancel Request?</AlertDialogTitle>
                                  <AlertDialogDescription>Cancel this access request for {r.resource_name}?</AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Keep</AlertDialogCancel>
                                  <AlertDialogAction onClick={() => cancelMutation.mutate(r.id)}>Cancel Request</AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pending-approvals">
          <Card>
            <CardHeader><CardTitle>Pending Approvals</CardTitle></CardHeader>
            <CardContent>
              {pendingLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               pendingApprovals.length === 0 ? <p className="text-center py-8 text-muted-foreground">No pending approvals</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Requester</TableHead><TableHead>Resource</TableHead><TableHead>Type</TableHead>
                    <TableHead>Priority</TableHead><TableHead>Submitted</TableHead><TableHead>Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {pendingApprovals.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button size="sm" onClick={() => openApproval(r, 'approve')}><CheckCircle className="h-3 w-3 mr-1" />Approve</Button>
                            <Button variant="destructive" size="sm" onClick={() => openApproval(r, 'deny')}><XCircle className="h-3 w-3 mr-1" />Deny</Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="all-requests">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>All Access Requests</CardTitle>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[180px]"><SelectValue placeholder="Filter by status" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="approved">Approved</SelectItem>
                    <SelectItem value="denied">Denied</SelectItem>
                    <SelectItem value="fulfilled">Fulfilled</SelectItem>
                    <SelectItem value="cancelled">Cancelled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {allLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               allRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">No requests found</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Requester</TableHead><TableHead>Resource</TableHead><TableHead>Type</TableHead>
                    <TableHead>Status</TableHead><TableHead>Priority</TableHead><TableHead>Created</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {allRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600" title={`Expires ${new Date(r.expires_at).toLocaleString()}`}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Request Access</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Resource Type</label>
              <Select value={newReq.resource_type} onValueChange={v => setNewReq(p => ({ ...p, resource_type: v }))}>
                <SelectTrigger><SelectValue placeholder="Select type" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="role">Role</SelectItem>
                  <SelectItem value="group">Group</SelectItem>
                  <SelectItem value="application">Application</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Resource Name</label>
              <Input placeholder="Enter resource name" value={newReq.resource_name}
                onChange={e => setNewReq(p => ({ ...p, resource_name: e.target.value }))} />
            </div>
            <div>
              <label className="text-sm font-medium">Justification</label>
              <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder="Explain why you need access..."
                value={newReq.justification} onChange={e => setNewReq(p => ({ ...p, justification: e.target.value }))} />
            </div>
            <div>
              <label className="text-sm font-medium">Priority</label>
              <Select value={newReq.priority} onValueChange={v => setNewReq(p => ({ ...p, priority: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="normal">Normal</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="urgent">Urgent</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Access Duration</label>
              <Select value={newReq.duration} onValueChange={v => setNewReq(p => ({ ...p, duration: v }))}>
                <SelectTrigger><SelectValue placeholder="Permanent" /></SelectTrigger>
                <SelectContent>
                  {DURATION_OPTIONS.map(opt => (
                    <SelectItem key={opt.value || 'permanent'} value={opt.value || 'permanent'}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {newReq.duration ? 'Access will be automatically revoked after the duration expires.' : 'Access will not expire automatically.'}
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button disabled={!newReq.resource_type || !newReq.resource_name || createMutation.isPending}
                onClick={() => createMutation.mutate(newReq)}>
                {createMutation.isPending ? 'Submitting...' : 'Submit Request'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Approve/Deny Dialog */}
      <Dialog open={approvalOpen} onOpenChange={setApprovalOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{approvalAction === 'approve' ? 'Approve' : 'Deny'} Request</DialogTitle></DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <p><span className="font-medium">Requester:</span> {selectedRequest.requester_name}</p>
                <p><span className="font-medium">Resource:</span> {selectedRequest.resource_name}</p>
                <p><span className="font-medium">Type:</span> {selectedRequest.resource_type}</p>
                {selectedRequest.justification && <p><span className="font-medium">Justification:</span> {selectedRequest.justification}</p>}
              </div>
              <div>
                <label className="text-sm font-medium">Comments</label>
                <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder="Add comments..."
                  value={comments} onChange={e => setComments(e.target.value)} />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setApprovalOpen(false)}>Cancel</Button>
                <Button variant={approvalAction === 'approve' ? 'default' : 'destructive'}
                  disabled={approveMutation.isPending || denyMutation.isPending}
                  onClick={() => {
                    if (approvalAction === 'approve') approveMutation.mutate({ id: selectedRequest.id, comments })
                    else denyMutation.mutate({ id: selectedRequest.id, comments })
                  }}>
                  {approvalAction === 'approve' ? 'Approve' : 'Deny'}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
