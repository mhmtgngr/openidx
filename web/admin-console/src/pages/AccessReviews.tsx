import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Check, X, Filter } from 'lucide-react'
import { governanceApi } from '@/lib/api/governance'
import { Button } from '@/components/ui/button'
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { formatDateTime } from '@/lib/utils/date'
import { useToast } from '@/components/ui/use-toast'
import type { AccessReview, AccessReviewItem } from '@/lib/api/types'

const statusColors: Record<AccessReview['status'], 'success' | 'destructive' | 'warning' | 'secondary'> = {
  pending: 'warning',
  approved: 'success',
  denied: 'destructive',
  expired: 'secondary',
}

export function AccessReviews() {
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState<AccessReview['status'] | 'all'>('all')
  const [selectedReview, setSelectedReview] = useState<(AccessReview & { items: AccessReviewItem[] }) | null>(null)
  const [selectedItems, setSelectedItems] = useState<string[]>([])
  const [bulkReason, setBulkReason] = useState('')
  const [isBulkDialogOpen, setIsBulkDialogOpen] = useState(false)
  const [bulkDecision, setBulkDecision] = useState<'approve' | 'deny'>('approve')
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['reviews', page, statusFilter],
    queryFn: () =>
      governanceApi.getReviews({
        page,
        per_page: 25,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
  })

  const decisionMutation = useMutation({
    mutationFn: ({ reviewId, itemId, decision }: {
      reviewId: string
      itemId: string
      decision: { decision: 'approve' | 'deny'; reason?: string }
    }) =>
      governanceApi.submitDecision(reviewId, itemId, decision),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reviews'] })
      toast({
        title: 'Success',
        description: 'Decision submitted successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to submit decision',
        variant: 'destructive',
      })
    },
  })

  const bulkDecisionMutation = useMutation({
    mutationFn: ({ reviewId, decision, itemIds }: {
      reviewId: string
      decision: { decision: 'approve' | 'deny'; reason?: string }
      itemIds?: string[]
    }) =>
      governanceApi.submitBulkDecision(reviewId, decision, itemIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reviews'] })
      setIsBulkDialogOpen(false)
      setSelectedItems([])
      setBulkReason('')
      toast({
        title: 'Success',
        description: 'Bulk decision submitted successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to submit bulk decision',
        variant: 'destructive',
      })
    },
  })

  const handleDecision = (reviewId: string, itemId: string, decision: 'approve' | 'deny') => {
    decisionMutation.mutate({
      reviewId,
      itemId,
      decision: { decision },
    })
  }

  const handleBulkDecision = () => {
    if (selectedReview && selectedItems.length > 0) {
      bulkDecisionMutation.mutate({
        reviewId: selectedReview.id,
        decision: { decision: bulkDecision, reason: bulkReason || undefined },
        itemIds: selectedItems,
      })
    }
  }

  const openReviewDetail = async (review: AccessReview) => {
    const detail = await governanceApi.getReview(review.id)
    setSelectedReview(detail)
  }

  const toggleItemSelection = (itemId: string) => {
    setSelectedItems((prev) =>
      prev.includes(itemId)
        ? prev.filter((id) => id !== itemId)
        : [...prev, itemId]
    )
  }

  const toggleAllItems = () => {
    const pendingItems = selectedReview?.items.filter((i) => i.status === 'pending') || []
    if (selectedItems.length === pendingItems.length) {
      setSelectedItems([])
    } else {
      setSelectedItems(pendingItems.map((i) => i.id))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Access Reviews</h1>
          <p className="text-muted-foreground">
            Review and decide on access requests
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>All Reviews</CardTitle>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Select
                value={statusFilter}
                onValueChange={(v) => setStatusFilter(v as typeof statusFilter)}
              >
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="denied">Denied</SelectItem>
                  <SelectItem value="expired">Expired</SelectItem>
                </SelectContent>
              </Select>
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
                    <TableHead>Title</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Requester</TableHead>
                    <TableHead>Due Date</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data?.data.map((review) => (
                    <TableRow key={review.id}>
                      <TableCell className="font-medium">{review.title}</TableCell>
                      <TableCell>
                        <Badge variant={statusColors[review.status]}>
                          {review.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{review.requester_id}</TableCell>
                      <TableCell>
                        {review.due_date ? formatDateTime(review.due_date) : '-'}
                      </TableCell>
                      <TableCell>{formatDateTime(review.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openReviewDetail(review)}
                        >
                          Review
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {data && data.total_pages > 1 && (
                <div className="flex items-center justify-end gap-2 mt-4">
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
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Review Detail Dialog */}
      <Dialog open={!!selectedReview} onOpenChange={() => setSelectedReview(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          {selectedReview && (
            <>
              <DialogHeader>
                <DialogTitle>{selectedReview.title}</DialogTitle>
                <DialogDescription>
                  {selectedReview.description || 'Review the following access requests'}
                </DialogDescription>
              </DialogHeader>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <Badge variant={statusColors[selectedReview.status]}>
                    {selectedReview.status}
                  </Badge>
                  {selectedReview.due_date && (
                    <span className="text-sm text-muted-foreground">
                      Due: {formatDateTime(selectedReview.due_date)}
                    </span>
                  )}
                </div>
                {selectedReview.items.filter((i) => i.status === 'pending').length > 0 && (
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={toggleAllItems}
                    >
                      {selectedItems.length === selectedReview.items.filter((i) => i.status === 'pending').length
                        ? 'Deselect All'
                        : 'Select All'}
                    </Button>
                    {selectedItems.length > 0 && (
                      <>
                        <Button
                          size="sm"
                          variant="default"
                          onClick={() => {
                            setBulkDecision('approve')
                            setIsBulkDialogOpen(true)
                          }}
                        >
                          Approve Selected ({selectedItems.length})
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => {
                            setBulkDecision('deny')
                            setIsBulkDialogOpen(true)
                          }}
                        >
                          Deny Selected ({selectedItems.length})
                        </Button>
                      </>
                    )}
                  </div>
                )}
              </div>

              <div className="space-y-2">
                {selectedReview.items.map((item) => (
                  <div
                    key={item.id}
                    className={`flex items-center justify-between p-4 border rounded-lg transition-colors ${
                      selectedItems.includes(item.id) ? 'bg-accent' : ''
                    } ${item.status !== 'pending' ? 'opacity-50' : ''}`}
                  >
                    <div className="flex items-center gap-4">
                      <input
                        type="checkbox"
                        checked={selectedItems.includes(item.id)}
                        onChange={() => toggleItemSelection(item.id)}
                        disabled={item.status !== 'pending'}
                        className="h-4 w-4"
                      />
                      <div>
                        <p className="font-medium">{item.resource_name}</p>
                        <p className="text-sm text-muted-foreground">
                          {item.resource_type}:{item.resource_id}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Requested by {item.requested_at} • {formatDateTime(item.requested_at)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={
                        item.status === 'approved' ? 'success' :
                        item.status === 'denied' ? 'destructive' :
                        'warning'
                      }>
                        {item.status}
                      </Badge>
                      {item.status === 'pending' && (
                        <div className="flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 text-green-500 hover:text-green-600 hover:bg-green-50"
                            onClick={() => handleDecision(selectedReview.id, item.id, 'approve')}
                            disabled={decisionMutation.isPending}
                          >
                            <Check className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-50"
                            onClick={() => handleDecision(selectedReview.id, item.id, 'deny')}
                            disabled={decisionMutation.isPending}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {selectedReview.items.length === 0 && (
                <p className="text-center text-muted-foreground py-8">
                  No items in this review
                </p>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Bulk Decision Dialog */}
      <Dialog open={isBulkDialogOpen} onOpenChange={setIsBulkDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {bulkDecision === 'approve' ? 'Approve' : 'Deny'} Selected Items
            </DialogTitle>
            <DialogDescription>
              {bulkDecision === 'approve'
                ? 'Approve the selected access requests'
                : 'Deny the selected access requests'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="reason">Reason (optional)</Label>
              <Textarea
                id="reason"
                placeholder="Provide a reason for this decision..."
                value={bulkReason}
                onChange={(e) => setBulkReason(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsBulkDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant={bulkDecision === 'deny' ? 'destructive' : 'default'}
              onClick={handleBulkDecision}
              disabled={bulkDecisionMutation.isPending}
            >
              {bulkDecisionMutation.isPending
                ? 'Submitting...'
                : bulkDecision === 'approve'
                ? 'Approve'
                : 'Deny'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
