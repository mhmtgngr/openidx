import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus, Search, ClipboardCheck, Clock, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'

interface AccessReview {
  id: string
  name: string
  description: string
  type: string
  status: string
  reviewer_id: string
  start_date: string
  end_date: string
  created_at: string
  completed_at: string | null
  total_items: number
  reviewed_items: number
}

const statusIcons: Record<string, React.ReactNode> = {
  pending: <Clock className="h-4 w-4" />,
  in_progress: <ClipboardCheck className="h-4 w-4" />,
  completed: <CheckCircle className="h-4 w-4" />,
  expired: <XCircle className="h-4 w-4" />,
  canceled: <AlertTriangle className="h-4 w-4" />,
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  expired: 'bg-red-100 text-red-800',
  canceled: 'bg-gray-100 text-gray-800',
}

const typeLabels: Record<string, string> = {
  user_access: 'User Access',
  role_assignment: 'Role Assignment',
  application_access: 'Application Access',
  privileged_access: 'Privileged Access',
}

export function AccessReviewsPage() {
  const [search, setSearch] = useState('')

  const { data: reviews, isLoading } = useQuery({
    queryKey: ['access-reviews', search],
    queryFn: () => api.get<AccessReview[]>('/api/v1/governance/reviews'),
  })

  const filteredReviews = reviews?.filter(review =>
    review.name.toLowerCase().includes(search.toLowerCase()) ||
    review.description?.toLowerCase().includes(search.toLowerCase()) ||
    review.type.toLowerCase().includes(search.toLowerCase())
  )

  const getProgress = (review: AccessReview) => {
    if (review.total_items === 0) return 0
    return Math.round((review.reviewed_items / review.total_items) * 100)
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Access Reviews</h1>
          <p className="text-muted-foreground">Manage access certifications and reviews</p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Create Review
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Clock className="h-6 w-6 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'pending').length || 0}
                </p>
                <p className="text-sm text-gray-500">Pending</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-blue-100 flex items-center justify-center">
                <ClipboardCheck className="h-6 w-6 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'in_progress').length || 0}
                </p>
                <p className="text-sm text-gray-500">In Progress</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'completed').length || 0}
                </p>
                <p className="text-sm text-gray-500">Completed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-gray-100 flex items-center justify-center">
                <XCircle className="h-6 w-6 text-gray-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'expired' || r.status === 'canceled').length || 0}
                </p>
                <p className="text-sm text-gray-500">Expired/Canceled</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search reviews..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Review</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Status</th>
                  <th className="p-3 text-left text-sm font-medium">Period</th>
                  <th className="p-3 text-left text-sm font-medium">Progress</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={5} className="p-4 text-center">Loading...</td></tr>
                ) : filteredReviews?.length === 0 ? (
                  <tr><td colSpan={5} className="p-4 text-center">No access reviews found</td></tr>
                ) : (
                  filteredReviews?.map((review) => (
                    <tr key={review.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-indigo-100 flex items-center justify-center">
                            <ClipboardCheck className="h-5 w-5 text-indigo-700" />
                          </div>
                          <div>
                            <p className="font-medium">{review.name}</p>
                            <p className="text-sm text-gray-500 max-w-xs truncate">{review.description || '-'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline">
                          {typeLabels[review.type] || review.type}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[review.status] || 'bg-gray-100 text-gray-800'}`}>
                          {statusIcons[review.status]}
                          {review.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="text-sm">
                          <p>{formatDate(review.start_date)}</p>
                          <p className="text-gray-500">to {formatDate(review.end_date)}</p>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="w-32">
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span>{review.reviewed_items || 0}/{review.total_items || 0}</span>
                            <span className="text-gray-500">{getProgress(review)}%</span>
                          </div>
                          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-indigo-600 rounded-full transition-all"
                              style={{ width: `${getProgress(review)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
