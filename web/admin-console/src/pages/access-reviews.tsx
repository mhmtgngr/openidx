import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Plus, Search, ClipboardCheck, ClipboardList, Clock, CheckCircle, XCircle, AlertTriangle, Edit, Play, Eye, MoreHorizontal, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

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
  canceled: 'bg-muted text-foreground',
}

// Review-type labels resolve through i18n; keys pinned in i18n.test.ts.
const REVIEW_TYPES = [
  'user_access',
  'role_assignment',
  'application_access',
  'privileged_access',
] as const

export function AccessReviewsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const { user } = useAuth()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedReview, setSelectedReview] = useState<AccessReview | null>(null)
  const [newReview, setNewReview] = useState({
    name: '',
    description: '',
    type: 'user_access',
    start_date: '',
    end_date: '',
  })
  const [editReview, setEditReview] = useState({
    name: '',
    description: '',
    type: 'user_access',
    start_date: '',
    end_date: '',
  })
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: reviews, isLoading, isError, error } = useQuery({
    queryKey: ['access-reviews', search, statusFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (statusFilter) params.set('status', statusFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<AccessReview[]>(`/api/v1/governance/reviews?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  // Create access review mutation
  const createReviewMutation = useMutation({
    mutationFn: (reviewData: { name: string; description: string; type: string; reviewer_id: string; start_date: string; end_date: string }) => api.post('/api/v1/governance/reviews', reviewData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: t('common.success'),
        description: t('pages.accessReviews.toasts.created'),
        variant: 'success',
      })
      setCreateModal(false)
      setNewReview({
        name: '',
        description: '',
        type: 'user_access',
        start_date: '',
        end_date: '',
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('common.error'),
        description: t('pages.accessReviews.toasts.createFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  // Reviews are filtered server-side via search param
  const filteredReviews = reviews

  const getProgress = (review: AccessReview) => {
    if (review.total_items === 0) return 0
    return Math.round((review.reviewed_items / review.total_items) * 100)
  }

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const handleNewReviewChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setNewReview(prev => ({ ...prev, [name]: value }))
  }

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (newReview.end_date && newReview.start_date && new Date(newReview.end_date) <= new Date(newReview.start_date)) {
      toast({ title: t('pages.accessReviews.toasts.validationTitle'), description: t('pages.accessReviews.toasts.validationDates'), variant: 'destructive' })
      return
    }
    createReviewMutation.mutate({
      name: newReview.name,
      description: newReview.description,
      type: newReview.type,
      reviewer_id: user?.id || '',
      start_date: new Date(newReview.start_date).toISOString(),
      end_date: new Date(newReview.end_date).toISOString(),
    })
  }

  const handleEditReview = (review: AccessReview) => {
    setSelectedReview(review)
    setEditReview({
      name: review.name,
      description: review.description || '',
      type: review.type,
      start_date: review.start_date.split('T')[0], // Extract date part
      end_date: review.end_date.split('T')[0], // Extract date part
    })
    setEditModal(true)
  }

  const handleEditReviewChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target
    setEditReview(prev => ({ ...prev, [name]: value }))
  }

  const updateReviewMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AccessReview> }) =>
      api.put(`/api/v1/governance/reviews/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: t('common.success'),
        description: t('pages.accessReviews.toasts.updated'),
        variant: 'success',
      })
      setEditModal(false)
      setSelectedReview(null)
    },
    onError: (error: Error) => {
      toast({
        title: t('common.error'),
        description: t('pages.accessReviews.toasts.updateFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  const startReviewMutation = useMutation({
    mutationFn: (id: string) => api.patch(`/api/v1/governance/reviews/${id}/status`, { status: 'in_progress' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-reviews'] })
      toast({
        title: t('pages.accessReviews.toasts.startedTitle'),
        description: t('pages.accessReviews.toasts.startedDesc'),
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('common.error'),
        description: t('pages.accessReviews.toasts.startFailed', { message: error.message }),
        variant: 'destructive',
      })
    },
  })

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedReview) return

    updateReviewMutation.mutate({
      id: selectedReview.id,
      data: {
        name: editReview.name,
        description: editReview.description,
        start_date: new Date(editReview.start_date).toISOString(),
        end_date: new Date(editReview.end_date).toISOString(),
      },
    })
  }

  const handleStartReview = (review: AccessReview) => {
    startReviewMutation.mutate(review.id)
  }

  const handleViewReview = (review: AccessReview) => {
    navigate(`/access-reviews/${review.id}`)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.accessReviews')}</h1>
          <p className="text-muted-foreground">{t('pages.accessReviews.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.accessReviews.createReview')}
        </Button>
      </div>

      <RelatedLinks
        links={[
          { to: '/certification-campaigns', label: t('nav.items.certCampaigns') },
          { to: '/attestation-campaigns', label: t('nav.items.attestation') },
        ]}
      />

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
                <p className="text-sm text-muted-foreground">{t('pages.accessReviews.stats.pending')}</p>
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
                <p className="text-sm text-muted-foreground">{t('pages.accessReviews.stats.inProgress')}</p>
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
                <p className="text-sm text-muted-foreground">{t('pages.accessReviews.stats.completed')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-muted flex items-center justify-center">
                <XCircle className="h-6 w-6 text-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {reviews?.filter(r => r.status === 'expired' || r.status === 'canceled').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">{t('pages.accessReviews.stats.expiredCanceled')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={t('pages.accessReviews.searchPlaceholder')}
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={(val) => { setStatusFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[180px]" aria-label={t('pages.accessReviews.filter.statusLabel')}>
                <SelectValue placeholder={t('pages.accessReviews.filter.all')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('pages.accessReviews.filter.all')}</SelectItem>
                <SelectItem value="pending">{t('pages.accessReviews.filter.pending')}</SelectItem>
                <SelectItem value="in_progress">{t('pages.accessReviews.filter.inProgress')}</SelectItem>
                <SelectItem value="completed">{t('pages.accessReviews.filter.completed')}</SelectItem>
                <SelectItem value="expired">{t('pages.accessReviews.filter.expired')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">{t('pages.accessReviews.loading')}</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.accessReviews.resourceName')} />
          ) : !filteredReviews || filteredReviews.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ClipboardList className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.accessReviews.empty')}</p>
              <p className="text-sm">{t('pages.accessReviews.emptyHint')}</p>
            </div>
          ) : (
          <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.accessReviews.table.review')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.accessReviews.table.type')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.accessReviews.table.status')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.accessReviews.table.period')}</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">{t('pages.accessReviews.table.progress')}</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">{t('pages.accessReviews.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {
                  filteredReviews?.map((review) => (
                    <TableRow key={review.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-indigo-100 flex items-center justify-center">
                            <ClipboardCheck className="h-5 w-5 text-indigo-700" />
                          </div>
                          <div>
                            <p className="font-medium">{review.name}</p>
                            <p className="text-sm text-muted-foreground max-w-xs truncate">{review.description || '-'}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge variant="outline">
                          {(REVIEW_TYPES as readonly string[]).includes(review.type) ? t(`pages.accessReviews.types.${review.type}`) : review.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[review.status] || 'bg-muted text-foreground'}`}>
                          {statusIcons[review.status]}
                          {review.status.replace('_', ' ')}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="text-sm">
                          <p>{formatDate(review.start_date)}</p>
                          <p className="text-muted-foreground">{t('pages.accessReviews.periodTo', { date: formatDate(review.end_date) })}</p>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="w-32">
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span>{review.reviewed_items || 0}/{review.total_items || 0}</span>
                            <span className="text-muted-foreground">{getProgress(review)}%</span>
                          </div>
                          <div className="h-2 bg-muted rounded-full overflow-hidden">
                            <div
                              className="h-full bg-indigo-600 rounded-full transition-all"
                              style={{ width: `${getProgress(review)}%` }}
                            />
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleViewReview(review)}>
                                <Eye className="h-4 w-4 mr-2" />
                                {t('pages.accessReviews.menu.view')}
                              </DropdownMenuItem>
                              {review.status === 'pending' && (
                                <>
                                  <DropdownMenuItem onClick={() => handleStartReview(review)}>
                                    <Play className="h-4 w-4 mr-2" />
                                    {t('pages.accessReviews.menu.start')}
                                  </DropdownMenuItem>
                                  <DropdownMenuItem onClick={() => handleEditReview(review)}>
                                    <Edit className="h-4 w-4 mr-2" />
                                    {t('pages.accessReviews.menu.edit')}
                                  </DropdownMenuItem>
                                </>
                              )}
                              {review.status === 'in_progress' && (
                                <DropdownMenuItem onClick={() => handleViewReview(review)}>
                                  <ClipboardCheck className="h-4 w-4 mr-2" />
                                  {t('pages.accessReviews.menu.continue')}
                                </DropdownMenuItem>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-muted-foreground">
                {t('pages.accessReviews.showing', { from: page * PAGE_SIZE + 1, to: Math.min((page + 1) * PAGE_SIZE, totalCount), total: totalCount })}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  {t('common.pagination.previous')}
                </Button>
                <span className="text-sm text-muted-foreground">
                  {t('common.pagination.pageOf', { page: page + 1, pages: Math.ceil(totalCount / PAGE_SIZE) })}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => p + 1)}
                  disabled={(page + 1) * PAGE_SIZE >= totalCount}
                >
                  {t('common.pagination.next')}
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
          </>
          )}
        </CardContent>
      </Card>

      {/* Create Access Review Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.accessReviews.createDialog.title')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t('pages.accessReviews.form.name')}</Label>
              <Input
                id="name"
                name="name"
                value={newReview.name}
                onChange={handleNewReviewChange}
                placeholder={t('pages.accessReviews.form.namePlaceholder')}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">{t('pages.accessReviews.form.description')}</Label>
              <Textarea
                id="description"
                name="description"
                value={newReview.description}
                onChange={handleNewReviewChange}
                placeholder={t('pages.accessReviews.form.descriptionPlaceholder')}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">{t('pages.accessReviews.form.type')}</Label>
              <Select value={newReview.type} onValueChange={(val) => setNewReview(prev => ({ ...prev, type: val }))}>
                <SelectTrigger id="type" className="w-full">
                  <SelectValue placeholder={t('pages.accessReviews.form.typePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">{t('pages.accessReviews.form.typeUserAccess')}</SelectItem>
                  <SelectItem value="role_assignment">{t('pages.accessReviews.form.typeRoleAssignment')}</SelectItem>
                  <SelectItem value="application_access">{t('pages.accessReviews.form.typeApplicationAccess')}</SelectItem>
                  <SelectItem value="privileged_access">{t('pages.accessReviews.form.typePrivilegedAccess')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="start_date">{t('pages.accessReviews.form.startDate')}</Label>
                <Input
                  id="start_date"
                  name="start_date"
                  type="date"
                  value={newReview.start_date}
                  onChange={handleNewReviewChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="end_date">{t('pages.accessReviews.form.endDate')}</Label>
                <Input
                  id="end_date"
                  name="end_date"
                  type="date"
                  value={newReview.end_date}
                  onChange={handleNewReviewChange}
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateModal(false)}
                disabled={createReviewMutation.isPending}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={createReviewMutation.isPending}>
                {createReviewMutation.isPending ? t('pages.accessReviews.createDialog.creating') : t('pages.accessReviews.createReview')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Access Review Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.accessReviews.editDialog.title')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">{t('pages.accessReviews.form.name')}</Label>
              <Input
                id="edit-name"
                name="name"
                value={editReview.name}
                onChange={handleEditReviewChange}
                placeholder={t('pages.accessReviews.form.namePlaceholder')}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">{t('pages.accessReviews.form.description')}</Label>
              <Textarea
                id="edit-description"
                name="description"
                value={editReview.description}
                onChange={handleEditReviewChange}
                placeholder={t('pages.accessReviews.form.descriptionPlaceholder')}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">{t('pages.accessReviews.form.type')}</Label>
              <Select value={editReview.type} onValueChange={(val) => setEditReview(prev => ({ ...prev, type: val }))}>
                <SelectTrigger id="edit-type" className="w-full">
                  <SelectValue placeholder={t('pages.accessReviews.form.typePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user_access">{t('pages.accessReviews.form.typeUserAccess')}</SelectItem>
                  <SelectItem value="role_assignment">{t('pages.accessReviews.form.typeRoleAssignment')}</SelectItem>
                  <SelectItem value="application_access">{t('pages.accessReviews.form.typeApplicationAccess')}</SelectItem>
                  <SelectItem value="privileged_access">{t('pages.accessReviews.form.typePrivilegedAccess')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-start_date">{t('pages.accessReviews.form.startDate')}</Label>
                <Input
                  id="edit-start_date"
                  name="start_date"
                  type="date"
                  value={editReview.start_date}
                  onChange={handleEditReviewChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-end_date">{t('pages.accessReviews.form.endDate')}</Label>
                <Input
                  id="edit-end_date"
                  name="end_date"
                  type="date"
                  value={editReview.end_date}
                  onChange={handleEditReviewChange}
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditModal(false)}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit">
                {t('pages.accessReviews.editDialog.save')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
