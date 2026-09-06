import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search, Plus, Webhook, Trash2, RefreshCw, CheckCircle, XCircle, Clock } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'

interface Subscription {
  id: string
  name: string
  url: string
  events: string[]
  status: string
  created_by: string
  created_at: string
}

interface Delivery {
  id: string
  subscription_id: string
  event_type: string
  response_status?: number
  attempt: number
  status: string
  created_at: string
  delivered_at?: string
}

/**
 * The event names a subscriber matches on. They are wire identifiers, not
 * prose, so they stay raw in the picker, on the subscription card and in
 * the delivery log.
 */
const EVENT_TYPES = [
  'user.created',
  'user.updated',
  'user.deleted',
  'login.success',
  'login.failed',
  'login.high_risk',
  'group.updated',
  'role.updated',
  'policy.violated',
  'review.completed',
]

export function WebhooksPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 10

  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [newSecret, setNewSecret] = useState('')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])

  const [deleteTarget, setDeleteTarget] = useState<Subscription | null>(null)
  const [expandedSubscription, setExpandedSubscription] = useState<string | null>(null)

  const { data: subsData, isLoading, isError, error } = useQuery({
    queryKey: ['webhooks', page, search],
    queryFn: () =>
      api.get<{ subscriptions: Subscription[] }>(
        `/api/v1/webhooks?page=${page}&page_size=${pageSize}&search=${encodeURIComponent(search)}`
      ),
  })

  const subscriptions = subsData?.subscriptions || []

  const createMutation = useMutation({
    mutationFn: (body: { name: string; url: string; secret: string; events: string[] }) =>
      api.post('/api/v1/webhooks', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setCreateOpen(false)
      setNewName('')
      setNewUrl('')
      setNewSecret('')
      setSelectedEvents([])
      toast({ title: t('pages.webhooks.toasts.created') })
    },
    onError: () => {
      toast({ title: t('pages.webhooks.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/webhooks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setDeleteTarget(null)
      toast({ title: t('pages.webhooks.toasts.deleted') })
    },
    onError: () => {
      toast({ title: t('pages.webhooks.toasts.deleteFailed'), variant: 'destructive' })
    },
  })

  function toggleEvent(event: string) {
    setSelectedEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    )
  }

  function truncateUrl(url: string, maxLen = 50) {
    return url.length > maxLen ? url.substring(0, maxLen) + '...' : url
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.webhooks')}</h1>
          <p className="text-muted-foreground">{t('pages.webhooks.subtitle')}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          {t('pages.webhooks.create')}
        </Button>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t('pages.webhooks.searchPlaceholder')}
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">{t('pages.webhooks.loading')}</p>
        </div>
      ) : isError ? (
        <QueryError error={error} resource={t('pages.webhooks.resource')} />
      ) : subscriptions.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Webhook className="h-12 w-12 text-muted-foreground/40 mb-3" />
          <p className="font-medium">{t('pages.webhooks.emptyTitle')}</p>
          <p className="text-sm">{t('pages.webhooks.emptyHint')}</p>
        </div>
      ) : (
        <div className="space-y-4">
          {subscriptions.map((sub) => (
            <Card key={sub.id}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div className="flex items-center gap-3">
                  <Webhook className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <CardTitle className="text-base">{sub.name}</CardTitle>
                    <p className="text-sm text-muted-foreground font-mono">{truncateUrl(sub.url)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={sub.status === 'active' ? 'default' : 'secondary'}>
                    {t(`pages.webhooks.statuses.${sub.status}`, { defaultValue: sub.status })}
                  </Badge>
                  <div className="flex gap-1 flex-wrap max-w-xs">
                    {sub.events.slice(0, 3).map((event) => (
                      <Badge key={event} variant="outline" className="text-xs">
                        {event}
                      </Badge>
                    ))}
                    {sub.events.length > 3 && (
                      <Badge variant="outline" className="text-xs">
                        +{sub.events.length - 3}
                      </Badge>
                    )}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setExpandedSubscription(
                        expandedSubscription === sub.id ? null : sub.id
                      )
                    }
                  >
                    {t('pages.webhooks.deliveries')}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setDeleteTarget(sub)}
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </CardHeader>

              {expandedSubscription === sub.id && (
                <CardContent>
                  <DeliveryHistorySection subscriptionId={sub.id} />
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Create Webhook Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.webhooks.form.title')}</DialogTitle>
            <DialogDescription>{t('pages.webhooks.form.desc')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.webhooks.form.name')}</label>
              <Input
                placeholder={t('pages.webhooks.form.namePlaceholder')}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.webhooks.form.url')}</label>
              {/* The sample URL teaches the format the API accepts. */}
              <Input
                placeholder="https://example.com/webhook"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.webhooks.form.secret')}</label>
              <Input
                placeholder={t('pages.webhooks.form.secretPlaceholder')}
                type="password"
                value={newSecret}
                onChange={(e) => setNewSecret(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.webhooks.form.events')}</label>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {EVENT_TYPES.map((event) => (
                  <label
                    key={event}
                    className="flex items-center gap-2 text-sm cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selectedEvents.includes(event)}
                      onChange={() => toggleEvent(event)}
                      className="rounded border-border"
                    />
                    {event}
                  </label>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              disabled={!newName.trim() || !newUrl.trim() || selectedEvents.length === 0 || createMutation.isPending}
              onClick={() =>
                createMutation.mutate({
                  name: newName,
                  url: newUrl,
                  secret: newSecret,
                  events: selectedEvents,
                })
              }
            >
              {createMutation.isPending
                ? t('pages.webhooks.form.creating')
                : t('pages.webhooks.form.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.webhooks.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.webhooks.deleteDialog.desc', {
                name: deleteTarget?.name ?? '',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function DeliveryHistorySection({ subscriptionId }: { subscriptionId: string }) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()

  const { data: deliveriesData, isLoading, isError, error } = useQuery({
    queryKey: ['webhook-deliveries', subscriptionId],
    queryFn: () =>
      api.get<{ deliveries: Delivery[] }>(
        `/api/v1/webhooks/${subscriptionId}/deliveries`
      ),
  })

  const retryMutation = useMutation({
    mutationFn: (deliveryId: string) =>
      api.post(`/api/v1/webhooks/deliveries/${deliveryId}/retry`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhook-deliveries', subscriptionId] })
      toast({ title: t('pages.webhooks.toasts.retryQueued') })
    },
    onError: () => {
      toast({ title: t('pages.webhooks.toasts.retryFailed'), variant: 'destructive' })
    },
  })

  const deliveries = deliveriesData?.deliveries || []

  function statusBadge(status: string) {
    switch (status) {
      case 'delivered':
        return (
          <Badge className="bg-green-100 text-green-800 hover:bg-green-100">
            <CheckCircle className="mr-1 h-3 w-3" />
            {t('pages.webhooks.deliveryStatuses.delivered')}
          </Badge>
        )
      case 'failed':
        return (
          <Badge className="bg-red-100 text-red-800 hover:bg-red-100">
            <XCircle className="mr-1 h-3 w-3" />
            {t('pages.webhooks.deliveryStatuses.failed')}
          </Badge>
        )
      case 'pending':
        return (
          <Badge className="bg-yellow-100 text-yellow-800 hover:bg-yellow-100">
            <Clock className="mr-1 h-3 w-3" />
            {t('pages.webhooks.deliveryStatuses.pending')}
          </Badge>
        )
      default:
        return (
          <Badge variant="secondary">
            {t(`pages.webhooks.deliveryStatuses.${status}`, { defaultValue: status })}
          </Badge>
        )
    }
  }

  return (
    <div className="space-y-3 border-t pt-4">
      <h4 className="text-sm font-medium">{t('pages.webhooks.history.title')}</h4>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">
          {t('pages.webhooks.history.loading')}
        </p>
      ) : isError ? (
        <QueryError error={error} resource={t('pages.webhooks.history.resource')} />
      ) : deliveries.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('pages.webhooks.history.empty')}
        </p>
      ) : (
        <div className="space-y-2">
          {deliveries.map((delivery) => (
            <div
              key={delivery.id}
              className="flex items-center justify-between p-3 border rounded-md"
            >
              <div className="flex items-center gap-3">
                {statusBadge(delivery.status)}
                <Badge variant="outline" className="text-xs">
                  {delivery.event_type}
                </Badge>
                {delivery.response_status && (
                  <span className="text-xs text-muted-foreground">
                    {t('pages.webhooks.history.httpStatus', {
                      code: delivery.response_status,
                    })}
                  </span>
                )}
                <span className="text-xs text-muted-foreground">
                  {t('pages.webhooks.history.attempt', { n: delivery.attempt })}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">
                  {new Date(delivery.created_at).toLocaleString()}
                </span>
                {delivery.status === 'failed' && (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={retryMutation.isPending}
                    onClick={() => retryMutation.mutate(delivery.id)}
                  >
                    <RefreshCw className="mr-1 h-3 w-3" />
                    {t('pages.webhooks.history.retry')}
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
