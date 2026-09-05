import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  MonitorPlay,
  CheckCircle2,
  XCircle,
  Clock,
  Download,
  StopCircle,
  Eye,
  Lock,
  Unlock,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import i18n from '../i18n'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ──────────────────────────────────────────────────────────────────────────────
// DTOs — mirror the backend structs exactly
// ──────────────────────────────────────────────────────────────────────────────

interface GuacSessionRequest {
  id: string
  org_id: string
  connection_id: string
  requester_id: string
  reason?: string
  status: string
  approver_id?: string
  decided_at?: string
  expires_at?: string
  created_at: string
}

/** Live active connection returned by the Guacamole REST API. */
interface GuacActiveSession {
  /** Active-connection UUID — used for terminate / share. */
  identifier: string
  connectionIdentifier: string
  username: string
  remoteHost: string
  /** Epoch milliseconds. */
  startDate: number
  /** Real OpenIDX user who launched the session (Guacamole itself only sees the
   * shared broker account). Present when resolvable from OpenIDX's ledger. */
  openidx_user?: string
}

/** Row from the guacamole_sessions DB table. */
interface GuacSessionRow {
  id: string
  connection_id: string
  user_id?: string
  guac_session_uuid?: string
  started_at: string
  ended_at?: string
  status: string
  transcript_available: boolean
  transcript_generated_at?: string
  recording_available: boolean
  on_legal_hold: boolean
}

// ──────────────────────────────────────────────────────────────────────────────
// Page
// ──────────────────────────────────────────────────────────────────────────────

export function GuacamoleSessionsPage() {
  const { t } = useTranslation()
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t('nav.items.privilegedSessions')}</h1>
        <p className="text-muted-foreground">{t('pages.guacSessions.subtitle')}</p>
      </div>

      <Tabs defaultValue="requests">
        <TabsList>
          <TabsTrigger value="requests">{t('pages.guacSessions.tabs.requests')}</TabsTrigger>
          <TabsTrigger value="active">{t('pages.guacSessions.tabs.active')}</TabsTrigger>
          <TabsTrigger value="history">{t('pages.guacSessions.tabs.history')}</TabsTrigger>
        </TabsList>

        <TabsContent value="requests">
          <PendingRequestsTab />
        </TabsContent>

        <TabsContent value="active">
          <ActiveSessionsTab />
        </TabsContent>

        <TabsContent value="history">
          <SessionHistoryTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tab: Pending Requests
// ──────────────────────────────────────────────────────────────────────────────

function PendingRequestsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['guac-session-requests'],
    queryFn: () =>
      api.get<{ requests: GuacSessionRequest[] }>(
        '/api/v1/access/guacamole/session-requests',
      ),
  })

  const requests: GuacSessionRequest[] = data?.requests ?? []

  const approveMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/access/guacamole/session-requests/${id}/approve`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-requests'] })
      toast({ title: t('pages.guacSessions.requests.toasts.approved') })
    },
    onError: () =>
      toast({
        title: t('pages.guacSessions.requests.toasts.approveFailed'),
        variant: 'destructive',
      }),
  })

  const denyMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/access/guacamole/session-requests/${id}/deny`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-requests'] })
      toast({ title: t('pages.guacSessions.requests.toasts.denied') })
    },
    onError: () =>
      toast({
        title: t('pages.guacSessions.requests.toasts.denyFailed'),
        variant: 'destructive',
      }),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Clock className="h-5 w-5" />
          {t('pages.guacSessions.requests.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="py-12 flex justify-center">
            <LoadingSpinner />
          </div>
        ) : isError ? (
          <QueryError error={error} resource={t('pages.guacSessions.requests.resourceName')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.guacSessions.requests.table.requester')}</TableHead>
                <TableHead>{t('pages.guacSessions.requests.table.connection')}</TableHead>
                <TableHead>{t('pages.guacSessions.requests.table.reason')}</TableHead>
                <TableHead>{t('pages.guacSessions.requests.table.requested')}</TableHead>
                <TableHead>{t('pages.guacSessions.requests.table.expires')}</TableHead>
                <TableHead className="w-40" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {requests.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-xs">{r.requester_id}</TableCell>
                  <TableCell className="font-mono text-xs">{r.connection_id}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {r.reason ?? '—'}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(r.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {r.expires_at ? new Date(r.expires_at).toLocaleString() : '—'}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-green-700 border-green-300 hover:bg-green-50"
                        disabled={approveMutation.isPending}
                        onClick={() => approveMutation.mutate(r.id)}
                      >
                        <CheckCircle2 className="mr-1 h-3 w-3" />
                        {t('pages.guacSessions.requests.approve')}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-destructive border-destructive/30 hover:bg-destructive/10"
                        disabled={denyMutation.isPending}
                        onClick={() => denyMutation.mutate(r.id)}
                      >
                        <XCircle className="mr-1 h-3 w-3" />
                        {t('pages.guacSessions.requests.deny')}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {requests.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center py-8 text-muted-foreground"
                  >
                    {t('pages.guacSessions.requests.empty')}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tab: Active Sessions
// ──────────────────────────────────────────────────────────────────────────────

function ActiveSessionsTab() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [terminateTarget, setTerminateTarget] = useState<GuacActiveSession | null>(null)
  const [terminateReason, setTerminateReason] = useState('')

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['guac-active-sessions'],
    queryFn: () =>
      api.get<{ sessions: GuacActiveSession[] }>('/api/v1/access/guacamole/sessions'),
    retry: (_, err: unknown) => {
      // Don't retry on 503 (Guacamole unconfigured)
      const status = (err as { response?: { status?: number } })?.response?.status
      return status !== 503
    },
  })

  const terminateMutation = useMutation({
    mutationFn: ({ identifier, reason }: { identifier: string; reason?: string }) =>
      api.post(`/api/v1/access/guacamole/sessions/${identifier}/terminate`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-active-sessions'] })
      toast({ title: t('pages.guacSessions.active.toasts.terminated') })
      setTerminateTarget(null)
      setTerminateReason('')
    },
    onError: () =>
      toast({
        title: t('pages.guacSessions.active.toasts.terminateFailed'),
        variant: 'destructive',
      }),
  })

  const monitorMutation = useMutation({
    mutationFn: (identifier: string) =>
      api.post<{ share_url: string }>(
        `/api/v1/access/guacamole/sessions/${identifier}/share`,
      ),
    onSuccess: (data) => {
      window.open((data as { share_url: string }).share_url, '_blank')
    },
    onError: (err: unknown) => {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 501) {
        toast({
          title: t('pages.guacSessions.active.toasts.monitorUnsupported'),
          variant: 'destructive',
        })
      } else {
        toast({
          title: t('pages.guacSessions.active.toasts.monitorFailed'),
          variant: 'destructive',
        })
      }
    },
  })

  // 503 → Guacamole unconfigured — show empty state instead of error
  const is503 =
    isError &&
    (error as { response?: { status?: number } })?.response?.status === 503

  const sessions: GuacActiveSession[] = data?.sessions ?? []

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MonitorPlay className="h-5 w-5" />
            {t('pages.guacSessions.active.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 flex justify-center">
              <LoadingSpinner />
            </div>
          ) : is503 ? (
            <p className="py-8 text-center text-muted-foreground">
              {t('pages.guacSessions.active.unconfigured')}
            </p>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.guacSessions.active.resourceName')} />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.guacSessions.active.table.user')}</TableHead>
                  <TableHead>{t('pages.guacSessions.active.table.remoteHost')}</TableHead>
                  <TableHead>{t('pages.guacSessions.active.table.connection')}</TableHead>
                  <TableHead>{t('pages.guacSessions.active.table.started')}</TableHead>
                  <TableHead className="w-48" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.identifier}>
                    <TableCell className="font-medium">
                      {s.openidx_user || s.username}
                      {s.openidx_user && (
                        <span className="block text-xs font-normal text-muted-foreground">
                          {t('pages.guacSessions.active.via', { username: s.username })}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{s.remoteHost}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {s.connectionIdentifier}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(s.startDate).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={monitorMutation.isPending}
                          onClick={() => monitorMutation.mutate(s.identifier)}
                        >
                          <Eye className="mr-1 h-3 w-3" />
                          {t('pages.guacSessions.active.monitor')}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-destructive border-destructive/30 hover:bg-destructive/10"
                          onClick={() => {
                            setTerminateTarget(s)
                            setTerminateReason('')
                          }}
                        >
                          <StopCircle className="mr-1 h-3 w-3" />
                          {t('pages.guacSessions.active.terminate')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {sessions.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center py-8 text-muted-foreground"
                    >
                      {t('pages.guacSessions.active.empty')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Terminate AlertDialog — rendered outside the table so it mounts at the
          document level and doesn't create nested interactive elements */}
      <AlertDialog
        open={!!terminateTarget}
        onOpenChange={(open) => {
          if (!open) {
            setTerminateTarget(null)
            setTerminateReason('')
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.guacSessions.active.confirmTerminate.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.guacSessions.active.confirmTerminate.descriptionBefore')}
              <span className="font-medium">{terminateTarget?.openidx_user || terminateTarget?.username}</span>
              {t('pages.guacSessions.active.confirmTerminate.descriptionMiddle')}
              <span className="font-mono text-xs">{terminateTarget?.connectionIdentifier}</span>
              {t('pages.guacSessions.active.confirmTerminate.descriptionAfter')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-2">
            <label className="text-sm font-medium">
              {t('pages.guacSessions.active.confirmTerminate.reason')}
            </label>
            <Input
              className="mt-1"
              placeholder={t('pages.guacSessions.active.confirmTerminate.reasonPlaceholder')}
              value={terminateReason}
              onChange={(e) => setTerminateReason(e.target.value)}
            />
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive hover:bg-destructive/90"
              onClick={() => {
                if (terminateTarget) {
                  terminateMutation.mutate({
                    identifier: terminateTarget.identifier,
                    reason: terminateReason || undefined,
                  })
                }
              }}
            >
              {t('pages.guacSessions.active.terminate')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Tab: Session History
// ──────────────────────────────────────────────────────────────────────────────

function SessionHistoryTab() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [holdTarget, setHoldTarget] = useState<{
    session: GuacSessionRow
    action: 'place' | 'release'
  } | null>(null)
  const [holdReason, setHoldReason] = useState('')

  const placeHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/access/guacamole/sessions/${id}/legal-hold`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-history'] })
      toast({ title: t('pages.guacSessions.history.toasts.held') })
      setHoldTarget(null)
      setHoldReason('')
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.guacSessions.history.toasts.holdFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const releaseHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.delete(`/api/v1/access/guacamole/sessions/${id}/legal-hold`, {
        data: { reason },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-history'] })
      toast({ title: t('pages.guacSessions.history.toasts.released') })
      setHoldTarget(null)
      setHoldReason('')
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.guacSessions.history.toasts.releaseFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['guac-session-history'],
    queryFn: () =>
      api.get<{ sessions: GuacSessionRow[] }>(
        '/api/v1/access/guacamole/session-history',
      ),
  })

  const sessions: GuacSessionRow[] = data?.sessions ?? []

  return (
    <>
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MonitorPlay className="h-5 w-5" />
          {t('pages.guacSessions.history.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="py-12 flex justify-center">
            <LoadingSpinner />
          </div>
        ) : isError ? (
          <QueryError error={error} resource={t('pages.guacSessions.history.resourceName')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.guacSessions.history.table.user')}</TableHead>
                <TableHead>{t('pages.guacSessions.history.table.connection')}</TableHead>
                <TableHead>{t('pages.guacSessions.history.table.started')}</TableHead>
                <TableHead>{t('pages.guacSessions.history.table.ended')}</TableHead>
                <TableHead>{t('pages.guacSessions.history.table.status')}</TableHead>
                <TableHead className="w-64" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-mono text-xs">
                    {s.user_id ?? '—'}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{s.connection_id}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(s.started_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {s.ended_at ? new Date(s.ended_at).toLocaleString() : '—'}
                  </TableCell>
                  <TableCell>
                    <SessionStatusBadge status={s.status} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!s.transcript_available}
                        title={
                          s.transcript_available
                            ? t('pages.guacSessions.history.transcriptAvailable')
                            : t('pages.guacSessions.history.transcriptUnavailable')
                        }
                        onClick={() => downloadTranscript(s.id, toast)}
                      >
                        <Download className="mr-1 h-3 w-3" />
                        {t('pages.guacSessions.history.transcript')}
                      </Button>
                      {s.recording_available &&
                        (s.on_legal_hold ? (
                          <>
                            <Badge variant="secondary" className="text-amber-700">
                              {t('pages.guacSessions.history.onHold')}
                            </Badge>
                            <Button
                              size="sm"
                              variant="outline"
                              title={t('pages.guacSessions.history.releaseHoldTitle')}
                              onClick={() => {
                                setHoldTarget({ session: s, action: 'release' })
                                setHoldReason('')
                              }}
                            >
                              <Unlock className="mr-1 h-3 w-3 text-amber-600" />
                              {t('pages.guacSessions.history.releaseHold')}
                            </Button>
                          </>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            title={t('pages.guacSessions.history.placeHoldTitle')}
                            onClick={() => {
                              setHoldTarget({ session: s, action: 'place' })
                              setHoldReason('')
                            }}
                          >
                            <Lock className="mr-1 h-3 w-3" />
                            {t('pages.guacSessions.history.placeHold')}
                          </Button>
                        ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {sessions.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center py-8 text-muted-foreground"
                  >
                    {t('pages.guacSessions.history.empty')}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>

    {/* Legal-hold reason dialog — replaces the old window.prompt flow so the
        audited reason gets a proper, accessible input */}
    <AlertDialog
      open={!!holdTarget}
      onOpenChange={(open) => {
        if (!open) {
          setHoldTarget(null)
          setHoldReason('')
        }
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {holdTarget?.action === 'place'
              ? t('pages.guacSessions.history.holdDialog.placeTitle')
              : t('pages.guacSessions.history.holdDialog.releaseTitle')}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {holdTarget?.action === 'place'
              ? t('pages.guacSessions.history.holdDialog.placeDescription')
              : t('pages.guacSessions.history.holdDialog.releaseDescription')}{' '}
            {t('pages.guacSessions.history.holdDialog.audited')}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="py-2">
          <label className="text-sm font-medium">
            {t('pages.guacSessions.history.holdDialog.reason')}
            {holdTarget?.action === 'place' && <span className="text-red-500 ml-1">*</span>}
          </label>
          <Input
            className="mt-1"
            placeholder={t('pages.guacSessions.history.holdDialog.reasonPlaceholder')}
            value={holdReason}
            onChange={(e) => setHoldReason(e.target.value)}
          />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
          <AlertDialogAction
            disabled={holdTarget?.action === 'place' && !holdReason.trim()}
            onClick={() => {
              if (!holdTarget) return
              if (holdTarget.action === 'place') {
                placeHoldMutation.mutate({ id: holdTarget.session.id, reason: holdReason })
              } else {
                releaseHoldMutation.mutate({ id: holdTarget.session.id, reason: holdReason })
              }
            }}
          >
            {holdTarget?.action === 'place'
              ? t('pages.guacSessions.history.placeHold')
              : t('pages.guacSessions.history.releaseHold')}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function SessionStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation()
  switch (status) {
    case 'active':
      return (
        <Badge variant="success">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          {t('pages.guacSessions.statuses.active')}
        </Badge>
      )
    case 'ended':
    case 'completed':
      return <Badge variant="secondary">{status}</Badge>
    case 'error':
    case 'failed':
      return <Badge variant="destructive">{status}</Badge>
    default:
      return <Badge variant="secondary">{status}</Badge>
  }
}

/**
 * Download the session transcript via the shared axios client so the
 * Authorization header is sent automatically. We request the response as a
 * blob, create an object URL, click a temporary anchor, then revoke the URL.
 * This mirrors the remote-support.tsx downloadRecording approach but uses
 * api.get with responseType:'blob' instead of raw fetch.
 */
async function downloadTranscript(
  sessionId: string,
  toast: ReturnType<typeof useToast>['toast'],
) {
  try {
    const blob = await api.get<Blob>(
      `/api/v1/access/guacamole/sessions/${sessionId}/transcript`,
      { responseType: 'blob' },
    )
    const objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = `transcript-${sessionId}.txt`
    a.click()
    URL.revokeObjectURL(objectUrl)
  } catch (err: unknown) {
    const status = (err as { response?: { status?: number } })?.response?.status
    if (status === 404) {
      toast({
        title: i18n.t('pages.guacSessions.history.toasts.transcriptMissing'),
        variant: 'destructive',
      })
    } else {
      toast({
        title: i18n.t('pages.guacSessions.history.toasts.transcriptFailed'),
        variant: 'destructive',
      })
    }
  }
}
