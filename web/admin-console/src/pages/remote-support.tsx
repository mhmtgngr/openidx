import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Video, Play, Square, MonitorPlay, Eye, MousePointer2, Clock,
  CheckCircle2, XCircle, AlertCircle, Download, Trash2, Infinity as InfinityIcon,
  Lock, Unlock, Shield, Globe,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api, baseURL } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { RemoteSupportViewer } from '../components/remote-support/remote-support-viewer'
import { RelayRenderer } from '../components/remote-support/relay-renderer'
import { ConfirmAction } from '../components/confirm-action'

/**
 * Remote support admin page (Phase 4). Lists sessions, lets an admin start
 * a new one against an enrolled agent, and opens an embedded WebRTC viewer
 * that streams the device screen and dispatches input back over a data
 * channel.
 */

interface RemoteSession {
  id: string
  agent_id: string
  admin_user_id: string
  status: 'pending' | 'active' | 'ended' | 'expired' | 'declined'
  mode: 'interactive' | 'view'
  transport?: 'webrtc' | 'relay'
  ice_servers: unknown
  end_reason?: string
  recording_url?: string
  recording_enabled: boolean
  recording_size_bytes?: number
  recording_chunk_count?: number
  recording_finalized_at?: string
  is_on_legal_hold: boolean
  started_at: string
  accepted_at?: string
  ended_at?: string
  notes?: string
  last_activity_at: string
}

interface StartSessionResponse {
  id: string
  status: string
  agent_id: string
  mode: string
  admin_ws: string
  agent_ws: string
  ice_servers: unknown
  recording_enabled: boolean
  transport?: 'webrtc' | 'relay'
}

export function RemoteSupportPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [startOpen, setStartOpen] = useState(false)
  const [viewerSession, setViewerSession] = useState<{
    id: string
    agentId: string
    mode: 'interactive' | 'view'
    transport: 'webrtc' | 'relay'
    wsPath: string
    iceServers: unknown
    recordingEnabled: boolean
  } | null>(null)

  const { data: sessions = [], isLoading, isError, error } = useQuery({
    queryKey: ['remote-support-sessions'],
    queryFn: async () => {
      // Normalize every rendered field so a nil/absent value from the backend
      // (Go zero-value / dropped JSON key) can't blow up the row render — e.g.
      // `id` feeds `.slice(0,8)` and numeric byte/chunk counts feed formatting.
      const raw = await api.get<RemoteSession[]>('/api/v1/access/remote-support/sessions')
      return (raw ?? []).map((s) => ({
        ...s,
        id: s.id ?? '',
        agent_id: s.agent_id ?? '',
        recording_size_bytes: s.recording_size_bytes ?? 0,
        recording_chunk_count: s.recording_chunk_count ?? 0,
        recording_enabled: s.recording_enabled ?? false,
        is_on_legal_hold: s.is_on_legal_hold ?? false,
      }))
    },
    refetchInterval: 5000,
  })

  const endMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/access/remote-support/sessions/${id}/end`, { reason: 'admin_ended' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-support-sessions'] })
      toast({ title: t('pages.remoteSupport.toasts.ended') })
    },
    onError: () =>
      toast({ title: t('pages.remoteSupport.toasts.endFailed'), variant: 'destructive' }),
  })

  const placeHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/access/remote-support/sessions/${id}/legal-hold`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-support-sessions'] })
      toast({ title: t('pages.remoteSupport.toasts.held') })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.remoteSupport.toasts.holdFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const releaseHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.delete(`/api/v1/access/remote-support/sessions/${id}/legal-hold`, {
        data: { reason },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-support-sessions'] })
      toast({ title: t('pages.remoteSupport.toasts.released') })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.remoteSupport.toasts.releaseFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  function openViewer(session: RemoteSession, wsPath: string) {
    setViewerSession({
      id: session.id,
      agentId: session.agent_id,
      mode: session.mode,
      transport: session.transport === 'relay' ? 'relay' : 'webrtc',
      wsPath,
      iceServers: session.ice_servers,
      recordingEnabled: session.recording_enabled,
    })
  }

  return (
    <div className="space-y-6 p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">{t('pages.remoteSupport.title')}</h1>
          <p className="text-muted-foreground">{t('pages.remoteSupport.subtitle')}</p>
        </div>
        <Button onClick={() => setStartOpen(true)}>
          <Video className="mr-2 h-4 w-4" /> {t('pages.remoteSupport.startSession')}
        </Button>
      </div>

      <RetentionPolicyCard />

      <Card>
        <CardHeader>
          <CardTitle>{t('pages.remoteSupport.listTitle')}</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 flex justify-center"><LoadingSpinner /></div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.remoteSupport.resourceName')} />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.remoteSupport.table.session')}</TableHead>
                  <TableHead>{t('pages.remoteSupport.table.agent')}</TableHead>
                  <TableHead>{t('pages.remoteSupport.table.mode')}</TableHead>
                  <TableHead>{t('pages.remoteSupport.table.connection')}</TableHead>
                  <TableHead>{t('pages.remoteSupport.table.status')}</TableHead>
                  <TableHead>{t('pages.remoteSupport.table.started')}</TableHead>
                  <TableHead className="w-48" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-mono text-xs">{s.id.slice(0, 8)}…</TableCell>
                    <TableCell className="font-mono">{s.agent_id}</TableCell>
                    <TableCell><ModeBadge mode={s.mode} /></TableCell>
                    <TableCell><TransportBadge transport={s.transport} /></TableCell>
                    <TableCell><StatusBadge status={s.status} reason={s.end_reason} /></TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(s.started_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {(s.status === 'pending' || s.status === 'active') && (
                          <>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openViewer(s, `/api/v1/access/remote-support/sessions/${s.id}/ws`)}
                            >
                              <MonitorPlay className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.openViewer')}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-destructive"
                              onClick={() => endMutation.mutate(s.id)}
                            >
                              <Square className="h-3 w-3" />
                            </Button>
                          </>
                        )}
                        {s.recording_url && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => downloadRecording(s.id)}
                            title={t('pages.remoteSupport.downloadRecording', {
                              size: formatBytes(s.recording_size_bytes ?? 0),
                            })}
                          >
                            <Download className="h-3 w-3" />
                          </Button>
                        )}
                        {s.recording_url && (
                          s.is_on_legal_hold ? (
                            <ConfirmAction
                              title={t('pages.remoteSupport.confirmRelease.title')}
                              description={t('pages.remoteSupport.confirmRelease.description')}
                              destructive
                              requireReason
                              confirmLabel={t('pages.remoteSupport.confirmRelease.confirm')}
                              onConfirm={(reason) =>
                                releaseHoldMutation.mutateAsync({ id: s.id, reason: reason! })
                              }
                            >
                              {(open) => (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  title={t('pages.remoteSupport.confirmRelease.buttonTitle')}
                                  onClick={open}
                                >
                                  <Unlock className="h-3 w-3 text-amber-600" />
                                </Button>
                              )}
                            </ConfirmAction>
                          ) : (
                            <ConfirmAction
                              title={t('pages.remoteSupport.confirmHold.title')}
                              description={t('pages.remoteSupport.confirmHold.description')}
                              requireReason
                              confirmLabel={t('pages.remoteSupport.confirmHold.confirm')}
                              onConfirm={(reason) =>
                                placeHoldMutation.mutateAsync({ id: s.id, reason: reason! })
                              }
                            >
                              {(open) => (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  title={t('pages.remoteSupport.confirmHold.buttonTitle')}
                                  onClick={open}
                                >
                                  <Lock className="h-3 w-3" />
                                </Button>
                              )}
                            </ConfirmAction>
                          )
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {sessions.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      {t('pages.remoteSupport.empty')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {startOpen && (
        <StartSessionDialog
          onClose={() => setStartOpen(false)}
          onStarted={(resp) => {
            queryClient.invalidateQueries({ queryKey: ['remote-support-sessions'] })
            setStartOpen(false)
            openViewer(
              {
                id: resp.id,
                agent_id: resp.agent_id,
                admin_user_id: '',
                status: (resp.status as RemoteSession['status']),
                mode: (resp.mode === 'view' ? 'view' : 'interactive'),
                transport: resp.transport === 'relay' ? 'relay' : 'webrtc',
                ice_servers: resp.ice_servers,
                recording_enabled: resp.recording_enabled,
                is_on_legal_hold: false,
                started_at: new Date().toISOString(),
                last_activity_at: new Date().toISOString(),
              },
              resp.admin_ws,
            )
          }}
        />
      )}

      {viewerSession && (
        <Dialog open onOpenChange={(o) => !o && setViewerSession(null)}>
          <DialogContent
            className="max-w-5xl"
            // The viewer is an interactive control surface: clicking / dragging
            // on the remote screen and typing must go to the video overlay, not
            // dismiss the dialog or get swallowed by Radix's focus trap. Disable
            // outside-interaction auto-close and focus-steal so pointer + key
            // events reach the RemoteSupportViewer.
            onPointerDownOutside={(e) => e.preventDefault()}
            onInteractOutside={(e) => e.preventDefault()}
            onOpenAutoFocus={(e) => e.preventDefault()}
          >
            <DialogHeader>
              <DialogTitle>
                {t('pages.remoteSupport.viewer.title', { agent: viewerSession.agentId })}
                <Badge className="ml-2" variant={viewerSession.mode === 'interactive' ? 'default' : 'secondary'}>
                  {t(`pages.remoteSupport.modes.${viewerSession.mode}`)}
                </Badge>
              </DialogTitle>
              <DialogDescription>
                {t('pages.remoteSupport.viewer.description')}
              </DialogDescription>
            </DialogHeader>
            {viewerSession.transport === 'relay' ? (
              <RelayRenderer
                wsUrl={(baseURL.replace(/^http/, 'ws') + viewerSession.wsPath)}
                mode={viewerSession.mode}
                onPopOut={() => {
                  // Open the session in a dedicated window (second-monitor
                  // friendly). The dialog stays open so the End button and
                  // session state remain here; closing the popout just stops
                  // viewing. Relay-only (reconstructable from a URL).
                  const q = new URLSearchParams({
                    session: viewerSession.id,
                    ws: viewerSession.wsPath,
                    mode: viewerSession.mode,
                  })
                  window.open(
                    `${window.location.origin}/remote-support/live?${q.toString()}`,
                    `oidx-rs-${viewerSession.id}`,
                    'noopener,width=1280,height=800',
                  )
                  setViewerSession(null)
                }}
                onEnd={() => {
                  endMutation.mutate(viewerSession.id)
                  setViewerSession(null)
                }}
              />
            ) : (
              <RemoteSupportViewer
                wsUrl={(baseURL.replace(/^http/, 'ws') + viewerSession.wsPath)}
                mode={viewerSession.mode}
                iceServers={normalizeIce(viewerSession.iceServers)}
                sessionId={viewerSession.id}
                recordingEnabled={viewerSession.recordingEnabled}
                onClose={() => setViewerSession(null)}
                onEnd={() => {
                  endMutation.mutate(viewerSession.id)
                  setViewerSession(null)
                }}
              />
            )}
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}

interface RetentionPolicyResponse {
  org_id: string
  retention_days: number
  /** "policy" when a per-org row exists, "default" when falling back to the
   *  server's configured default. The editor uses this to label the source
   *  and decide whether the displayed value is editable-with-pending-state. */
  source: 'policy' | 'default'
  updated_at?: string
  updated_by?: string
}

/**
 * Per-tenant recording-retention editor. Reads the caller's org policy
 * (falls back to the server's configured default when no row exists) and
 * lets admins set / change / clear it. retention_days = 0 means "infinite"
 * — we show that as a distinct UI state with an explicit "Set to
 * infinite" affordance so it's not a hand-typed surprise.
 */
function RetentionPolicyCard() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const qc = useQueryClient()
  const [pending, setPending] = useState<number | ''>('')

  const { data, isLoading } = useQuery({
    queryKey: ['recording-retention-policy'],
    queryFn: () => api.get<RetentionPolicyResponse>('/api/v1/access/recording-retention-policy'),
  })

  const saveMutation = useMutation({
    mutationFn: (retentionDays: number) =>
      api.put<RetentionPolicyResponse>('/api/v1/access/recording-retention-policy', {
        retention_days: retentionDays,
      }),
    onSuccess: (resp) => {
      qc.setQueryData(['recording-retention-policy'], resp)
      setPending('')
      toast({
        title: resp.retention_days === 0
          ? t('pages.remoteSupport.retention.savedInfinite')
          : t('pages.remoteSupport.retention.savedDays', { count: resp.retention_days }),
      })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.remoteSupport.retention.saveFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const currentDays = data?.retention_days ?? 0
  const source = data?.source ?? 'default'

  function commit(value: number) {
    if (Number.isNaN(value) || value < 0) return
    saveMutation.mutate(value)
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between text-base">
          <span>{t('pages.remoteSupport.retention.title')}</span>
          <RetentionSourceBadge source={source} />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSpinner />
        ) : (
          <div className="space-y-3">
            <div className="text-sm">
              {currentDays === 0 ? (
                <span className="inline-flex items-center gap-2">
                  <InfinityIcon className="h-4 w-4 text-amber-600" />
                  {t('pages.remoteSupport.retention.infinite')}
                </span>
              ) : (
                <span>
                  {t('pages.remoteSupport.retention.keptBefore')}
                  <strong>{t('pages.remoteSupport.retention.keptDays', { count: currentDays })}</strong>
                  {source === 'default' && (
                    <span className="text-muted-foreground">
                      {t('pages.remoteSupport.retention.serverDefaultNote')}
                    </span>
                  )}.
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={0}
                placeholder={currentDays === 0
                  ? t('pages.remoteSupport.retention.daysPlaceholder')
                  : String(currentDays)}
                value={pending}
                onChange={(e) => {
                  const v = e.target.value
                  setPending(v === '' ? '' : Math.max(0, parseInt(v, 10) || 0))
                }}
                className="w-32"
                disabled={saveMutation.isPending}
              />
              <span className="text-sm text-muted-foreground">{t('pages.remoteSupport.retention.days')}</span>
              <Button
                size="sm"
                disabled={pending === '' || saveMutation.isPending}
                onClick={() => commit(pending as number)}
              >
                {t('pages.remoteSupport.retention.save')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={saveMutation.isPending || currentDays === 0}
                onClick={() => commit(0)}
                title={t('pages.remoteSupport.retention.setInfiniteTitle')}
              >
                <InfinityIcon className="mr-1 h-3 w-3" />
                {t('pages.remoteSupport.retention.setInfinite')}
              </Button>
            </div>

            <p className="text-xs text-muted-foreground">
              {t('pages.remoteSupport.retention.hintBefore')}
              <code>0</code>
              {t('pages.remoteSupport.retention.hintAfter')}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function RetentionSourceBadge({ source }: { source: 'policy' | 'default' }) {
  const { t } = useTranslation()
  if (source === 'policy')
    return <Badge variant="success">{t('pages.remoteSupport.retention.sourcePolicy')}</Badge>
  return (
    <Badge variant="secondary" className="gap-1">
      <Trash2 className="h-3 w-3" /> {t('pages.remoteSupport.retention.sourceDefault')}
    </Badge>
  )
}

function ModeBadge({ mode }: { mode: 'interactive' | 'view' }) {
  const { t } = useTranslation()
  if (mode === 'interactive')
    return <Badge><MousePointer2 className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.modes.interactive')}</Badge>
  return <Badge variant="secondary"><Eye className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.modes.view')}</Badge>
}

// TransportBadge shows how the session's media travels. Relay is the zero-trust
// path (media + control over the Ziti overlay through the broker); WebRTC is
// direct P2P. Makes "did it go over Ziti?" answerable at a glance.
function TransportBadge({ transport }: { transport?: 'webrtc' | 'relay' }) {
  const { t } = useTranslation()
  if (transport === 'relay')
    return (
      <Badge className="bg-emerald-600 hover:bg-emerald-600" title={t('pages.remoteSupport.transports.relayTitle')}>
        <Shield className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.transports.relay')}
      </Badge>
    )
  if (transport === 'webrtc')
    return (
      <Badge variant="secondary" title={t('pages.remoteSupport.transports.directTitle')}>
        <Globe className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.transports.direct')}
      </Badge>
    )
  return <span className="text-muted-foreground text-xs">—</span>
}

function StatusBadge({ status, reason }: { status: RemoteSession['status']; reason?: string }) {
  const { t } = useTranslation()
  switch (status) {
    case 'active':
      return <Badge variant="success"><CheckCircle2 className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.statuses.active')}</Badge>
    case 'pending':
      return <Badge variant="warning"><Clock className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.statuses.pending')}</Badge>
    case 'ended':
      return <Badge variant="secondary" title={reason}>{t('pages.remoteSupport.statuses.ended')}</Badge>
    case 'expired':
      return <Badge variant="destructive"><AlertCircle className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.statuses.expired')}</Badge>
    case 'declined':
      return <Badge variant="destructive"><XCircle className="mr-1 h-3 w-3" /> {t('pages.remoteSupport.statuses.declined')}</Badge>
    default:
      return <Badge variant="secondary">{status}</Badge>
  }
}

// supportsRelay reports whether this browser can decode the relay transport's
// VP8 stream (WebCodecs). Chromium-based browsers can; Firefox/Safari currently
// cannot, so we transparently prefer WebRTC there.
function supportsRelay(): boolean {
  return typeof window !== 'undefined' && 'VideoDecoder' in window
}

interface StartSessionDialogProps {
  onClose: () => void
  onStarted: (resp: StartSessionResponse) => void
}

// AgentSummary is the subset of the /agents list the picker needs.
interface AgentSummary {
  agent_id: string
  hostname?: string
  platform?: string
  status?: string
  last_seen_at?: string | null
}

// isOnline treats a device as online if it reported within the last ~2 minutes
// (the agent baseline poll is 30s, so this tolerates a couple of missed beats).
function isOnline(a: AgentSummary): boolean {
  if (!a.last_seen_at) return false
  return Date.now() - new Date(a.last_seen_at).getTime() < 120_000
}

// isRecent keeps a device in the default picker if it has been seen in the last
// 24h — recent enough to be a real, reachable target rather than a stale
// duplicate from a long-ago install.
function isRecent(a: AgentSummary): boolean {
  if (!a.last_seen_at) return false
  return Date.now() - new Date(a.last_seen_at).getTime() < 24 * 60 * 60 * 1000
}

// onlineRank sorts online devices first, then by most-recently-seen.
function onlineRank(a: AgentSummary): number {
  const seen = a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0
  return (isOnline(a) ? 0 : 1e15) - seen
}

function StartSessionDialog({ onClose, onStarted }: StartSessionDialogProps) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [agentId, setAgentId] = useState('')
  const [mode, setMode] = useState<'interactive' | 'view'>('interactive')
  const [notes, setNotes] = useState('')
  const [record, setRecord] = useState(false)
  const [consentRequired, setConsentRequired] = useState(false)
  // Default to the zero-trust relay transport on browsers that can decode it
  // (Chromium). It carries media over the Ziti overlay too and enables pop-out.
  // Falls back to WebRTC automatically on browsers without WebCodecs.
  const [transport, setTransport] = useState<'' | 'webrtc' | 'relay'>(
    supportsRelay() ? 'relay' : 'webrtc',
  )

  // Load enrolled agents so the admin can pick a device by hostname instead of
  // pasting an opaque agent id. Online devices (seen recently) float to the top.
  const { data: agents = [] } = useQuery<AgentSummary[]>({
    queryKey: ['agents-for-support'],
    queryFn: async () => {
      const raw = await api.get<AgentSummary[]>('/api/v1/access/agents')
      return (raw ?? []).map((a) => ({ ...a, agent_id: a.agent_id ?? '' }))
    },
    refetchInterval: 10000,
  })
  const [showAll, setShowAll] = useState(false)
  // By default show only usable targets: active devices that have reported
  // recently. Revoked/stale duplicate registrations are hidden (a "show all"
  // toggle reveals everything). Online devices sort first.
  const visibleAgents = agents.filter(
    (a) => showAll || (a.status !== 'revoked' && isRecent(a)),
  )
  const sortedAgents = [...visibleAgents].sort((a, b) => onlineRank(a) - onlineRank(b))

  const startMutation = useMutation({
    mutationFn: () =>
      api.post<StartSessionResponse>('/api/v1/access/remote-support/sessions', {
        agent_id: agentId,
        mode,
        notes,
        record,
        consent_required: consentRequired,
        ...(transport ? { transport } : {}),
      }),
    onSuccess: (data) => {
      toast({ title: t('pages.remoteSupport.toasts.created') })
      onStarted(data)
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || t('pages.remoteSupport.toasts.startFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('pages.remoteSupport.startDialog.title')}</DialogTitle>
          <DialogDescription>
            {t('pages.remoteSupport.startDialog.description')}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label htmlFor="remote-support-target" className="text-sm font-medium">{t('pages.remoteSupport.startDialog.target')}</label>
            <select id="remote-support-target"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">{t('pages.remoteSupport.startDialog.selectDevice')}</option>
              {sortedAgents.map((a) => {
                const online = isOnline(a)
                const label = a.hostname
                  ? `${online ? '🟢' : '⚪'} ${a.hostname}${a.platform ? ` (${a.platform})` : ''} — ${a.agent_id}`
                  : `${online ? '🟢' : '⚪'} ${a.agent_id}`
                return (
                  <option key={a.agent_id} value={a.agent_id}>
                    {label}
                  </option>
                )
              })}
            </select>
            <div className="mt-1 flex items-center justify-between gap-2">
              <Input
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                placeholder={t('pages.remoteSupport.startDialog.agentIdPlaceholder')}
                className="text-xs"
              />
              <label className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={showAll}
                  onChange={(e) => setShowAll(e.target.checked)}
                />
                {t('pages.remoteSupport.startDialog.showAll')}
              </label>
            </div>
          </div>
          <div>
            <label htmlFor="remote-support-mode" className="text-sm font-medium">{t('pages.remoteSupport.startDialog.mode')}</label>
            <select id="remote-support-mode"
              value={mode}
              onChange={(e) => setMode(e.target.value as 'interactive' | 'view')}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="interactive">{t('pages.remoteSupport.startDialog.modeInteractive')}</option>
              <option value="view">{t('pages.remoteSupport.startDialog.modeView')}</option>
            </select>
          </div>
          <div>
            <label htmlFor="remote-support-connection" className="text-sm font-medium">{t('pages.remoteSupport.startDialog.connection')}</label>
            <select id="remote-support-connection"
              value={transport}
              onChange={(e) => setTransport(e.target.value as '' | 'webrtc' | 'relay')}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="relay" disabled={!supportsRelay()}>
                {supportsRelay()
                  ? t('pages.remoteSupport.startDialog.relayRecommended')
                  : t('pages.remoteSupport.startDialog.relayUnsupported')}
              </option>
              <option value="webrtc">{t('pages.remoteSupport.startDialog.webrtc')}</option>
              <option value="">{t('pages.remoteSupport.startDialog.serverDefault')}</option>
            </select>
            <p className="mt-1 text-xs text-muted-foreground">
              {transport === 'relay'
                ? t('pages.remoteSupport.startDialog.relayHint')
                : transport === 'webrtc'
                  ? t('pages.remoteSupport.startDialog.webrtcHint')
                  : t('pages.remoteSupport.startDialog.defaultHint')}
            </p>
          </div>
          <div>
            <label className="text-sm font-medium">{t('pages.remoteSupport.startDialog.notes')}</label>
            <Input
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={t('pages.remoteSupport.startDialog.notesPlaceholder')}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={consentRequired}
              onChange={(e) => setConsentRequired(e.target.checked)}
            />
            {t('pages.remoteSupport.startDialog.consent')}
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={record}
              onChange={(e) => setRecord(e.target.checked)}
            />
            {t('pages.remoteSupport.startDialog.record')}
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            onClick={() => startMutation.mutate()}
            disabled={!agentId || startMutation.isPending}
          >
            <Play className="mr-1 h-4 w-4" />
            {startMutation.isPending
              ? t('pages.remoteSupport.startDialog.starting')
              : t('pages.remoteSupport.startDialog.start')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Trigger a browser download of the assembled recording. We construct a
 * link with the OAuth bearer in a query param won't work — the endpoint
 * requires the Authorization header — so we fetch the blob through the
 * shared axios client, then create an object URL and click an anchor.
 */
async function downloadRecording(sessionId: string) {
  const token = localStorage.getItem('token')
  const url = `/api/v1/access/remote-support/sessions/${sessionId}/recording`
  const resp = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!resp.ok) {
    console.warn('recording download failed', resp.status)
    return
  }
  const blob = await resp.blob()
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = `openidx-recording-${sessionId}.webm`
  a.click()
  URL.revokeObjectURL(objectUrl)
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`
}

function normalizeIce(raw: unknown): RTCIceServer[] {
  if (!Array.isArray(raw)) return []
  const out: RTCIceServer[] = []
  for (const entry of raw) {
    if (typeof entry === 'string') {
      out.push({ urls: entry })
    } else if (entry && typeof entry === 'object') {
      // Accept both the WebRTC-native shape ({ urls: string | string[] }) and
      // the legacy singular ({ url: string }) form. The server emits `urls`
      // (plural, per the RTCIceServer spec) for STUN/TURN, so handling only
      // `url` here silently dropped every ICE server and left the browser with
      // no candidates to negotiate — the media path never came up.
      const e = entry as {
        urls?: string | string[]
        url?: string
        username?: string
        credential?: string
      }
      const urls = e.urls ?? e.url
      if (urls) {
        out.push({ urls, username: e.username, credential: e.credential })
      }
    }
  }
  return out
}
