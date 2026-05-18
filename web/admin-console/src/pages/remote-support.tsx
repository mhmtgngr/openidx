import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Video, Play, Square, MonitorPlay, Eye, MousePointer2, Clock,
  CheckCircle2, XCircle, AlertCircle, Download, Trash2, Infinity as InfinityIcon,
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
import { RemoteSupportViewer } from '../components/remote-support/remote-support-viewer'

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
  ice_servers: unknown
  end_reason?: string
  recording_url?: string
  recording_enabled: boolean
  recording_size_bytes?: number
  recording_chunk_count?: number
  recording_finalized_at?: string
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
}

export function RemoteSupportPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [startOpen, setStartOpen] = useState(false)
  const [viewerSession, setViewerSession] = useState<{
    id: string
    agentId: string
    mode: 'interactive' | 'view'
    wsPath: string
    iceServers: unknown
    recordingEnabled: boolean
  } | null>(null)

  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['remote-support-sessions'],
    queryFn: () => api.get<RemoteSession[]>('/api/v1/access/remote-support/sessions'),
    refetchInterval: 5000,
  })

  const endMutation = useMutation({
    mutationFn: (id: string) =>
      api.post(`/api/v1/access/remote-support/sessions/${id}/end`, { reason: 'admin_ended' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-support-sessions'] })
      toast({ title: 'Session ended' })
    },
    onError: () => toast({ title: 'Failed to end session', variant: 'destructive' }),
  })

  function openViewer(session: RemoteSession, wsPath: string) {
    setViewerSession({
      id: session.id,
      agentId: session.agent_id,
      mode: session.mode,
      wsPath,
      iceServers: session.ice_servers,
      recordingEnabled: session.recording_enabled,
    })
  }

  return (
    <div className="space-y-6 p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Remote support</h1>
          <p className="text-muted-foreground">
            Live screen view and (with consent) control of enrolled Android agents.
          </p>
        </div>
        <Button onClick={() => setStartOpen(true)}>
          <Video className="mr-2 h-4 w-4" /> Start session
        </Button>
      </div>

      <RetentionPolicyCard />

      <Card>
        <CardHeader>
          <CardTitle>Sessions</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 flex justify-center"><LoadingSpinner /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="w-48" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-mono text-xs">{s.id.slice(0, 8)}…</TableCell>
                    <TableCell className="font-mono">{s.agent_id}</TableCell>
                    <TableCell><ModeBadge mode={s.mode} /></TableCell>
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
                              <MonitorPlay className="mr-1 h-3 w-3" /> Open viewer
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
                            title={`Download recording (${formatBytes(s.recording_size_bytes ?? 0)})`}
                          >
                            <Download className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {sessions.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      No sessions yet.
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
                ice_servers: resp.ice_servers,
                recording_enabled: resp.recording_enabled,
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
          <DialogContent className="max-w-5xl">
            <DialogHeader>
              <DialogTitle>
                Live session — {viewerSession.agentId}
                <Badge className="ml-2" variant={viewerSession.mode === 'interactive' ? 'default' : 'secondary'}>
                  {viewerSession.mode}
                </Badge>
              </DialogTitle>
              <DialogDescription>
                The user sees a non-suppressible banner on the device while you are connected.
              </DialogDescription>
            </DialogHeader>
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
          ? 'Retention set to infinite — recordings will not be auto-purged.'
          : `Retention set to ${resp.retention_days} day${resp.retention_days === 1 ? '' : 's'}.`,
      })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Failed to save retention policy'
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
          <span>Recording retention</span>
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
                  Recordings are kept indefinitely until explicitly deleted.
                </span>
              ) : (
                <span>
                  Recordings are kept for <strong>{currentDays} day{currentDays === 1 ? '' : 's'}</strong>
                  {source === 'default' && (
                    <span className="text-muted-foreground"> (server default — no per-org policy yet)</span>
                  )}.
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={0}
                placeholder={currentDays === 0 ? 'days' : String(currentDays)}
                value={pending}
                onChange={(e) => {
                  const v = e.target.value
                  setPending(v === '' ? '' : Math.max(0, parseInt(v, 10) || 0))
                }}
                className="w-32"
                disabled={saveMutation.isPending}
              />
              <span className="text-sm text-muted-foreground">days</span>
              <Button
                size="sm"
                disabled={pending === '' || saveMutation.isPending}
                onClick={() => commit(pending as number)}
              >
                Save
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={saveMutation.isPending || currentDays === 0}
                onClick={() => commit(0)}
                title="Disable auto-purge for this org"
              >
                <InfinityIcon className="mr-1 h-3 w-3" />
                Set to infinite
              </Button>
            </div>

            <p className="text-xs text-muted-foreground">
              Sweep runs hourly. Per-session overrides on start-session take
              precedence; the global default is used when no per-org policy
              is set. Setting <code>0</code> disables auto-purge entirely.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function RetentionSourceBadge({ source }: { source: 'policy' | 'default' }) {
  if (source === 'policy') return <Badge variant="success">org policy</Badge>
  return (
    <Badge variant="secondary" className="gap-1">
      <Trash2 className="h-3 w-3" /> server default
    </Badge>
  )
}

function ModeBadge({ mode }: { mode: 'interactive' | 'view' }) {
  if (mode === 'interactive') return <Badge><MousePointer2 className="mr-1 h-3 w-3" /> interactive</Badge>
  return <Badge variant="secondary"><Eye className="mr-1 h-3 w-3" /> view</Badge>
}

function StatusBadge({ status, reason }: { status: RemoteSession['status']; reason?: string }) {
  switch (status) {
    case 'active':
      return <Badge variant="success"><CheckCircle2 className="mr-1 h-3 w-3" /> active</Badge>
    case 'pending':
      return <Badge variant="warning"><Clock className="mr-1 h-3 w-3" /> pending</Badge>
    case 'ended':
      return <Badge variant="secondary" title={reason}>ended</Badge>
    case 'expired':
      return <Badge variant="destructive"><AlertCircle className="mr-1 h-3 w-3" /> expired</Badge>
    case 'declined':
      return <Badge variant="destructive"><XCircle className="mr-1 h-3 w-3" /> declined</Badge>
    default:
      return <Badge variant="secondary">{status}</Badge>
  }
}

interface StartSessionDialogProps {
  onClose: () => void
  onStarted: (resp: StartSessionResponse) => void
}

function StartSessionDialog({ onClose, onStarted }: StartSessionDialogProps) {
  const { toast } = useToast()
  const [agentId, setAgentId] = useState('')
  const [mode, setMode] = useState<'interactive' | 'view'>('interactive')
  const [notes, setNotes] = useState('')
  const [record, setRecord] = useState(false)

  const startMutation = useMutation({
    mutationFn: () =>
      api.post<StartSessionResponse>('/api/v1/access/remote-support/sessions', {
        agent_id: agentId,
        mode,
        notes,
        record,
      }),
    onSuccess: (data) => {
      toast({ title: 'Session created' })
      onStarted(data)
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Failed to start session'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Start remote support session</DialogTitle>
          <DialogDescription>
            The user will see a banner: "An OpenIDX admin can see and control this device."
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">Target agent ID</label>
            <Input
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="agent-xxxxxxxx"
            />
          </div>
          <div>
            <label className="text-sm font-medium">Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'interactive' | 'view')}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="interactive">interactive — view + control</option>
              <option value="view">view-only — no input dispatch</option>
            </select>
          </div>
          <div>
            <label className="text-sm font-medium">Notes</label>
            <Input
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="case ID, user-reported issue, etc."
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={record}
              onChange={(e) => setRecord(e.target.checked)}
            />
            Record session (browser captures the device screen; chunks
            upload to OpenIDX. The device banner still says "session
            active" but the recording itself is server-side audit.)
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startMutation.mutate()}
            disabled={!agentId || startMutation.isPending}
          >
            <Play className="mr-1 h-4 w-4" />
            {startMutation.isPending ? 'Starting…' : 'Start'}
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
    } else if (entry && typeof entry === 'object' && 'url' in entry) {
      const e = entry as { url: string; username?: string; credential?: string }
      out.push({ urls: e.url, username: e.username, credential: e.credential })
    }
  }
  return out
}
