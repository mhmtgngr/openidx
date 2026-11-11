import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Download, X } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { LoadingSpinner } from './ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// One fleet command as GET /agents/:id/commands lists it (Faz B8.6).
export interface AgentCommandRecord {
  id: string
  agent_id: string
  kind: string
  status: string
  reason?: string
  created_at: string
  delivered_at?: string | null
  completed_at?: string | null
  expires_at: string
  result?: { error?: string; message?: string } | null
  artifact_name?: string
  artifact_sha256?: string
  artifact_size?: number
}

export const COMMAND_KINDS = ['restart', 'collect_logs', 'update_now', 'set_options', 'reenroll', 'uninstall'] as const
type CommandKind = (typeof COMMAND_KINDS)[number]

// AgentCommandsDialog queues fleet commands for one device and shows the
// ones it has had, with a download for a collected log bundle.
export function AgentCommandsDialog({
  agentId, label, open, onOpenChange,
}: { agentId: string | null; label: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<CommandKind>('restart')
  const [reason, setReason] = useState('')
  const [logLevel, setLogLevel] = useState('')
  const [trayHidden, setTrayHidden] = useState<'' | 'true' | 'false'>('')
  const [tunnel, setTunnel] = useState<'' | 'true' | 'false'>('')

  const key = ['agent-commands', agentId]
  const { data: commands = [], isLoading } = useQuery({
    queryKey: key,
    queryFn: () => api.get<AgentCommandRecord[]>(`/api/v1/access/agents/${agentId}/commands`),
    enabled: open && !!agentId,
    refetchInterval: open ? 10_000 : false,
  })

  const queue = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = { kind }
      if (reason.trim()) body.reason = reason.trim()
      if (kind === 'set_options') {
        const args: Record<string, unknown> = {}
        if (logLevel) args.log_level = logLevel
        if (trayHidden) args.tray_hidden = trayHidden === 'true'
        if (tunnel) args.tunnel_enabled = tunnel === 'true'
        body.args = args
      }
      return api.post(`/api/v1/access/agents/${agentId}/commands`, body)
    },
    onSuccess: () => {
      setReason('')
      queryClient.invalidateQueries({ queryKey: key })
      toast({ title: t('pages.agentFleet.commands.queued') })
    },
    onError: () => toast({ title: t('pages.agentFleet.commands.queueFailed'), variant: 'destructive' }),
  })

  const cancel = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/agents/${agentId}/commands/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: key }),
  })

  async function download(c: AgentCommandRecord) {
    const blob = await api.get<Blob>(`/api/v1/access/agents/${agentId}/commands/${c.id}/artifact`, { responseType: 'blob' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = c.artifact_name || 'openidx-logs.tar.gz'
    a.click()
    URL.revokeObjectURL(url)
  }

  const needsReason = kind === 'uninstall'
  const optionsEmpty = kind === 'set_options' && !logLevel && !trayHidden && !tunnel
  const canQueue = !queue.isPending && !optionsEmpty && (!needsReason || reason.trim().length >= 10)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>{t('pages.agentFleet.commands.title', { device: label })}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <div>
              <label htmlFor="agent-command-kind" className="text-sm font-medium">{t('pages.agentFleet.commands.kind')}</label>
              <select
                id="agent-command-kind"
                value={kind}
                onChange={(e) => setKind(e.target.value as CommandKind)}
                className="h-9 rounded-md border border-input bg-background px-3 text-sm block"
              >
                {COMMAND_KINDS.map((k) => (
                  <option key={k} value={k}>{t(`pages.agentFleet.commands.kinds.${k}`)}</option>
                ))}
              </select>
            </div>
            {kind === 'set_options' && (
              <>
                <select aria-label={t('pages.agentFleet.commands.logLevel')} value={logLevel} onChange={(e) => setLogLevel(e.target.value)}
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm">
                  <option value="">{t('pages.agentFleet.commands.logLevel')}</option>
                  {['debug', 'info', 'warn', 'error'].map((l) => <option key={l} value={l}>{l}</option>)}
                </select>
                <select aria-label={t('pages.agentFleet.commands.trayHidden')} value={trayHidden} onChange={(e) => setTrayHidden(e.target.value as '' | 'true' | 'false')}
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm">
                  <option value="">{t('pages.agentFleet.commands.trayHidden')}</option>
                  <option value="true">{t('pages.agentFleet.commands.hide')}</option>
                  <option value="false">{t('pages.agentFleet.commands.show')}</option>
                </select>
                <select aria-label={t('pages.agentFleet.commands.tunnel')} value={tunnel} onChange={(e) => setTunnel(e.target.value as '' | 'true' | 'false')}
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm">
                  <option value="">{t('pages.agentFleet.commands.tunnel')}</option>
                  <option value="true">{t('pages.agentFleet.commands.on')}</option>
                  <option value="false">{t('pages.agentFleet.commands.off')}</option>
                </select>
              </>
            )}
            <div className="flex-1 min-w-48">
              <label htmlFor="agent-command-reason" className="text-sm font-medium">
                {needsReason ? t('pages.agentFleet.commands.reasonRequired') : t('pages.agentFleet.commands.reason')}
              </label>
              <Input id="agent-command-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
            <Button onClick={() => queue.mutate()} disabled={!canQueue}
              variant={kind === 'uninstall' ? 'destructive' : 'default'}>
              {t('pages.agentFleet.commands.send')}
            </Button>
          </div>
          {(kind === 'uninstall' || kind === 'reenroll') && (
            <p className="text-xs text-muted-foreground">{t('pages.agentFleet.commands.freshMfa')}</p>
          )}
          {isLoading ? (
            <LoadingSpinner />
          ) : commands.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('pages.agentFleet.commands.none')}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.agentFleet.commands.kind')}</TableHead>
                  <TableHead>{t('pages.agentFleet.commands.status')}</TableHead>
                  <TableHead>{t('pages.agentFleet.commands.when')}</TableHead>
                  <TableHead>{t('pages.agentFleet.commands.outcome')}</TableHead>
                  <TableHead className="w-20" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {commands.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell>{t(`pages.agentFleet.commands.kinds.${c.kind}`, { defaultValue: c.kind })}</TableCell>
                    <TableCell>
                      <Badge variant={c.status === 'failed' ? 'destructive' : 'outline'}>
                        {t(`pages.agentFleet.commands.statuses.${c.status}`, { defaultValue: c.status })}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{new Date(c.created_at).toLocaleString()}</TableCell>
                    <TableCell className="text-xs">{c.result?.error || c.result?.message || c.reason || ''}</TableCell>
                    <TableCell>
                      {c.artifact_size ? (
                        <Button size="icon" variant="ghost" aria-label={t('pages.agentFleet.commands.download')} onClick={() => download(c)}>
                          <Download className="h-4 w-4" />
                        </Button>
                      ) : c.status === 'queued' ? (
                        <Button size="icon" variant="ghost" aria-label={t('pages.agentFleet.commands.cancel')} onClick={() => cancel.mutate(c.id)}>
                          <X className="h-4 w-4" />
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
