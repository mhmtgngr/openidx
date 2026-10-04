import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle, XCircle, Eye, UserCheck, Square } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { useSessionQueue, type QueuedLaunch, type QueuedModeration } from '../hooks/use-session-queue'

/**
 * The privileged-session decisions waiting for the caller, in the same queue
 * as their access requests: one approval screen (section 6.9 of the
 * third-party access framework). Each list comes from the access service and
 * answers only what the caller may act on:
 *
 *   - an administrator decides every pending launch approval and joins every
 *     moderation request as its moderator;
 *   - a sponsor decides their external (vendor) users' launch approvals, joins
 *     their moderation requests, and watches or ends their live sessions;
 *   - a moderator watches and ends the session their moderation admitted.
 *
 * An administrator who is not an external user's sponsor can deny that user's
 * launch but not approve it, so the queue offers them Deny only and says why.
 * The decisions that open or watch a session ask for a fresh second factor on
 * the server, and the server's own refusal is what the toast shows.
 */

type ApiFailure = { response?: { status?: number; data?: { error?: string; error_description?: string } } }

function failureText(err: unknown, fallback: string): string {
  const d = (err as ApiFailure).response?.data
  return d?.error_description || d?.error || fallback
}

export function SessionQueue({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { launches, moderation, moderated, sessions } = useSessionQueue(isAdmin)

  const refresh = () => {
    for (const key of ['pam-entry-requests', 'pam-sponsored-requests', 'pam-moderation-pending',
      'pam-sponsored-moderation', 'pam-moderating', 'pam-sponsored-sessions']) {
      queryClient.invalidateQueries({ queryKey: [key] })
    }
  }
  const failed = (fallback: string) => (err: unknown) => {
    refresh()
    toast({ title: failureText(err, t(fallback)), variant: 'destructive' })
  }
  const openShare = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer')
  }

  const decide = useMutation({
    mutationFn: ({ r, approve }: { r: QueuedLaunch; approve: boolean }) => {
      if (r.asSponsor) {
        return approve ? api.pam.approveSponsoredRequest(r.id) : api.pam.denySponsoredRequest(r.id)
      }
      return approve ? api.pam.approveRequest(r.id) : api.pam.denyRequest(r.id)
    },
    onSuccess: (_, { approve }) => {
      refresh()
      toast({ title: t(approve ? 'components.sessionQueue.toasts.approved' : 'components.sessionQueue.toasts.denied') })
    },
    onError: failed('components.sessionQueue.toasts.decideFailed'),
  })
  const join = useMutation({
    mutationFn: (m: QueuedModeration) => (m.asSponsor ? api.pam.joinSponsoredModeration(m.id) : api.pam.joinModeration(m.id)),
    onSuccess: () => {
      refresh()
      toast({ title: t('components.sessionQueue.toasts.joined') })
    },
    onError: failed('components.sessionQueue.toasts.joinFailed'),
  })
  const watchModerated = useMutation({
    mutationFn: (id: string) => api.pam.watchModeration(id),
    onSuccess: (res) => openShare(res.share_url),
    onError: failed('components.sessionQueue.toasts.watchFailed'),
  })
  const endModerated = useMutation({
    mutationFn: (id: string) => api.pam.endModeration(id),
    onSuccess: () => {
      refresh()
      toast({ title: t('components.sessionQueue.toasts.ended') })
    },
    onError: failed('components.sessionQueue.toasts.endFailed'),
  })
  const watchSponsored = useMutation({
    mutationFn: (id: string) => api.pam.watchSponsoredSession(id),
    onSuccess: (res) => openShare(res.share_url),
    onError: failed('components.sessionQueue.toasts.watchFailed'),
  })
  const endSponsored = useMutation({
    mutationFn: (id: string) => api.pam.endSponsoredSession(id),
    onSuccess: () => {
      refresh()
      toast({ title: t('components.sessionQueue.toasts.ended') })
    },
    onError: failed('components.sessionQueue.toasts.endFailed'),
  })

  const when = (d: string) => new Date(d).toLocaleString()

  if (launches.length + moderation.length + moderated.length + sessions.length === 0) {
    return null
  }

  return (
    <div className="space-y-4">
      {launches.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('components.sessionQueue.launches.title')}</CardTitle>
            <CardDescription>{t('components.sessionQueue.launches.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('components.sessionQueue.table.requester')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.entry')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.reason')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.asked')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {launches.map((r) => {
                  // Only the sponsor approves an external user's launch.
                  const sponsorOnly = !!r.external && !r.asSponsor
                  return (
                    <TableRow key={r.id}>
                      <TableCell className="font-medium">
                        {r.requester || r.requester_id}
                        {r.external && (
                          <Badge variant="outline" className="ml-2">{t('components.sessionQueue.external')}</Badge>
                        )}
                      </TableCell>
                      <TableCell>{r.entry_name}</TableCell>
                      <TableCell className="text-muted-foreground">{r.reason}</TableCell>
                      <TableCell>{when(r.created_at)}</TableCell>
                      <TableCell>
                        <div className="flex gap-2 items-center">
                          <Button
                            size="sm"
                            disabled={sponsorOnly || decide.isPending}
                            title={sponsorOnly ? t('components.sessionQueue.sponsorApproves') : undefined}
                            onClick={() => decide.mutate({ r, approve: true })}
                          >
                            <CheckCircle className="h-3 w-3 mr-1" />{t('components.sessionQueue.approve')}
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            disabled={decide.isPending}
                            onClick={() => decide.mutate({ r, approve: false })}
                          >
                            <XCircle className="h-3 w-3 mr-1" />{t('components.sessionQueue.deny')}
                          </Button>
                          {sponsorOnly && (
                            <span className="text-xs text-muted-foreground">{t('components.sessionQueue.sponsorApproves')}</span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {moderation.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('components.sessionQueue.moderation.title')}</CardTitle>
            <CardDescription>{t('components.sessionQueue.moderation.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('components.sessionQueue.table.requester')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.entry')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.reason')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.asked')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {moderation.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell className="font-medium">{m.requester}</TableCell>
                    <TableCell>{m.name}</TableCell>
                    <TableCell className="text-muted-foreground">{m.reason}</TableCell>
                    <TableCell>{when(m.created_at)}</TableCell>
                    <TableCell>
                      <Button size="sm" disabled={join.isPending} onClick={() => join.mutate(m)}>
                        <UserCheck className="h-3 w-3 mr-1" />{t('components.sessionQueue.join')}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {moderated.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('components.sessionQueue.moderating.title')}</CardTitle>
            <CardDescription>{t('components.sessionQueue.moderating.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('components.sessionQueue.table.requester')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.entry')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.session')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {moderated.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell className="font-medium">{m.requester}</TableCell>
                    <TableCell>{m.entry_name}</TableCell>
                    <TableCell>
                      {m.session_live
                        ? <Badge variant="secondary">{t('components.sessionQueue.live')}</Badge>
                        : <span className="text-muted-foreground text-sm">{t('components.sessionQueue.notStarted')}</span>}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!m.session_live || watchModerated.isPending}
                          onClick={() => watchModerated.mutate(m.id)}
                        >
                          <Eye className="h-3 w-3 mr-1" />{t('components.sessionQueue.watch')}
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={endModerated.isPending}
                          onClick={() => endModerated.mutate(m.id)}
                        >
                          <Square className="h-3 w-3 mr-1" />{t('components.sessionQueue.end')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {sessions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t('components.sessionQueue.sponsored.title')}</CardTitle>
            <CardDescription>{t('components.sessionQueue.sponsored.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('components.sessionQueue.table.vendorUser')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.entry')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.started')}</TableHead>
                  <TableHead>{t('components.sessionQueue.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium">{s.user}</TableCell>
                    <TableCell>
                      {s.entry_name}
                      {s.recorded && (
                        <Badge variant="outline" className="ml-2">{t('components.sessionQueue.recorded')}</Badge>
                      )}
                    </TableCell>
                    <TableCell>{when(s.started_at)}</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={watchSponsored.isPending}
                          onClick={() => watchSponsored.mutate(s.id)}
                        >
                          <Eye className="h-3 w-3 mr-1" />{t('components.sessionQueue.watch')}
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={endSponsored.isPending}
                          onClick={() => endSponsored.mutate(s.id)}
                        >
                          <Square className="h-3 w-3 mr-1" />{t('components.sessionQueue.end')}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
