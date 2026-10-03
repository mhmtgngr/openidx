import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Loader2, Play, UserCheck } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { api } from '../lib/api'
import { apiErrorBody } from '../lib/api-error'

/**
 * ModerationWaitDialog is what Connect opens when an entry's session waits for
 * a moderator (428, moderation_required). The user asks for one; the dialog
 * follows the request until a moderator joins, and then offers Connect, which
 * the moderator's join admits once, within its wait window.
 */
export function ModerationWaitDialog({
  entry,
  onClose,
  onConnect,
}: {
  entry: { id: string; name: string } | null
  onClose: () => void
  onConnect: (entry: { id: string; name: string }) => void
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const [moderationId, setModerationId] = useState<string | null>(null)

  const ask = useMutation({
    mutationFn: () => api.pam.requestModeration(entry!.id, reason || undefined),
    onSuccess: (res) => setModerationId(res.id),
  })
  // Followed every few seconds until a moderator joins or the request ends.
  const status = useQuery({
    queryKey: ['pam-moderation', moderationId],
    enabled: !!moderationId,
    queryFn: () => api.pam.getModeration(moderationId!),
    refetchInterval: (q) => (q.state.data && q.state.data.status !== 'pending' ? false : 3000),
  })
  const state = status.data?.status

  const close = () => {
    setReason('')
    setModerationId(null)
    ask.reset()
    onClose()
  }

  return (
    <Dialog open={!!entry} onOpenChange={(o) => { if (!o) close() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('components.moderationWait.title', { name: entry?.name ?? '' })}</DialogTitle>
          <DialogDescription>{t('components.moderationWait.description')}</DialogDescription>
        </DialogHeader>

        {!moderationId && (
          <div className="space-y-2">
            <label htmlFor="moderation-reason" className="text-sm font-medium">{t('components.moderationWait.reason')}</label>
            <Input id="moderation-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            {ask.isError && (
              <p className="text-sm text-destructive">
                {String(apiErrorBody(ask.error)?.error ?? t('components.moderationWait.askFailed'))}
              </p>
            )}
          </div>
        )}
        {moderationId && (state === undefined || state === 'pending') && (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />{t('components.moderationWait.waiting')}
          </p>
        )}
        {state === 'active' && (
          <p className="flex items-center gap-2 text-sm"><UserCheck className="h-4 w-4" />{t('components.moderationWait.joined')}</p>
        )}
        {(state === 'expired' || state === 'ended' || state === 'denied') && (
          <p className="text-sm text-destructive">{t(`components.moderationWait.${state}`)}</p>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={close}>{t('common.cancel')}</Button>
          {!moderationId && (
            <Button onClick={() => ask.mutate()} disabled={ask.isPending}>
              <UserCheck className="h-4 w-4 mr-1" />{t('components.moderationWait.ask')}
            </Button>
          )}
          {state === 'active' && entry && (
            <Button onClick={() => { const e = entry; close(); onConnect(e) }}>
              <Play className="h-4 w-4 mr-1" />{t('components.moderationWait.connect')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
