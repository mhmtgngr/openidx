import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Eye, Square } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { RelayRenderer } from './remote-support/relay-renderer'
import { api, baseURL } from '../lib/api'
import { apiErrorText } from '../lib/external-access'
import { useToast } from '../hooks/use-toast'

// SponsoredVendorSupport lists the live remote-support sessions of the vendor
// technicians the caller sponsors (GET /api/v1/access/remote-support/
// sponsored/sessions) and lets them watch one or end it. Watching is
// read-only in the broker: whatever this viewer sends, the device receives
// only keyframe requests from it. Nothing renders for someone who sponsors no
// one.

export interface SponsoredSupportSession {
  id: string
  agent_id: string
  device_name: string
  technician: string
  engagement_title: string
  status: string
  consent_status: string
  started_at: string
  expires_at?: string
  watch_ws: string
}

export function SponsoredVendorSupport() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [watching, setWatching] = useState<SponsoredSupportSession | null>(null)
  const { data } = useQuery({
    queryKey: ['sponsored-support-sessions'],
    queryFn: () => api.get<{ sessions: SponsoredSupportSession[] }>('/api/v1/access/remote-support/sponsored/sessions'),
    refetchInterval: 30_000,
  })
  const end = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/remote-support/sponsored/sessions/${id}/end`, {}),
    onSuccess: () => {
      setWatching(null)
      queryClient.invalidateQueries({ queryKey: ['sponsored-support-sessions'] })
      toast({ title: t('common.success'), description: t('components.sponsoredSupport.ended'), variant: 'success' })
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('components.sponsoredSupport.endFailed')), variant: 'destructive' }),
  })
  const sessions = data?.sessions ?? []
  if (sessions.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('components.sponsoredSupport.title')}</CardTitle>
        <CardDescription>{t('components.sponsoredSupport.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('components.sponsoredSupport.technician')}</TableHead>
              <TableHead>{t('components.sponsoredSupport.device')}</TableHead>
              <TableHead>{t('components.sponsoredSupport.engagement')}</TableHead>
              <TableHead>{t('components.sponsoredSupport.started')}</TableHead>
              <TableHead>{t('components.sponsoredSupport.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sessions.map((s) => (
              <TableRow key={s.id}>
                <TableCell className="font-medium">{s.technician}</TableCell>
                <TableCell>
                  {s.device_name}
                  {s.consent_status !== 'granted' && (
                    <Badge variant="outline" className="ml-2">{t('components.sponsoredSupport.awaitingConsent')}</Badge>
                  )}
                </TableCell>
                <TableCell>{s.engagement_title}</TableCell>
                <TableCell>{new Date(s.started_at).toLocaleString()}</TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setWatching(s)}>
                      <Eye className="h-3 w-3 mr-1" />{t('components.sponsoredSupport.watch')}
                    </Button>
                    <Button variant="destructive" size="sm" disabled={end.isPending} onClick={() => end.mutate(s.id)}>
                      <Square className="h-3 w-3 mr-1" />{t('components.sponsoredSupport.end')}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
      {watching && (
        <Dialog open onOpenChange={(o) => { if (!o) setWatching(null) }}>
          <DialogContent className="max-w-6xl" onOpenAutoFocus={(e) => e.preventDefault()}>
            <DialogHeader>
              <DialogTitle>{t('components.sponsoredSupport.watchTitle', { technician: watching.technician, device: watching.device_name })}</DialogTitle>
              <DialogDescription>{t('components.sponsoredSupport.watchDescription')}</DialogDescription>
            </DialogHeader>
            <RelayRenderer wsUrl={baseURL.replace(/^http/, 'ws') + watching.watch_ws} mode="view" onEnd={() => end.mutate(watching.id)} />
          </DialogContent>
        </Dialog>
      )}
    </Card>
  )
}
