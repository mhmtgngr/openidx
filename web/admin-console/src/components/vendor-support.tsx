import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LifeBuoy } from 'lucide-react'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './ui/dialog'
import { RelayRenderer } from './remote-support/relay-renderer'
import { api, baseURL } from '../lib/api'
import { apiErrorText } from '../lib/external-access'
import { useToast } from '../hooks/use-toast'

// VendorSupportButton starts a vendor's remote-support session on a device
// their running engagement covers (POST /api/v1/access/my/remote-support/
// sessions) and shows it in the relay viewer. The server decides everything
// that matters: the person at the device must Allow it first, it goes through
// the relay, the broker records it, and it ends with the engagement. The
// viewer only shows what the device streams once allowed.

interface Started {
  id: string
  admin_ws: string
  expires_at: string
}

export function VendorSupportButton({ agentId, deviceName }: { agentId: string; deviceName: string }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [session, setSession] = useState<Started | null>(null)
  const start = useMutation({
    mutationFn: () => api.post<Started>('/api/v1/access/my/remote-support/sessions', { agent_id: agentId }),
    onSuccess: (s) => setSession(s),
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('components.vendorSupport.failed')), variant: 'destructive' }),
  })
  const end = () => {
    if (session) void api.post(`/api/v1/access/my/remote-support/sessions/${session.id}/end`, {}).catch(() => undefined)
    setSession(null)
  }
  return (
    <>
      <Button size="sm" variant="outline" disabled={start.isPending} onClick={() => start.mutate()}>
        <LifeBuoy className="mr-2 h-4 w-4" />
        {t('components.vendorSupport.start')}
      </Button>
      {session && (
        <Dialog open onOpenChange={(o) => { if (!o) end() }}>
          <DialogContent
            className="max-w-6xl"
            onPointerDownOutside={(e) => e.preventDefault()}
            onInteractOutside={(e) => e.preventDefault()}
            onOpenAutoFocus={(e) => e.preventDefault()}
          >
            <DialogHeader>
              <DialogTitle>{t('components.vendorSupport.title', { device: deviceName })}</DialogTitle>
              <DialogDescription>
                {t('components.vendorSupport.description', { until: new Date(session.expires_at).toLocaleString() })}
              </DialogDescription>
            </DialogHeader>
            <RelayRenderer wsUrl={baseURL.replace(/^http/, 'ws') + session.admin_ws} mode="interactive" onEnd={end} />
          </DialogContent>
        </Dialog>
      )}
    </>
  )
}
