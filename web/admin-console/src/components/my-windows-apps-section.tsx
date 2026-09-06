import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { AppWindow, Play, Layers, Server, AlertTriangle, CheckCircle2, ShieldCheck } from 'lucide-react'
import { Card, CardContent } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from './ui/dialog'
import { api, MyWindowsApp, WindowsAppLaunchConflict } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { isAxiosError } from 'axios'
import { useTranslation } from 'react-i18next'

// A launch conflict the user must resolve (server replied 409).
type Conflict = { app: MyWindowsApp; body: WindowsAppLaunchConflict }

/**
 * MyWindowsAppsSection is the "Windows apps" block of the combined My Apps &
 * Network page: the RemoteApp Windows programs the user may launch in the
 * browser, with the same placement + approval gates as before (a 409 opens the
 * explicit "disconnect & launch here" dialog). The caller owns the shared search
 * box; the section hides itself when the user has no published apps.
 */
export function MyWindowsAppsSection({ search }: { search: string }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [conflict, setConflict] = useState<Conflict | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['my-windows-apps'],
    queryFn: () => api.windowsApps.listMine(),
  })
  const all = data?.apps ?? []
  const term = search.trim().toLowerCase()
  const apps = all.filter((a) =>
    !term ||
    a.display_name.toLowerCase().includes(term) ||
    (a.pool_name || a.host_name || '').toLowerCase().includes(term)
  )

  const launch = useMutation({
    mutationFn: (v: { app: MyWindowsApp; replaceSessionId?: string }) =>
      api.windowsApps.launch(v.app.id, v.replaceSessionId),
    onSuccess: (r) => {
      setConflict(null)
      window.open(r.connect_url, '_blank', 'noopener')
      toast({
        title: t('components.windowsApps.launching'),
        description: t(r.recorded ? 'components.windowsApps.sessionRecorded' : 'components.windowsApps.sessionLive', { host: r.host_name }),
      })
    },
    onError: (e: unknown, v) => {
      if (isAxiosError(e) && e.response?.status === 409 && e.response.data) {
        setConflict({ app: v.app, body: e.response.data as WindowsAppLaunchConflict })
        return
      }
      toast({ title: t('components.windowsApps.launchFailed'), description: (e as Error).message, variant: 'destructive' })
    },
  })

  // Hide the whole section when no Windows apps are published to the user.
  if (!isLoading && !isError && all.length === 0) {
    return null
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">{t('components.windowsApps.heading')}</h2>
        <p className="text-sm text-muted-foreground">
          {t('components.windowsApps.subtitle')}
        </p>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8"><LoadingSpinner /></div>
      ) : isError ? (
        <QueryError error={error} resource={t('components.windowsApps.resource')} />
      ) : apps.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('components.windowsApps.noMatch', { search })}</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {apps.map((app) => (
            <Card key={app.id} className="hover:border-primary/40 transition-colors">
              <CardContent className="py-4 space-y-3">
                <div className="flex items-start gap-3">
                  {app.has_icon ? (
                    <img src={api.windowsApps.iconURL(app.id)} alt="" className="h-9 w-9 rounded shrink-0" />
                  ) : (
                    <div className="h-9 w-9 rounded bg-muted flex items-center justify-center shrink-0">
                      <AppWindow className="h-5 w-5 text-muted-foreground" />
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <p className="font-medium truncate">{app.display_name}</p>
                    <p className="text-xs text-muted-foreground truncate flex items-center gap-1">
                      {app.pool_name ? <Layers className="h-3 w-3" /> : <Server className="h-3 w-3" />}
                      {app.pool_name || app.host_name}
                    </p>
                  </div>
                </div>
                {app.require_approval && (
                  <Badge variant="outline" className="text-amber-700 border-amber-300">
                    <ShieldCheck className="h-3 w-3 mr-1" /> {t('components.windowsApps.needsApproval')}
                  </Badge>
                )}
                <Button className="w-full" onClick={() => launch.mutate({ app })} disabled={launch.isPending}>
                  <Play className="h-4 w-4 mr-1" /> {t('components.windowsApps.launch')}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Placement conflict — explicit, never a silent disconnect. */}
      <Dialog open={!!conflict} onOpenChange={(o) => { if (!o) setConflict(null) }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              {t(conflict?.body.reason === 'no_capacity' ? 'components.windowsApps.noFreeHost' : 'components.windowsApps.activeSession')}
            </DialogTitle>
          </DialogHeader>
          {conflict && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">{conflict.body.message}</p>
              <div className="space-y-2">
                {conflict.body.conflicts.map((c) => (
                  <div key={c.session_id} className="flex items-center justify-between rounded-md border p-2 text-sm">
                    <div className="min-w-0">
                      <p className="font-medium flex items-center gap-1.5 truncate">
                        <Server className="h-3.5 w-3.5 shrink-0" /> {c.host_name}
                      </p>
                      <p className="text-xs text-muted-foreground truncate">
                        {c.app_name ? `${c.app_name} · ` : ''}{t('components.windowsApps.since', { time: new Date(c.started_at).toLocaleTimeString() })}
                      </p>
                    </div>
                    <Button
                      size="sm" variant="outline" disabled={launch.isPending}
                      onClick={() => conflict && launch.mutate({ app: conflict.app, replaceSessionId: c.session_id })}
                    >
                      {t('components.windowsApps.disconnectAndLaunch')}
                    </Button>
                  </div>
                ))}
              </div>
              <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 mt-px" />
                {t('components.windowsApps.nothingDisconnected')}
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setConflict(null)}>{t('common.cancel')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
