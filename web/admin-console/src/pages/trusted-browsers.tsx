import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Monitor, Trash2, AlertTriangle, CheckCircle2, XCircle, Clock, Shield, Globe } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
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
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface TrustedBrowser {
  id: string
  name: string
  ip_address: string
  trusted_at: string
  expires_at: string
  last_used_at?: string
  revoked: boolean
  active: boolean
}

interface CheckResult {
  trusted: boolean
  browser_id?: string
  name?: string
  expires_at?: string
}

export function TrustedBrowsersPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [revokeDialog, setRevokeDialog] = useState(false)
  const [revokeAllDialog, setRevokeAllDialog] = useState(false)
  const [selectedBrowser, setSelectedBrowser] = useState<TrustedBrowser | null>(null)
  const [trustDialog, setTrustDialog] = useState(false)

  // Fetch trusted browsers
  const { data: browsersRaw, isLoading, isError, error } = useQuery({
    queryKey: ['trusted-browsers'],
    queryFn: async () => {
      return api.get<TrustedBrowser[]>('/api/v1/identity/trusted-browsers')
    }
  })
  const browsers: TrustedBrowser[] = Array.isArray(browsersRaw) ? browsersRaw : []

  // Check if current browser is trusted
  const { data: checkResult } = useQuery<CheckResult>({
    queryKey: ['trusted-browser-check'],
    queryFn: async () => {
      return api.get<CheckResult>('/api/v1/identity/trusted-browsers/check')
    }
  })

  // Mutations
  const trustMutation = useMutation({
    mutationFn: () => api.post('/api/v1/identity/trusted-browsers', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: t('pages.trustedBrowsers.toasts.trusted'), description: t('pages.trustedBrowsers.toasts.trustedDesc') })
      setTrustDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    }
  })

  const revokeMutation = useMutation({
    mutationFn: (browserId: string) =>
      api.delete(`/api/v1/identity/trusted-browsers/${browserId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: t('pages.trustedBrowsers.toasts.revoked'), description: t('pages.trustedBrowsers.toasts.revokedDesc') })
      setRevokeDialog(false)
    }
  })

  const revokeAllMutation = useMutation({
    mutationFn: () => api.delete('/api/v1/identity/trusted-browsers'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trusted-browsers'] })
      queryClient.invalidateQueries({ queryKey: ['trusted-browser-check'] })
      toast({ title: t('pages.trustedBrowsers.toasts.allRevoked'), description: t('pages.trustedBrowsers.toasts.allRevokedDesc') })
      setRevokeAllDialog(false)
    }
  })

  const openRevoke = (browser: TrustedBrowser) => {
    setSelectedBrowser(browser)
    setRevokeDialog(true)
  }

  const activeBrowsers = browsers.filter(b => b.active)
  const inactiveBrowsers = browsers.filter(b => !b.active)

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const daysUntilExpiry = (expiresAt: string) => {
    const days = Math.ceil((new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
    return days
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource={t('pages.trustedBrowsers.resourceName')} />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t('nav.items.trustedBrowsers')}</h1>
          <p className="text-muted-foreground">{t('pages.trustedBrowsers.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          {browsers.length > 0 && (
            <Button variant="outline" onClick={() => setRevokeAllDialog(true)}>
              <Trash2 className="h-4 w-4 mr-2" />
              {t('pages.trustedBrowsers.revokeAll')}
            </Button>
          )}
          {!checkResult?.trusted && (
            <Button onClick={() => setTrustDialog(true)}>
              <Shield className="h-4 w-4 mr-2" />
              {t('pages.trustedBrowsers.trustThis')}
            </Button>
          )}
        </div>
      </div>

      {/* Current Browser Status */}
      <Card className={checkResult?.trusted ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50'}>
        <CardContent className="pt-4">
          <div className="flex items-center gap-3">
            {checkResult?.trusted ? (
              <>
                <CheckCircle2 className="h-5 w-5 text-green-600" />
                <div>
                  <p className="font-medium text-green-900">{t('pages.trustedBrowsers.current.trusted')}</p>
                  <p className="text-sm text-green-800">
                    {t('pages.trustedBrowsers.current.trustedUntil', { date: checkResult.expires_at ? formatDate(checkResult.expires_at) : '' })}
                  </p>
                </div>
              </>
            ) : (
              <>
                <AlertTriangle className="h-5 w-5 text-amber-600" />
                <div>
                  <p className="font-medium text-amber-900">{t('pages.trustedBrowsers.current.notTrusted')}</p>
                  <p className="text-sm text-amber-800">
                    {t('pages.trustedBrowsers.current.notTrustedHint')}
                  </p>
                </div>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Info Card */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium">{t('pages.trustedBrowsers.how.title')}</p>
              <ul className="text-sm text-muted-foreground mt-1 space-y-1">
                <li>{t('pages.trustedBrowsers.how.p1')}</li>
                <li>{t('pages.trustedBrowsers.how.p2')}</li>
                <li>{t('pages.trustedBrowsers.how.p3')}</li>
                <li>{t('pages.trustedBrowsers.how.p4')}</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Active Browsers */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-green-600" />
            {t('pages.trustedBrowsers.active.title')}
          </CardTitle>
          <CardDescription>{t('pages.trustedBrowsers.active.hint')}</CardDescription>
        </CardHeader>
        <CardContent>
          {activeBrowsers.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Monitor className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>{t('pages.trustedBrowsers.active.empty')}</p>
            </div>
          ) : (
            <div className="space-y-3">
              {activeBrowsers.map((browser) => (
                <div
                  key={browser.id}
                  className="flex items-center justify-between p-4 border rounded-lg bg-background"
                >
                  <div className="flex items-center gap-4">
                    <Monitor className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{browser.name}</p>
                        <Badge className="bg-green-100 text-green-800">{t('pages.trustedBrowsers.badges.active')}</Badge>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        <span className="flex items-center gap-1">
                          <Globe className="h-3 w-3" />
                          {browser.ip_address}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {t('pages.trustedBrowsers.active.expiresIn', { count: daysUntilExpiry(browser.expires_at) })}
                        </span>
                      </div>
                      {browser.last_used_at && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {t('pages.trustedBrowsers.active.lastUsed', { date: formatDate(browser.last_used_at) })}
                        </p>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => openRevoke(browser)}
                    className="text-red-600"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Inactive/Revoked Browsers */}
      {inactiveBrowsers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-muted-foreground" />
              {t('pages.trustedBrowsers.inactive.title')}
            </CardTitle>
            <CardDescription>{t('pages.trustedBrowsers.inactive.hint')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {inactiveBrowsers.map((browser) => (
                <div
                  key={browser.id}
                  className="flex items-center justify-between p-4 border rounded-lg bg-muted opacity-60"
                >
                  <div className="flex items-center gap-4">
                    <Monitor className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{browser.name}</p>
                        {browser.revoked ? (
                          <Badge variant="secondary">{t('pages.trustedBrowsers.badges.revoked')}</Badge>
                        ) : (
                          <Badge variant="secondary">{t('pages.trustedBrowsers.badges.expired')}</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {browser.revoked
                          ? t('pages.trustedBrowsers.inactive.revokedAt', { date: formatDate(browser.expires_at) })
                          : t('pages.trustedBrowsers.inactive.expiredAt', { date: formatDate(browser.expires_at) })}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Trust Dialog */}
      <Dialog open={trustDialog} onOpenChange={setTrustDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.trustedBrowsers.trustDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('pages.trustedBrowsers.trustDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5" />
                <div className="text-sm text-amber-800">
                  <p className="font-medium">{t('pages.trustedBrowsers.trustDialog.noticeTitle')}</p>
                  <p>{t('pages.trustedBrowsers.trustDialog.notice')}</p>
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTrustDialog(false)}>{t('common.cancel')}</Button>
            <Button onClick={() => trustMutation.mutate()}>
              <Shield className="h-4 w-4 mr-2" />
              {t('pages.trustedBrowsers.trustThis')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke Dialog */}
      <AlertDialog open={revokeDialog} onOpenChange={setRevokeDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.trustedBrowsers.revokeDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.trustedBrowsers.revokeDialog.description', { name: selectedBrowser?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedBrowser && revokeMutation.mutate(selectedBrowser.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              {t('pages.trustedBrowsers.revokeDialog.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke All Dialog */}
      <AlertDialog open={revokeAllDialog} onOpenChange={setRevokeAllDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.trustedBrowsers.revokeAllDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.trustedBrowsers.revokeAllDialog.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => revokeAllMutation.mutate()}
              className="bg-red-600 hover:bg-red-700"
            >
              {t('pages.trustedBrowsers.revokeAll')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
