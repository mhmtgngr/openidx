import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search, Smartphone, Monitor, Tablet, MoreHorizontal, ShieldCheck, ShieldX, Trash2, Copy, ChevronLeft, ChevronRight, Network, Wifi, WifiOff } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
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
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface EnrichedDevice {
  id: string
  fingerprint: string
  name: string
  ip_address: string
  user_agent: string
  location: string
  trusted: boolean
  last_seen_at: string
  created_at: string
  user_id: string
  username: string
  email: string
  first_name: string
  last_name: string
  ziti_id: string
  ziti_enrolled: boolean
  ziti_attributes: string[]
}

export function DevicesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [deleteDevice, setDeleteDevice] = useState<EnrichedDevice | null>(null)
  const pageSize = 20

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['devices', page],
    queryFn: () => api.get<{ devices: EnrichedDevice[]; total: number }>(`/api/v1/access/devices/enriched?limit=${pageSize}&offset=${(page - 1) * pageSize}`),
  })

  const { data: riskStats } = useQuery({
    queryKey: ['risk-stats'],
    queryFn: () => api.get<Record<string, number>>('/api/v1/risk/stats'),
  })

  const syncDeviceTrust = (userId: string) => {
    if (userId) {
      api.post(`/api/v1/access/ziti/sync/device-trust/${userId}`).catch(() => {})
    }
  }

  const trustMutation = useMutation({
    mutationFn: (deviceId: string) => api.post<{ user_id: string }>(`/api/v1/devices/${deviceId}/trust`),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      if (data?.user_id) syncDeviceTrust(data.user_id)
      toast({ title: t('pages.devices.toasts.trusted') })
    },
    onError: () => {
      toast({ title: t('pages.devices.toasts.trustFailed'), variant: 'destructive' })
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (deviceId: string) => api.delete<{ user_id: string }>(`/api/v1/devices/${deviceId}`),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      setDeleteDevice(null)
      if (data?.user_id) syncDeviceTrust(data.user_id)
      toast({ title: t('pages.devices.toasts.removed') })
    },
    onError: () => {
      toast({ title: t('pages.devices.toasts.removeFailed'), variant: 'destructive' })
    },
  })

  const devices = data?.devices || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize)

  const filteredDevices = devices.filter(
    (d: EnrichedDevice) =>
      d.name.toLowerCase().includes(search.toLowerCase()) ||
      d.ip_address.includes(search) ||
      d.location.toLowerCase().includes(search.toLowerCase()) ||
      d.fingerprint.includes(search) ||
      d.username.toLowerCase().includes(search.toLowerCase()) ||
      d.email.toLowerCase().includes(search.toLowerCase())
  )

  const deviceIcon = (userAgent: string) => {
    const ua = userAgent.toLowerCase()
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone'))
      return <Smartphone className="h-4 w-4 text-muted-foreground" />
    if (ua.includes('tablet') || ua.includes('ipad'))
      return <Tablet className="h-4 w-4 text-muted-foreground" />
    return <Monitor className="h-4 w-4 text-muted-foreground" />
  }

  // Returns the catalog key rather than an English word, so the icon
  // column and the badge beside it are driven off one list.
  const deviceTypeKey = (userAgent: string) => {
    const ua = userAgent.toLowerCase()
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) return 'mobile'
    if (ua.includes('tablet') || ua.includes('ipad')) return 'tablet'
    return 'desktop'
  }

  const copyFingerprint = (fp: string) => {
    navigator.clipboard.writeText(fp)
    toast({ title: t('pages.devices.toasts.fingerprintCopied') })
  }

  const getZitiStatus = (device: EnrichedDevice) => {
    if (!device.ziti_id) return 'none'
    if (device.ziti_enrolled) return 'enrolled'
    return 'pending'
  }

  const getNetworkAccess = (device: EnrichedDevice) => {
    return device.trusted && device.ziti_id !== '' && device.ziti_enrolled
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.devices')}</h1>
        <p className="text-muted-foreground">{t('pages.devices.subtitle')}</p>
      </div>

      {/* Risk Stats */}
      {riskStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold">{riskStats.total_devices ?? 0}</div>
              <p className="text-xs text-muted-foreground">{t('pages.devices.stats.total')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-green-600">{riskStats.trusted_devices ?? 0}</div>
              <p className="text-xs text-muted-foreground">{t('pages.devices.stats.trusted')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-primary">{riskStats.new_devices_today ?? 0}</div>
              <p className="text-xs text-muted-foreground">{t('pages.devices.stats.newToday')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-red-600">{riskStats.high_risk_logins_today ?? 0}</div>
              <p className="text-xs text-muted-foreground">{t('pages.devices.stats.highRiskToday')}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Device Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t('pages.devices.searchPlaceholder')}
                className="pl-10"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource={t('pages.devices.resource')} />
          ) : isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">
                {t('pages.devices.loading')}
              </p>
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Smartphone className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">{t('pages.devices.emptyTitle')}</p>
              <p className="text-sm">{t('pages.devices.emptyHint')}</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('pages.devices.colDevice')}</TableHead>
                      <TableHead>{t('pages.devices.colUser')}</TableHead>
                      <TableHead>{t('pages.devices.colType')}</TableHead>
                      <TableHead>{t('pages.devices.colIp')}</TableHead>
                      <TableHead>{t('pages.devices.colTrust')}</TableHead>
                      <TableHead>{t('pages.devices.colZiti')}</TableHead>
                      <TableHead>{t('pages.devices.colNetwork')}</TableHead>
                      <TableHead>{t('pages.devices.colLastSeen')}</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredDevices.map((device: EnrichedDevice) => {
                      const zitiStatus = getZitiStatus(device)
                      const networkAccess = getNetworkAccess(device)
                      return (
                        <TableRow key={device.id}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {deviceIcon(device.user_agent)}
                              <span className="font-medium">
                                {device.name || t('pages.devices.unknownDevice')}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="text-sm">
                              <div className="font-medium">{device.first_name ? `${device.first_name} ${device.last_name}`.trim() : device.username}</div>
                              <div className="text-xs text-muted-foreground">{device.email}</div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">
                              {t(
                                `pages.devices.deviceTypes.${deviceTypeKey(device.user_agent)}`,
                              )}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{device.ip_address}</TableCell>
                          <TableCell>
                            {device.trusted ? (
                              <Badge className="bg-green-100 text-green-800">
                                {t('pages.devices.trusted')}
                              </Badge>
                            ) : (
                              <Badge variant="outline">{t('pages.devices.untrusted')}</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            {zitiStatus === 'enrolled' ? (
                              <Badge className="bg-blue-100 text-blue-800">
                                <Network className="h-3 w-3 mr-1" />
                                {t('pages.devices.zitiStatuses.enrolled')}
                              </Badge>
                            ) : zitiStatus === 'pending' ? (
                              <Badge className="bg-yellow-100 text-yellow-800">
                                {t('pages.devices.zitiStatuses.pending')}
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="text-muted-foreground">
                                {t('pages.devices.zitiStatuses.none')}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            {networkAccess ? (
                              <Badge className="bg-emerald-100 text-emerald-800">
                                <Wifi className="h-3 w-3 mr-1" />
                                {t('pages.devices.networkActive')}
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="text-muted-foreground">
                                <WifiOff className="h-3 w-3 mr-1" />
                                {t('pages.devices.networkInactive')}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(device.last_seen_at).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {!device.trusted ? (
                                  <DropdownMenuItem
                                    onClick={() => trustMutation.mutate(device.id)}
                                    disabled={trustMutation.isPending}
                                  >
                                    <ShieldCheck className="mr-2 h-4 w-4 text-green-600" />
                                    {t('pages.devices.trustDevice')}
                                  </DropdownMenuItem>
                                ) : (
                                  <DropdownMenuItem
                                    onClick={() => trustMutation.mutate(device.id)}
                                    disabled={trustMutation.isPending}
                                  >
                                    <ShieldX className="mr-2 h-4 w-4 text-yellow-600" />
                                    {t('pages.devices.revokeTrust')}
                                  </DropdownMenuItem>
                                )}
                                <DropdownMenuItem
                                  onClick={() => copyFingerprint(device.fingerprint)}
                                >
                                  <Copy className="mr-2 h-4 w-4" />
                                  {t('pages.devices.copyFingerprint')}
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  onClick={() => setDeleteDevice(device)}
                                  className="text-red-600 focus:text-red-600"
                                >
                                  <Trash2 className="mr-2 h-4 w-4" />
                                  {t('pages.devices.deleteDevice')}
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                  <p className="text-sm text-muted-foreground">
                    {t('pages.devices.showing', {
                      from: (page - 1) * pageSize + 1,
                      to: Math.min(page * pageSize, total),
                      total,
                      count: total,
                    })}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(page - 1)}
                      disabled={page === 1}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <span className="text-sm">
                      {t('common.pagination.pageOf', { page, pages: totalPages })}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(page + 1)}
                      disabled={page === totalPages}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteDevice} onOpenChange={() => setDeleteDevice(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.devices.removeDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.devices.removeDialog.desc')}
              {/* Name, IP and username are the device record as stored. */}
              {deleteDevice && (
                <span className="block mt-2 font-medium">
                  {deleteDevice.name} ({deleteDevice.ip_address}) — {deleteDevice.username}
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteDevice && revokeMutation.mutate(deleteDevice.id)}
            >
              {t('pages.devices.removeDialog.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
