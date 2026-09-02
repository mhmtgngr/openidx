import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ShieldAlert, Plus, Trash2, MoreHorizontal, CheckCircle, Search as SearchIcon, Eye } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'

interface SecurityAlert {
  id: string
  user_id?: string
  alert_type: string
  severity: string
  status: string
  title: string
  description: string
  source_ip: string
  created_at: string
}

interface IPThreat {
  id: string
  ip_address: string
  threat_type: string
  reason: string
  blocked_until?: string
  permanent: boolean
  created_at: string
}

const severityBadge = (severity: string) => {
  const map: Record<string, string> = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
  }
  return map[severity] || 'bg-muted text-foreground'
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    open: 'bg-red-100 text-red-800',
    investigating: 'bg-yellow-100 text-yellow-800',
    resolved: 'bg-green-100 text-green-800',
    false_positive: 'bg-muted text-foreground',
  }
  return map[status] || 'bg-muted text-foreground'
}

export function SecurityAlertsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [detailAlert, setDetailAlert] = useState<SecurityAlert | null>(null)
  const [blockOpen, setBlockOpen] = useState(false)
  const [newIP, setNewIP] = useState({ ip_address: '', threat_type: 'manual', reason: '', permanent: false })

  const { data: alertsData, isLoading: alertsLoading, isError: alertsError, error: alertsErrorObj } = useQuery({
    queryKey: ['security-alerts', statusFilter, severityFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (statusFilter !== 'all') params.set('status', statusFilter)
      if (severityFilter !== 'all') params.set('severity', severityFilter)
      return api.get<{ alerts: SecurityAlert[]; total: number }>(`/api/v1/security-alerts?${params.toString()}`)
    },
  })
  const alerts = alertsData?.alerts || []

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ['ip-threats'],
    queryFn: () => api.get<{ threats: IPThreat[]; total: number }>('/api/v1/ip-threats'),
  })
  const threats = threatsData?.threats || []

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.put(`/api/v1/security-alerts/${id}/status`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-alerts'] })
      toast({ title: t('pages.securityAlerts.toasts.statusUpdated') })
      setDetailAlert(null)
    },
  })

  const blockIPMutation = useMutation({
    mutationFn: (data: typeof newIP) => api.post('/api/v1/ip-threats', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-threats'] })
      toast({ title: t('pages.securityAlerts.toasts.ipBlocked') })
      setBlockOpen(false)
      setNewIP({ ip_address: '', threat_type: 'manual', reason: '', permanent: false })
    },
    onError: () =>
      toast({ title: t('pages.securityAlerts.toasts.blockFailed'), variant: 'destructive' }),
  })

  const removeIPMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/ip-threats/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-threats'] })
      toast({ title: t('pages.securityAlerts.toasts.ipRemoved') })
    },
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  const openCount = alerts.filter(a => a.status === 'open').length
  const criticalCount = alerts.filter(a => a.severity === 'critical' && a.status === 'open').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.securityAlerts')}</h1>
        <p className="text-muted-foreground">{t('pages.securityAlerts.subtitle')}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">{t('pages.securityAlerts.stats.open')}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold">{openCount}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">{t('pages.securityAlerts.stats.critical')}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold text-red-600">{criticalCount}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">{t('pages.securityAlerts.stats.blockedIps')}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold">{threats.length}</div></CardContent>
        </Card>
      </div>

      <Tabs defaultValue="alerts">
        <TabsList>
          <TabsTrigger value="alerts">
            <ShieldAlert className="mr-2 h-4 w-4" />
            {t('pages.securityAlerts.tabs.alerts')}
          </TabsTrigger>
          <TabsTrigger value="ip-threats">{t('pages.securityAlerts.tabs.threats')}</TabsTrigger>
        </TabsList>

        <TabsContent value="alerts">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-4">
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[150px]">
                    <SelectValue placeholder={t('pages.securityAlerts.statusFilter.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('pages.securityAlerts.statusFilter.all')}</SelectItem>
                    <SelectItem value="open">{t('pages.securityAlerts.statusFilter.open')}</SelectItem>
                    <SelectItem value="investigating">{t('pages.securityAlerts.statusFilter.investigating')}</SelectItem>
                    <SelectItem value="resolved">{t('pages.securityAlerts.statusFilter.resolved')}</SelectItem>
                    <SelectItem value="false_positive">{t('pages.securityAlerts.statusFilter.falsePositive')}</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-[150px]">
                    <SelectValue placeholder={t('pages.securityAlerts.severityFilter.placeholder')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{t('pages.securityAlerts.severityFilter.all')}</SelectItem>
                    <SelectItem value="critical">{t('pages.securityAlerts.severityFilter.critical')}</SelectItem>
                    <SelectItem value="high">{t('pages.securityAlerts.severityFilter.high')}</SelectItem>
                    <SelectItem value="medium">{t('pages.securityAlerts.severityFilter.medium')}</SelectItem>
                    <SelectItem value="low">{t('pages.securityAlerts.severityFilter.low')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {alertsLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">{t('pages.securityAlerts.loading')}</p>
                </div>
              ) : alertsError ? (
                <QueryError error={alertsErrorObj} resource={t('pages.securityAlerts.resourceName')} />
              ) : alerts.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">{t('pages.securityAlerts.empty')}</p>
                  <p className="text-sm">{t('pages.securityAlerts.emptyHint')}</p>
                </div>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>{t('pages.securityAlerts.table.severity')}</TableHead>
                      <TableHead>{t('pages.securityAlerts.table.type')}</TableHead>
                      <TableHead>{t('pages.securityAlerts.table.title')}</TableHead>
                      <TableHead>{t('pages.securityAlerts.table.sourceIp')}</TableHead>
                      <TableHead>{t('pages.securityAlerts.table.status')}</TableHead>
                      <TableHead>{t('pages.securityAlerts.table.created')}</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {alerts.map(a => (
                        <TableRow key={a.id}>
                          <TableCell><Badge className={severityBadge(a.severity)}>{a.severity}</Badge></TableCell>
                          <TableCell><Badge variant="outline">{a.alert_type}</Badge></TableCell>
                          <TableCell className="font-medium">{a.title}</TableCell>
                          <TableCell className="font-mono text-sm">{a.source_ip}</TableCell>
                          <TableCell><Badge className={statusBadge(a.status)}>{a.status}</Badge></TableCell>
                          <TableCell className="text-sm text-muted-foreground">{formatDate(a.created_at)}</TableCell>
                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => setDetailAlert(a)}>
                                  <Eye className="mr-2 h-4 w-4" />
                                  {t('pages.securityAlerts.menu.view')}
                                </DropdownMenuItem>
                                {a.status === 'open' && (
                                  <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'investigating' })}>
                                      <SearchIcon className="mr-2 h-4 w-4" />
                                      {t('pages.securityAlerts.menu.investigating')}
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'resolved' })}>
                                      <CheckCircle className="mr-2 h-4 w-4 text-green-600" />
                                      {t('pages.securityAlerts.menu.resolve')}
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'false_positive' })}>
                                      {t('pages.securityAlerts.menu.falsePositive')}
                                    </DropdownMenuItem>
                                  </>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ip-threats">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{t('pages.securityAlerts.threats.title')}</CardTitle>
                <Button onClick={() => setBlockOpen(true)}>
                  <Plus className="mr-2 h-4 w-4" />
                  {t('pages.securityAlerts.threats.blockIp')}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {threatsLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">{t('pages.securityAlerts.threats.loading')}</p>
                </div>
              ) : threats.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">{t('pages.securityAlerts.threats.empty')}</p>
                  <p className="text-sm">{t('pages.securityAlerts.threats.emptyHint')}</p>
                </div>
              ) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>{t('pages.securityAlerts.threats.table.ip')}</TableHead>
                    <TableHead>{t('pages.securityAlerts.threats.table.type')}</TableHead>
                    <TableHead>{t('pages.securityAlerts.threats.table.reason')}</TableHead>
                    <TableHead>{t('pages.securityAlerts.threats.table.permanent')}</TableHead>
                    <TableHead>{t('pages.securityAlerts.threats.table.blockedUntil')}</TableHead>
                    <TableHead>{t('pages.securityAlerts.threats.table.actions')}</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {threats.map(threat => (
                      <TableRow key={threat.id}>
                        <TableCell className="font-mono">{threat.ip_address}</TableCell>
                        <TableCell><Badge variant="outline">{threat.threat_type}</Badge></TableCell>
                        <TableCell>{threat.reason}</TableCell>
                        <TableCell>
                          {threat.permanent ? (
                            <Badge>{t('pages.securityAlerts.threats.isPermanent')}</Badge>
                          ) : (
                            t('pages.securityAlerts.threats.no')
                          )}
                        </TableCell>
                        <TableCell>{threat.blocked_until ? formatDate(threat.blocked_until) : '-'}</TableCell>
                        <TableCell>
                          <ConfirmAction
                            title={t('pages.securityAlerts.threats.confirmUnblock.title')}
                            description={t('pages.securityAlerts.threats.confirmUnblock.description', {
                              ip: threat.ip_address,
                            })}
                            destructive
                            confirmLabel={t('pages.securityAlerts.threats.confirmUnblock.confirm')}
                            onConfirm={() => removeIPMutation.mutateAsync(threat.id)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" onClick={open}>
                                <Trash2 className="h-4 w-4 text-red-500" />
                              </Button>
                            )}
                          </ConfirmAction>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Alert Detail Dialog */}
      <Dialog open={!!detailAlert} onOpenChange={open => !open && setDetailAlert(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>{detailAlert?.title}</DialogTitle></DialogHeader>
          {detailAlert && (
            <div className="space-y-3 text-sm">
              <p>{detailAlert.description}</p>
              <div className="grid grid-cols-2 gap-2">
                <p><span className="font-medium">{t('pages.securityAlerts.detail.type')}</span> {detailAlert.alert_type}</p>
                <p><span className="font-medium">{t('pages.securityAlerts.detail.severity')}</span> {detailAlert.severity}</p>
                <p><span className="font-medium">{t('pages.securityAlerts.detail.status')}</span> {detailAlert.status}</p>
                <p><span className="font-medium">{t('pages.securityAlerts.detail.sourceIp')}</span> {detailAlert.source_ip}</p>
              </div>
              {detailAlert.status === 'open' && (
                <div className="flex gap-2 pt-2">
                  <Button size="sm" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'investigating' })}>
                    {t('pages.securityAlerts.menu.investigating')}
                  </Button>
                  <Button size="sm" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'resolved' })}>
                    {t('pages.securityAlerts.menu.resolve')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'false_positive' })}>
                    {t('pages.securityAlerts.menu.falsePositive')}
                  </Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Block IP Dialog */}
      <Dialog open={blockOpen} onOpenChange={setBlockOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.securityAlerts.blockDialog.title')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.securityAlerts.blockDialog.ip')}</label>
              <Input placeholder="192.168.1.1" value={newIP.ip_address}
                onChange={e => setNewIP(p => ({ ...p, ip_address: e.target.value }))} />
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.securityAlerts.blockDialog.threatType')}</label>
              <Select value={newIP.threat_type} onValueChange={v => setNewIP(p => ({ ...p, threat_type: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="manual">{t('pages.securityAlerts.blockDialog.typeManual')}</SelectItem>
                  <SelectItem value="brute_force">{t('pages.securityAlerts.blockDialog.typeBruteForce')}</SelectItem>
                  <SelectItem value="suspicious">{t('pages.securityAlerts.blockDialog.typeSuspicious')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.securityAlerts.blockDialog.reason')}</label>
              <Input placeholder={t('pages.securityAlerts.blockDialog.reasonPlaceholder')} value={newIP.reason}
                onChange={e => setNewIP(p => ({ ...p, reason: e.target.value }))} />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={newIP.permanent} onChange={e => setNewIP(p => ({ ...p, permanent: e.target.checked }))} />
              {t('pages.securityAlerts.blockDialog.permanent')}
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBlockOpen(false)}>{t('common.cancel')}</Button>
            <Button disabled={!newIP.ip_address || blockIPMutation.isPending}
              onClick={() => blockIPMutation.mutate(newIP)}>
              {blockIPMutation.isPending
                ? t('pages.securityAlerts.blockDialog.blocking')
                : t('pages.securityAlerts.blockDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
