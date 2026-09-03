import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { Search, Import, RefreshCw, CheckCircle2, Shield, Loader2 } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface DiscoveredService {
  ziti_id: string
  name: string
  protocol: string
  host?: string
  port?: number
  managed_by_openidx: boolean
  can_import: boolean
  role_attributes?: string[]
}

interface DiscoveryResult {
  discovered_services: DiscoveredService[]
  already_managed: number
  available_for_import: number
  discovered_at: string
}

interface ImportResult {
  route_id: string
  message: string
}

interface BulkImportResult {
  total_imported: number
  total_failed: number
  results: Array<{ ziti_id: string; success: boolean; error?: string }>
}

export function ZitiDiscoveryPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [importModal, setImportModal] = useState(false)
  const [singleImport, setSingleImport] = useState<DiscoveredService | null>(null)
  const [importConfig, setImportConfig] = useState({
    route_name: '',
    from_url: '',
    description: '',
  })

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['ziti-discovery'],
    queryFn: async () => {
      return api.get<DiscoveryResult>('/api/v1/access/ziti/discover')
    },
  })

  const importService = useMutation({
    mutationFn: async (req: { ziti_id: string; route_name?: string; from_url?: string; description?: string }) => {
      return api.post<ImportResult>('/api/v1/access/ziti/import', req)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-discovery'] })
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      toast({
        title: t('pages.zitiDiscovery.toasts.imported'),
        description: t('pages.zitiDiscovery.toasts.importedDesc'),
      })
      setSingleImport(null)
      setImportConfig({ route_name: '', from_url: '', description: '' })
    },
    onError: (error: Error) => {
      // The message is the API's own, so it is surfaced verbatim.
      toast({
        title: t('pages.zitiDiscovery.toasts.importFailed'),
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const bulkImport = useMutation({
    mutationFn: async (zitiIds: string[]) => {
      return api.post<BulkImportResult>('/api/v1/access/ziti/import/bulk', { ziti_ids: zitiIds })
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-discovery'] })
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      toast({
        title: t('pages.zitiDiscovery.toasts.bulkComplete'),
        description: t('pages.zitiDiscovery.toasts.bulkSummary', {
          imported: t('pages.zitiDiscovery.toasts.bulkImported', {
            count: data.total_imported,
          }),
          failed: t('pages.zitiDiscovery.toasts.bulkFailed', { n: data.total_failed }),
        }),
      })
      setSelected(new Set())
      setImportModal(false)
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.zitiDiscovery.toasts.bulkFailedTitle'),
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const filteredServices = data?.discovered_services?.filter(
    (svc) => svc.name.toLowerCase().includes(search.toLowerCase())
  ) || []

  const importableServices = filteredServices.filter((s) => s.can_import)

  const toggleService = (zitiId: string) => {
    const newSelected = new Set(selected)
    if (newSelected.has(zitiId)) {
      newSelected.delete(zitiId)
    } else {
      newSelected.add(zitiId)
    }
    setSelected(newSelected)
  }

  const selectAll = () => {
    if (selected.size === importableServices.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(importableServices.map((s) => s.ziti_id)))
    }
  }

  const handleSingleImport = () => {
    if (!singleImport) return
    importService.mutate({
      ziti_id: singleImport.ziti_id,
      route_name: importConfig.route_name || undefined,
      from_url: importConfig.from_url || undefined,
      description: importConfig.description || undefined,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8 text-purple-500" />
            {t('pages.zitiDiscovery.title')}
          </h1>
          <p className="text-muted-foreground mt-1">
            {t('pages.zitiDiscovery.subtitle')}
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          {t('common.refresh')}
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.zitiDiscovery.stats.total')}</CardDescription>
            <CardTitle className="text-2xl">{data?.discovered_services?.length || 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.zitiDiscovery.stats.managed')}</CardDescription>
            <CardTitle className="text-2xl text-green-600">{data?.already_managed || 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>{t('pages.zitiDiscovery.stats.available')}</CardDescription>
            <CardTitle className="text-2xl text-primary">{data?.available_for_import || 0}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Actions Bar */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={t('pages.zitiDiscovery.searchPlaceholder')}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            <Button
              onClick={() => setImportModal(true)}
              disabled={selected.size === 0}
            >
              <Import className="h-4 w-4 mr-2" />
              {t('pages.zitiDiscovery.importSelected', { n: selected.size })}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Services List */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner />
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.zitiDiscovery.resource')} />
          ) : (
            <Table>
                <TableHeader className="bg-muted">
                  <TableRow>
                    <TableHead className="w-12 p-4">
                      <Checkbox aria-label={t('common.selectAll')}
                        checked={selected.size === importableServices.length && importableServices.length > 0}
                        onCheckedChange={selectAll}
                      />
                    </TableHead>
                    <TableHead className="text-left p-4 font-medium">
                      {t('pages.zitiDiscovery.colName')}
                    </TableHead>
                    <TableHead className="text-left p-4 font-medium">
                      {t('pages.zitiDiscovery.colProtocol')}
                    </TableHead>
                    <TableHead className="text-left p-4 font-medium">
                      {t('pages.zitiDiscovery.colHostPort')}
                    </TableHead>
                    <TableHead className="text-left p-4 font-medium">
                      {t('pages.zitiDiscovery.colStatus')}
                    </TableHead>
                    <TableHead className="text-left p-4 font-medium">
                      {t('pages.zitiDiscovery.colActions')}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y">
                  {filteredServices.map((service) => (
                    <TableRow key={service.ziti_id} className="hover:bg-muted/50">
                      <TableCell className="p-4">
                        <Checkbox aria-label={t('pages.zitiDiscovery.selectService', { name: service.name })}
                          checked={selected.has(service.ziti_id)}
                          onCheckedChange={() => toggleService(service.ziti_id)}
                          disabled={!service.can_import}
                        />
                      </TableCell>
                      <TableCell className="p-4">
                        <div className="font-medium">{service.name}</div>
                        <div className="text-xs text-muted-foreground font-mono">{service.ziti_id}</div>
                      </TableCell>
                      {/* Protocol and host:port are the service as the
                          controller reports it, so both render as sent. */}
                      <TableCell className="p-4">
                        <Badge variant="secondary">{service.protocol || 'tcp'}</Badge>
                      </TableCell>
                      <TableCell className="p-4 text-sm font-mono">
                        {service.host && service.port ? `${service.host}:${service.port}` : '-'}
                      </TableCell>
                      <TableCell className="p-4">
                        {service.managed_by_openidx ? (
                          <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            {t('pages.zitiDiscovery.managed')}
                          </Badge>
                        ) : (
                          <Badge variant="secondary">
                            {t('pages.zitiDiscovery.available')}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="p-4">
                        {service.can_import && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setSingleImport(service)
                              setImportConfig({
                                route_name: service.name,
                                from_url: '/' + service.name.toLowerCase().replace(/\s+/g, '-'),
                                description: '',
                              })
                            }}
                          >
                            <Import className="h-4 w-4 mr-1" />
                            {t('pages.zitiDiscovery.import')}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredServices.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="p-8 text-center text-muted-foreground">
                        {t('pages.zitiDiscovery.empty')}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
          )}
        </CardContent>
      </Card>

      {/* Single Import Modal */}
      <Dialog open={singleImport !== null} onOpenChange={() => setSingleImport(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.zitiDiscovery.single.title')}</DialogTitle>
          </DialogHeader>
          {singleImport && (
            <div className="space-y-4">
              <div className="p-3 bg-muted rounded-lg">
                <div className="font-medium">{singleImport.name}</div>
                <div className="text-sm text-muted-foreground font-mono">{singleImport.ziti_id}</div>
              </div>
              <div>
                <Label>{t('pages.zitiDiscovery.single.routeName')}</Label>
                <Input
                  value={importConfig.route_name}
                  onChange={(e) => setImportConfig({ ...importConfig, route_name: e.target.value })}
                  placeholder={t('pages.zitiDiscovery.single.routeNamePlaceholder')}
                />
              </div>
              <div>
                <Label>{t('pages.zitiDiscovery.single.urlPath')}</Label>
                {/* The sample path teaches the format a route accepts. */}
                <Input
                  value={importConfig.from_url}
                  onChange={(e) => setImportConfig({ ...importConfig, from_url: e.target.value })}
                  placeholder="/my-service"
                />
              </div>
              <div>
                <Label>{t('pages.zitiDiscovery.single.description')}</Label>
                <Input
                  value={importConfig.description}
                  onChange={(e) => setImportConfig({ ...importConfig, description: e.target.value })}
                  placeholder={t('pages.zitiDiscovery.single.descriptionPlaceholder')}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setSingleImport(null)}>
              {t('common.cancel')}
            </Button>
            <Button onClick={handleSingleImport} disabled={importService.isPending}>
              {importService.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t('pages.zitiDiscovery.import')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Import Modal */}
      <Dialog open={importModal} onOpenChange={setImportModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.zitiDiscovery.bulk.title')}</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <p>
              <Trans
                i18nKey="pages.zitiDiscovery.bulk.confirm"
                count={selected.size}
                components={[<strong key="0" />]}
              />
            </p>
            <p className="text-sm text-muted-foreground mt-2">
              {t('pages.zitiDiscovery.bulk.note')}
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportModal(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => bulkImport.mutate(Array.from(selected))}
              disabled={bulkImport.isPending}
            >
              {bulkImport.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {t('pages.zitiDiscovery.bulk.submit', { count: selected.size })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
