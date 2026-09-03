import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Globe, Shield, Edit, Trash2, Power, PowerOff, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, Terminal, Monitor, Network, Zap } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
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
import { useToast } from '../hooks/use-toast'
import { ServiceFeaturePanel } from '../components/ServiceFeaturePanel'
import { RouteFeatureToggles } from '../components/RouteFeatureToggles'
import { ConnectionTestButton } from '../components/ConnectionTestButton'

interface ProxyRoute {
  id: string
  name: string
  description: string
  from_url: string
  to_url: string
  preserve_host: boolean
  require_auth: boolean
  allowed_roles: string[] | null
  allowed_groups: string[] | null
  policy_ids: string[] | null
  idle_timeout: number
  absolute_timeout: number
  enabled: boolean
  priority: number
  ziti_enabled: boolean
  ziti_service_name: string
  idp_id: string
  route_type: string
  remote_host: string
  remote_port: number
  reverify_interval: number
  posture_check_ids: string[] | null
  inline_policy: string
  require_device_trust: boolean
  allowed_countries: string[] | null
  max_risk_score: number
  guacamole_connection_id: string
  landing_path: string
  hosting_mode: string
  created_at: string
  updated_at: string
  // Set when an application's route_id points at this route — the same link
  // that decides real access under ACCESS_ASSIGNMENT_ENFORCE. When present,
  // allowed_roles/allowed_groups are vestigial: Manage Access on that
  // application is the actual grant.
  application_id?: string
  application_name?: string
}

// Ziti/BrowZer hosting mode. "identity" (Auto) lets the reconciler auto-select
// hop vs direct for BrowZer routes from the upstream; hop/direct force it.
// These are the backend's enum values; the label and hint for each come from
// pages.proxyRoutes.hostingModes / .hostingModeHints at render time.
const HOSTING_MODES = ['identity', 'hop', 'direct'] as const

const ROUTE_TYPES = ['http', 'ssh', 'rdp', 'vnc', 'telnet'] as const

const routeTypeIcon = (type: string) => {
  switch (type) {
    case 'ssh': case 'telnet': return <Terminal className="h-5 w-5" />
    case 'rdp': case 'vnc': return <Monitor className="h-5 w-5" />
    default: return <Globe className="h-5 w-5" />
  }
}

export function ProxyRoutesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [quickCreateModal, setQuickCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [deleteModal, setDeleteModal] = useState(false)
  const [expandedRoute, setExpandedRoute] = useState<string | null>(null)
  const [selectedRoute, setSelectedRoute] = useState<ProxyRoute | null>(null)
  const [page, setPage] = useState(0)
  const pageSize = 20

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    from_url: '',
    to_url: '',
    preserve_host: false,
    require_auth: true,
    allowed_roles: '',
    allowed_groups: '',
    policy_ids: '',
    idle_timeout: 900,
    absolute_timeout: 43200,
    enabled: true,
    priority: 0,
    route_type: 'http',
    remote_host: '',
    remote_port: 0,
    reverify_interval: 0,
    inline_policy: '',
    require_device_trust: false,
    allowed_countries: '',
    max_risk_score: 100,
    landing_path: '/',
    hosting_mode: 'identity',
  })

  const [quickFormData, setQuickFormData] = useState({
    name: '',
    target_url: '',
    domain: '',
    path_prefix: '',
    ziti_enabled: true,
    browzer_enabled: true,
    allowed_roles: '',
    allowed_groups: '',
  })

  const resetQuickForm = () => {
    setQuickFormData({
      name: '',
      target_url: '',
      domain: '',
      path_prefix: '',
      ziti_enabled: true,
      browzer_enabled: true,
      allowed_roles: '',
      allowed_groups: '',
    })
  }

  const quickCreateMutation = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      return api.post('/api/v1/access/services/quick-create', data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      setQuickCreateModal(false)
      resetQuickForm()
      toast({ title: t('pages.proxyRoutes.toast.serviceCreated'), description: t('pages.proxyRoutes.toast.serviceCreatedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.proxyRoutes.toast.serviceCreateFailed'), variant: 'destructive' })
    },
  })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['proxy-routes', page],
    queryFn: async () => {
      return api.get<{ routes: ProxyRoute[]; total: number }>(`/api/v1/access/routes?offset=${page * pageSize}&limit=${pageSize}`)
    },
  })

  const createMutation = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      return api.post('/api/v1/access/routes', data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      setCreateModal(false)
      resetForm()
      toast({ title: t('pages.proxyRoutes.toast.routeCreated'), description: t('pages.proxyRoutes.toast.routeCreatedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.proxyRoutes.toast.routeCreateFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Record<string, unknown> }) => {
      return api.put(`/api/v1/access/routes/${id}`, data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      setEditModal(false)
      setSelectedRoute(null)
      toast({ title: t('pages.proxyRoutes.toast.routeUpdated'), description: t('pages.proxyRoutes.toast.routeUpdatedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.proxyRoutes.toast.routeUpdateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return api.delete(`/api/v1/access/routes/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      setDeleteModal(false)
      setSelectedRoute(null)
      toast({ title: t('pages.proxyRoutes.toast.routeDeleted'), description: t('pages.proxyRoutes.toast.routeDeletedDesc') })
    },
    onError: () => {
      toast({ title: t('common.error'), description: t('pages.proxyRoutes.toast.routeDeleteFailed'), variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      from_url: '',
      to_url: '',
      preserve_host: false,
      require_auth: true,
      allowed_roles: '',
      allowed_groups: '',
      policy_ids: '',
      idle_timeout: 900,
      absolute_timeout: 43200,
      enabled: true,
      priority: 0,
      route_type: 'http',
      remote_host: '',
      remote_port: 0,
      reverify_interval: 0,
      inline_policy: '',
      require_device_trust: false,
      allowed_countries: '',
      max_risk_score: 100,
      landing_path: '/',
      hosting_mode: 'identity',
    })
  }

  const openEdit = (route: ProxyRoute) => {
    setSelectedRoute(route)
    setFormData({
      name: route.name,
      description: route.description || '',
      from_url: route.from_url,
      to_url: route.to_url,
      preserve_host: route.preserve_host,
      require_auth: route.require_auth,
      allowed_roles: route.allowed_roles?.join(', ') || '',
      allowed_groups: route.allowed_groups?.join(', ') || '',
      policy_ids: route.policy_ids?.join(', ') || '',
      idle_timeout: route.idle_timeout,
      absolute_timeout: route.absolute_timeout,
      enabled: route.enabled,
      priority: route.priority,
      route_type: route.route_type || 'http',
      remote_host: route.remote_host || '',
      remote_port: route.remote_port || 0,
      reverify_interval: route.reverify_interval || 0,
      inline_policy: route.inline_policy || '',
      require_device_trust: route.require_device_trust || false,
      allowed_countries: route.allowed_countries?.join(', ') || '',
      max_risk_score: route.max_risk_score || 100,
      landing_path: route.landing_path || '/',
      hosting_mode: route.hosting_mode || 'identity',
    })
    setEditModal(true)
  }

  const buildPayload = () => {
    return {
      name: formData.name,
      description: formData.description,
      from_url: formData.from_url,
      to_url: formData.to_url,
      preserve_host: formData.preserve_host,
      require_auth: formData.require_auth,
      allowed_roles: formData.allowed_roles ? formData.allowed_roles.split(',').map(s => s.trim()).filter(Boolean) : [],
      allowed_groups: formData.allowed_groups ? formData.allowed_groups.split(',').map(s => s.trim()).filter(Boolean) : [],
      policy_ids: formData.policy_ids ? formData.policy_ids.split(',').map(s => s.trim()).filter(Boolean) : [],
      idle_timeout: formData.idle_timeout,
      absolute_timeout: formData.absolute_timeout,
      enabled: formData.enabled,
      priority: formData.priority,
      route_type: formData.route_type,
      remote_host: formData.remote_host,
      remote_port: formData.remote_port,
      reverify_interval: formData.reverify_interval,
      inline_policy: formData.inline_policy,
      require_device_trust: formData.require_device_trust,
      allowed_countries: formData.allowed_countries ? formData.allowed_countries.split(',').map(s => s.trim()).filter(Boolean) : [],
      max_risk_score: formData.max_risk_score,
      landing_path: formData.landing_path,
      hosting_mode: formData.hosting_mode,
    }
  }

  const routes = data?.routes || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize)

  const filtered = routes.filter(r =>
    r.name.toLowerCase().includes(search.toLowerCase()) ||
    r.from_url.toLowerCase().includes(search.toLowerCase()) ||
    r.to_url.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('nav.items.proxyRoutes')}</h1>
          <p className="text-muted-foreground">{t('pages.proxyRoutes.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => { resetQuickForm(); setQuickCreateModal(true) }}>
            <Zap className="mr-2 h-4 w-4" />
            {t('pages.proxyRoutes.quickCreate')}
          </Button>
          <Button onClick={() => { resetForm(); setCreateModal(true) }}>
            <Plus className="mr-2 h-4 w-4" />
            {t('pages.proxyRoutes.addRoute')}
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t('pages.proxyRoutes.searchPlaceholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Badge variant="outline">{t('pages.proxyRoutes.routeCount', { count: total })}</Badge>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">{t('pages.proxyRoutes.loading')}</p>
        </div>
      ) : isError ? (
        <QueryError error={error} resource={t('pages.proxyRoutes.resourceName')} />
      ) : filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
            <Network className="h-12 w-12 text-muted-foreground/40 mb-3" />
            <p className="font-medium">{t('pages.proxyRoutes.emptyTitle')}</p>
            <p className="text-sm">{t('pages.proxyRoutes.emptyHint')}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((route) => (
            <Card key={route.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${route.enabled ? 'bg-green-100' : 'bg-muted'}`}>
                      {route.enabled ? (
                        route.route_type && route.route_type !== 'http' ? (
                          <span className="text-green-700">{routeTypeIcon(route.route_type)}</span>
                        ) : (
                          <Shield className="h-5 w-5 text-green-700" />
                        )
                      ) : (
                        <PowerOff className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{route.name}</h3>
                        <Badge variant={route.enabled ? 'default' : 'secondary'}>
                          {route.enabled ? t('pages.proxyRoutes.badges.active') : t('pages.proxyRoutes.badges.disabled')}
                        </Badge>
                        {route.route_type && route.route_type !== 'http' && (
                          <Badge variant="default" className="bg-primary">{route.route_type.toUpperCase()}</Badge>
                        )}
                        {route.require_auth && (
                          <Badge variant="outline">{t('pages.proxyRoutes.badges.authRequired')}</Badge>
                        )}
                        {route.require_device_trust && (
                          <Badge variant="outline" className="border-orange-300 text-orange-700">{t('pages.proxyRoutes.badges.deviceTrust')}</Badge>
                        )}
                        {route.ziti_enabled && (
                          <Badge variant="default" className="bg-purple-600">Ziti</Badge>
                        )}
                        {route.priority > 0 && (
                          <Badge variant="outline">{t('pages.proxyRoutes.badges.priority', { n: route.priority })}</Badge>
                        )}
                      </div>
                      {route.description && (
                        <p className="text-sm text-muted-foreground mt-0.5">{route.description}</p>
                      )}
                    </div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="sm">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => openEdit(route)}>
                        <Edit className="mr-2 h-4 w-4" /> {t('pages.proxyRoutes.actions.edit')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => {
                        updateMutation.mutate({
                          id: route.id,
                          data: { enabled: !route.enabled }
                        })
                      }}>
                        {route.enabled ? (
                          <><PowerOff className="mr-2 h-4 w-4" /> {t('pages.proxyRoutes.actions.disable')}</>
                        ) : (
                          <><Power className="mr-2 h-4 w-4" /> {t('pages.proxyRoutes.actions.enable')}</>
                        )}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-red-600"
                        onClick={() => { setSelectedRoute(route); setDeleteModal(true) }}
                      >
                        <Trash2 className="mr-2 h-4 w-4" /> {t('pages.proxyRoutes.actions.delete')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.from')}</span>{' '}
                    <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{route.from_url}</code>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.to')}</span>{' '}
                    <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{route.to_url}</code>
                  </div>
                  {route.route_type && route.route_type !== 'http' && route.remote_host && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.remoteTarget')}</span>{' '}
                      <code className="bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded text-xs">
                        {route.remote_host}:{route.remote_port}
                      </code>
                      {route.guacamole_connection_id && (
                        <Badge variant="outline" className="ml-2 text-xs">{t('pages.proxyRoutes.badges.guacamoleConnected')}</Badge>
                      )}
                    </div>
                  )}
                  {route.ziti_enabled && route.ziti_service_name && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.zitiService')}</span>{' '}
                      <code className="bg-purple-50 text-purple-700 px-1.5 py-0.5 rounded text-xs">{route.ziti_service_name}</code>
                    </div>
                  )}
                  {route.inline_policy && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.policy')}</span>{' '}
                      <code className="bg-amber-50 text-amber-700 px-1.5 py-0.5 rounded text-xs">{route.inline_policy}</code>
                    </div>
                  )}
                  {route.allowed_countries && route.allowed_countries.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.geoFence')}</span>{' '}
                      {route.allowed_countries.map(c => (
                        <Badge key={c} variant="outline" className="mr-1 text-xs">{c}</Badge>
                      ))}
                    </div>
                  )}
                  {route.allowed_roles && route.allowed_roles.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.roles')}</span>{' '}
                      {route.allowed_roles.map(r => (
                        <Badge key={r} variant="outline" className="mr-1 text-xs">{r}</Badge>
                      ))}
                    </div>
                  )}
                  {route.allowed_groups && route.allowed_groups.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.groups')}</span>{' '}
                      {route.allowed_groups.map(g => (
                        <Badge key={g} variant="outline" className="mr-1 text-xs">{g}</Badge>
                      ))}
                    </div>
                  )}
                  {route.application_id && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">{t('pages.proxyRoutes.fields.managedBy')}</span>{' '}
                      <Link to="/applications" className="underline text-xs">
                        {t('pages.proxyRoutes.fields.manageAccessLink', { app: route.application_name || route.application_id })}
                      </Link>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-3 pt-3 border-t">
                  <ConnectionTestButton routeId={route.id} size="sm" />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setExpandedRoute(expandedRoute === route.id ? null : route.id)}
                  >
                    {expandedRoute === route.id ? (
                      <ChevronUp className="h-4 w-4 mr-1" />
                    ) : (
                      <ChevronDown className="h-4 w-4 mr-1" />
                    )}
                    {t('pages.proxyRoutes.actions.features')}
                  </Button>
                  {(!route.route_type || route.route_type === 'http') && (
                    <div className="ml-auto">
                      <RouteFeatureToggles
                        routeId={route.id}
                        onUpdate={() => queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })}
                      />
                    </div>
                  )}
                </div>
                {expandedRoute === route.id && (
                  <div className="mt-3 pt-3 border-t">
                    <ServiceFeaturePanel
                      routeId={route.id}
                      routeType={route.route_type || 'http'}
                      onUpdate={() => queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })}
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          ))}

          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4">
              <p className="text-sm text-muted-foreground">
                {t('pages.proxyRoutes.showing', {
                  from: page * pageSize + 1,
                  to: Math.min((page + 1) * pageSize, total),
                  total,
                })}
              </p>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage(p => p - 1)} disabled={page === 0}>
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}>
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Create Route Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('pages.proxyRoutes.createTitle')}</DialogTitle>
          </DialogHeader>
          <RouteForm
            formData={formData}
            setFormData={setFormData}
            onSubmit={() => createMutation.mutate(buildPayload())}
            isLoading={createMutation.isPending}
            submitLabel={t('pages.proxyRoutes.createSubmit')}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Route Dialog */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('pages.proxyRoutes.editTitle')}</DialogTitle>
          </DialogHeader>
          <RouteForm
            formData={formData}
            setFormData={setFormData}
            onSubmit={() => selectedRoute && updateMutation.mutate({ id: selectedRoute.id, data: buildPayload() })}
            isLoading={updateMutation.isPending}
            submitLabel={t('pages.proxyRoutes.editSubmit')}
            managedApplication={
              selectedRoute?.application_id
                ? { id: selectedRoute.application_id, name: selectedRoute.application_name || selectedRoute.application_id }
                : null
            }
          />
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteModal} onOpenChange={setDeleteModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.proxyRoutes.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.proxyRoutes.deleteConfirm', { name: selectedRoute?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => selectedRoute && deleteMutation.mutate(selectedRoute.id)}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Quick Create Dialog */}
      <Dialog open={quickCreateModal} onOpenChange={setQuickCreateModal}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.proxyRoutes.quick.title')}</DialogTitle>
          </DialogHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              quickCreateMutation.mutate({
                name: quickFormData.name,
                target_url: quickFormData.target_url,
                domain: quickFormData.domain,
                path_prefix: quickFormData.path_prefix || undefined,
                ziti_enabled: quickFormData.ziti_enabled,
                browzer_enabled: quickFormData.browzer_enabled,
                allowed_roles: quickFormData.allowed_roles ? quickFormData.allowed_roles.split(',').map(s => s.trim()).filter(Boolean) : [],
                allowed_groups: quickFormData.allowed_groups ? quickFormData.allowed_groups.split(',').map(s => s.trim()).filter(Boolean) : [],
              })
            }}
            className="space-y-4"
          >
            <p className="text-sm text-muted-foreground">
              {t('pages.proxyRoutes.quick.intro')}
            </p>
            <div className="space-y-2">
              <Label>{t('pages.proxyRoutes.quick.serviceName')}</Label>
              <Input
                value={quickFormData.name}
                onChange={(e) => setQuickFormData({ ...quickFormData, name: e.target.value })}
                placeholder="my-internal-app"
                required
              />
            </div>
            <div className="space-y-2">
              <Label>{t('pages.proxyRoutes.quick.targetUrl')}</Label>
              <Input
                value={quickFormData.target_url}
                onChange={(e) => setQuickFormData({ ...quickFormData, target_url: e.target.value })}
                placeholder="http://internal-app:8080"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('pages.proxyRoutes.quick.domain')}</Label>
                <Input
                  value={quickFormData.domain}
                  onChange={(e) => setQuickFormData({ ...quickFormData, domain: e.target.value })}
                  placeholder="browzer.localtest.me"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.proxyRoutes.quick.pathPrefix')}</Label>
                <Input
                  value={quickFormData.path_prefix}
                  onChange={(e) => {
                    const val = e.target.value
                    setQuickFormData({
                      ...quickFormData,
                      path_prefix: val,
                      domain: val ? 'browzer.localtest.me' : quickFormData.domain,
                    })
                  }}
                  placeholder="/demo"
                />
                {quickFormData.path_prefix && (
                  <p className="text-xs text-muted-foreground">{t('pages.proxyRoutes.quick.pathPrefixHint')}</p>
                )}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('pages.proxyRoutes.quick.allowedRoles')}</Label>
                <Input
                  value={quickFormData.allowed_roles}
                  onChange={(e) => setQuickFormData({ ...quickFormData, allowed_roles: e.target.value })}
                  placeholder="admin, user"
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.proxyRoutes.quick.allowedGroups')}</Label>
                <Input
                  value={quickFormData.allowed_groups}
                  onChange={(e) => setQuickFormData({ ...quickFormData, allowed_groups: e.target.value })}
                  placeholder="engineering"
                />
              </div>
            </div>
            <div className="flex items-center gap-6">
              <label className="flex items-center gap-2 text-sm">
                <Switch
                  checked={quickFormData.ziti_enabled}
                  onCheckedChange={(checked) => setQuickFormData({ ...quickFormData, ziti_enabled: checked, browzer_enabled: checked ? quickFormData.browzer_enabled : false })}
                />
                {t('pages.proxyRoutes.quick.zitiNetwork')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Switch
                  checked={quickFormData.browzer_enabled}
                  onCheckedChange={(checked) => setQuickFormData({ ...quickFormData, browzer_enabled: checked, ziti_enabled: checked ? true : quickFormData.ziti_enabled })}
                />
                {t('pages.proxyRoutes.quick.browzerAccess')}
              </label>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="outline" onClick={() => setQuickCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={quickCreateMutation.isPending}>
                {quickCreateMutation.isPending ? t('pages.proxyRoutes.quick.creating') : t('pages.proxyRoutes.quick.submit')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function RouteForm({
  formData,
  setFormData,
  onSubmit,
  isLoading,
  submitLabel,
  managedApplication = null,
}: {
  managedApplication?: { id: string; name: string } | null
  formData: {
    name: string
    description: string
    from_url: string
    to_url: string
    preserve_host: boolean
    require_auth: boolean
    allowed_roles: string
    allowed_groups: string
    policy_ids: string
    idle_timeout: number
    absolute_timeout: number
    enabled: boolean
    priority: number
    route_type: string
    remote_host: string
    remote_port: number
    reverify_interval: number
    inline_policy: string
    require_device_trust: boolean
    allowed_countries: string
    max_risk_score: number
    landing_path: string
    hosting_mode: string
  }
  setFormData: (data: typeof formData) => void
  onSubmit: () => void
  isLoading: boolean
  submitLabel: string
}) {
  const { t } = useTranslation()
  // Placeholders that are sample values ("admin, developer", "192.168.1.100",
  // the DSL expression) stay raw: they are format examples, not prose, and a
  // translated example would stop matching what the backend accepts. Only
  // placeholders that read as instructions go through the catalog.
  const isRemoteAccess = formData.route_type !== 'http'

  return (
    <form
      onSubmit={(e) => { e.preventDefault(); onSubmit() }}
      className="space-y-4 max-h-[70vh] overflow-y-auto pr-2"
    >
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.name')}</Label>
          <Input
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="My Internal App"
            required
          />
        </div>
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.routeType')}</Label>
          <Select value={formData.route_type} onValueChange={(value) => setFormData({ ...formData, route_type: value })}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder={t('pages.proxyRoutes.form.routeTypePlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              {ROUTE_TYPES.map(value => (
                <SelectItem key={value} value={value}>{t(`pages.proxyRoutes.routeTypes.${value}`)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label>{t('pages.proxyRoutes.form.description')}</Label>
        <Input
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder={t('pages.proxyRoutes.form.descriptionPlaceholder')}
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.fromUrl')}</Label>
          <Input
            value={formData.from_url}
            onChange={(e) => setFormData({ ...formData, from_url: e.target.value })}
            placeholder="https://app.company.com"
            required
          />
        </div>
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.toUrl')}</Label>
          <Input
            value={formData.to_url}
            onChange={(e) => setFormData({ ...formData, to_url: e.target.value })}
            placeholder="http://internal-app:8080"
            required
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label>{t('pages.proxyRoutes.form.hostingMode')}</Label>
        <Select value={formData.hosting_mode} onValueChange={(value) => setFormData({ ...formData, hosting_mode: value })}>
          <SelectTrigger className="w-full">
            <SelectValue placeholder={t('pages.proxyRoutes.form.hostingModePlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            {HOSTING_MODES.map(value => (
              <SelectItem key={value} value={value}>{t(`pages.proxyRoutes.hostingModes.${value}`)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          {/* An unrecognised mode has no hint, exactly as before. */}
          {t(`pages.proxyRoutes.hostingModeHints.${formData.hosting_mode}`, { defaultValue: '' })}
        </p>
      </div>

      <div className="space-y-2">
        <Label>{t('pages.proxyRoutes.form.landingPath')}</Label>
        <Input
          value={formData.landing_path}
          onChange={(e) => setFormData({ ...formData, landing_path: e.target.value })}
          placeholder="/"
        />
        <p className="text-xs text-muted-foreground">
          {t('pages.proxyRoutes.form.landingPathOpens')} <code>/ui/</code>.{' '}
          {t('pages.proxyRoutes.form.landingPathRedirect')} <code>/</code>.{' '}
          {t('pages.proxyRoutes.form.landingPathDefault')} <code>/</code>.
        </p>
      </div>

      {isRemoteAccess && (
        <div className="grid grid-cols-2 gap-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
          <div className="space-y-2">
            <Label>{t('pages.proxyRoutes.form.remoteHost')}</Label>
            <Input
              value={formData.remote_host}
              onChange={(e) => setFormData({ ...formData, remote_host: e.target.value })}
              placeholder="192.168.1.100"
            />
          </div>
          <div className="space-y-2">
            <Label>{t('pages.proxyRoutes.form.remotePort')}</Label>
            <Input
              type="number"
              value={formData.remote_port || ''}
              onChange={(e) => setFormData({ ...formData, remote_port: parseInt(e.target.value) || 0 })}
              placeholder={formData.route_type === 'ssh' ? '22' : formData.route_type === 'rdp' ? '3389' : '5900'}
            />
          </div>
        </div>
      )}

      {managedApplication && (
        <p className="text-xs text-muted-foreground bg-muted/50 rounded p-2">
          {t('pages.proxyRoutes.form.managedIntro')} <strong>{managedApplication.name}</strong>.{' '}
          {t('pages.proxyRoutes.form.managedBody')}{' '}
          <Link to="/applications" className="underline">
            {t('pages.proxyRoutes.form.managedLink')}
          </Link>
          .
        </p>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.allowedRoles')}</Label>
          <Input
            value={formData.allowed_roles}
            onChange={(e) => setFormData({ ...formData, allowed_roles: e.target.value })}
            placeholder="admin, developer"
          />
        </div>
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.allowedGroups')}</Label>
          <Input
            value={formData.allowed_groups}
            onChange={(e) => setFormData({ ...formData, allowed_groups: e.target.value })}
            placeholder="engineering, devops"
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label>{t('pages.proxyRoutes.form.policyIds')}</Label>
        <Input
          value={formData.policy_ids}
          onChange={(e) => setFormData({ ...formData, policy_ids: e.target.value })}
          placeholder={t('pages.proxyRoutes.form.policyIdsPlaceholder')}
        />
      </div>

      {/* Zero Trust Context Fields */}
      <div className="space-y-3 p-3 bg-amber-50 rounded-lg border border-amber-200">
        <p className="text-sm font-medium text-amber-800">{t('pages.proxyRoutes.form.contextTitle')}</p>

        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.inlinePolicy')}</Label>
          <textarea
            value={formData.inline_policy}
            onChange={(e) => setFormData({ ...formData, inline_policy: e.target.value })}
            placeholder='user.roles in ["admin"] AND geo.country == "US"'
            className="flex min-h-[60px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
            rows={2}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>{t('pages.proxyRoutes.form.allowedCountries')}</Label>
            <Input
              value={formData.allowed_countries}
              onChange={(e) => setFormData({ ...formData, allowed_countries: e.target.value })}
              placeholder="US, GB, DE"
            />
          </div>
          <div className="space-y-2">
            <Label>{t('pages.proxyRoutes.form.maxRisk')}</Label>
            <Input
              type="number"
              value={formData.max_risk_score}
              onChange={(e) => setFormData({ ...formData, max_risk_score: parseInt(e.target.value) || 100 })}
              min={0}
              max={100}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.reverify')}</Label>
          <Input
            type="number"
            value={formData.reverify_interval}
            onChange={(e) => setFormData({ ...formData, reverify_interval: parseInt(e.target.value) || 0 })}
            placeholder="0"
          />
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.idleTimeout')}</Label>
          <Input
            type="number"
            value={formData.idle_timeout}
            onChange={(e) => setFormData({ ...formData, idle_timeout: parseInt(e.target.value) || 900 })}
          />
        </div>
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.absTimeout')}</Label>
          <Input
            type="number"
            value={formData.absolute_timeout}
            onChange={(e) => setFormData({ ...formData, absolute_timeout: parseInt(e.target.value) || 43200 })}
          />
        </div>
        <div className="space-y-2">
          <Label>{t('pages.proxyRoutes.form.priority')}</Label>
          <Input
            type="number"
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
          />
        </div>
      </div>

      <div className="flex items-center gap-6 flex-wrap">
        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={formData.require_auth}
            onCheckedChange={(checked) => setFormData({ ...formData, require_auth: checked })}
          />
          {t('pages.proxyRoutes.form.requireAuth')}
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={formData.require_device_trust}
            onCheckedChange={(checked) => setFormData({ ...formData, require_device_trust: checked })}
          />
          {t('pages.proxyRoutes.form.requireDeviceTrust')}
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={formData.preserve_host}
            onCheckedChange={(checked) => setFormData({ ...formData, preserve_host: checked })}
          />
          {t('pages.proxyRoutes.form.preserveHost')}
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={formData.enabled}
            onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
          />
          {t('pages.proxyRoutes.form.enabled')}
        </label>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button type="submit" disabled={isLoading}>
          {isLoading ? t('pages.proxyRoutes.saving') : submitLabel}
        </Button>
      </div>
    </form>
  )
}
