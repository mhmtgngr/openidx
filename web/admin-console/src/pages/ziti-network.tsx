import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Network, Server, Users2, Copy, CheckCircle,
  Shield, Router, Fingerprint, RefreshCw, FileKey, AlertTriangle,
  Monitor, ExternalLink, MoreHorizontal, Search, ChevronDown, ChevronRight,
  LayoutDashboard, Clock, Link2, Key, Terminal, MonitorPlay,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Switch } from '../components/ui/switch'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ZitiService {
  id: string
  ziti_id: string
  name: string
  description?: string
  protocol: string
  host: string
  port: number
  route_id?: string
  enabled: boolean
  created_at: string
}

interface ZitiIdentity {
  id: string
  ziti_id: string
  name: string
  identity_type: string
  user_id?: string
  enrolled: boolean
  attributes: string[]
  created_at: string
}

interface ZitiStatus {
  enabled: boolean
  sdk_ready: boolean
  controller_reachable?: boolean
  controller_error?: string
  controller_version?: Record<string, unknown>
  services_count: number
  identities_count: number
}

interface FabricRouter {
  id: string
  name: string
  is_online: boolean
  hostname: string
  fingerprint: string
  created_at: string
  updated_at: string
}

interface FabricOverview {
  controller_online: boolean
  router_count: number
  service_count: number
  identity_count: number
  healthy_routers: number
  unhealthy_routers: number
}

interface PostureCheck {
  id: string
  name: string
  check_type: string
  parameters: Record<string, unknown>
  enabled: boolean
  severity: string
  created_at: string
}

interface PostureSummary {
  total_checks: number
  enabled_checks: number
  disabled_checks: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

interface PolicySync {
  id: string
  governance_policy_id: string
  ziti_policy_id: string
  sync_status: string
  last_synced_at: string
  error_message: string
}

interface Certificate {
  id: string
  name: string
  cert_type: string
  subject: string
  issuer: string
  fingerprint: string
  not_before: string
  not_after: string
  auto_renew: boolean
  status: string
  days_until_expiry: number
}

interface GuacConnection {
  id: string
  route_id: string
  guacamole_connection_id: string
  protocol: string
  hostname: string
  port: number
  parameters: Record<string, string>
  created_at: string
  updated_at: string
}

interface BrowZerStatus {
  enabled: boolean
  configured?: boolean
  external_jwt_signer_id?: string
  auth_policy_id?: string
  dial_policy_id?: string
  oidc_issuer?: string
  oidc_client_id?: string
  bootstrapper_url?: string
  reason?: string
}

interface TempAccessLink {
  id: string
  token: string
  name: string
  description?: string
  protocol: string
  target_host: string
  target_port: number
  username?: string
  created_by: string
  created_by_email: string
  expires_at: string
  max_uses: number
  current_uses: number
  allowed_ips?: string[]
  require_mfa: boolean
  notify_on_use: boolean
  notify_email?: string
  access_url: string
  status: 'active' | 'expired' | 'revoked' | 'used'
  last_used_at?: string
  last_used_ip?: string
  created_at: string
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function TruncatedId({ value, label }: { value: string; label?: string }) {
  const { toast } = useToast()
  const short = value.length > 12 ? value.slice(0, 8) + '...' : value
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value)
        toast({ title: 'Copied', description: `${label || 'ID'} copied to clipboard.` })
      }}
      className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
      title={value}
    >
      {short}
      <Copy className="h-3 w-3" />
    </button>
  )
}

function Spinner() {
  return (
    <div className="flex justify-center py-12">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
    </div>
  )
}

function EmptyState({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Icon className="h-12 w-12 text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium">{title}</h3>
        <p className="text-muted-foreground mt-1 text-center max-w-md">{description}</p>
      </CardContent>
    </Card>
  )
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative flex-1 max-w-sm">
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pl-9"
      />
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function ZitiNetworkPage() {
  const [activeTab, setActiveTab] = useState('overview')

  const { data: status } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Ziti Network</h1>
          <p className="text-muted-foreground">Manage your OpenZiti zero-trust network overlay</p>
        </div>
        <div className="flex items-center gap-3">
          {status && (
            <>
              <div className="flex items-center gap-1.5 text-sm">
                {status.controller_reachable ? (
                  <span className="flex items-center gap-1.5 text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                    Connected
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-red-500">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    Disconnected
                  </span>
                )}
              </div>
              <Badge variant="outline">{status.services_count} services</Badge>
              <Badge variant="outline">{status.identities_count} identities</Badge>
            </>
          )}
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <LayoutDashboard className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="services" className="gap-1.5">
            <Server className="h-4 w-4" />
            Services
          </TabsTrigger>
          <TabsTrigger value="identities" className="gap-1.5">
            <Users2 className="h-4 w-4" />
            Identities
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="remote-access" className="gap-1.5">
            <Monitor className="h-4 w-4" />
            Remote Access
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab onNavigate={setActiveTab} />
        </TabsContent>
        <TabsContent value="services">
          <ServicesTab />
        </TabsContent>
        <TabsContent value="identities">
          <IdentitiesTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="remote-access">
          <RemoteAccessTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { toast } = useToast()

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  const { data: overview } = useQuery({
    queryKey: ['ziti-fabric-overview'],
    queryFn: () => api.get<FabricOverview>('/api/v1/access/ziti/fabric/overview'),
    refetchInterval: 15000,
  })

  const { data: routersData } = useQuery({
    queryKey: ['ziti-fabric-routers'],
    queryFn: () => api.get<FabricRouter[]>('/api/v1/access/ziti/fabric/routers'),
  })

  const reconnectMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/fabric/reconnect', {}),
    onSuccess: () => toast({ title: 'Reconnect initiated', description: 'Fabric reconnect has been triggered.' }),
    onError: () => toast({ title: 'Error', description: 'Failed to trigger reconnect.', variant: 'destructive' }),
  })

  const healthCheckMutation = useMutation({
    mutationFn: () => api.get('/api/v1/access/ziti/fabric/health'),
    onSuccess: () => toast({ title: 'Health check passed', description: 'Fabric health check completed successfully.' }),
    onError: () => toast({ title: 'Health check failed', description: 'Fabric health check reported issues.', variant: 'destructive' }),
  })

  const routers = Array.isArray(routersData) ? routersData : []

  if (statusLoading) return <Spinner />

  const statCards = [
    {
      title: 'Controller',
      value: overview?.controller_online || status?.controller_reachable ? 'Online' : 'Offline',
      description: status?.sdk_ready ? 'SDK Ready' : 'SDK Not Ready',
      icon: Network,
      color: (overview?.controller_online || status?.controller_reachable) ? 'text-green-600' : 'text-red-500',
      isStatus: true,
    },
    {
      title: 'Routers',
      value: overview?.router_count || 0,
      description: `${overview?.healthy_routers || 0} healthy, ${overview?.unhealthy_routers || 0} unhealthy`,
      icon: Router,
      color: 'text-blue-600',
    },
    {
      title: 'Services',
      value: status?.services_count || 0,
      description: 'Registered services',
      icon: Server,
      color: 'text-purple-600',
      onClick: () => onNavigate('services'),
    },
    {
      title: 'Identities',
      value: status?.identities_count || 0,
      description: 'Registered identities',
      icon: Users2,
      color: 'text-orange-600',
      onClick: () => onNavigate('identities'),
    },
  ]

  return (
    <div className="space-y-6 mt-4">
      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Card
            key={stat.title}
            className={stat.onClick ? 'cursor-pointer hover:shadow-md transition-all hover:scale-[1.02]' : ''}
            onClick={stat.onClick}
          >
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {stat.isStatus ? (
                  <span className={stat.color}>{stat.value}</span>
                ) : (
                  String(stat.value)
                )}
              </div>
              <p className="text-xs text-muted-foreground">{stat.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Routers section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Edge Routers</h3>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => healthCheckMutation.mutate()} disabled={healthCheckMutation.isPending}>
              <CheckCircle className="mr-2 h-4 w-4" />
              {healthCheckMutation.isPending ? 'Checking...' : 'Health Check'}
            </Button>
            <Button variant="outline" size="sm" onClick={() => reconnectMutation.mutate()} disabled={reconnectMutation.isPending}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {reconnectMutation.isPending ? 'Reconnecting...' : 'Reconnect'}
            </Button>
          </div>
        </div>

        {routers.length === 0 ? (
          <EmptyState icon={Router} title="No edge routers" description="No routers are registered in the Ziti fabric." />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {routers.map((router) => (
                  <TableRow key={router.id} className="hover:bg-muted/50">
                    <TableCell className="font-medium">{router.name}</TableCell>
                    <TableCell>
                      <Badge variant={router.is_online ? 'default' : 'destructive'}>
                        {router.is_online ? 'Online' : 'Offline'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{router.hostname}</TableCell>
                    <TableCell><TruncatedId value={router.fingerprint} label="Fingerprint" /></TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(router.created_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>
    </div>
  )
}

// ─── Services Tab ────────────────────────────────────────────────────────────

function ServicesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiService | null>(null)
  const [form, setForm] = useState({ name: '', description: '', host: '', port: 8080, protocol: 'tcp' })

  const { data, isLoading } = useQuery({
    queryKey: ['ziti-services'],
    queryFn: () => api.get<{ services: ZitiService[] }>('/api/v1/access/ziti/services'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/services', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', description: '', host: '', port: 8080, protocol: 'tcp' })
      toast({ title: 'Service created', description: 'Ziti service has been created.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create Ziti service.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/services/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Service deleted', description: 'Ziti service has been deleted.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete Ziti service.', variant: 'destructive' }),
  })

  const services = (data?.services || []).filter((svc) =>
    !search || svc.name.toLowerCase().includes(search.toLowerCase()) ||
    svc.host.toLowerCase().includes(search.toLowerCase()) ||
    svc.description?.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4 mt-4">
      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search services..." />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Service
        </Button>
      </div>

      {services.length === 0 ? (
        <EmptyState
          icon={Server}
          title={search ? 'No matching services' : 'No Ziti services'}
          description={search ? 'Try a different search term.' : 'Register upstream services to route traffic through the Ziti overlay.'}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Ziti ID</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((svc) => (
                <TableRow key={svc.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div>
                      <p className="font-medium">{svc.name}</p>
                      {svc.description && (
                        <p className="text-xs text-muted-foreground">{svc.description}</p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{svc.protocol.toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{svc.host}:{svc.port}</code>
                  </TableCell>
                  <TableCell><TruncatedId value={svc.ziti_id} label="Ziti ID" /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(svc.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(svc.ziti_id)
                          toast({ title: 'Copied', description: 'Ziti ID copied to clipboard.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Ziti ID
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(svc)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Ziti Service</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Service Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="internal-app" required />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>Host</Label>
                <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="internal-app" required />
              </div>
              <div className="space-y-2">
                <Label>Port</Label>
                <Input type="number" value={form.port} onChange={(e) => setForm({ ...form, port: parseInt(e.target.value) || 8080 })} required />
              </div>
              <div className="space-y-2">
                <Label>Protocol</Label>
                <select
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Service'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Service</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? This will remove it from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ─── Identities Tab ──────────────────────────────────────────────────────────

function IdentitiesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiIdentity | null>(null)
  const [jwtModal, setJwtModal] = useState<{ jwt: string; name: string } | null>(null)
  const [form, setForm] = useState({ name: '', identity_type: 'Device', user_id: '', attributes: '' })

  const { data, isLoading } = useQuery({
    queryKey: ['ziti-identities'],
    queryFn: () => api.get<{ identities: ZitiIdentity[] }>('/api/v1/access/ziti/identities'),
  })

  const createMutation = useMutation({
    mutationFn: async (data: typeof form) => {
      const payload: Record<string, unknown> = {
        name: data.name,
        identity_type: data.identity_type,
        attributes: data.attributes ? data.attributes.split(',').map(s => s.trim()).filter(Boolean) : [],
      }
      if (data.user_id) payload.user_id = data.user_id
      return api.post<{ enrollment_jwt: string; name: string }>('/api/v1/access/ziti/identities', payload)
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', identity_type: 'Device', user_id: '', attributes: '' })
      const data = result as { enrollment_jwt?: string; name?: string }
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: data.name || form.name })
      }
      toast({ title: 'Identity created', description: 'Ziti identity has been created.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create Ziti identity.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/identities/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Identity deleted', description: 'Ziti identity has been deleted.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete Ziti identity.', variant: 'destructive' }),
  })

  const fetchJWT = async (identity: ZitiIdentity) => {
    try {
      const data = await api.get<{ enrollment_jwt: string }>(`/api/v1/access/ziti/identities/${identity.id}/enrollment-jwt`)
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: identity.name })
      } else {
        toast({ title: 'No JWT', description: 'Enrollment JWT is not available.', variant: 'destructive' })
      }
    } catch {
      toast({ title: 'Error', description: 'Failed to fetch enrollment JWT.', variant: 'destructive' })
    }
  }

  const identities = (data?.identities || []).filter((ident) =>
    !search || ident.name.toLowerCase().includes(search.toLowerCase()) ||
    ident.identity_type.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4 mt-4">
      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search identities..." />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Identity
        </Button>
      </div>

      {identities.length === 0 ? (
        <EmptyState
          icon={Users2}
          title={search ? 'No matching identities' : 'No Ziti identities'}
          description={search ? 'Try a different search term.' : 'Create identities for desktop tunneler enrollment.'}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Identity</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Ziti ID</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {identities.map((ident) => (
                <TableRow key={ident.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${ident.enrolled ? 'bg-green-100' : 'bg-yellow-100'}`}>
                        <Shield className={`h-4 w-4 ${ident.enrolled ? 'text-green-700' : 'text-yellow-700'}`} />
                      </div>
                      <div>
                        <p className="font-medium">{ident.name}</p>
                        {ident.user_id && <p className="text-xs text-muted-foreground">User: {ident.user_id.slice(0, 8)}...</p>}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell><Badge variant="outline">{ident.identity_type}</Badge></TableCell>
                  <TableCell>
                    <Badge variant={ident.enrolled ? 'default' : 'secondary'}>
                      {ident.enrolled ? 'Enrolled' : 'Pending'}
                    </Badge>
                  </TableCell>
                  <TableCell><TruncatedId value={ident.ziti_id} label="Ziti ID" /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(ident.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(ident.ziti_id)
                          toast({ title: 'Copied', description: 'Ziti ID copied to clipboard.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Ziti ID
                        </DropdownMenuItem>
                        {!ident.enrolled && (
                          <DropdownMenuItem onClick={() => fetchJWT(ident)}>
                            <FileKey className="mr-2 h-4 w-4" /> Get Enrollment JWT
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(ident)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Ziti Identity</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Identity Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="john-laptop" required />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Type</Label>
                <select
                  value={form.identity_type}
                  onChange={(e) => setForm({ ...form, identity_type: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="Device">Device</option>
                  <option value="User">User</option>
                  <option value="Service">Service</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>User ID (optional)</Label>
                <Input value={form.user_id} onChange={(e) => setForm({ ...form, user_id: e.target.value })} placeholder="UUID of OpenIDX user" />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Role Attributes (comma-separated)</Label>
              <Input value={form.attributes} onChange={(e) => setForm({ ...form, attributes: e.target.value })} placeholder="developers, vpn-users" />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Identity'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* JWT Modal */}
      <Dialog open={!!jwtModal} onOpenChange={() => setJwtModal(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enrollment JWT for {jwtModal?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Use this JWT to enroll an OpenZiti Desktop Edge tunneler. This is a one-time token.
            </p>
            <div className="relative">
              <textarea
                readOnly
                value={jwtModal?.jwt || ''}
                className="w-full h-32 rounded-md border bg-muted p-3 text-xs font-mono"
              />
              <Button
                variant="outline"
                size="sm"
                className="absolute top-2 right-2"
                onClick={() => {
                  if (jwtModal) {
                    navigator.clipboard.writeText(jwtModal.jwt)
                    toast({ title: 'Copied', description: 'Enrollment JWT copied to clipboard.' })
                  }
                }}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Identity</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? This will revoke the identity from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ─── Security Tab ────────────────────────────────────────────────────────────

function CollapsibleSection({ title, count, icon: Icon, defaultOpen, children }: {
  title: string; count: number; icon: React.ElementType; defaultOpen?: boolean; children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen ?? true)
  return (
    <div className="border rounded-lg">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span className="font-semibold">{title}</span>
          <Badge variant="secondary" className="ml-1">{count}</Badge>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 pb-4 pt-1">{children}</div>}
    </div>
  )
}

function SecurityTab() {
  return (
    <div className="space-y-4 mt-4">
      <PostureSection />
      <CertificatesSection />
      <PolicySyncSection />
    </div>
  )
}

function PostureSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<PostureCheck | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<PostureCheck | null>(null)
  const [form, setForm] = useState({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true })

  const { data: summary } = useQuery({
    queryKey: ['ziti-posture-summary'],
    queryFn: () => api.get<PostureSummary>('/api/v1/access/ziti/posture/summary'),
  })

  const { data: checksData, isLoading } = useQuery({
    queryKey: ['ziti-posture-checks'],
    queryFn: () => api.get<PostureCheck[]>('/api/v1/access/ziti/posture/checks'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/posture/checks', { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Posture check created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create posture check.', variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) =>
      api.put(`/api/v1/access/ziti/posture/checks/${id}`, { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setEditTarget(null)
      resetForm()
      toast({ title: 'Posture check updated' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to update posture check.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/posture/checks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setDeleteTarget(null)
      toast({ title: 'Posture check deleted' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete posture check.', variant: 'destructive' }),
  })

  const resetForm = () => setForm({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true })

  const openEditModal = (check: PostureCheck) => {
    setForm({
      name: check.name,
      check_type: check.check_type,
      parameters: JSON.stringify(check.parameters, null, 2),
      severity: check.severity,
      enabled: check.enabled,
    })
    setEditTarget(check)
  }

  const checks = (Array.isArray(checksData) ? checksData : []).filter((c) =>
    !search || c.name.toLowerCase().includes(search.toLowerCase()) || c.check_type.toLowerCase().includes(search.toLowerCase())
  )

  const severityColor = (severity: string): 'default' | 'destructive' | 'secondary' | 'outline' => {
    if (severity === 'critical' || severity === 'high') return 'destructive'
    if (severity === 'medium') return 'default'
    return 'secondary'
  }

  const totalChecks = summary?.total_checks || (Array.isArray(checksData) ? checksData.length : 0)

  return (
    <CollapsibleSection title="Posture Checks" count={totalChecks} icon={Fingerprint} defaultOpen>
      {/* Summary row */}
      {summary && (
        <div className="flex gap-4 mb-4 text-sm">
          <span className="text-green-600 font-medium">{summary.enabled_checks} enabled</span>
          <span className="text-muted-foreground">{summary.disabled_checks} disabled</span>
          {summary.by_type && Object.entries(summary.by_type).map(([type, count]) => (
            <Badge key={type} variant="outline" className="text-xs">{type}: {count}</Badge>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search posture checks..." />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> Add Check
        </Button>
      </div>

      {isLoading ? <Spinner /> : checks.length === 0 ? (
        <EmptyState icon={Fingerprint} title="No posture checks" description="Create posture checks to enforce device compliance." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {checks.map((check) => (
                <TableRow key={check.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{check.name}</TableCell>
                  <TableCell><Badge variant="outline">{check.check_type}</Badge></TableCell>
                  <TableCell><Badge variant={severityColor(check.severity)}>{check.severity}</Badge></TableCell>
                  <TableCell>
                    <Badge variant={check.enabled ? 'default' : 'secondary'}>
                      {check.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(check.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => openEditModal(check)}>Edit</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(check)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: 'Create Posture Check', onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: 'Create Check' },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: 'Edit Posture Check', onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: 'Update Check' },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Posture check name" required />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Check Type</Label>
                  <select value={form.check_type} onChange={(e) => setForm({ ...form, check_type: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    <option value="OS">OS</option>
                    <option value="Domain">Domain</option>
                    <option value="MFA">MFA</option>
                    <option value="Process">Process</option>
                    <option value="MAC">MAC</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Severity</Label>
                  <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Parameters (JSON)</Label>
                <textarea
                  value={form.parameters}
                  onChange={(e) => setForm({ ...form, parameters: e.target.value })}
                  className="w-full h-24 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  placeholder='{"os_type": "Windows", "min_version": "10"}'
                />
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={form.enabled} onCheckedChange={(checked) => setForm({ ...form, enabled: checked })} />
                <Label>Enabled</Label>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>Cancel</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? 'Saving...' : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Posture Check</AlertDialogTitle>
            <AlertDialogDescription>Are you sure you want to delete &quot;{deleteTarget?.name}&quot;?</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function CertificatesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data: certsData, isLoading } = useQuery({
    queryKey: ['ziti-certificates'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates'),
  })

  const { data: expiryAlerts } = useQuery({
    queryKey: ['ziti-certificates-expiry'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates/expiry-alerts?threshold_days=30'),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/certificates/${id}/rotate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates-expiry'] })
      toast({ title: 'Certificate rotated', description: 'Certificate rotation has been initiated.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to rotate certificate.', variant: 'destructive' }),
  })

  const certs = Array.isArray(certsData) ? certsData : []
  const alerts = Array.isArray(expiryAlerts) ? expiryAlerts : []

  const expiryBadge = (days: number) => {
    const variant: 'default' | 'destructive' | 'secondary' = days < 30 ? 'destructive' : days <= 60 ? 'secondary' : 'default'
    const label = days < 0 ? 'Expired' : days === 0 ? 'Expires today' : `${days}d remaining`
    return <Badge variant={variant}>{label}</Badge>
  }

  return (
    <CollapsibleSection title="Certificates" count={certs.length} icon={FileKey}>
      {/* Expiry alerts */}
      {alerts.length > 0 && (
        <div className="mb-4 p-3 rounded-lg border border-yellow-300 bg-yellow-50">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-yellow-600" />
            <span className="text-sm font-medium text-yellow-800">Certificates Expiring Soon ({alerts.length})</span>
          </div>
          <div className="space-y-1">
            {alerts.map((cert) => (
              <div key={cert.id} className="flex items-center justify-between text-sm">
                <span className="font-medium text-yellow-900">{cert.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-yellow-700">
                    {cert.days_until_expiry < 0 ? `Expired ${Math.abs(cert.days_until_expiry)} days ago` : `${cert.days_until_expiry} days left`}
                  </span>
                  <Button variant="outline" size="sm" onClick={() => rotateMutation.mutate(cert.id)} disabled={rotateMutation.isPending}>
                    Rotate
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {isLoading ? <Spinner /> : certs.length === 0 ? (
        <EmptyState icon={FileKey} title="No certificates" description="No Ziti certificates are being managed." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Subject</TableHead>
                <TableHead>Expiry</TableHead>
                <TableHead>Auto Renew</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {certs.map((cert) => (
                <TableRow key={cert.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{cert.name}</TableCell>
                  <TableCell><Badge variant="outline">{cert.cert_type}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate" title={cert.subject}>{cert.subject}</TableCell>
                  <TableCell>{expiryBadge(cert.days_until_expiry)}</TableCell>
                  <TableCell>
                    <Badge variant={cert.auto_renew ? 'default' : 'secondary'}>{cert.auto_renew ? 'Yes' : 'No'}</Badge>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(cert.fingerprint)
                          toast({ title: 'Copied', description: 'Fingerprint copied.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Fingerprint
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => rotateMutation.mutate(cert.id)}>
                          <RefreshCw className="mr-2 h-4 w-4" /> Rotate
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </CollapsibleSection>
  )
}

function PolicySyncSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PolicySync | null>(null)
  const [form, setForm] = useState({ governance_policy_id: '', config: '{}' })

  const { data: syncsData, isLoading } = useQuery({
    queryKey: ['ziti-policy-sync'],
    queryFn: () => api.get<PolicySync[]>('/api/v1/access/ziti/policy-sync'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/policy-sync', { governance_policy_id: data.governance_policy_id, config: JSON.parse(data.config) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setCreateModal(false)
      setForm({ governance_policy_id: '', config: '{}' })
      toast({ title: 'Policy sync created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create policy sync.', variant: 'destructive' }),
  })

  const triggerMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/policy-sync/${id}/trigger`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      toast({ title: 'Re-sync triggered' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to trigger re-sync.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/policy-sync/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setDeleteTarget(null)
      toast({ title: 'Policy sync deleted' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete policy sync.', variant: 'destructive' }),
  })

  const syncs = Array.isArray(syncsData) ? syncsData : []

  const statusVariant = (status: string): 'default' | 'destructive' | 'secondary' => {
    if (status === 'synced') return 'default'
    if (status === 'error') return 'destructive'
    return 'secondary'
  }

  return (
    <CollapsibleSection title="Policy Sync" count={syncs.length} icon={RefreshCw} defaultOpen={false}>
      <div className="flex items-center justify-end mb-3">
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Sync Policy
        </Button>
      </div>

      {isLoading ? <Spinner /> : syncs.length === 0 ? (
        <EmptyState icon={RefreshCw} title="No policy sync mappings" description="Sync governance policies to Ziti network policies." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Governance Policy</TableHead>
                <TableHead>Ziti Policy</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Synced</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncs.map((sync) => (
                <TableRow key={sync.id} className="hover:bg-muted/50">
                  <TableCell><TruncatedId value={sync.governance_policy_id} label="Governance Policy ID" /></TableCell>
                  <TableCell>
                    {sync.ziti_policy_id ? <TruncatedId value={sync.ziti_policy_id} label="Ziti Policy ID" /> : <span className="text-muted-foreground">-</span>}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(sync.sync_status)}>{sync.sync_status}</Badge>
                    {sync.error_message && (
                      <p className="text-xs text-red-500 mt-0.5 max-w-[200px] truncate" title={sync.error_message}>{sync.error_message}</p>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {sync.last_synced_at ? new Date(sync.last_synced_at).toLocaleString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => triggerMutation.mutate(sync.id)}>
                          <RefreshCw className="mr-2 h-4 w-4" /> Re-sync
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(sync)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader><DialogTitle>Sync Policy to Ziti</DialogTitle></DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Governance Policy ID</Label>
              <Input value={form.governance_policy_id} onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })} placeholder="UUID of governance policy" required />
            </div>
            <div className="space-y-2">
              <Label>Config (JSON)</Label>
              <textarea
                value={form.config}
                onChange={(e) => setForm({ ...form, config: e.target.value })}
                className="w-full h-32 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                placeholder='{"action": "allow", "service_roles": ["#web"]}'
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Syncing...' : 'Sync Policy'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy Sync</AlertDialogTitle>
            <AlertDialogDescription>Are you sure? The Ziti policy will also be removed.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

// ─── Remote Access Tab ───────────────────────────────────────────────────────

function RemoteAccessTab() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  // BrowZer status
  const { data: browzerStatus, isLoading: browzerLoading } = useQuery<BrowZerStatus>({
    queryKey: ['browzer-status'],
    queryFn: () => api.get<BrowZerStatus>('/api/v1/access/ziti/browzer/status'),
  })

  // Guacamole connections
  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ['guacamole-connections'],
    queryFn: () => api.get<{ connections: GuacConnection[] }>('/api/v1/access/guacamole/connections'),
  })

  // Services for per-service BrowZer toggle
  const { data: servicesData } = useQuery<ZitiService[]>({
    queryKey: ['ziti-services-browzer'],
    queryFn: () => api.get<ZitiService[]>('/api/v1/access/ziti/services'),
  })

  const enableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/enable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: 'BrowZer enabled' }) },
    onError: () => toast({ title: 'Failed to enable BrowZer', variant: 'destructive' }),
  })

  const disableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/disable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: 'BrowZer disabled' }) },
    onError: () => toast({ title: 'Failed to disable BrowZer', variant: 'destructive' }),
  })

  const connectMutation = useMutation({
    mutationFn: async (routeId: string) => api.post<{ connect_url: string }>(`/api/v1/access/guacamole/connections/${routeId}/connect`, {}),
    onSuccess: (resp) => {
      const connectUrl = (resp as Record<string, string>)?.connect_url
      if (connectUrl) window.open(connectUrl, '_blank')
    },
    onError: () => toast({ title: 'Error', description: 'Failed to get connection URL.', variant: 'destructive' }),
  })

  const enableOnServiceMutation = useMutation({
    mutationFn: (serviceId: string) => api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/enable`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-services'] }); toast({ title: 'BrowZer enabled on service' }) },
    onError: () => toast({ title: 'Failed to enable BrowZer on service', variant: 'destructive' }),
  })

  const disableOnServiceMutation = useMutation({
    mutationFn: (serviceId: string) => api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/disable`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-services'] }); toast({ title: 'BrowZer disabled on service' }) },
    onError: () => toast({ title: 'Failed to disable BrowZer on service', variant: 'destructive' }),
  })

  const connections = connData?.connections || []
  const services = Array.isArray(servicesData) ? servicesData : []
  const [showHowItWorks, setShowHowItWorks] = useState(false)

  if (browzerLoading || connLoading) return <Spinner />

  const protocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-blue-600'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-6 mt-4">
      {/* BrowZer Status Banner */}
      <Card className={browzerStatus?.enabled ? 'border-green-200 bg-green-50/50' : ''}>
        <CardContent className="flex items-center justify-between py-4">
          <div className="flex items-center gap-4">
            <div className={`p-2.5 rounded-lg ${browzerStatus?.enabled ? 'bg-green-100' : 'bg-muted'}`}>
              <Monitor className={`h-5 w-5 ${browzerStatus?.enabled ? 'text-green-700' : 'text-muted-foreground'}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold">BrowZer</h3>
                <Badge variant={browzerStatus?.enabled ? 'default' : 'secondary'}>
                  {browzerStatus?.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                Browser-native zero-trust access via Ziti Service Worker
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {browzerStatus?.enabled && browzerStatus.bootstrapper_url && (
              <a
                href={browzerStatus.bootstrapper_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-sm text-primary hover:underline"
              >
                Open Bootstrapper <ExternalLink className="h-3 w-3" />
              </a>
            )}
            <Button
              variant={browzerStatus?.enabled ? 'destructive' : 'default'}
              size="sm"
              onClick={() => browzerStatus?.enabled ? disableMutation.mutate() : enableMutation.mutate()}
              disabled={enableMutation.isPending || disableMutation.isPending}
            >
              {browzerStatus?.enabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* BrowZer Config Details (when enabled) */}
      {browzerStatus?.enabled && (browzerStatus.oidc_issuer || browzerStatus.external_jwt_signer_id) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {browzerStatus.bootstrapper_url && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">Bootstrapper URL</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.bootstrapper_url}</code>
            </div>
          )}
          {browzerStatus.oidc_issuer && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">OIDC Issuer</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_issuer}</code>
            </div>
          )}
          {browzerStatus.oidc_client_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">OIDC Client ID</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_client_id}</code>
            </div>
          )}
          {browzerStatus.external_jwt_signer_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">JWT Signer</span>
              <TruncatedId value={browzerStatus.external_jwt_signer_id} label="JWT Signer ID" />
            </div>
          )}
        </div>
      )}

      {/* Guacamole Connections */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold">Connections</h3>
        {connections.length === 0 ? (
          <EmptyState
            icon={Monitor}
            title="No remote access connections"
            description="Create a proxy route with type SSH, RDP, or VNC to auto-provision Guacamole connections."
          />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Guacamole ID</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {connections.map((conn) => (
                  <TableRow key={conn.id} className="hover:bg-muted/50">
                    <TableCell>
                      <Badge variant="default" className={protocolColor(conn.protocol)}>
                        {conn.protocol.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{conn.hostname}:{conn.port}</code>
                    </TableCell>
                    <TableCell><TruncatedId value={conn.guacamole_connection_id} label="Guacamole ID" /></TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(conn.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" onClick={() => connectMutation.mutate(conn.route_id)} disabled={connectMutation.isPending}>
                        <ExternalLink className="mr-1 h-3 w-3" /> Connect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>

      {/* Per-Service BrowZer Toggle */}
      {browzerStatus?.enabled && services.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold">BrowZer-Enabled Services</h3>
          <p className="text-sm text-muted-foreground">
            Toggle BrowZer access per service. Enabled services get the &quot;browzer-enabled&quot; role attribute.
          </p>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Service</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>BrowZer</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {services.map((svc) => {
                  const isBrowzerEnabled = false
                  return (
                    <TableRow key={svc.id} className="hover:bg-muted/50">
                      <TableCell className="font-medium">{svc.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{svc.host}:{svc.port}</TableCell>
                      <TableCell>
                        <Badge variant={isBrowzerEnabled ? 'default' : 'secondary'}>
                          {isBrowzerEnabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant={isBrowzerEnabled ? 'destructive' : 'outline'}
                          onClick={() => isBrowzerEnabled ? disableOnServiceMutation.mutate(svc.ziti_id) : enableOnServiceMutation.mutate(svc.ziti_id)}
                        >
                          {isBrowzerEnabled ? 'Disable' : 'Enable'}
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* Temporary Access Links Section */}
      <TempAccessLinksSection />

      {/* How it works - collapsible */}
      <button
        onClick={() => setShowHowItWorks(!showHowItWorks)}
        className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        {showHowItWorks ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        How BrowZer Works
      </button>
      {showHowItWorks && (
        <Card>
          <CardContent className="pt-4 space-y-3">
            <ol className="text-sm space-y-1.5 list-decimal list-inside text-muted-foreground">
              <li>User visits the BrowZer Bootstrapper URL</li>
              <li>Bootstrapper redirects to OpenIDX OAuth for OIDC login</li>
              <li>After authentication, the Ziti BrowZer Runtime (ZBR) is injected into the browser</li>
              <li>ZBR registers a Service Worker that intercepts HTTP requests</li>
              <li>The browser gets an ephemeral Ziti identity from the JWT token</li>
              <li>All traffic flows through the Ziti overlay via WebSocket to the edge router</li>
              <li>Press <kbd className="bg-muted px-1 py-0.5 rounded text-xs">Alt+F12</kbd> to open the ZBR debug panel</li>
            </ol>
            <div className="p-3 bg-muted rounded-lg">
              <p className="text-xs font-medium mb-1">Connection Flow</p>
              <code className="text-xs text-muted-foreground">
                Browser (ZBR + SW) &rarr; WSS &rarr; Edge Router &rarr; Ziti Circuit &rarr; Access Service &rarr; Upstream
              </code>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Temporary Access Links Section ──────────────────────────────────────────

function TempAccessLinksSection() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [createModal, setCreateModal] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<TempAccessLink | null>(null)

  const [form, setForm] = useState({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  // Fetch temp access links
  const { data: linksData, isLoading } = useQuery({
    queryKey: ['temp-access-links'],
    queryFn: () => api.get<{ links: TempAccessLink[] }>('/api/v1/access/temp-access'),
  })

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post<TempAccessLink>('/api/v1/access/temp-access', {
      ...data,
      target_port: Number(data.target_port),
      duration_mins: Number(data.duration_mins),
      max_uses: Number(data.max_uses),
      allowed_ips: data.allowed_ips ? data.allowed_ips.split(',').map(ip => ip.trim()).filter(Boolean) : [],
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Temporary access link created', description: 'Share the URL with your support vendor.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create access link.', variant: 'destructive' }),
  })

  // Revoke mutation
  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/temp-access/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setDeleteTarget(null)
      toast({ title: 'Access link revoked' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to revoke access link.', variant: 'destructive' }),
  })

  const resetForm = () => setForm({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast({ title: 'Copied to clipboard' })
    setTimeout(() => setCopiedId(null), 2000)
  }

  const links = linksData?.links || []

  const getStatusBadge = (link: TempAccessLink) => {
    const now = new Date()
    const expires = new Date(link.expires_at)
    if (link.status === 'revoked') return <Badge variant="destructive">Revoked</Badge>
    if (link.status === 'expired' || expires < now) return <Badge variant="secondary">Expired</Badge>
    if (link.max_uses > 0 && link.current_uses >= link.max_uses) return <Badge variant="secondary">Used</Badge>
    return <Badge className="bg-green-600">Active</Badge>
  }

  const getTimeRemaining = (expiresAt: string) => {
    const now = new Date()
    const expires = new Date(expiresAt)
    const diff = expires.getTime() - now.getTime()
    if (diff <= 0) return 'Expired'
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m`
  }

  const protocolIcon = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return <Terminal className="h-4 w-4" />
      case 'rdp': return <MonitorPlay className="h-4 w-4" />
      case 'vnc': return <Monitor className="h-4 w-4" />
      default: return <Server className="h-4 w-4" />
    }
  }

  const protocolColor = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-blue-600'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-4" data-testid="temp-access-section">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-lg font-semibold">Temporary Access Links</h3>
          <Badge variant="outline" className="ml-2">{links.length}</Badge>
        </div>
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Create Temp Access
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        Generate time-limited access URLs for support vendors or temporary access needs.
      </p>

      {isLoading ? (
        <Spinner />
      ) : links.length === 0 ? (
        <EmptyState
          icon={Link2}
          title="No temporary access links"
          description="Create a temporary access link to share with support vendors."
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Usage</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Access URL</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {links.map((link) => (
                <TableRow key={link.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded ${protocolColor(link.protocol)}`}>
                        {protocolIcon(link.protocol)}
                      </div>
                      <div>
                        <p className="font-medium">{link.name}</p>
                        {link.description && (
                          <p className="text-xs text-muted-foreground">{link.description}</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">
                      {link.target_host}:{link.target_port}
                    </code>
                  </TableCell>
                  <TableCell>{getStatusBadge(link)}</TableCell>
                  <TableCell>
                    <span className="text-sm">
                      {link.current_uses}{link.max_uses > 0 ? `/${link.max_uses}` : ''} uses
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-sm">{getTimeRemaining(link.expires_at)}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded max-w-[200px] truncate">
                        {link.access_url}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => copyToClipboard(link.access_url, link.id)}
                      >
                        {copiedId === link.id ? (
                          <CheckCircle className="h-3.5 w-3.5 text-green-600" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => copyToClipboard(link.access_url, link.id)}>
                          <Copy className="h-4 w-4 mr-2" />
                          Copy URL
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => window.open(link.access_url, '_blank')}>
                          <ExternalLink className="h-4 w-4 mr-2" />
                          Open Link
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => setDeleteTarget(link)}
                          disabled={link.status !== 'active'}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Revoke Access
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Temporary Access Link</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <Label>Name</Label>
                <Input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Vendor SSH Access"
                  required
                />
              </div>
              <div className="col-span-2">
                <Label>Description (optional)</Label>
                <Input
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Temporary access for ABC Corp support"
                />
              </div>
              <div>
                <Label>Protocol</Label>
                <select
                  value={form.protocol}
                  onChange={(e) => {
                    const proto = e.target.value
                    const port = proto === 'ssh' ? 22 : proto === 'rdp' ? 3389 : proto === 'vnc' ? 5900 : 22
                    setForm({ ...form, protocol: proto, target_port: port })
                  }}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="ssh">SSH</option>
                  <option value="rdp">RDP</option>
                  <option value="vnc">VNC</option>
                </select>
              </div>
              <div>
                <Label>Target Host</Label>
                <Input
                  value={form.target_host}
                  onChange={(e) => setForm({ ...form, target_host: e.target.value })}
                  placeholder="192.168.31.76"
                  required
                />
              </div>
              <div>
                <Label>Port</Label>
                <Input
                  type="number"
                  value={form.target_port}
                  onChange={(e) => setForm({ ...form, target_port: parseInt(e.target.value) || 22 })}
                  required
                />
              </div>
              <div>
                <Label>Username (optional)</Label>
                <Input
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="support"
                />
              </div>
              <div>
                <Label>Duration (minutes)</Label>
                <Input
                  type="number"
                  value={form.duration_mins}
                  onChange={(e) => setForm({ ...form, duration_mins: parseInt(e.target.value) || 120 })}
                  min={5}
                  max={10080}
                  required
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {form.duration_mins >= 60 ? `${Math.floor(form.duration_mins / 60)}h ${form.duration_mins % 60}m` : `${form.duration_mins}m`}
                </p>
              </div>
              <div>
                <Label>Max Uses (0 = unlimited)</Label>
                <Input
                  type="number"
                  value={form.max_uses}
                  onChange={(e) => setForm({ ...form, max_uses: parseInt(e.target.value) || 0 })}
                  min={0}
                />
              </div>
              <div className="col-span-2">
                <Label>Allowed IPs (comma-separated, optional)</Label>
                <Input
                  value={form.allowed_ips}
                  onChange={(e) => setForm({ ...form, allowed_ips: e.target.value })}
                  placeholder="1.2.3.4, 5.6.7.8"
                />
              </div>
              <div className="col-span-2 flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Switch
                    checked={form.notify_on_use}
                    onCheckedChange={(v) => setForm({ ...form, notify_on_use: v })}
                  />
                  <Label className="text-sm">Notify on use</Label>
                </div>
                {form.notify_on_use && (
                  <Input
                    value={form.notify_email}
                    onChange={(e) => setForm({ ...form, notify_email: e.target.value })}
                    placeholder="admin@company.com"
                    className="flex-1"
                  />
                )}
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => { setCreateModal(false); resetForm() }}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Access Link'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Temporary Access</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke &quot;{deleteTarget?.name}&quot;? The link will no longer work.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && revokeMutation.mutate(deleteTarget.id)}
            >
              Revoke Access
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
