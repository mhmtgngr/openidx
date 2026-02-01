import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Network, Server, Users2, Copy, CheckCircle, XCircle, Shield, Router, Fingerprint, RefreshCw, FileKey, AlertTriangle, Monitor, ExternalLink } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

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

type TabType = 'status' | 'services' | 'identities' | 'routers' | 'posture' | 'policy-sync' | 'certificates' | 'remote-access'

const TAB_LABELS: Record<TabType, string> = {
  status: 'Status',
  services: 'Services',
  identities: 'Identities',
  routers: 'Routers',
  posture: 'Posture',
  'policy-sync': 'Policy Sync',
  certificates: 'Certificates',
  'remote-access': 'Remote Access',
}

export function ZitiNetworkPage() {
  const [activeTab, setActiveTab] = useState<TabType>('status')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Ziti Network</h1>
        <p className="text-muted-foreground">Manage OpenZiti zero-trust network overlay</p>
      </div>

      <div className="flex gap-2 border-b">
        {(Object.keys(TAB_LABELS) as TabType[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      {activeTab === 'status' && <StatusTab />}
      {activeTab === 'services' && <ServicesTab />}
      {activeTab === 'identities' && <IdentitiesTab />}
      {activeTab === 'routers' && <RoutersTab />}
      {activeTab === 'posture' && <PostureTab />}
      {activeTab === 'policy-sync' && <PolicySyncTab />}
      {activeTab === 'certificates' && <CertificatesTab />}
      {activeTab === 'remote-access' && <RemoteAccessTab />}
    </div>
  )
}

function StatusTab() {
  const { data: status, isLoading } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Integration</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            {status?.enabled ? (
              <CheckCircle className="h-5 w-5 text-green-500" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500" />
            )}
            <span className="text-lg font-semibold">
              {status?.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            SDK: {status?.sdk_ready ? 'Ready' : 'Not Ready'}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Controller</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            {status?.controller_reachable ? (
              <CheckCircle className="h-5 w-5 text-green-500" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500" />
            )}
            <span className="text-lg font-semibold">
              {status?.controller_reachable ? 'Connected' : 'Unreachable'}
            </span>
          </div>
          {status?.controller_error && (
            <p className="text-sm text-red-500 mt-1">{status.controller_error}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Resources</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-6">
            <div>
              <p className="text-2xl font-bold">{status?.services_count || 0}</p>
              <p className="text-sm text-muted-foreground">Services</p>
            </div>
            <div>
              <p className="text-2xl font-bold">{status?.identities_count || 0}</p>
              <p className="text-sm text-muted-foreground">Identities</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function ServicesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
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
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create Ziti service.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/services/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Service deleted', description: 'Ziti service has been deleted.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete Ziti service.', variant: 'destructive' })
    },
  })

  const services = data?.services || []

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{services.length} Ziti services registered</p>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Service
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : services.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Server className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No Ziti services</h3>
            <p className="text-muted-foreground mt-1">Register upstream services to route traffic through the Ziti overlay.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {services.map((svc) => (
            <Card key={svc.id}>
              <CardContent className="flex items-center justify-between py-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-100">
                    <Network className="h-5 w-5 text-purple-700" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{svc.name}</h3>
                      <Badge variant="outline">{svc.protocol}</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {svc.host}:{svc.port}
                      {svc.description && ` - ${svc.description}`}
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Ziti ID: {svc.ziti_id}
                    </p>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-red-600"
                  onClick={() => setDeleteTarget(svc)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
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
                <Input value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })} placeholder="tcp" />
              </div>
            </div>
            <div className="flex justify-end">
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Service'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Service</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteTarget?.name}"? This will remove it from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function IdentitiesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
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
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create Ziti identity.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/identities/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Identity deleted', description: 'Ziti identity has been deleted.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete Ziti identity.', variant: 'destructive' })
    },
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied', description: 'Enrollment JWT copied to clipboard.' })
  }

  const identities = data?.identities || []

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{identities.length} Ziti identities registered</p>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Identity
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : identities.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Users2 className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No Ziti identities</h3>
            <p className="text-muted-foreground mt-1">Create identities for desktop tunneler enrollment.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {identities.map((ident) => (
            <Card key={ident.id}>
              <CardContent className="flex items-center justify-between py-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${ident.enrolled ? 'bg-green-100' : 'bg-yellow-100'}`}>
                    <Shield className={`h-5 w-5 ${ident.enrolled ? 'text-green-700' : 'text-yellow-700'}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{ident.name}</h3>
                      <Badge variant="outline">{ident.identity_type}</Badge>
                      <Badge variant={ident.enrolled ? 'default' : 'secondary'}>
                        {ident.enrolled ? 'Enrolled' : 'Pending'}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Ziti ID: {ident.ziti_id}
                      {ident.user_id && ` | User: ${ident.user_id}`}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2">
                  {!ident.enrolled && (
                    <Button variant="outline" size="sm" onClick={() => fetchJWT(ident)}>
                      <Copy className="h-4 w-4 mr-1" /> JWT
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-600"
                    onClick={() => setDeleteTarget(ident)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
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
            <div className="flex justify-end">
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Identity'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Enrollment JWT Modal */}
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
                onClick={() => jwtModal && copyToClipboard(jwtModal.jwt)}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Identity</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteTarget?.name}"? This will revoke the identity from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ==================== ROUTERS TAB ====================

function RoutersTab() {
  const { toast } = useToast()

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['ziti-fabric-overview'],
    queryFn: () => api.get<FabricOverview>('/api/v1/access/ziti/fabric/overview'),
    refetchInterval: 15000,
  })

  const { data: routersData, isLoading: routersLoading } = useQuery({
    queryKey: ['ziti-fabric-routers'],
    queryFn: () => api.get<FabricRouter[]>('/api/v1/access/ziti/fabric/routers'),
  })

  const reconnectMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/fabric/reconnect', {}),
    onSuccess: () => {
      toast({ title: 'Reconnect initiated', description: 'Fabric reconnect has been triggered.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to trigger reconnect.', variant: 'destructive' })
    },
  })

  const healthCheckMutation = useMutation({
    mutationFn: () => api.get('/api/v1/access/ziti/fabric/health'),
    onSuccess: () => {
      toast({ title: 'Health check passed', description: 'Fabric health check completed successfully.' })
    },
    onError: () => {
      toast({ title: 'Health check failed', description: 'Fabric health check reported issues.', variant: 'destructive' })
    },
  })

  const routers = Array.isArray(routersData) ? routersData : []
  const isLoading = overviewLoading || routersLoading

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Overview cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Controller</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              {overview?.controller_online ? (
                <CheckCircle className="h-5 w-5 text-green-500" />
              ) : (
                <XCircle className="h-5 w-5 text-red-500" />
              )}
              <span className="text-lg font-semibold">
                {overview?.controller_online ? 'Online' : 'Offline'}
              </span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Routers</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{overview?.router_count || 0}</p>
            <p className="text-sm text-muted-foreground">
              {overview?.healthy_routers || 0} healthy / {overview?.unhealthy_routers || 0} unhealthy
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Services</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{overview?.service_count || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Identities</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{overview?.identity_count || 0}</p>
          </CardContent>
        </Card>
      </div>

      {/* Actions */}
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{routers.length} fabric routers</p>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => healthCheckMutation.mutate()} disabled={healthCheckMutation.isPending}>
            <CheckCircle className="mr-2 h-4 w-4" />
            {healthCheckMutation.isPending ? 'Checking...' : 'Health Check'}
          </Button>
          <Button variant="outline" onClick={() => reconnectMutation.mutate()} disabled={reconnectMutation.isPending}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {reconnectMutation.isPending ? 'Reconnecting...' : 'Reconnect'}
          </Button>
        </div>
      </div>

      {/* Router list */}
      {routers.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Router className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No fabric routers</h3>
            <p className="text-muted-foreground mt-1">No routers are registered in the Ziti fabric.</p>
          </CardContent>
        </Card>
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
                <TableRow key={router.id}>
                  <TableCell className="font-medium">{router.name}</TableCell>
                  <TableCell>
                    <Badge variant={router.is_online ? 'default' : 'destructive'}>
                      {router.is_online ? 'Online' : 'Offline'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{router.hostname}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground max-w-[200px] truncate">
                    {router.fingerprint}
                  </TableCell>
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
  )
}

// ==================== POSTURE TAB ====================

function PostureTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<PostureCheck | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<PostureCheck | null>(null)
  const [form, setForm] = useState({
    name: '',
    check_type: 'OS',
    parameters: '{}',
    severity: 'medium',
    enabled: true,
  })

  const { data: summary } = useQuery({
    queryKey: ['ziti-posture-summary'],
    queryFn: () => api.get<PostureSummary>('/api/v1/access/ziti/posture/summary'),
  })

  const { data: checksData, isLoading } = useQuery({
    queryKey: ['ziti-posture-checks'],
    queryFn: () => api.get<PostureCheck[]>('/api/v1/access/ziti/posture/checks'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => {
      const payload = {
        ...data,
        parameters: JSON.parse(data.parameters),
      }
      return api.post('/api/v1/access/ziti/posture/checks', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Posture check created', description: 'Posture check has been created.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create posture check.', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => {
      const payload = {
        ...data,
        parameters: JSON.parse(data.parameters),
      }
      return api.put(`/api/v1/access/ziti/posture/checks/${id}`, payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setEditTarget(null)
      resetForm()
      toast({ title: 'Posture check updated', description: 'Posture check has been updated.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update posture check.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/posture/checks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setDeleteTarget(null)
      toast({ title: 'Posture check deleted', description: 'Posture check has been deleted.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete posture check.', variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setForm({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true })
  }

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

  const checks = Array.isArray(checksData) ? checksData : []

  const severityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'outline'
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Posture summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Checks</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{summary?.total_checks || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Enabled</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-green-600">{summary?.enabled_checks || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Disabled</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-muted-foreground">{summary?.disabled_checks || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">By Type</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1">
              {summary?.by_type && Object.entries(summary.by_type).map(([type, count]) => (
                <Badge key={type} variant="outline">{type}: {count}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{checks.length} posture checks configured</p>
        <Button onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> Add Posture Check
        </Button>
      </div>

      {checks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Fingerprint className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No posture checks</h3>
            <p className="text-muted-foreground mt-1">Create posture checks to enforce device compliance.</p>
          </CardContent>
        </Card>
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
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {checks.map((check) => (
                <TableRow key={check.id}>
                  <TableCell className="font-medium">{check.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{check.check_type}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={severityColor(check.severity)}>{check.severity}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={check.enabled ? 'default' : 'secondary'}>
                      {check.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(check.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => openEditModal(check)}>
                        Edit
                      </Button>
                      <Button variant="ghost" size="sm" className="text-red-600" onClick={() => setDeleteTarget(check)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Posture Check</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Posture check name" required />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Check Type</Label>
                <select
                  value={form.check_type}
                  onChange={(e) => setForm({ ...form, check_type: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="OS">OS</option>
                  <option value="Domain">Domain</option>
                  <option value="MFA">MFA</option>
                  <option value="Process">Process</option>
                  <option value="MAC">MAC</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Severity</Label>
                <select
                  value={form.severity}
                  onChange={(e) => setForm({ ...form, severity: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
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
              <input
                type="checkbox"
                id="posture-enabled"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="rounded border-input"
              />
              <Label htmlFor="posture-enabled">Enabled</Label>
            </div>
            <div className="flex justify-end">
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Check'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editTarget} onOpenChange={() => { setEditTarget(null); resetForm() }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Posture Check</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); editTarget && updateMutation.mutate({ id: editTarget.id, data: form }) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Check Type</Label>
                <select
                  value={form.check_type}
                  onChange={(e) => setForm({ ...form, check_type: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="OS">OS</option>
                  <option value="Domain">Domain</option>
                  <option value="MFA">MFA</option>
                  <option value="Process">Process</option>
                  <option value="MAC">MAC</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Severity</Label>
                <select
                  value={form.severity}
                  onChange={(e) => setForm({ ...form, severity: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
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
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="posture-enabled-edit"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="rounded border-input"
              />
              <Label htmlFor="posture-enabled-edit">Enabled</Label>
            </div>
            <div className="flex justify-end">
              <Button type="submit" disabled={updateMutation.isPending}>
                {updateMutation.isPending ? 'Updating...' : 'Update Check'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Posture Check</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteTarget?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ==================== POLICY SYNC TAB ====================

function PolicySyncTab() {
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
    mutationFn: (data: typeof form) => {
      const payload = {
        governance_policy_id: data.governance_policy_id,
        config: JSON.parse(data.config),
      }
      return api.post('/api/v1/access/ziti/policy-sync', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setCreateModal(false)
      setForm({ governance_policy_id: '', config: '{}' })
      toast({ title: 'Policy sync created', description: 'Policy sync mapping has been created.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create policy sync.', variant: 'destructive' })
    },
  })

  const triggerMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/policy-sync/${id}/trigger`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      toast({ title: 'Re-sync triggered', description: 'Policy re-sync has been triggered.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to trigger re-sync.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/policy-sync/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setDeleteTarget(null)
      toast({ title: 'Policy sync deleted', description: 'Policy sync mapping has been deleted.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete policy sync.', variant: 'destructive' })
    },
  })

  const syncs = Array.isArray(syncsData) ? syncsData : []

  const statusBadgeVariant = (status: string): 'default' | 'destructive' | 'secondary' | 'outline' => {
    switch (status) {
      case 'synced': return 'default'
      case 'error': return 'destructive'
      case 'pending': return 'secondary'
      default: return 'outline'
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{syncs.length} policy sync mappings</p>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Sync Policy
        </Button>
      </div>

      {syncs.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <RefreshCw className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No policy sync mappings</h3>
            <p className="text-muted-foreground mt-1">Sync governance policies to Ziti network policies.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Governance Policy ID</TableHead>
                <TableHead>Ziti Policy ID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Synced</TableHead>
                <TableHead>Error</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncs.map((sync) => (
                <TableRow key={sync.id}>
                  <TableCell className="font-mono text-sm">{sync.governance_policy_id}</TableCell>
                  <TableCell className="font-mono text-sm">{sync.ziti_policy_id || '-'}</TableCell>
                  <TableCell>
                    <Badge variant={statusBadgeVariant(sync.sync_status)}>
                      {sync.sync_status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {sync.last_synced_at ? new Date(sync.last_synced_at).toLocaleString() : 'Never'}
                  </TableCell>
                  <TableCell className="text-sm text-red-500 max-w-[200px] truncate">
                    {sync.error_message || '-'}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => triggerMutation.mutate(sync.id)}
                        disabled={triggerMutation.isPending}
                      >
                        <RefreshCw className="h-4 w-4 mr-1" /> Re-sync
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-600"
                        onClick={() => setDeleteTarget(sync)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Sync Policy to Ziti</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Governance Policy ID</Label>
              <Input
                value={form.governance_policy_id}
                onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })}
                placeholder="UUID of governance policy"
                required
              />
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
            <div className="flex justify-end">
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Syncing...' : 'Sync Policy'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy Sync</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this policy sync mapping? The Ziti policy will also be removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ==================== CERTIFICATES TAB ====================

function CertificatesTab() {
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
    onError: () => {
      toast({ title: 'Error', description: 'Failed to rotate certificate.', variant: 'destructive' })
    },
  })

  const certs = Array.isArray(certsData) ? certsData : []
  const alerts = Array.isArray(expiryAlerts) ? expiryAlerts : []

  const expiryBadgeVariant = (days: number): 'default' | 'destructive' | 'secondary' | 'outline' => {
    if (days < 30) return 'destructive'
    if (days <= 60) return 'secondary'
    return 'default'
  }

  const expiryBadgeLabel = (days: number) => {
    if (days < 0) return 'Expired'
    if (days === 0) return 'Expires today'
    return `${days}d remaining`
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Expiry alerts */}
      {alerts.length > 0 && (
        <Card className="border-yellow-300 bg-yellow-50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-yellow-800">
              <AlertTriangle className="h-4 w-4" />
              Certificates Expiring Soon ({alerts.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {alerts.map((cert) => (
                <div key={cert.id} className="flex items-center justify-between text-sm">
                  <span className="font-medium text-yellow-900">{cert.name}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-yellow-700">
                      {cert.days_until_expiry < 0
                        ? `Expired ${Math.abs(cert.days_until_expiry)} days ago`
                        : `Expires in ${cert.days_until_expiry} days`}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => rotateMutation.mutate(cert.id)}
                      disabled={rotateMutation.isPending}
                    >
                      Rotate
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{certs.length} certificates managed</p>
      </div>

      {certs.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileKey className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No certificates</h3>
            <p className="text-muted-foreground mt-1">No Ziti certificates are being managed.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Subject</TableHead>
                <TableHead>Issuer</TableHead>
                <TableHead>Expiry</TableHead>
                <TableHead>Auto Renew</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {certs.map((cert) => (
                <TableRow key={cert.id}>
                  <TableCell className="font-medium">{cert.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{cert.cert_type}</Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[150px] truncate">
                    {cert.subject}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[150px] truncate">
                    {cert.issuer}
                  </TableCell>
                  <TableCell>
                    <Badge variant={expiryBadgeVariant(cert.days_until_expiry)}>
                      {expiryBadgeLabel(cert.days_until_expiry)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={cert.auto_renew ? 'default' : 'secondary'}>
                      {cert.auto_renew ? 'Yes' : 'No'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{cert.status}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => rotateMutation.mutate(cert.id)}
                      disabled={rotateMutation.isPending}
                    >
                      <RefreshCw className="h-4 w-4 mr-1" /> Rotate
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  )
}

// ---- Remote Access Tab (Guacamole Connections) ----

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

function RemoteAccessTab() {
  const { toast } = useToast()

  const { data, isLoading } = useQuery({
    queryKey: ['guacamole-connections'],
    queryFn: async () => {
      return api.get<{ connections: GuacConnection[] }>('/api/v1/access/guacamole/connections')
    },
  })

  const connectMutation = useMutation({
    mutationFn: async (routeId: string) => {
      return api.post<{ connect_url: string; connection_id: string }>(`/api/v1/access/guacamole/connections/${routeId}/connect`, {})
    },
    onSuccess: (resp) => {
      const connectUrl = (resp as Record<string, string>)?.connect_url
      if (connectUrl) {
        window.open(connectUrl, '_blank')
      }
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to get connection URL.', variant: 'destructive' })
    },
  })

  const connections = data?.connections || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  if (connections.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Monitor className="h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="text-lg font-medium">No remote access connections</h3>
          <p className="text-muted-foreground mt-1">
            Create a proxy route with type SSH, RDP, or VNC to auto-provision Guacamole connections.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Apache Guacamole provides clientless remote access to SSH, RDP, VNC, and Telnet targets through the browser.
        </p>
        <Badge variant="outline">{connections.length} connections</Badge>
      </div>

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
              <TableRow key={conn.id}>
                <TableCell>
                  <Badge variant="default" className={
                    conn.protocol === 'ssh' ? 'bg-green-600' :
                    conn.protocol === 'rdp' ? 'bg-blue-600' :
                    conn.protocol === 'vnc' ? 'bg-purple-600' : 'bg-gray-600'
                  }>
                    {conn.protocol.toUpperCase()}
                  </Badge>
                </TableCell>
                <TableCell>
                  <code className="text-sm">{conn.hostname}:{conn.port}</code>
                </TableCell>
                <TableCell>
                  <code className="text-xs text-muted-foreground">{conn.guacamole_connection_id}</code>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {new Date(conn.created_at).toLocaleDateString()}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="sm"
                    onClick={() => connectMutation.mutate(conn.route_id)}
                    disabled={connectMutation.isPending}
                  >
                    <ExternalLink className="mr-1 h-3 w-3" />
                    Connect
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  )
}
