import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Network, Server, Users2, Copy, CheckCircle, XCircle, Shield } from 'lucide-react'
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

type TabType = 'status' | 'services' | 'identities'

export function ZitiNetworkPage() {
  const [activeTab, setActiveTab] = useState<TabType>('status')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Ziti Network</h1>
        <p className="text-muted-foreground">Manage OpenZiti zero-trust network overlay</p>
      </div>

      <div className="flex gap-2 border-b">
        {(['status', 'services', 'identities'] as TabType[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === 'status' && <StatusTab />}
      {activeTab === 'services' && <ServicesTab />}
      {activeTab === 'identities' && <IdentitiesTab />}
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
