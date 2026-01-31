import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Globe, Shield, Edit, Trash2, Power, PowerOff, ChevronLeft, ChevronRight } from 'lucide-react'
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
  created_at: string
  updated_at: string
}

export function ProxyRoutesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [deleteModal, setDeleteModal] = useState(false)
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
  })

  const { data, isLoading } = useQuery({
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
      toast({ title: 'Route created', description: 'Proxy route has been created successfully.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create proxy route.', variant: 'destructive' })
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
      toast({ title: 'Route updated', description: 'Proxy route has been updated.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update proxy route.', variant: 'destructive' })
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
      toast({ title: 'Route deleted', description: 'Proxy route has been deleted.' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete proxy route.', variant: 'destructive' })
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
          <h1 className="text-2xl font-bold">Proxy Routes</h1>
          <p className="text-muted-foreground">Manage zero trust access proxy routes for internal applications</p>
        </div>
        <Button onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" />
          Add Route
        </Button>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search routes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Badge variant="outline">{total} routes</Badge>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : filtered.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Globe className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No proxy routes configured</h3>
            <p className="text-muted-foreground mt-1">Add a route to start proxying requests to internal applications.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((route) => (
            <Card key={route.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${route.enabled ? 'bg-green-100' : 'bg-gray-100'}`}>
                      {route.enabled ? (
                        <Shield className="h-5 w-5 text-green-700" />
                      ) : (
                        <PowerOff className="h-5 w-5 text-gray-500" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{route.name}</h3>
                        <Badge variant={route.enabled ? 'default' : 'secondary'}>
                          {route.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                        {route.require_auth && (
                          <Badge variant="outline">Auth Required</Badge>
                        )}
                        {route.ziti_enabled && (
                          <Badge variant="default" className="bg-purple-600">Ziti</Badge>
                        )}
                        {route.priority > 0 && (
                          <Badge variant="outline">Priority: {route.priority}</Badge>
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
                        <Edit className="mr-2 h-4 w-4" /> Edit
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => {
                        updateMutation.mutate({
                          id: route.id,
                          data: { enabled: !route.enabled }
                        })
                      }}>
                        {route.enabled ? (
                          <><PowerOff className="mr-2 h-4 w-4" /> Disable</>
                        ) : (
                          <><Power className="mr-2 h-4 w-4" /> Enable</>
                        )}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-red-600"
                        onClick={() => { setSelectedRoute(route); setDeleteModal(true) }}
                      >
                        <Trash2 className="mr-2 h-4 w-4" /> Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">From:</span>{' '}
                    <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{route.from_url}</code>
                  </div>
                  <div>
                    <span className="text-muted-foreground">To:</span>{' '}
                    <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{route.to_url}</code>
                  </div>
                  {route.ziti_enabled && route.ziti_service_name && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">Ziti Service:</span>{' '}
                      <code className="bg-purple-50 text-purple-700 px-1.5 py-0.5 rounded text-xs">{route.ziti_service_name}</code>
                    </div>
                  )}
                  {route.allowed_roles && route.allowed_roles.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Roles:</span>{' '}
                      {route.allowed_roles.map(r => (
                        <Badge key={r} variant="outline" className="mr-1 text-xs">{r}</Badge>
                      ))}
                    </div>
                  )}
                  {route.allowed_groups && route.allowed_groups.length > 0 && (
                    <div>
                      <span className="text-muted-foreground">Groups:</span>{' '}
                      {route.allowed_groups.map(g => (
                        <Badge key={g} variant="outline" className="mr-1 text-xs">{g}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}

          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4">
              <p className="text-sm text-muted-foreground">
                Showing {page * pageSize + 1}-{Math.min((page + 1) * pageSize, total)} of {total}
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
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Proxy Route</DialogTitle>
          </DialogHeader>
          <RouteForm
            formData={formData}
            setFormData={setFormData}
            onSubmit={() => createMutation.mutate(buildPayload())}
            isLoading={createMutation.isPending}
            submitLabel="Create Route"
          />
        </DialogContent>
      </Dialog>

      {/* Edit Route Dialog */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Proxy Route</DialogTitle>
          </DialogHeader>
          <RouteForm
            formData={formData}
            setFormData={setFormData}
            onSubmit={() => selectedRoute && updateMutation.mutate({ id: selectedRoute.id, data: buildPayload() })}
            isLoading={updateMutation.isPending}
            submitLabel="Save Changes"
          />
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteModal} onOpenChange={setDeleteModal}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Proxy Route</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the route "{selectedRoute?.name}"? This will stop proxying traffic for this route.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => selectedRoute && deleteMutation.mutate(selectedRoute.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function RouteForm({
  formData,
  setFormData,
  onSubmit,
  isLoading,
  submitLabel,
}: {
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
  }
  setFormData: (data: typeof formData) => void
  onSubmit: () => void
  isLoading: boolean
  submitLabel: string
}) {
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); onSubmit() }}
      className="space-y-4"
    >
      <div className="space-y-2">
        <Label>Name</Label>
        <Input
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="My Internal App"
          required
        />
      </div>

      <div className="space-y-2">
        <Label>Description</Label>
        <Input
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="Optional description"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>From URL (public)</Label>
          <Input
            value={formData.from_url}
            onChange={(e) => setFormData({ ...formData, from_url: e.target.value })}
            placeholder="https://app.company.com"
            required
          />
        </div>
        <div className="space-y-2">
          <Label>To URL (upstream)</Label>
          <Input
            value={formData.to_url}
            onChange={(e) => setFormData({ ...formData, to_url: e.target.value })}
            placeholder="http://internal-app:8080"
            required
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Allowed Roles (comma-separated)</Label>
          <Input
            value={formData.allowed_roles}
            onChange={(e) => setFormData({ ...formData, allowed_roles: e.target.value })}
            placeholder="admin, developer"
          />
        </div>
        <div className="space-y-2">
          <Label>Allowed Groups (comma-separated)</Label>
          <Input
            value={formData.allowed_groups}
            onChange={(e) => setFormData({ ...formData, allowed_groups: e.target.value })}
            placeholder="engineering, devops"
          />
        </div>
      </div>

      <div className="space-y-2">
        <Label>Policy IDs (comma-separated)</Label>
        <Input
          value={formData.policy_ids}
          onChange={(e) => setFormData({ ...formData, policy_ids: e.target.value })}
          placeholder="Governance policy IDs to evaluate"
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Idle Timeout (sec)</Label>
          <Input
            type="number"
            value={formData.idle_timeout}
            onChange={(e) => setFormData({ ...formData, idle_timeout: parseInt(e.target.value) || 900 })}
          />
        </div>
        <div className="space-y-2">
          <Label>Abs. Timeout (sec)</Label>
          <Input
            type="number"
            value={formData.absolute_timeout}
            onChange={(e) => setFormData({ ...formData, absolute_timeout: parseInt(e.target.value) || 43200 })}
          />
        </div>
        <div className="space-y-2">
          <Label>Priority</Label>
          <Input
            type="number"
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
          />
        </div>
      </div>

      <div className="flex items-center gap-6">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={formData.require_auth}
            onChange={(e) => setFormData({ ...formData, require_auth: e.target.checked })}
            className="rounded"
          />
          Require Authentication
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={formData.preserve_host}
            onChange={(e) => setFormData({ ...formData, preserve_host: e.target.checked })}
            className="rounded"
          />
          Preserve Host Header
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={formData.enabled}
            onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
            className="rounded"
          />
          Enabled
        </label>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Saving...' : submitLabel}
        </Button>
      </div>
    </form>
  )
}
