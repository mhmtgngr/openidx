import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Edit, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
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
import { api, IdentityProvider } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'

interface ProviderFormData {
  name: string
  provider_type: 'oidc' | 'saml'
  issuer_url: string
  client_id: string
  client_secret: string
  scopes: string
  enabled: boolean
}

const emptyForm: ProviderFormData = {
  name: '',
  provider_type: 'oidc',
  issuer_url: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid,profile,email',
  enabled: true,
}

export function IdentityProvidersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [addModal, setAddModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState<IdentityProvider | null>(null)
  const [formData, setFormData] = useState<ProviderFormData>(emptyForm)
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: providers, isLoading } = useQuery({
    queryKey: ['identity-providers', page],
    queryFn: async () => {
      const { data, headers } = await api.getWithHeaders<IdentityProvider[]>(
        `/api/v1/identity/providers?offset=${page * PAGE_SIZE}&limit=${PAGE_SIZE}`
      )
      setTotalCount(parseInt(headers['x-total-count'] || '0', 10))
      return data
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: ProviderFormData) =>
      api.createIdentityProvider({
        name: data.name,
        provider_type: data.provider_type,
        issuer_url: data.issuer_url,
        client_id: data.client_id,
        client_secret: data.client_secret,
        scopes: data.scopes.split(',').map((s) => s.trim()).filter(Boolean),
        enabled: data.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      setAddModal(false)
      setFormData(emptyForm)
      toast({ title: 'Identity provider created successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create identity provider.', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ProviderFormData }) =>
      api.updateIdentityProvider(id, {
        name: data.name,
        provider_type: data.provider_type,
        issuer_url: data.issuer_url,
        client_id: data.client_id,
        client_secret: data.client_secret,
        scopes: data.scopes.split(',').map((s) => s.trim()).filter(Boolean),
        enabled: data.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      setEditModal(false)
      setSelectedProvider(null)
      toast({ title: 'Identity provider updated successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update identity provider.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteIdentityProvider(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-providers'] })
      toast({ title: 'Identity provider deleted successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete identity provider.', variant: 'destructive' })
    },
  })

  const handleAdd = () => {
    setFormData(emptyForm)
    setAddModal(true)
  }

  const handleEdit = (provider: IdentityProvider) => {
    setSelectedProvider(provider)
    setFormData({
      name: provider.name,
      provider_type: provider.provider_type,
      issuer_url: provider.issuer_url,
      client_id: provider.client_id,
      client_secret: provider.client_secret,
      scopes: (provider.scopes || []).join(', '),
      enabled: provider.enabled,
    })
    setEditModal(true)
  }

  const handleDelete = (provider: IdentityProvider) => {
    setDeleteTarget({ id: provider.id, name: provider.name })
  }

  const handleFormSubmit = () => {
    if (editModal && selectedProvider) {
      updateMutation.mutate({ id: selectedProvider.id, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const filteredProviders = (providers || []).filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.provider_type.toLowerCase().includes(search.toLowerCase()) ||
      p.issuer_url.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner />
      </div>
    )
  }

  const formContent = (
    <div className="space-y-4">
      <div>
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="Provider name"
        />
      </div>
      <div>
        <Label>Provider Type</Label>
        <Select
          value={formData.provider_type}
          onValueChange={(v) => setFormData({ ...formData, provider_type: v as 'oidc' | 'saml' })}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="oidc">OIDC</SelectItem>
            <SelectItem value="saml">SAML</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label htmlFor="issuer_url">Issuer URL</Label>
        <Input
          id="issuer_url"
          value={formData.issuer_url}
          onChange={(e) => setFormData({ ...formData, issuer_url: e.target.value })}
          placeholder="https://accounts.google.com"
        />
      </div>
      <div>
        <Label htmlFor="client_id">Client ID</Label>
        <Input
          id="client_id"
          value={formData.client_id}
          onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
          placeholder="Client ID"
        />
      </div>
      <div>
        <Label htmlFor="client_secret">Client Secret</Label>
        <Input
          id="client_secret"
          type="password"
          value={formData.client_secret}
          onChange={(e) => setFormData({ ...formData, client_secret: e.target.value })}
          placeholder="Client secret"
        />
      </div>
      <div>
        <Label htmlFor="scopes">Scopes (comma-separated)</Label>
        <Input
          id="scopes"
          value={formData.scopes}
          onChange={(e) => setFormData({ ...formData, scopes: e.target.value })}
          placeholder="openid, profile, email"
        />
      </div>
      <div className="flex items-center gap-2">
        <Switch
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
        />
        <Label>Enabled</Label>
      </div>
      <div className="flex justify-end gap-2 pt-4">
        <Button variant="outline" onClick={() => { setAddModal(false); setEditModal(false) }}>
          Cancel
        </Button>
        <Button onClick={handleFormSubmit} disabled={createMutation.isPending || updateMutation.isPending}>
          {editModal ? 'Update' : 'Create'}
        </Button>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Identity Providers</h1>
        <Button onClick={handleAdd}>
          <Plus className="h-4 w-4 mr-2" />
          Add Provider
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configured Providers</CardTitle>
          <CardDescription>
            Manage external identity providers for Single Sign-On (SSO).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search providers..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Issuer URL</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredProviders.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    No identity providers found.
                  </TableCell>
                </TableRow>
              ) : (
                filteredProviders.map((provider) => (
                  <TableRow key={provider.id}>
                    <TableCell className="font-medium">{provider.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {provider.provider_type.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-xs truncate">{provider.issuer_url}</TableCell>
                    <TableCell>
                      <Badge variant={provider.enabled ? 'default' : 'secondary'}>
                        {provider.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleEdit(provider)}>
                            <Edit className="mr-2 h-4 w-4" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDelete(provider)} className="text-red-600">
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>

          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-muted-foreground">
                Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={(page + 1) * PAGE_SIZE >= totalCount}
                >
                  Next
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Provider Dialog */}
      <Dialog open={addModal} onOpenChange={setAddModal}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Identity Provider</DialogTitle>
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Edit Provider Dialog */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Identity Provider</DialogTitle>
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Delete Provider Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete identity provider "${deleteTarget.name}"? This action cannot be undone.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
