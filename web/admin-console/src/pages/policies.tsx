import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Scale, Shield, Clock, MapPin, AlertTriangle, Edit, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
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
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Policy {
  id: string
  name: string
  description: string
  type: string
  enabled: boolean
  priority: number
  rules: PolicyRule[]
  created_at: string
  updated_at: string
}

interface PolicyRule {
  id: string
  condition: Record<string, unknown>
  effect: string
  priority: number
}

const policyTypeIcons: Record<string, React.ReactNode> = {
  separation_of_duty: <Shield className="h-4 w-4" />,
  risk_based: <AlertTriangle className="h-4 w-4" />,
  timebound: <Clock className="h-4 w-4" />,
  location: <MapPin className="h-4 w-4" />,
}

const policyTypeColors: Record<string, string> = {
  separation_of_duty: 'bg-purple-100 text-purple-800',
  risk_based: 'bg-red-100 text-red-800',
  timebound: 'bg-blue-100 text-blue-800',
  location: 'bg-green-100 text-green-800',
}

const policyTypeLabels: Record<string, string> = {
  separation_of_duty: 'Separation of Duty',
  risk_based: 'Risk-based',
  timebound: 'Timebound',
  location: 'Location-based',
}

export function PoliciesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'separation_of_duty',
    enabled: true,
    priority: 0,
  })

  const { data: policies, isLoading } = useQuery({
    queryKey: ['policies', search],
    queryFn: () => api.get<Policy[]>('/api/v1/governance/policies'),
  })

  const createPolicyMutation = useMutation({
    mutationFn: (policyData: Partial<Policy>) => api.post('/api/v1/governance/policies', policyData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy created successfully!',
        variant: 'success',
      })
      setCreateModal(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Policy> }) =>
      api.put(`/api/v1/governance/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy updated successfully!',
        variant: 'success',
      })
      setEditModal(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const deletePolicyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy deleted successfully!',
        variant: 'success',
      })
      setDeleteDialog(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const togglePolicyMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/governance/policies/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy status updated!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const filteredPolicies = policies?.filter(policy =>
    policy.name.toLowerCase().includes(search.toLowerCase()) ||
    policy.description?.toLowerCase().includes(search.toLowerCase()) ||
    policy.type.toLowerCase().includes(search.toLowerCase())
  )

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      type: 'separation_of_duty',
      enabled: true,
      priority: 0,
    })
  }

  const handleFormChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'number' ? parseInt(value) || 0 : value,
    }))
  }

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createPolicyMutation.mutate({
      id: crypto.randomUUID(),
      ...formData,
      rules: [],
    })
  }

  const handleEditClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setFormData({
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      enabled: policy.enabled,
      priority: policy.priority,
    })
    setEditModal(true)
  }

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedPolicy) return
    updatePolicyMutation.mutate({
      id: selectedPolicy.id,
      data: formData,
    })
  }

  const handleDeleteClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setDeleteDialog(true)
  }

  const handleToggleEnabled = (policy: Policy) => {
    togglePolicyMutation.mutate({
      id: policy.id,
      enabled: !policy.enabled,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Policies</h1>
          <p className="text-muted-foreground">Manage access control policies</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Policy
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'separation_of_duty').length || 0}
                </p>
                <p className="text-sm text-gray-500">SoD Policies</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-red-100 flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'risk_based').length || 0}
                </p>
                <p className="text-sm text-gray-500">Risk-based</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                <ToggleRight className="h-6 w-6 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.enabled).length || 0}
                </p>
                <p className="text-sm text-gray-500">Active</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-gray-100 flex items-center justify-center">
                <Scale className="h-6 w-6 text-gray-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{policies?.length || 0}</p>
                <p className="text-sm text-gray-500">Total Policies</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search policies..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Policy</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Status</th>
                  <th className="p-3 text-left text-sm font-medium">Priority</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={5} className="p-4 text-center">Loading...</td></tr>
                ) : filteredPolicies?.length === 0 ? (
                  <tr><td colSpan={5} className="p-4 text-center">No policies found</td></tr>
                ) : (
                  filteredPolicies?.map((policy) => (
                    <tr key={policy.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className={`h-10 w-10 rounded-lg ${policyTypeColors[policy.type]?.split(' ')[0] || 'bg-gray-100'} flex items-center justify-center`}>
                            {policyTypeIcons[policy.type] || <Scale className="h-5 w-5" />}
                          </div>
                          <div>
                            <p className="font-medium">{policy.name}</p>
                            <p className="text-sm text-gray-500 max-w-xs truncate">{policy.description || '-'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${policyTypeColors[policy.type] || 'bg-gray-100 text-gray-800'}`}>
                          {policyTypeIcons[policy.type]}
                          {policyTypeLabels[policy.type] || policy.type}
                        </span>
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => handleToggleEnabled(policy)}
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium cursor-pointer ${
                            policy.enabled
                              ? 'bg-green-100 text-green-800'
                              : 'bg-gray-100 text-gray-600'
                          }`}
                        >
                          {policy.enabled ? (
                            <>
                              <ToggleRight className="h-4 w-4" />
                              Enabled
                            </>
                          ) : (
                            <>
                              <ToggleLeft className="h-4 w-4" />
                              Disabled
                            </>
                          )}
                        </button>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline">{policy.priority}</Badge>
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEditClick(policy)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteClick(policy)}
                            className="text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Create Policy Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Policy</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Policy Name *</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                placeholder="e.g., SoD - Finance/Approver"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                placeholder="Describe what this policy enforces..."
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">Policy Type *</Label>
              <select
                id="type"
                name="type"
                value={formData.type}
                onChange={handleFormChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              >
                <option value="separation_of_duty">Separation of Duty (SoD)</option>
                <option value="risk_based">Risk-based</option>
                <option value="timebound">Timebound</option>
                <option value="location">Location-based</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Input
                id="priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
              <p className="text-xs text-gray-500">Higher priority policies are evaluated first</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="enabled">Enable policy immediately</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setCreateModal(false); resetForm(); }}
                disabled={createPolicyMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createPolicyMutation.isPending}>
                {createPolicyMutation.isPending ? 'Creating...' : 'Create Policy'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Policy Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Policy</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Policy Name *</Label>
              <Input
                id="edit-name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">Policy Type *</Label>
              <select
                id="edit-type"
                name="type"
                value={formData.type}
                onChange={handleFormChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              >
                <option value="separation_of_duty">Separation of Duty (SoD)</option>
                <option value="risk_based">Risk-based</option>
                <option value="timebound">Timebound</option>
                <option value="location">Location-based</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-priority">Priority</Label>
              <Input
                id="edit-priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="edit-enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="edit-enabled">Policy enabled</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setEditModal(false); setSelectedPolicy(null); }}
                disabled={updatePolicyMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updatePolicyMutation.isPending}>
                {updatePolicyMutation.isPending ? 'Saving...' : 'Save Changes'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedPolicy?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePolicyMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedPolicy && deletePolicyMutation.mutate(selectedPolicy.id)}
              disabled={deletePolicyMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {deletePolicyMutation.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
