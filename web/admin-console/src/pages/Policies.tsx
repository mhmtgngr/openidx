import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Edit, Power, PowerOff } from 'lucide-react'
import { governanceApi } from '@/lib/api/governance'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { formatDateTime } from '@/lib/utils/date'
import { useToast } from '@/components/ui/use-toast'
import type { Policy, CreatePolicyRequest, PolicyRule } from '@/lib/api/types'

const typeColors: Record<Policy['type'], 'default' | 'secondary' | 'outline'> = {
  rbac: 'default',
  abac: 'secondary',
  custom: 'outline',
}

export function Policies() {
  const [page, setPage] = useState(1)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [formData, setFormData] = useState<CreatePolicyRequest>({
    name: '',
    description: '',
    type: 'rbac',
    rules: [],
  })
  const [newRule, setNewRule] = useState<Omit<PolicyRule, 'id'>>({
    effect: 'allow',
    actions: [],
    resources: [],
  })
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['policies', page],
    queryFn: () =>
      governanceApi.getPolicies({
        page,
        per_page: 25,
      }),
  })

  const createMutation = useMutation({
    mutationFn: (data: CreatePolicyRequest) => governanceApi.createPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      setIsCreateDialogOpen(false)
      resetForm()
      toast({
        title: 'Success',
        description: 'Policy created successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to create policy',
        variant: 'destructive',
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreatePolicyRequest> }) =>
      governanceApi.updatePolicy(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      setIsEditDialogOpen(false)
      setSelectedPolicy(null)
      toast({
        title: 'Success',
        description: 'Policy updated successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update policy',
        variant: 'destructive',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => governanceApi.deletePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy deleted successfully',
      })
    },
    onError: (error: any) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to delete policy',
        variant: 'destructive',
      })
    },
  })

  const toggleStatusMutation = useMutation({
    mutationFn: ({ id, activate }: { id: string; activate: boolean }) =>
      activate ? governanceApi.activatePolicy(id) : governanceApi.deactivatePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy status updated',
      })
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      type: 'rbac',
      rules: [],
    })
    setNewRule({
      effect: 'allow',
      actions: [],
      resources: [],
    })
  }

  const addRule = () => {
    if (newRule.actions.length > 0 && newRule.resources.length > 0) {
      setFormData({
        ...formData,
        rules: [...formData.rules, newRule],
      })
      setNewRule({
        effect: 'allow',
        actions: [],
        resources: [],
      })
    }
  }

  const removeRule = (index: number) => {
    setFormData({
      ...formData,
      rules: formData.rules.filter((_, i) => i !== index),
    })
  }

  const handleCreate = () => {
    if (formData.rules.length === 0) {
      toast({
        title: 'Validation Error',
        description: 'Please add at least one rule',
        variant: 'destructive',
      })
      return
    }
    createMutation.mutate(formData)
  }

  const handleUpdate = () => {
    if (selectedPolicy) {
      updateMutation.mutate({
        id: selectedPolicy.id,
        data: formData,
      })
    }
  }

  const openEditDialog = (policy: Policy) => {
    setSelectedPolicy(policy)
    setFormData({
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      rules: policy.rules.map(({ id, ...rule }) => rule),
    })
    setIsEditDialogOpen(true)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Policies</h1>
          <p className="text-muted-foreground">
            Manage governance and access policies
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={(open) => {
          setIsCreateDialogOpen(open)
          if (!open) resetForm()
        }}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              New Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create Policy</DialogTitle>
              <DialogDescription>
                Define access control rules for the system
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Policy Name</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) =>
                      setFormData({ ...formData, name: e.target.value })
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="type">Policy Type</Label>
                  <Select
                    value={formData.type}
                    onValueChange={(v: any) => setFormData({ ...formData, type: v })}
                  >
                    <SelectTrigger id="type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="rbac">RBAC</SelectItem>
                      <SelectItem value="abac">ABAC</SelectItem>
                      <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) =>
                    setFormData({ ...formData, description: e.target.value })
                  }
                />
              </div>

              <div className="space-y-4 border-t pt-4">
                <div className="flex items-center justify-between">
                  <Label>Rules</Label>
                  <Badge variant="outline">{formData.rules.length} rules</Badge>
                </div>

                {formData.rules.map((rule, index) => (
                  <div key={index} className="p-4 border rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <Badge variant={rule.effect === 'allow' ? 'success' : 'destructive'}>
                        {rule.effect}
                      </Badge>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeRule(index)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="text-sm">
                      <div><strong>Actions:</strong> {rule.actions.join(', ')}</div>
                      <div><strong>Resources:</strong> {rule.resources.join(', ')}</div>
                    </div>
                  </div>
                ))}

                <div className="p-4 border rounded-lg space-y-3 bg-muted/50">
                  <div className="flex items-center gap-4">
                    <Label>Effect</Label>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={newRule.effect === 'deny'}
                        onCheckedChange={(checked) =>
                          setNewRule({ ...newRule, effect: checked ? 'deny' : 'allow' })
                        }
                      />
                      <span className="text-sm">{newRule.effect}</span>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>Actions (comma-separated)</Label>
                    <Input
                      placeholder="read, write, delete"
                      value={newRule.actions.join(', ')}
                      onChange={(e) =>
                        setNewRule({
                          ...newRule,
                          actions: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Resources (comma-separated)</Label>
                    <Input
                      placeholder="/api/users/*, /api/admin/*"
                      value={newRule.resources.join(', ')}
                      onChange={(e) =>
                        setNewRule({
                          ...newRule,
                          resources: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                        })
                      }
                    />
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={addRule}
                    disabled={newRule.actions.length === 0 || newRule.resources.length === 0}
                  >
                    Add Rule
                  </Button>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Policies</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Rules</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data?.data.map((policy) => (
                    <TableRow key={policy.id}>
                      <TableCell className="font-medium">{policy.name}</TableCell>
                      <TableCell>
                        <Badge variant={typeColors[policy.type]}>
                          {policy.type.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>{policy.rules.length} rules</TableCell>
                      <TableCell>
                        <Badge variant={policy.status === 'active' ? 'success' : 'secondary'}>
                          {policy.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{formatDateTime(policy.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => toggleStatusMutation.mutate({
                              id: policy.id,
                              activate: policy.status !== 'active'
                            })}
                            title={policy.status === 'active' ? 'Deactivate' : 'Activate'}
                          >
                            {policy.status === 'active' ? (
                              <PowerOff className="h-4 w-4" />
                            ) : (
                              <Power className="h-4 w-4" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(policy)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            onClick={() => deleteMutation.mutate(policy.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {data && data.total_pages > 1 && (
                <div className="flex items-center justify-end gap-2 mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    Page {page} of {data.total_pages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => p + 1)}
                    disabled={page >= data.total_pages}
                  >
                    Next
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Edit Dialog - similar structure to create dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={(open) => {
        setIsEditDialogOpen(open)
        if (!open) setSelectedPolicy(null)
      }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Policy</DialogTitle>
            <DialogDescription>
              Update policy configuration
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4 max-h-[60vh] overflow-y-auto">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-name">Policy Name</Label>
                <Input
                  id="edit-name"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-type">Policy Type</Label>
                <Select
                  value={formData.type}
                  onValueChange={(v: any) => setFormData({ ...formData, type: v })}
                >
                  <SelectTrigger id="edit-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="rbac">RBAC</SelectItem>
                    <SelectItem value="abac">ABAC</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Updating...' : 'Update'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
