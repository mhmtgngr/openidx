import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Users, MoreHorizontal, FolderTree, Edit, Trash2, UserPlus, Settings } from 'lucide-react'
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
import { useToast } from '../hooks/use-toast'

interface Group {
  id: string
  name: string
  description: string
  parent_id: string | null
  allow_self_join: boolean
  require_approval: boolean
  max_members: number | null
  member_count: number
  created_at: string
  updated_at: string
}

export function GroupsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createGroupModal, setCreateGroupModal] = useState(false)
  const [editGroupModal, setEditGroupModal] = useState(false)
  const [manageMembersModal, setManageMembersModal] = useState(false)
  const [groupSettingsModal, setGroupSettingsModal] = useState(false)
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
  })
  const [groupSettings, setGroupSettings] = useState({
    allowSelfJoin: false,
    requireApproval: false,
    maxMembers: '',
  })

  const { data: groups, isLoading } = useQuery({
    queryKey: ['groups', search],
    queryFn: () => api.get<Group[]>('/api/v1/identity/groups'),
  })

  // Create group mutation
  const createGroupMutation = useMutation({
    mutationFn: (groupData: Partial<Group>) =>
      api.post<Group>('/api/v1/identity/groups', groupData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: `Group ${data.name} created successfully!`,
        variant: 'success',
      })
      setCreateGroupModal(false)
      setFormData({ name: '', description: '' })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update group mutation
  const updateGroupMutation = useMutation({
    mutationFn: ({ id, ...groupData }: Partial<Group> & { id: string }) =>
      api.put<Group>(`/api/v1/identity/groups/${id}`, groupData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: `Group ${data.name} updated successfully!`,
        variant: 'success',
      })
      setEditGroupModal(false)
      setSelectedGroup(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete group mutation
  const deleteGroupMutation = useMutation({
    mutationFn: (groupId: string) =>
      api.delete(`/api/v1/identity/groups/${groupId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: 'Group deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const filteredGroups = groups?.filter(group =>
    group.name.toLowerCase().includes(search.toLowerCase()) ||
    group.description?.toLowerCase().includes(search.toLowerCase())
  )

  const handleCreateGroup = () => {
    setFormData({ name: '', description: '' })
    setCreateGroupModal(true)
  }

  const handleEditGroup = (group: Group) => {
    setSelectedGroup(group)
    setFormData({
      name: group.name,
      description: group.description || '',
    })
    setEditGroupModal(true)
  }

  const handleManageMembers = (groupId: string) => {
    const group = groups?.find(g => g.id === groupId)
    if (group) {
      setSelectedGroup(group)
      setManageMembersModal(true)
    }
  }

  const handleGroupSettings = (groupId: string) => {
    const group = groups?.find(g => g.id === groupId)
    if (group) {
      setSelectedGroup(group)
      setGroupSettingsModal(true)
    }
  }

  const handleSettingsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target
    setGroupSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  const handleSettingsSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedGroup) {
      updateGroupMutation.mutate({
        id: selectedGroup.id,
        name: selectedGroup.name,
        description: selectedGroup.description,
        allow_self_join: groupSettings.allowSelfJoin,
        require_approval: groupSettings.requireApproval,
        max_members: groupSettings.maxMembers || null,
      })
    }
  }

  // Handle group settings update success
  React.useEffect(() => {
    if (updateGroupMutation.isSuccess && groupSettingsModal) {
      toast({
        title: 'Success',
        description: `Group settings updated for "${selectedGroup?.name}"`,
        variant: 'success',
      })
      setGroupSettingsModal(false)
      setSelectedGroup(null)
      setGroupSettings({
        allowSelfJoin: false,
        requireApproval: false,
        maxMembers: '',
      })
    }
  }, [updateGroupMutation.isSuccess])

  const handleDeleteGroup = (groupId: string, groupName: string) => {
    if (confirm(`Are you sure you want to delete group: ${groupName}? This action cannot be undone.`)) {
      deleteGroupMutation.mutate(groupId)
    }
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (createGroupModal) {
      createGroupMutation.mutate({
        name: formData.name,
        description: formData.description,
      })
    } else if (editGroupModal && selectedGroup) {
      updateGroupMutation.mutate({
        id: selectedGroup.id,
        name: formData.name,
        description: formData.description,
      })
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Groups</h1>
          <p className="text-muted-foreground">Manage user groups and memberships</p>
        </div>
        <Button onClick={handleCreateGroup}>
          <Plus className="mr-2 h-4 w-4" /> Create Group
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search groups..."
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
                  <th className="p-3 text-left text-sm font-medium">Group</th>
                  <th className="p-3 text-left text-sm font-medium">Description</th>
                  <th className="p-3 text-left text-sm font-medium">Members</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Created</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="p-4 text-center">Loading...</td></tr>
                ) : filteredGroups?.length === 0 ? (
                  <tr><td colSpan={6} className="p-4 text-center">No groups found</td></tr>
                ) : (
                  filteredGroups?.map((group) => (
                    <tr key={group.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                            {group.parent_id ? (
                              <FolderTree className="h-5 w-5 text-purple-700" />
                            ) : (
                              <Users className="h-5 w-5 text-purple-700" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium">{group.name}</p>
                            {group.parent_id && (
                              <p className="text-xs text-gray-500">Subgroup</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-gray-600 max-w-xs truncate">
                        {group.description || '-'}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <Users className="h-4 w-4 text-gray-400" />
                          {group.member_count}
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant={group.parent_id ? 'secondary' : 'default'}>
                          {group.parent_id ? 'Subgroup' : 'Root'}
                        </Badge>
                      </td>
                      <td className="p-3 text-gray-500">
                        {new Date(group.created_at).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditGroup(group)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit Group
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleManageMembers(group.id)}>
                              <UserPlus className="mr-2 h-4 w-4" />
                              Manage Members
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleGroupSettings(group.id)}>
                              <Settings className="mr-2 h-4 w-4" />
                              Group Settings
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => handleDeleteGroup(group.id, group.name)}
                              disabled={deleteGroupMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteGroupMutation.isPending ? 'Deleting...' : 'Delete Group'}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Create Group Modal */}
      <Dialog open={createGroupModal} onOpenChange={setCreateGroupModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Group</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Group Name</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
                placeholder="Enter group name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Enter group description (optional)"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateGroupModal(false)}
                disabled={createGroupMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createGroupMutation.isPending}>
                {createGroupMutation.isPending ? 'Creating...' : 'Create Group'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Group Modal */}
      <Dialog open={editGroupModal} onOpenChange={setEditGroupModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Group</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Group Name</Label>
              <Input
                id="edit-name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Input
                id="edit-description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Enter group description (optional)"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditGroupModal(false)}
                disabled={updateGroupMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateGroupMutation.isPending}>
                {updateGroupMutation.isPending ? 'Updating...' : 'Update Group'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Manage Members Modal */}
      <Dialog open={manageMembersModal} onOpenChange={setManageMembersModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Members - {selectedGroup?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="text-sm text-gray-600">
              Current members: {selectedGroup?.member_count || 0}
            </div>
            <div className="space-y-2">
              <Label>Add Member</Label>
              <div className="flex gap-2">
                <Input placeholder="Enter username or email" />
                <Button type="button" size="sm">
                  Add
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label>Current Members</Label>
              <div className="max-h-32 overflow-y-auto space-y-1">
                {/* Mock member list - in real app this would come from API */}
                <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                  <span className="text-sm">john.doe@example.com</span>
                  <Button type="button" variant="outline" size="sm">
                    Remove
                  </Button>
                </div>
                <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                  <span className="text-sm">jane.smith@example.com</span>
                  <Button type="button" variant="outline" size="sm">
                    Remove
                  </Button>
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setManageMembersModal(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Group Settings Modal */}
      <Dialog open={groupSettingsModal} onOpenChange={setGroupSettingsModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Group Settings - {selectedGroup?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSettingsSubmit} className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="allowSelfJoin"
                  name="allowSelfJoin"
                  checked={groupSettings.allowSelfJoin}
                  onChange={handleSettingsChange}
                  className="rounded"
                />
                <Label htmlFor="allowSelfJoin">Allow users to join without approval</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="requireApproval"
                  name="requireApproval"
                  checked={groupSettings.requireApproval}
                  onChange={handleSettingsChange}
                  className="rounded"
                />
                <Label htmlFor="requireApproval">Require admin approval for new members</Label>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="maxMembers">Maximum Members (optional)</Label>
              <Input
                id="maxMembers"
                name="maxMembers"
                type="number"
                value={groupSettings.maxMembers}
                onChange={handleSettingsChange}
                placeholder="Leave empty for unlimited"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setGroupSettingsModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Save Settings</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
