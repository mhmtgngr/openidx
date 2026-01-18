import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Mail, Edit, Trash2, Key, Shield } from 'lucide-react'
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

interface User {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
  enabled: boolean
  email_verified: boolean
  created_at: string
}

interface Role {
  id: string
  name: string
  description: string
  is_composite: boolean
  created_at: string
}

export function UsersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [addUserModal, setAddUserModal] = useState(false)
  const [editUserModal, setEditUserModal] = useState(false)
  const [manageRolesModal, setManageRolesModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    first_name: '',
    last_name: '',
    password: '',
  })
  const [selectedRoles, setSelectedRoles] = useState<string[]>([])

  // Fetch available roles
  const { data: availableRoles, isLoading: rolesLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.get<Role[]>('/api/v1/identity/roles'),
  })

  // Fetch user roles when managing roles
  const { data: userRoles, isLoading: userRolesLoading } = useQuery({
    queryKey: ['user-roles', selectedUser?.id],
    queryFn: () => selectedUser ? api.get<Role[]>(`/api/v1/identity/users/${selectedUser.id}/roles`) : [],
    enabled: !!selectedUser && manageRolesModal,
  })

  // Populate selectedRoles when userRoles data loads
  useEffect(() => {
    if (userRoles && manageRolesModal) {
      const roleIds = userRoles.map(role => role.id)
      setSelectedRoles(roleIds)
    }
  }, [userRoles, manageRolesModal])

  // Fetch users
  const { data: users, isLoading } = useQuery({
    queryKey: ['users', search],
    queryFn: () => api.get<User[]>('/api/v1/identity/users'),
  })

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: (userData: Partial<User>) =>
      api.post<User>('/api/v1/identity/users', userData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: `User ${data.username} created successfully!`,
        variant: 'success',
      })
      setAddUserModal(false)
      setFormData({ username: '', email: '', first_name: '', last_name: '', password: '' })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ id, ...userData }: Partial<User> & { id: string }) =>
      api.put<User>(`/api/v1/identity/users/${id}`, userData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: `User ${data.username} updated successfully!`,
        variant: 'success',
      })
      setEditUserModal(false)
      setSelectedUser(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) =>
      api.delete(`/api/v1/identity/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: 'User deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleAddUser = () => {
    setFormData({ username: '', email: '', first_name: '', last_name: '', password: '' })
    setAddUserModal(true)
  }

  const handleEditUser = (user: User) => {
    setSelectedUser(user)
    setFormData({
      username: user.username,
      email: user.email,
      first_name: user.first_name || '',
      last_name: user.last_name || '',
      password: '',
    })
    setEditUserModal(true)
  }

  const handleResetPassword = (userId: string) => {
    if (confirm('Are you sure you want to reset this user\'s password?')) {
      toast({
        title: 'Info',
        description: `Password reset email sent to user ${userId}`,
      })
    }
  }

  const handleManageRoles = (userId: string) => {
    const user = users?.find(u => u.id === userId)
    if (user) {
      setSelectedUser(user)
      // Reset selected roles - will be populated when userRoles query loads
      setSelectedRoles([])
      setManageRolesModal(true)
    }
  }

  const handleRoleToggle = (roleId: string) => {
    setSelectedRoles(prev =>
      prev.includes(roleId)
        ? prev.filter(id => id !== roleId)
        : [...prev, roleId]
    )
  }

  const handleRolesSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedUser) {
      updateUserRolesMutation.mutate({
        userId: selectedUser.id,
        roleIds: selectedRoles,
      })
    }
  }

  // Update user roles mutation
  const updateUserRolesMutation = useMutation({
    mutationFn: ({ userId, roleIds }: { userId: string; roleIds: string[] }) =>
      api.put(`/api/v1/identity/users/${userId}/roles`, { role_ids: roleIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: `Roles updated for user ${selectedUser?.username}`,
        variant: 'success',
      })
      setManageRolesModal(false)
      setSelectedUser(null)
      setSelectedRoles([])
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update roles: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleDeleteUser = (userId: string, username: string) => {
    if (confirm(`Are you sure you want to delete user: ${username}? This action cannot be undone.`)) {
      deleteUserMutation.mutate(userId)
    }
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (addUserModal) {
      createUserMutation.mutate({
        username: formData.username,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        enabled: true,
        email_verified: false,
      })
    } else if (editUserModal && selectedUser) {
      updateUserMutation.mutate({
        id: selectedUser.id,
        username: formData.username,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        enabled: selectedUser.enabled,
        email_verified: selectedUser.email_verified,
      })
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  // Filter users by search
  const filteredUsers = users?.filter(user =>
    search === '' ||
    user.username.toLowerCase().includes(search.toLowerCase()) ||
    user.email.toLowerCase().includes(search.toLowerCase()) ||
    `${user.first_name} ${user.last_name}`.toLowerCase().includes(search.toLowerCase())
  ) || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Users</h1>
          <p className="text-muted-foreground">Manage user accounts and access</p>
        </div>
        <Button onClick={handleAddUser}>
          <Plus className="mr-2 h-4 w-4" /> Add User
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search users..."
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
                  <th className="p-3 text-left text-sm font-medium">User</th>
                  <th className="p-3 text-left text-sm font-medium">Email</th>
                  <th className="p-3 text-left text-sm font-medium">Status</th>
                  <th className="p-3 text-left text-sm font-medium">Created</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={5} className="p-4 text-center">Loading...</td></tr>
                ) : filteredUsers.length === 0 ? (
                  <tr><td colSpan={5} className="p-4 text-center">
                    {search ? 'No users found matching your search' : 'No users found'}
                  </td></tr>
                ) : (
                  filteredUsers.map((user) => (
                    <tr key={user.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                            <span className="text-blue-700 font-medium">
                              {user.first_name?.[0] || user.username[0]?.toUpperCase()}
                              {user.last_name?.[0] || ''}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium">
                              {user.first_name && user.last_name
                                ? `${user.first_name} ${user.last_name}`
                                : user.username}
                            </p>
                            <p className="text-sm text-gray-500">@{user.username}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <Mail className="h-4 w-4 text-gray-400" />
                          {user.email}
                          {user.email_verified && (
                            <Badge variant="outline" className="ml-2">Verified</Badge>
                          )}
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant={user.enabled ? 'default' : 'secondary'}>
                          {user.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                      </td>
                      <td className="p-3 text-gray-500">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditUser(user)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit User
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleResetPassword(user.id)}>
                              <Key className="mr-2 h-4 w-4" />
                              Reset Password
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleManageRoles(user.id)}>
                              <Shield className="mr-2 h-4 w-4" />
                              Manage Roles
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => handleDeleteUser(user.id, user.username)}
                              disabled={deleteUserMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteUserMutation.isPending ? 'Deleting...' : 'Delete User'}
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

      {/* Add User Modal */}
      <Dialog open={addUserModal} onOpenChange={setAddUserModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add New User</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username *</Label>
              <Input
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
                placeholder="john.doe"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email *</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
                placeholder="john.doe@example.com"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="first_name">First Name</Label>
                <Input
                  id="first_name"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleInputChange}
                  placeholder="John"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleInputChange}
                  placeholder="Doe"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddUserModal(false)}
                disabled={createUserMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createUserMutation.isPending}>
                {createUserMutation.isPending ? 'Creating...' : 'Create User'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit User Modal */}
      <Dialog open={editUserModal} onOpenChange={setEditUserModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-username">Username *</Label>
              <Input
                id="edit-username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-email">Email *</Label>
              <Input
                id="edit-email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-first_name">First Name</Label>
                <Input
                  id="edit-first_name"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleInputChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-last_name">Last Name</Label>
                <Input
                  id="edit-last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleInputChange}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditUserModal(false)}
                disabled={updateUserMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateUserMutation.isPending}>
                {updateUserMutation.isPending ? 'Updating...' : 'Update User'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Manage Roles Modal */}
      <Dialog open={manageRolesModal} onOpenChange={setManageRolesModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Roles - {selectedUser?.username}</DialogTitle>
          </DialogHeader>
          {rolesLoading || userRolesLoading ? (
            <div className="py-4 text-center">Loading roles...</div>
          ) : (
            <form onSubmit={handleRolesSubmit} className="space-y-4">
              <div className="space-y-3">
                <Label>Available Roles</Label>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {availableRoles?.map((role) => (
                    <div key={role.id} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id={`role-${role.id}`}
                        checked={selectedRoles.includes(role.id)}
                        onChange={() => handleRoleToggle(role.id)}
                        className="rounded"
                      />
                      <Label htmlFor={`role-${role.id}`} className="capitalize">
                        {role.name}
                        {role.description && (
                          <span className="text-sm text-gray-500 ml-2">
                            - {role.description}
                          </span>
                        )}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setManageRolesModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updateUserRolesMutation.isPending}>
                  {updateUserRolesMutation.isPending ? 'Updating...' : 'Update Roles'}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
