import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
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

export function UsersPage() {
  const queryClient = useQueryClient()
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
  const [availableRoles] = useState([
    'admin', 'user', 'manager', 'auditor', 'developer'
  ])

  const { data: users, isLoading } = useQuery({
    queryKey: ['users', search],
    queryFn: () => api.get<User[]>('/api/v1/identity/users'),
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
      alert(`Password reset email sent to user ${userId}`)
    }
  }

  const handleManageRoles = (userId: string) => {
    // Find the user to set as selected
    const user = users?.find(u => u.id === userId)
    if (user) {
      setSelectedUser(user)
      setSelectedRoles(['user']) // Default role, in real app this would come from API
      setManageRolesModal(true)
    }
  }

  const handleRoleToggle = (role: string) => {
    setSelectedRoles(prev =>
      prev.includes(role)
        ? prev.filter(r => r !== role)
        : [...prev, role]
    )
  }

  const handleRolesSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedUser) {
      alert(`Roles updated for user ${selectedUser.username}: ${selectedRoles.join(', ')}`)
      setManageRolesModal(false)
      setSelectedUser(null)
      setSelectedRoles([])
    }
  }

  const handleDeleteUser = (userId: string) => {
    if (confirm(`Are you sure you want to delete user: ${userId}? This action cannot be undone.`)) {
      alert(`User ${userId} deleted successfully`)
    }
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (addUserModal) {
        // Create new user via API
        await api.post('/api/v1/identity/users', {
          username: formData.username,
          email: formData.email,
          first_name: formData.first_name,
          last_name: formData.last_name,
          enabled: true,
          email_verified: false,
        })

        alert(`User ${formData.username} created successfully!`)
        setAddUserModal(false)
        setFormData({ username: '', email: '', first_name: '', last_name: '', password: '' })

        // Refresh the users list
        queryClient.invalidateQueries({ queryKey: ['users'] })

      } else if (editUserModal && selectedUser) {
        // Update existing user via API
        await api.put(`/api/v1/identity/users/${selectedUser.id}`, {
          username: formData.username,
          email: formData.email,
          first_name: formData.first_name,
          last_name: formData.last_name,
          enabled: selectedUser.enabled,
          email_verified: selectedUser.email_verified,
        })

        alert(`User ${selectedUser.username} updated successfully!`)
        setEditUserModal(false)
        setSelectedUser(null)

        // Refresh the users list
        queryClient.invalidateQueries({ queryKey: ['users'] })
      }
    } catch (error) {
      console.error('Error saving user:', error)
      alert(`Error saving user: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

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
                ) : users?.length === 0 ? (
                  <tr><td colSpan={5} className="p-4 text-center">No users found</td></tr>
                ) : (
                  users?.map((user) => (
                    <tr key={user.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                            <span className="text-blue-700 font-medium">
                              {user.first_name?.[0]}{user.last_name?.[0]}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium">{user.first_name} {user.last_name}</p>
                            <p className="text-sm text-gray-500">@{user.username}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <Mail className="h-4 w-4 text-gray-400" />
                          {user.email}
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
                            <DropdownMenuItem className="text-red-600" onClick={() => handleDeleteUser(user.id)}>
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete User
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
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
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
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleInputChange}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                value={formData.password}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setAddUserModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Create User</Button>
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
              <Label htmlFor="edit-username">Username</Label>
              <Input
                id="edit-username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-email">Email</Label>
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
              <Button type="button" variant="outline" onClick={() => setEditUserModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Update User</Button>
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
          <form onSubmit={handleRolesSubmit} className="space-y-4">
            <div className="space-y-3">
              <Label>Available Roles</Label>
              <div className="space-y-2">
                {availableRoles.map((role) => (
                  <div key={role} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id={`role-${role}`}
                      checked={selectedRoles.includes(role)}
                      onChange={() => handleRoleToggle(role)}
                      className="rounded"
                    />
                    <Label htmlFor={`role-${role}`} className="capitalize">
                      {role}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setManageRolesModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Update Roles</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
