import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Smartphone, Monitor, Tablet, Shield, ShieldCheck, ShieldX, Trash2, Edit, Plus, MoreHorizontal } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Device {
  id: string
  user_id: string
  fingerprint: string
  name: string
  device_type: string
  ip_address: string
  user_agent?: string
  location?: string
  trusted: boolean
  trust_requested?: boolean
  last_seen_at?: string
  created_at: string
}

export function MyDevicesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [trustDialog, setTrustDialog] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [registerDialog, setRegisterDialog] = useState(false)
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [editName, setEditName] = useState('')
  const [trustJustification, setTrustJustification] = useState('')
  const [newDeviceName, setNewDeviceName] = useState('')

  // Fetch devices
  const { data: devicesData, isLoading } = useQuery({
    queryKey: ['my-devices'],
    queryFn: async () => {
      const data = await api.get<{ devices: Device[] }>('/api/v1/identity/portal/devices')
      return data.devices
    }
  })

  const devices = devicesData || []

  // Register device mutation
  const registerMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      return api.post('/api/v1/identity/portal/devices', data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device registered', description: 'Your device has been registered successfully.' })
      setRegisterDialog(false)
      setNewDeviceName('')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to register device.', variant: 'destructive' })
    }
  })

  // Update device mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      return api.put(`/api/v1/identity/portal/devices/${id}`, { name })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device updated', description: 'Device name has been updated.' })
      setEditDialog(false)
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update device.', variant: 'destructive' })
    }
  })

  // Delete device mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return api.delete(`/api/v1/identity/portal/devices/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Device removed', description: 'The device has been removed from your account.' })
      setDeleteDialog(false)
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to remove device.', variant: 'destructive' })
    }
  })

  // Request trust mutation
  const trustMutation = useMutation({
    mutationFn: async ({ id, justification }: { id: string; justification: string }) => {
      return api.post(`/api/v1/identity/portal/devices/${id}/trust`, { justification })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-devices'] })
      toast({ title: 'Trust requested', description: 'Your trust request has been submitted for review.' })
      setTrustDialog(false)
      setTrustJustification('')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to submit trust request.', variant: 'destructive' })
    }
  })

  const handleEdit = (device: Device) => {
    setSelectedDevice(device)
    setEditName(device.name)
    setEditDialog(true)
  }

  const handleTrust = (device: Device) => {
    setSelectedDevice(device)
    setTrustJustification('')
    setTrustDialog(true)
  }

  const handleDelete = (device: Device) => {
    setSelectedDevice(device)
    setDeleteDialog(true)
  }

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'mobile':
        return <Smartphone className="h-8 w-8" />
      case 'tablet':
        return <Tablet className="h-8 w-8" />
      default:
        return <Monitor className="h-8 w-8" />
    }
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Never'
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  // Summary stats
  const trustedCount = devices.filter(d => d.trusted).length
  const untrustedCount = devices.filter(d => !d.trusted).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">My Devices</h1>
          <p className="text-muted-foreground">
            Manage devices registered to your account
          </p>
        </div>
        <Button onClick={() => setRegisterDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Register This Device
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Devices</CardTitle>
            <Monitor className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{devices.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Trusted</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{trustedCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Untrusted</CardTitle>
            <ShieldX className="h-4 w-4 text-amber-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{untrustedCount}</div>
          </CardContent>
        </Card>
      </div>

      {/* Devices List */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Devices</CardTitle>
          <CardDescription>
            Devices that have been used to access your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading devices...</p>
            </div>
          ) : devices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Monitor className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No devices registered</p>
              <p className="text-sm">Register this device to get started</p>
            </div>
          ) : (
            <div className="space-y-4">
              {devices.map((device) => (
                <div
                  key={device.id}
                  className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${device.trusted ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                      {getDeviceIcon(device.device_type)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{device.name}</span>
                        {device.trusted ? (
                          <Badge className="bg-green-100 text-green-800">
                            <ShieldCheck className="h-3 w-3 mr-1" />
                            Trusted
                          </Badge>
                        ) : (
                          <Badge variant="secondary">
                            <Shield className="h-3 w-3 mr-1" />
                            Untrusted
                          </Badge>
                        )}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {device.ip_address}
                        {device.location && ` - ${device.location}`}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        Last seen: {formatDate(device.last_seen_at)} | Registered: {formatDate(device.created_at)}
                      </div>
                    </div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="sm">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => handleEdit(device)}>
                        <Edit className="h-4 w-4 mr-2" />
                        Rename
                      </DropdownMenuItem>
                      {!device.trusted && (
                        <DropdownMenuItem onClick={() => handleTrust(device)}>
                          <ShieldCheck className="h-4 w-4 mr-2" />
                          Request Trust
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(device)}
                        className="text-red-600 focus:text-red-600"
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Remove
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Register Device Dialog */}
      <Dialog open={registerDialog} onOpenChange={setRegisterDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register This Device</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="device-name">Device Name</Label>
              <Input
                id="device-name"
                placeholder="e.g., Work Laptop, Personal Phone"
                value={newDeviceName}
                onChange={(e) => setNewDeviceName(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Give this device a friendly name to identify it later
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRegisterDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => registerMutation.mutate({ name: newDeviceName })}>
              Register Device
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Device Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Device</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Device Name</Label>
              <Input
                id="edit-name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => selectedDevice && updateMutation.mutate({ id: selectedDevice.id, name: editName })}>
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Request Trust Dialog */}
      <Dialog open={trustDialog} onOpenChange={setTrustDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request Device Trust</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Trusted devices may have fewer MFA prompts and enhanced access. Please provide a reason for trusting this device.
            </p>
            <div className="space-y-2">
              <Label htmlFor="justification">Justification</Label>
              <Textarea
                id="justification"
                placeholder="This is my work laptop used for daily tasks..."
                value={trustJustification}
                onChange={(e) => setTrustJustification(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTrustDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => selectedDevice && trustMutation.mutate({ id: selectedDevice.id, justification: trustJustification })}>
              Submit Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Device?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove "{selectedDevice?.name}" from your account?
              You may need to re-authenticate if you use this device again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedDevice && deleteMutation.mutate(selectedDevice.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              Remove Device
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
