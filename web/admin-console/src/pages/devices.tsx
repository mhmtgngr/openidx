import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Search, Smartphone, ShieldCheck, ShieldX, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
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

interface Device {
  id: string
  user_id: string
  fingerprint: string
  name: string
  ip_address: string
  user_agent: string
  location: string
  trusted: boolean
  last_seen_at: string
  created_at: string
}

export function DevicesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [deleteDevice, setDeleteDevice] = useState<Device | null>(null)
  const pageSize = 20

  const { data, isLoading } = useQuery({
    queryKey: ['devices', page],
    queryFn: () => api.get<{ devices: Device[]; total: number }>(`/api/v1/devices?limit=${pageSize}&offset=${(page - 1) * pageSize}`),
  })

  const { data: riskStats } = useQuery({
    queryKey: ['risk-stats'],
    queryFn: () => api.get<Record<string, number>>('/api/v1/risk/stats'),
  })

  const trustMutation = useMutation({
    mutationFn: (deviceId: string) => api.post(`/api/v1/devices/${deviceId}/trust`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      toast({ title: 'Device trusted successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to trust device', variant: 'destructive' })
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (deviceId: string) => api.delete(`/api/v1/devices/${deviceId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      setDeleteDevice(null)
      toast({ title: 'Device removed successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to remove device', variant: 'destructive' })
    },
  })

  const devices = data?.devices || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / pageSize)

  const filteredDevices = devices.filter(
    (d: Device) =>
      d.name.toLowerCase().includes(search.toLowerCase()) ||
      d.ip_address.includes(search) ||
      d.location.toLowerCase().includes(search.toLowerCase()) ||
      d.fingerprint.includes(search)
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Devices</h1>
          <p className="text-gray-500">Manage known devices and trust status for conditional access</p>
        </div>
      </div>

      {/* Risk Stats */}
      {riskStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold">{riskStats.total_devices ?? 0}</div>
              <p className="text-xs text-gray-500">Total Devices</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-green-600">{riskStats.trusted_devices ?? 0}</div>
              <p className="text-xs text-gray-500">Trusted Devices</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-blue-600">{riskStats.new_devices_today ?? 0}</div>
              <p className="text-xs text-gray-500">New Devices Today</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-red-600">{riskStats.high_risk_logins_today ?? 0}</div>
              <p className="text-xs text-gray-500">High-Risk Logins Today</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Search */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search by name, IP, location, or fingerprint..."
                className="pl-10"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-gray-500">Loading devices...</div>
          ) : filteredDevices.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <Smartphone className="mx-auto h-12 w-12 text-gray-300 mb-3" />
              <p>No devices found</p>
              <p className="text-sm">Devices will appear here when users log in</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b text-left text-sm text-gray-500">
                      <th className="pb-3 pr-4">Device</th>
                      <th className="pb-3 pr-4">IP Address</th>
                      <th className="pb-3 pr-4">Location</th>
                      <th className="pb-3 pr-4">Status</th>
                      <th className="pb-3 pr-4">Fingerprint</th>
                      <th className="pb-3 pr-4">Last Seen</th>
                      <th className="pb-3 pr-4">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {filteredDevices.map((device: Device) => (
                      <tr key={device.id} className="text-sm">
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <Smartphone className="h-4 w-4 text-gray-400" />
                            <span className="font-medium">{device.name || 'Unknown Device'}</span>
                          </div>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs">{device.ip_address}</td>
                        <td className="py-3 pr-4">{device.location || 'Unknown'}</td>
                        <td className="py-3 pr-4">
                          {device.trusted ? (
                            <Badge className="bg-green-100 text-green-800">Trusted</Badge>
                          ) : (
                            <Badge variant="outline">Untrusted</Badge>
                          )}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-gray-500">
                          {device.fingerprint.substring(0, 12)}...
                        </td>
                        <td className="py-3 pr-4 text-gray-500">
                          {new Date(device.last_seen_at).toLocaleString()}
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-1">
                            {!device.trusted ? (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => trustMutation.mutate(device.id)}
                                disabled={trustMutation.isPending}
                                title="Trust device"
                              >
                                <ShieldCheck className="h-4 w-4 text-green-600" />
                              </Button>
                            ) : (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled
                                title="Device is trusted"
                              >
                                <ShieldX className="h-4 w-4 text-gray-300" />
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setDeleteDevice(device)}
                              title="Remove device"
                            >
                              <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                  <p className="text-sm text-gray-500">
                    Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, total)} of {total} devices
                  </p>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(page - 1)}
                      disabled={page === 1}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <span className="text-sm">
                      Page {page} of {totalPages}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(page + 1)}
                      disabled={page === totalPages}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteDevice} onOpenChange={() => setDeleteDevice(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Device</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove this device? The device will need to be re-registered on next login.
              {deleteDevice && (
                <span className="block mt-2 font-medium">
                  {deleteDevice.name} ({deleteDevice.ip_address})
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteDevice && revokeMutation.mutate(deleteDevice.id)}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
