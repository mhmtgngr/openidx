import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Search, Smartphone, Monitor, Tablet, MoreHorizontal, ShieldCheck, ShieldX, Trash2, Copy, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
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
import { LoadingSpinner } from '../components/ui/loading-spinner'
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

  const deviceIcon = (userAgent: string) => {
    const ua = userAgent.toLowerCase()
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone'))
      return <Smartphone className="h-4 w-4 text-muted-foreground" />
    if (ua.includes('tablet') || ua.includes('ipad'))
      return <Tablet className="h-4 w-4 text-muted-foreground" />
    return <Monitor className="h-4 w-4 text-muted-foreground" />
  }

  const deviceType = (userAgent: string) => {
    const ua = userAgent.toLowerCase()
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) return 'Mobile'
    if (ua.includes('tablet') || ua.includes('ipad')) return 'Tablet'
    return 'Desktop'
  }

  const copyFingerprint = (fp: string) => {
    navigator.clipboard.writeText(fp)
    toast({ title: 'Fingerprint copied to clipboard' })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Devices</h1>
        <p className="text-muted-foreground">Manage known devices and trust status for conditional access</p>
      </div>

      {/* Risk Stats */}
      {riskStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold">{riskStats.total_devices ?? 0}</div>
              <p className="text-xs text-muted-foreground">Total Devices</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-green-600">{riskStats.trusted_devices ?? 0}</div>
              <p className="text-xs text-muted-foreground">Trusted Devices</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-blue-600">{riskStats.new_devices_today ?? 0}</div>
              <p className="text-xs text-muted-foreground">New Devices Today</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-red-600">{riskStats.high_risk_logins_today ?? 0}</div>
              <p className="text-xs text-muted-foreground">High-Risk Logins Today</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Device Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
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
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading devices...</p>
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Smartphone className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No devices found</p>
              <p className="text-sm">Devices will appear here when users log in</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Device</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Fingerprint</TableHead>
                      <TableHead>Last Seen</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredDevices.map((device: Device) => (
                      <TableRow key={device.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {deviceIcon(device.user_agent)}
                            <span className="font-medium">{device.name || 'Unknown Device'}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{deviceType(device.user_agent)}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{device.ip_address}</TableCell>
                        <TableCell>{device.location || 'Unknown'}</TableCell>
                        <TableCell>
                          {device.trusted ? (
                            <Badge className="bg-green-100 text-green-800">Trusted</Badge>
                          ) : (
                            <Badge variant="outline">Untrusted</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <button
                            onClick={() => copyFingerprint(device.fingerprint)}
                            className="inline-flex items-center gap-1.5 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
                            title="Click to copy full fingerprint"
                          >
                            {device.fingerprint.substring(0, 12)}...
                            <Copy className="h-3 w-3" />
                          </button>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(device.last_seen_at).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              {!device.trusted ? (
                                <DropdownMenuItem
                                  onClick={() => trustMutation.mutate(device.id)}
                                  disabled={trustMutation.isPending}
                                >
                                  <ShieldCheck className="mr-2 h-4 w-4 text-green-600" />
                                  Trust Device
                                </DropdownMenuItem>
                              ) : (
                                <DropdownMenuItem
                                  onClick={() => trustMutation.mutate(device.id)}
                                  disabled={trustMutation.isPending}
                                >
                                  <ShieldX className="mr-2 h-4 w-4 text-yellow-600" />
                                  Revoke Trust
                                </DropdownMenuItem>
                              )}
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                onClick={() => setDeleteDevice(device)}
                                className="text-red-600 focus:text-red-600"
                              >
                                <Trash2 className="mr-2 h-4 w-4" />
                                Delete Device
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4">
                  <p className="text-sm text-muted-foreground">
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
