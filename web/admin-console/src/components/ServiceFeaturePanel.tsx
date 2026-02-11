import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Shield, Globe, Monitor, Loader2, AlertCircle, CheckCircle2, XCircle } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Switch } from './ui/switch'
import { Badge } from './ui/badge'
import { Label } from './ui/label'
import { Input } from './ui/input'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from './ui/dialog'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ServiceFeature {
  id: string
  route_id: string
  feature_name: string
  enabled: boolean
  status: string
  health_status: string
  error_message?: string
  enabled_at?: string
}

interface ServiceStatus {
  route_id: string
  route_name: string
  route_type: string
  features: Record<string, ServiceFeature>
  overall_health: string
}

interface ServiceFeaturePanelProps {
  routeId: string
  routeType: string
  onUpdate?: () => void
}

const FeatureIcon = ({ feature }: { feature: string }) => {
  switch (feature) {
    case 'ziti':
      return <Shield className="h-5 w-5 text-blue-500" />
    case 'browzer':
      return <Globe className="h-5 w-5 text-green-500" />
    case 'guacamole':
      return <Monitor className="h-5 w-5 text-purple-500" />
    default:
      return null
  }
}

const HealthBadge = ({ status }: { status: string }) => {
  switch (status) {
    case 'healthy':
      return <Badge variant="default" className="bg-green-500"><CheckCircle2 className="h-3 w-3 mr-1" />Healthy</Badge>
    case 'degraded':
      return <Badge variant="default" className="bg-yellow-500"><AlertCircle className="h-3 w-3 mr-1" />Degraded</Badge>
    case 'unhealthy':
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Unhealthy</Badge>
    default:
      return <Badge variant="secondary">Unknown</Badge>
  }
}

export function ServiceFeaturePanel({ routeId, routeType, onUpdate }: ServiceFeaturePanelProps) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [configModal, setConfigModal] = useState<string | null>(null)
  const [featureConfig, setFeatureConfig] = useState({
    ziti_service_name: '',
    ziti_host: '',
    ziti_port: 0,
    guacamole_protocol: '',
    guacamole_host: '',
    guacamole_port: 22,
    guacamole_username: '',
    guacamole_password: '',
  })

  const { data: serviceStatus, isLoading } = useQuery({
    queryKey: ['service-status', routeId],
    queryFn: async () => {
      return api.get<ServiceStatus>(`/api/v1/access/services/${routeId}/status`)
    },
    refetchInterval: 30000,
  })

  const enableFeature = useMutation({
    mutationFn: async ({ feature, config }: { feature: string; config?: object }) => {
      await api.post(`/api/v1/access/services/${routeId}/features/${feature}/enable`, config || {})
    },
    onSuccess: (_, { feature }) => {
      queryClient.invalidateQueries({ queryKey: ['service-status', routeId] })
      toast({ title: 'Feature Enabled', description: `${feature} has been enabled on this service.` })
      setConfigModal(null)
      onUpdate?.()
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    },
  })

  const disableFeature = useMutation({
    mutationFn: async (feature: string) => {
      await api.post(`/api/v1/access/services/${routeId}/features/${feature}/disable`)
    },
    onSuccess: (_, feature) => {
      queryClient.invalidateQueries({ queryKey: ['service-status', routeId] })
      toast({ title: 'Feature Disabled', description: `${feature} has been disabled.` })
      onUpdate?.()
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    },
  })

  const handleToggle = (feature: string, currentlyEnabled: boolean) => {
    if (currentlyEnabled) {
      disableFeature.mutate(feature)
    } else {
      // Show config modal for initial setup
      if (feature === 'ziti' || feature === 'guacamole') {
        setConfigModal(feature)
      } else {
        enableFeature.mutate({ feature })
      }
    }
  }

  const handleEnableWithConfig = () => {
    if (!configModal) return
    enableFeature.mutate({ feature: configModal, config: featureConfig })
  }

  const isRemoteAccessRoute = ['ssh', 'rdp', 'vnc', 'telnet'].includes(routeType)

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin" />
        </CardContent>
      </Card>
    )
  }

  const features = serviceStatus?.features || {}

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Features
            {serviceStatus && <HealthBadge status={serviceStatus.overall_health} />}
          </CardTitle>
          <CardDescription>
            Enable or disable integration features for this service
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Ziti Feature */}
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div className="flex items-center gap-3">
              <FeatureIcon feature="ziti" />
              <div>
                <div className="font-medium">OpenZiti Zero Trust</div>
                <div className="text-sm text-muted-foreground">
                  Route traffic through secure Ziti overlay network
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {features.ziti?.enabled && (
                <HealthBadge status={features.ziti.health_status} />
              )}
              <Switch
                checked={features.ziti?.enabled || false}
                onCheckedChange={() => handleToggle('ziti', features.ziti?.enabled || false)}
                disabled={enableFeature.isPending || disableFeature.isPending}
              />
            </div>
          </div>

          {/* BrowZer Feature (only if Ziti is enabled) */}
          <div className={`flex items-center justify-between p-4 border rounded-lg ${!features.ziti?.enabled ? 'opacity-50' : ''}`}>
            <div className="flex items-center gap-3">
              <FeatureIcon feature="browzer" />
              <div>
                <div className="font-medium">BrowZer</div>
                <div className="text-sm text-muted-foreground">
                  Enable browser-native Ziti access (requires Ziti)
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {features.browzer?.enabled && (
                <HealthBadge status={features.browzer.health_status} />
              )}
              <Switch
                checked={features.browzer?.enabled || false}
                onCheckedChange={() => handleToggle('browzer', features.browzer?.enabled || false)}
                disabled={!features.ziti?.enabled || enableFeature.isPending || disableFeature.isPending}
              />
            </div>
          </div>

          {/* Guacamole Feature (only for remote access routes) */}
          {isRemoteAccessRoute && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center gap-3">
                <FeatureIcon feature="guacamole" />
                <div>
                  <div className="font-medium">Guacamole Remote Access</div>
                  <div className="text-sm text-muted-foreground">
                    Clientless {routeType.toUpperCase()} access through browser
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {features.guacamole?.enabled && (
                  <HealthBadge status={features.guacamole.health_status} />
                )}
                <Switch
                  checked={features.guacamole?.enabled || false}
                  onCheckedChange={() => handleToggle('guacamole', features.guacamole?.enabled || false)}
                  disabled={enableFeature.isPending || disableFeature.isPending}
                />
              </div>
            </div>
          )}

          {/* Error messages */}
          {Object.values(features).map((feature) =>
            feature.error_message && feature.enabled && (
              <div key={feature.id} className="p-3 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-lg">
                <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                  <AlertCircle className="h-4 w-4" />
                  <span className="font-medium">{feature.feature_name}:</span>
                  <span>{feature.error_message}</span>
                </div>
              </div>
            )
          )}
        </CardContent>
      </Card>

      {/* Config Modal */}
      <Dialog open={configModal !== null} onOpenChange={() => setConfigModal(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Configure {configModal === 'ziti' ? 'OpenZiti' : 'Guacamole'}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {configModal === 'ziti' && (
              <>
                <div>
                  <Label>Service Name (optional)</Label>
                  <Input
                    value={featureConfig.ziti_service_name}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, ziti_service_name: e.target.value })}
                    placeholder="Auto-generated if empty"
                  />
                </div>
                <div>
                  <Label>Target Host (optional)</Label>
                  <Input
                    value={featureConfig.ziti_host}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, ziti_host: e.target.value })}
                    placeholder="Uses route's remote_host if empty"
                  />
                </div>
                <div>
                  <Label>Target Port (optional)</Label>
                  <Input
                    type="number"
                    value={featureConfig.ziti_port || ''}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, ziti_port: parseInt(e.target.value) || 0 })}
                    placeholder="Uses route's remote_port if empty"
                  />
                </div>
              </>
            )}
            {configModal === 'guacamole' && (
              <>
                <div>
                  <Label>Protocol</Label>
                  <Input
                    value={featureConfig.guacamole_protocol}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, guacamole_protocol: e.target.value })}
                    placeholder="ssh, rdp, vnc, telnet"
                  />
                </div>
                <div>
                  <Label>Host (optional)</Label>
                  <Input
                    value={featureConfig.guacamole_host}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, guacamole_host: e.target.value })}
                    placeholder="Uses route's remote_host if empty"
                  />
                </div>
                <div>
                  <Label>Port (optional)</Label>
                  <Input
                    type="number"
                    value={featureConfig.guacamole_port || ''}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, guacamole_port: parseInt(e.target.value) || 0 })}
                    placeholder="22"
                  />
                </div>
                <div>
                  <Label>Username (optional)</Label>
                  <Input
                    value={featureConfig.guacamole_username}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, guacamole_username: e.target.value })}
                    placeholder="For pre-configured connections"
                  />
                </div>
                <div>
                  <Label>Password (optional)</Label>
                  <Input
                    type="password"
                    value={featureConfig.guacamole_password}
                    onChange={(e) => setFeatureConfig({ ...featureConfig, guacamole_password: e.target.value })}
                    placeholder="For pre-configured connections"
                  />
                </div>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfigModal(null)}>
              Cancel
            </Button>
            <Button onClick={handleEnableWithConfig} disabled={enableFeature.isPending}>
              {enableFeature.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Enable
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
