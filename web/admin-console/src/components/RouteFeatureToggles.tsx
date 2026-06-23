import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Shield, Globe, Loader2 } from 'lucide-react'
import { Switch } from './ui/switch'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ServiceFeature {
  enabled: boolean
  health_status?: string
}

interface ServiceStatus {
  features: Record<string, ServiceFeature>
}

interface RouteFeatureTogglesProps {
  routeId: string
  onUpdate?: () => void
}

/**
 * Compact, one-click OpenZiti + BrowZer switches for a proxy route, rendered
 * inline in the route's action bar. Shares the ['service-status', routeId]
 * query cache (and the same /services/:id/features/:feature endpoints) with
 * ServiceFeaturePanel, so toggling here keeps the expanded panel in sync.
 *
 * BrowZer requires Ziti, so its switch is disabled until Ziti is enabled —
 * matching the gating in ServiceFeaturePanel.
 */
export function RouteFeatureToggles({ routeId, onUpdate }: RouteFeatureTogglesProps) {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data, isLoading } = useQuery({
    queryKey: ['service-status', routeId],
    queryFn: () => api.get<ServiceStatus>(`/api/v1/access/services/${routeId}/status`),
    refetchInterval: 30000,
  })

  const toggle = useMutation({
    mutationFn: async ({ feature, enable }: { feature: 'ziti' | 'browzer'; enable: boolean }) => {
      const action = enable ? 'enable' : 'disable'
      await api.post(`/api/v1/access/services/${routeId}/features/${feature}/${action}`, enable ? {} : undefined)
    },
    onSuccess: (_, { feature, enable }) => {
      queryClient.invalidateQueries({ queryKey: ['service-status', routeId] })
      queryClient.invalidateQueries({ queryKey: ['proxy-routes'] })
      toast({
        title: enable ? 'Enabled' : 'Disabled',
        description: `${feature === 'ziti' ? 'OpenZiti' : 'BrowZer'} ${enable ? 'enabled' : 'disabled'} on this route.`,
      })
      onUpdate?.()
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    },
  })

  const zitiOn = data?.features?.ziti?.enabled || false
  const browzerOn = data?.features?.browzer?.enabled || false
  const pending = toggle.isPending || isLoading

  return (
    <div className="flex items-center gap-4">
      <label className="flex items-center gap-1.5 text-xs cursor-pointer" title="Route traffic through the secure OpenZiti overlay">
        <Shield className="h-3.5 w-3.5 text-blue-500" />
        <span className="text-muted-foreground">OpenZiti</span>
        <Switch
          checked={zitiOn}
          disabled={pending}
          onCheckedChange={(v) => toggle.mutate({ feature: 'ziti', enable: v })}
        />
      </label>
      <label
        className={`flex items-center gap-1.5 text-xs cursor-pointer ${!zitiOn ? 'opacity-50' : ''}`}
        title={zitiOn ? 'Clientless browser access via BrowZer' : 'Enable OpenZiti first'}
      >
        <Globe className="h-3.5 w-3.5 text-green-500" />
        <span className="text-muted-foreground">BrowZer</span>
        <Switch
          checked={browzerOn}
          disabled={pending || !zitiOn}
          onCheckedChange={(v) => toggle.mutate({ feature: 'browzer', enable: v })}
        />
      </label>
      {pending && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
    </div>
  )
}
