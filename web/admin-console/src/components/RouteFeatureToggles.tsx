import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()

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
      // The product name stays untranslated; only the sentence around it moves.
      const name = feature === 'ziti' ? 'OpenZiti' : 'BrowZer'
      toast({
        title: enable ? t('pages.proxyRoutes.featureToggles.enabled') : t('pages.proxyRoutes.featureToggles.disabled'),
        description: enable
          ? t('pages.proxyRoutes.featureToggles.enabledDesc', { feature: name })
          : t('pages.proxyRoutes.featureToggles.disabledDesc', { feature: name }),
      })
      onUpdate?.()
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    },
  })

  const zitiOn = data?.features?.ziti?.enabled || false
  const browzerOn = data?.features?.browzer?.enabled || false
  const pending = toggle.isPending || isLoading

  return (
    <div className="flex items-center gap-4">
      <label
        className="flex items-center gap-1.5 text-xs cursor-pointer"
        title={t('pages.proxyRoutes.featureToggles.zitiTitle')}
      >
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
        title={zitiOn ? t('pages.proxyRoutes.featureToggles.browzerTitle') : t('pages.proxyRoutes.featureToggles.browzerDisabledTitle')}
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
