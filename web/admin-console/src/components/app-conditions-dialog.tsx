import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './ui/dialog'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'

/** A resource_conditions row as GET/PUT /api/v1/applications/:id/conditions carry it. */
export interface ApplicationConditions {
  application_id: string
  require_device_trust: boolean
  max_risk_score: number | null
  allowed_countries: string[]
  require_step_up: boolean
  time_window?: unknown
  posture_profile_id: string | null
  declared: boolean
}

interface Props {
  app: { id: string; name: string } | null
  onClose: () => void
}

/**
 * The application's access conditions: a fresh second factor, a trusted
 * device, a risk ceiling, allowed countries. The time window and posture
 * profile are carried through unchanged.
 */
export function AppConditionsDialog({ app, onClose }: Props) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [stepUp, setStepUp] = useState(false)
  const [deviceTrust, setDeviceTrust] = useState(false)
  const [maxRisk, setMaxRisk] = useState('')
  const [countries, setCountries] = useState('')

  const query = useQuery({
    queryKey: ['app-conditions', app?.id],
    queryFn: () => api.get<ApplicationConditions>(`/api/v1/applications/${app!.id}/conditions`),
    enabled: !!app,
  })

  useEffect(() => {
    const d = query.data
    if (!d) return
    setStepUp(d.require_step_up)
    setDeviceTrust(d.require_device_trust)
    setMaxRisk(d.max_risk_score == null ? '' : String(d.max_risk_score))
    setCountries((d.allowed_countries || []).join(', '))
  }, [query.data])

  const save = useMutation({
    mutationFn: () =>
      api.put<ApplicationConditions>(`/api/v1/applications/${app!.id}/conditions`, {
        require_step_up: stepUp,
        require_device_trust: deviceTrust,
        max_risk_score: maxRisk.trim() === '' ? null : Number(maxRisk),
        allowed_countries: countries.split(',').map((c) => c.trim()).filter(Boolean),
        time_window: query.data?.time_window ?? null,
        posture_profile_id: query.data?.posture_profile_id ?? null,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['app-conditions', app?.id] })
      toast({ title: t('common.success'), description: t('pages.applications.conditionsDialog.saved'), variant: 'success' })
      onClose()
    },
    onError: (error: Error) => {
      toast({ title: t('common.error'), description: error.message, variant: 'destructive' })
    },
  })

  return (
    <Dialog open={!!app} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('pages.applications.conditionsDialog.title', { name: app?.name ?? '' })}</DialogTitle>
          <DialogDescription>{t('pages.applications.conditionsDialog.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            save.mutate()
          }}
        >
          <div className="flex items-center space-x-2">
            <input type="checkbox" id="cond-stepup" checked={stepUp} onChange={(e) => setStepUp(e.target.checked)} className="rounded" />
            <Label htmlFor="cond-stepup">{t('pages.applications.conditionsDialog.stepUp')}</Label>
          </div>
          <div className="flex items-center space-x-2">
            <input type="checkbox" id="cond-device" checked={deviceTrust} onChange={(e) => setDeviceTrust(e.target.checked)} className="rounded" />
            <Label htmlFor="cond-device">{t('pages.applications.conditionsDialog.deviceTrust')}</Label>
          </div>
          <div className="space-y-2">
            <Label htmlFor="cond-risk">{t('pages.applications.conditionsDialog.maxRisk')}</Label>
            <Input id="cond-risk" type="number" min={0} max={100} value={maxRisk} onChange={(e) => setMaxRisk(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="cond-countries">{t('pages.applications.conditionsDialog.countries')}</Label>
            <Input id="cond-countries" value={countries} onChange={(e) => setCountries(e.target.value)} placeholder="TR, DE" />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={save.isPending || query.isLoading}>{t('pages.applications.conditionsDialog.save')}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
