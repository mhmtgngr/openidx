import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { api } from '../lib/api'
import { apiErrorText, useVendors } from '../lib/external-access'
import { useToast } from '../hooks/use-toast'

// PublishToVendorDialog makes one resource available to a vendor in one
// step: it opens the resource to the vendor's closed list when the vendor has
// one (POST /vendor-orgs/:id/targets) and, when asked, starts an engagement
// covering it now, for every active account of the vendor, until the chosen
// end (POST /vendor-orgs/:id/engagements). Both routes keep their own checks;
// this dialog only saves the trip to External users.

type ApiError = { response?: { status?: number } }

export function PublishToVendorDialog({ targetType, targetId, targetName, open, onOpenChange }: {
  targetType: 'application' | 'pam_entry'
  targetId: string
  targetName: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { data: vendors = [] } = useVendors()
  const active = vendors.filter((v) => v.status === 'active')
  const [vendorId, setVendorId] = useState('')
  const [startEngagement, setStartEngagement] = useState(true)
  const [endsAt, setEndsAt] = useState('')
  const vendor = active.find((v) => v.id === vendorId)
  // Without a closed list there is nothing to open, so the engagement is the
  // whole of the publication.
  const needsEngagement = !!vendor && !vendor.closed_list
  const engage = startEngagement || needsEngagement

  const publish = useMutation({
    mutationFn: async () => {
      if (vendor?.closed_list) {
        try {
          await api.post(`/api/v1/identity/vendor-orgs/${vendorId}/targets`, { target_type: targetType, target_id: targetId })
        } catch (err) {
          // Already open to the vendor is what was asked for.
          if ((err as ApiError)?.response?.status !== 409) throw err
        }
      }
      if (engage) {
        await api.post(`/api/v1/identity/vendor-orgs/${vendorId}/engagements`, {
          title: targetName,
          ends_at: new Date(endsAt).toISOString(),
          targets: [{ target_type: targetType, target_id: targetId }],
        })
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engagements'] })
      queryClient.invalidateQueries({ queryKey: ['vendor-targets', vendorId] })
      toast({
        title: t('common.success'),
        description: t('components.publishToVendor.done', { name: targetName, vendor: vendor?.name ?? '' }),
        variant: 'success',
      })
      onOpenChange(false)
    },
    onError: (err) => toast({ title: t('common.error'), description: apiErrorText(err, t('components.publishToVendor.failed')), variant: 'destructive' }),
  })

  const canPublish = !!vendor && (!engage || !!endsAt) && !publish.isPending

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('components.publishToVendor.title', { name: targetName })}</DialogTitle>
          <DialogDescription>{t('components.publishToVendor.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); if (canPublish) publish.mutate() }}>
          <div className="space-y-1">
            <Label htmlFor="ptv-vendor">{t('components.publishToVendor.vendor')}</Label>
            <select id="ptv-vendor" value={vendorId} onChange={(e) => setVendorId(e.target.value)}
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm">
              <option value="">{t('components.publishToVendor.chooseVendor')}</option>
              {active.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
            {vendor?.closed_list && <p className="text-xs text-muted-foreground">{t('components.publishToVendor.closedList')}</p>}
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input id="ptv-engage" type="checkbox" className="mt-1" checked={engage} disabled={needsEngagement}
              onChange={(e) => setStartEngagement(e.target.checked)} />
            <span>
              <span className="font-medium">{t('components.publishToVendor.engage')}</span>
              <span className="block text-xs text-muted-foreground">{t('components.publishToVendor.engageHint')}</span>
            </span>
          </label>
          {engage && (
            <div className="space-y-1">
              <Label htmlFor="ptv-ends">{t('components.publishToVendor.ends')}</Label>
              <Input id="ptv-ends" type="datetime-local" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} />
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!canPublish}>{t('components.publishToVendor.publish')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
