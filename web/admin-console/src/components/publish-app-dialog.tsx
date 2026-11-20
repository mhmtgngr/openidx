import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Checkbox } from './ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { LoadingSpinner } from './ui/loading-spinner'
import { SiteSelect } from './site-select'
import { api } from '../lib/api'

// Dark publish (POST /api/v1/access/network-resources/publish): one short form
// that writes a network resource, who may use it and the trusted-device
// condition together. The result is hidden from the internet; people reach it
// only through the OpenIDX agent. What the installation actually enforces comes
// back with the answer, and this dialog says so: it never claims "only these
// people" while assignment or device trust is switched off.

interface PublishResult {
  url: string
  require_trusted_device: boolean
  enforcement: { assignment: boolean; device_trust: string }
}

interface GroupItem {
  id: string
  name: string
}

type ApiErr = { response?: { data?: { code?: string; error?: string } } }

const FIELD_OF: Record<string, 'name' | 'address'> = {
  invalid_name: 'name',
  invalid_address: 'address',
  target_refused: 'address',
  already_published: 'address',
}

export function PublishAppDialog(props: { open: boolean; onOpenChange: (open: boolean) => void; onPublished: () => void }) {
  const { open, onOpenChange, onPublished } = props
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [address, setAddress] = useState('')
  const [site, setSite] = useState('')
  const [groupIds, setGroupIds] = useState<string[]>([])
  const [trusted, setTrusted] = useState(true)
  const [fieldError, setFieldError] = useState<{ field: 'name' | 'address' | ''; text: string }>({ field: '', text: '' })
  const [generalError, setGeneralError] = useState('')
  const [done, setDone] = useState<PublishResult | null>(null)

  const { data: groups, isLoading } = useQuery({
    queryKey: ['groups-for-publish'],
    enabled: open,
    queryFn: async (): Promise<GroupItem[]> => {
      const raw = await api.get<Array<Record<string, unknown>>>('/api/v1/identity/groups')
      return (raw || []).map((g) => ({ id: String(g.id ?? ''), name: String(g.displayName ?? g.name ?? '') }))
    },
  })

  const publish = useMutation({
    mutationFn: () =>
      api.post<PublishResult>('/api/v1/access/network-resources/publish', {
        name: name.trim(),
        description: '',
        address: address.trim(),
        site,
        group_ids: groupIds,
        user_ids: [],
        require_trusted_device: trusted,
      }),
    onSuccess: (res) => {
      setDone(res)
      onPublished()
    },
    onError: (err: unknown) => {
      const data = (err as ApiErr)?.response?.data
      const code = data?.code ?? ''
      const known = ['invalid_name', 'invalid_address', 'target_refused', 'already_published', 'assignee_required', 'unknown_group', 'unknown_user', 'unknown_site']
      let text = t(`pages.networkResources.publish.errors.${known.includes(code) ? code : 'generic'}`)
      // What is wrong with an address is the server's to say (it names the part).
      if ((code === 'invalid_address' || code === 'target_refused') && data?.error) text = `${text} ${data.error}`
      const field = FIELD_OF[code]
      if (field) {
        setFieldError({ field, text })
        setGeneralError('')
      } else {
        setFieldError({ field: '', text: '' })
        setGeneralError(text)
      }
    },
  })

  const ready = name.trim() !== '' && address.trim() !== '' && groupIds.length > 0
  const toggle = (id: string) =>
    setGroupIds((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]))

  const close = (next: boolean) => {
    if (!next) {
      setName('')
      setAddress('')
      setSite('')
      setGroupIds([])
      setTrusted(true)
      setFieldError({ field: '', text: '' })
      setGeneralError('')
      setDone(null)
    }
    onOpenChange(next)
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('pages.networkResources.publish.title')}</DialogTitle>
          <DialogDescription>{t('pages.networkResources.publish.desc')}</DialogDescription>
        </DialogHeader>

        {done ? (
          <div className="space-y-3">
            <p className="font-medium">{t('pages.networkResources.publish.doneTitle')}</p>
            <p className="text-sm text-muted-foreground">{t('pages.networkResources.publish.doneDetail', { url: done.url })}</p>
            {!done.enforcement.assignment && (
              <p role="status" className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-2 text-sm">
                {t('pages.networkResources.publish.warnAssignment')}
              </p>
            )}
            {done.require_trusted_device && done.enforcement.device_trust !== 'enforce' && (
              <p role="status" className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-2 text-sm">
                {t('pages.networkResources.publish.warnDeviceTrust', { gate: done.enforcement.device_trust })}
              </p>
            )}
            <DialogFooter>
              <Button onClick={() => close(false)}>{t('pages.networkResources.publish.close')}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (ready && !publish.isPending) publish.mutate()
            }}
          >
            <div className="space-y-1" data-field="name">
              <Label htmlFor="pub-name">{t('pages.networkResources.publish.name')}</Label>
              <Input id="pub-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={255} />
              {fieldError.field === 'name' && <p className="text-xs text-destructive">{fieldError.text}</p>}
            </div>
            <div className="space-y-1" data-field="address">
              <Label htmlFor="pub-address">{t('pages.networkResources.publish.address')}</Label>
              <Input id="pub-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="https://wiki.corp.example" />
              <p className="text-xs text-muted-foreground">{t('pages.networkResources.publish.addressHelp')}</p>
              {fieldError.field === 'address' && <p className="text-xs text-destructive">{fieldError.text}</p>}
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('pages.networkResources.publish.groups')}</legend>
              <p className="text-xs text-muted-foreground">{t('pages.networkResources.publish.groupsHelp')}</p>
              {isLoading ? (
                <LoadingSpinner />
              ) : (groups ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('pages.networkResources.publish.groupsEmpty')}</p>
              ) : (
                <div className="max-h-40 space-y-1 overflow-y-auto rounded-md border p-2">
                  {(groups ?? []).map((g) => (
                    <div key={g.id} className="flex items-center gap-2">
                      <Checkbox id={`pub-g-${g.id}`} checked={groupIds.includes(g.id)} onCheckedChange={() => toggle(g.id)} />
                      <Label htmlFor={`pub-g-${g.id}`} className="font-normal">{g.name}</Label>
                    </div>
                  ))}
                </div>
              )}
            </fieldset>
            <div className="flex items-start gap-2">
              <Checkbox id="pub-trusted" checked={trusted} onCheckedChange={(v) => setTrusted(v === true)} />
              <div>
                <Label htmlFor="pub-trusted">{t('pages.networkResources.publish.trusted')}</Label>
                <p className="text-xs text-muted-foreground">{t('pages.networkResources.publish.trustedHelp')}</p>
              </div>
            </div>
            <details>
              <summary className="cursor-pointer text-sm text-muted-foreground">{t('pages.networkResources.publish.advanced')}</summary>
              <div className="pt-2">
                <SiteSelect id="pub-site" value={site} onChange={setSite} />
              </div>
            </details>
            {generalError && (
              <p role="alert" className="text-sm text-destructive">{generalError}</p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>{t('pages.networkResources.publish.cancel')}</Button>
              <Button type="submit" disabled={!ready || publish.isPending}>
                {publish.isPending ? t('pages.networkResources.publish.publishing') : t('pages.networkResources.publish.submit')}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
