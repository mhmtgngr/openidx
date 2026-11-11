import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Check, Copy, Plus, Router } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Badge } from './ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { api } from '../lib/api'

// Sites (migration 249): where a resource's hosting routers run.
// GET/POST /api/v1/access/sites, PATCH /api/v1/access/sites/:id,
// POST /api/v1/access/ziti/fabric/routers/enroll-token.

export interface Site {
  id: string
  slug: string
  name: string
  description: string
  hop_addr: string
  is_default: boolean
  routers?: number
}

export interface RouterOnboardResult {
  router_id: string
  name: string
  site_slug: string
  image_tag: string
  enrollment_jwt: string
  controller: string
  onboard_command: string
  warning?: string
}

interface EdgeRouterStatus {
  id: string
  isOnline?: boolean
  isVerified?: boolean
}

export const SITE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,38}$/

function apiError(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

export function useSites() {
  return useQuery({
    queryKey: ['sites'],
    queryFn: async () => (await api.get<{ sites: Site[] }>('/api/v1/access/sites')).sites ?? [],
  })
}

/**
 * SiteSelect picks the site whose routers host a resource. The value is a
 * slug; '' is the default site. Rendered as a native select so it works the
 * same inside every dialog.
 */
export function SiteSelect({ id, value, onChange }: { id: string; value: string; onChange: (slug: string) => void }) {
  const { t } = useTranslation()
  const { data: sites } = useSites()
  const list = sites ?? []
  const current = value || 'default'
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>{t('components.sites.label')}</Label>
      <select
        id={id}
        className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
        value={current}
        onChange={(e) => onChange(e.target.value === 'default' ? '' : e.target.value)}
      >
        {list.length === 0 && <option value="default">{t('components.sites.defaultSite')}</option>}
        {list.map((s) => (
          <option key={s.id} value={s.slug}>
            {s.is_default ? t('components.sites.defaultSite') : `${s.name} (${s.slug})`}
          </option>
        ))}
      </select>
      <p className="text-xs text-muted-foreground">{t('components.sites.hint')}</p>
    </div>
  )
}

/** AddRouterDialog onboards an edge router into a site and shows its command. */
export function AddRouterDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { data: sites } = useSites()
  const [site, setSite] = useState('default')
  const [newSlug, setNewSlug] = useState('')
  const [newName, setNewName] = useState('')
  const [name, setName] = useState('')
  const [address, setAddress] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState<RouterOnboardResult | null>(null)
  const [copied, setCopied] = useState(false)
  const creating = site === '__new__'

  const reset = () => {
    setSite('default'); setNewSlug(''); setNewName(''); setName(''); setAddress('')
    setError(''); setResult(null); setCopied(false)
  }

  const enroll = useMutation({
    mutationFn: async () => {
      let slug = site
      if (creating) {
        const s = await api.post<Site>('/api/v1/access/sites', { slug: newSlug.trim(), name: newName.trim() || undefined })
        slug = s.slug
      }
      return api.post<RouterOnboardResult>('/api/v1/access/ziti/fabric/routers/enroll-token', {
        name: name.trim() || undefined,
        site_slug: slug,
        advertised_address: address.trim(),
      })
    },
    onSuccess: (r) => {
      setResult(r)
      setError('')
      qc.invalidateQueries({ queryKey: ['sites'] })
      qc.invalidateQueries({ queryKey: ['ziti-fabric-routers'] })
    },
    onError: (e) => setError(apiError(e, t('components.sites.router.failed'))),
  })

  const { data: status } = useQuery({
    queryKey: ['ziti-fabric-router', result?.router_id],
    queryFn: () => api.get<EdgeRouterStatus>(`/api/v1/access/ziti/fabric/routers/${result!.router_id}`),
    enabled: !!result?.router_id,
    refetchInterval: (q) => ((q.state.data as EdgeRouterStatus | undefined)?.isOnline ? false : 5000),
  })

  const submit = () => {
    if (creating && !SITE_SLUG_RE.test(newSlug.trim())) {
      setError(t('components.sites.badSlug'))
      return
    }
    if (!address.trim()) {
      setError(t('components.sites.router.needAddress'))
      return
    }
    enroll.mutate()
  }

  const copy = async () => {
    if (!result) return
    await navigator.clipboard?.writeText(result.onboard_command)
    setCopied(true)
  }

  const enrollState = status?.isOnline ? 'online' : status?.isVerified ? 'enrolled' : 'waiting'

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) reset(); onOpenChange(o) }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('components.sites.router.title')}</DialogTitle>
          <DialogDescription>{t('components.sites.router.description')}</DialogDescription>
        </DialogHeader>
        {!result ? (
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="router-site">{t('components.sites.label')}</Label>
              <select
                id="router-site"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
                value={site}
                onChange={(e) => setSite(e.target.value)}
              >
                {(sites ?? []).map((s) => (
                  <option key={s.id} value={s.slug}>
                    {s.is_default ? t('components.sites.defaultSite') : `${s.name} (${s.slug})`}
                  </option>
                ))}
                {(sites ?? []).length === 0 && <option value="default">{t('components.sites.defaultSite')}</option>}
                <option value="__new__">{t('components.sites.newSite')}</option>
              </select>
            </div>
            {creating && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor="new-site-slug">{t('components.sites.slug')}</Label>
                  <Input id="new-site-slug" value={newSlug} onChange={(e) => setNewSlug(e.target.value)} placeholder="azure" />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="new-site-name">{t('components.sites.name')}</Label>
                  <Input id="new-site-name" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Azure West Europe" />
                </div>
              </div>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="router-name">{t('components.sites.router.name')}</Label>
                <Input id="router-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="azure-router-1" />
              </div>
              <div className="space-y-1">
                <Label htmlFor="router-address">{t('components.sites.router.address')}</Label>
                <Input id="router-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="router.azure.example.org" />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">{t('components.sites.router.addressHint')}</p>
            {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm">{t('components.sites.router.runThis', { site: result.site_slug })}</p>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs" data-testid="onboard-command">
              {result.onboard_command}
            </pre>
            {result.warning && <p className="text-sm text-amber-600">{result.warning}</p>}
            <div className="flex items-center gap-2 text-sm">
              <Router className="h-4 w-4" />
              {t('components.sites.router.status')}
              <Badge variant={enrollState === 'online' ? 'default' : 'secondary'}>
                {t(`components.sites.router.state.${enrollState}`)}
              </Badge>
            </div>
          </div>
        )}
        <DialogFooter>
          {!result ? (
            <Button onClick={submit} disabled={enroll.isPending}>
              <Plus className="mr-2 h-4 w-4" />
              {t('components.sites.router.submit')}
            </Button>
          ) : (
            <Button variant="outline" onClick={copy}>
              {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
              {copied ? t('components.sites.router.copied') : t('components.sites.router.copy')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
