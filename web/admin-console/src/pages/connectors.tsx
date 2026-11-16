import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ArrowRight, Check, CheckCircle2, Copy, Plug, Plus, Router, Server } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { isPlatformAdmin } from '../lib/platform-admin'
import { useSites, SiteSelect, type RouterOnboardResult } from '../components/site-select'

// Connectors — the plain-words view of the site edge routers. A "connector"
// is an edge router a customer runs inside their network; the page hides the
// Ziti vocabulary. List: GET /api/v1/access/ziti/fabric/routers (roleAttributes
// carry site-<slug>); detail/polling: GET .../routers/:id; create:
// POST .../routers/enroll-token. Org admins see the list read-only; only a
// platform admin (lib/platform-admin.ts) may add one.

interface FabricRouter {
  id: string
  name: string
  isOnline?: boolean
  isVerified?: boolean
  hostname?: string
  roleAttributes?: string[]
}

// The enroll-token response is gaining install_command (a one-line installer).
// Until every backend sends it, fall back to onboard_command.
type ConnectorOnboardResult = RouterOnboardResult & { install_command?: string }

export function connectorState(r: { isOnline?: boolean; isVerified?: boolean }): 'online' | 'enrolled' | 'waiting' {
  return r.isOnline ? 'online' : r.isVerified ? 'enrolled' : 'waiting'
}

export function routerSiteSlug(r: FabricRouter): string {
  const attr = (r.roleAttributes ?? []).find((a) => a.startsWith('site-'))
  return attr ? attr.slice('site-'.length) : ''
}

function apiError(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback
}

function StateBadge({ state }: { state: 'online' | 'enrolled' | 'waiting' }) {
  const { t } = useTranslation()
  return (
    <Badge variant={state === 'online' ? 'default' : 'secondary'} data-testid={`connector-state-${state}`}>
      {t(`components.sites.router.state.${state}`)}
    </Badge>
  )
}

export function ConnectorsPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const platformAdmin = isPlatformAdmin(user)
  const { data: sites } = useSites()
  const [wizardOpen, setWizardOpen] = useState(false)

  const { data: routersData, isLoading } = useQuery({
    queryKey: ['ziti-fabric-routers'],
    queryFn: () => api.get<FabricRouter[]>('/api/v1/access/ziti/fabric/routers'),
    refetchInterval: 15000,
  })
  const routers = Array.isArray(routersData) ? routersData : []

  // Group connectors by site slug. Routers whose attributes name no site
  // belong to the default site.
  const groups = useMemo(() => {
    const bySlug = new Map<string, FabricRouter[]>()
    for (const r of routers) {
      const slug = routerSiteSlug(r)
      const list = bySlug.get(slug) ?? []
      list.push(r)
      bySlug.set(slug, list)
    }
    const siteList = sites ?? []
    const known = siteList.map((s) => ({
      slug: s.is_default ? '' : s.slug,
      name: s.is_default ? t('components.sites.defaultSite') : s.name,
      routers: bySlug.get(s.is_default ? '' : s.slug) ?? bySlug.get(s.slug) ?? [],
    }))
    const knownSlugs = new Set(siteList.flatMap((s) => [s.slug, s.is_default ? '' : s.slug]))
    const orphans = [...bySlug.entries()].filter(([slug]) => !knownSlugs.has(slug))
    for (const [slug, list] of orphans) {
      known.push({ slug, name: slug || t('components.sites.defaultSite'), routers: list })
    }
    return known.filter((g) => g.routers.length > 0 || !g.slug)
  }, [routers, sites, t])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Plug className="h-6 w-6" />
            {t('pages.connectors.title')}
          </h1>
          <p className="text-muted-foreground">{t('pages.connectors.subtitle')}</p>
        </div>
        {platformAdmin && (
          <Button onClick={() => setWizardOpen(true)} data-testid="add-connector">
            <Plus className="mr-2 h-4 w-4" />
            {t('pages.connectors.add')}
          </Button>
        )}
      </div>
      {!platformAdmin && (
        <p className="text-sm text-muted-foreground" data-testid="read-only-note">
          {t('pages.connectors.readOnly')}
        </p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
      ) : routers.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center space-y-3">
            <Server className="mx-auto h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">{t('pages.connectors.empty')}</p>
            {platformAdmin && (
              <Button onClick={() => setWizardOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                {t('pages.connectors.add')}
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {groups.map((g) => (
            <div key={g.slug || '__default'} className="space-y-2">
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-semibold">{g.name}</h2>
                <span className="text-sm text-muted-foreground">
                  {t('pages.connectors.routerCount', { count: g.routers.length })}
                </span>
              </div>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {g.routers.map((r) => (
                  <Card key={r.id} data-testid="connector-card">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center justify-between gap-2">
                        <span className="flex items-center gap-2 truncate">
                          <Router className="h-4 w-4 shrink-0" />
                          <span className="truncate">{r.name}</span>
                        </span>
                        <StateBadge state={connectorState(r)} />
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="text-sm text-muted-foreground space-y-1">
                      <p>{t('pages.connectors.site')}: {g.name}</p>
                      {r.hostname && <p className="truncate">{r.hostname}</p>}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <ConnectorWizardDialog open={wizardOpen} onOpenChange={setWizardOpen} />
    </div>
  )
}

/**
 * ConnectorWizardDialog walks through adding a connector in three steps:
 * 1) what you need, 2) name/site/reachability, 3) run the install command and
 * watch the connector come online.
 */
export function ConnectorWizardDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [step, setStep] = useState(1)
  const [name, setName] = useState('')
  const [site, setSite] = useState('')
  const [isPublic, setIsPublic] = useState(false)
  const [address, setAddress] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState<ConnectorOnboardResult | null>(null)
  const [copied, setCopied] = useState(false)

  const reset = () => {
    setStep(1); setName(''); setSite(''); setIsPublic(false); setAddress('')
    setError(''); setResult(null); setCopied(false)
  }

  const enroll = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { site_slug: site || 'default' }
      if (name.trim()) body.name = name.trim()
      // Private mode (the default) omits the advertised address entirely:
      // the backend then issues a connector that only dials out.
      if (isPublic && address.trim()) body.advertised_address = address.trim()
      return api.post<ConnectorOnboardResult>('/api/v1/access/ziti/fabric/routers/enroll-token', body)
    },
    onSuccess: (r) => {
      setResult(r)
      setError('')
      setStep(3)
      qc.invalidateQueries({ queryKey: ['sites'] })
      qc.invalidateQueries({ queryKey: ['ziti-fabric-routers'] })
    },
    onError: (e) => setError(apiError(e, t('components.sites.router.failed'))),
  })

  const { data: status } = useQuery({
    queryKey: ['ziti-fabric-router', result?.router_id],
    queryFn: () => api.get<{ id: string; isOnline?: boolean; isVerified?: boolean }>(
      `/api/v1/access/ziti/fabric/routers/${result!.router_id}`,
    ),
    enabled: !!result?.router_id,
    refetchInterval: (q) => ((q.state.data as { isOnline?: boolean } | undefined)?.isOnline ? false : 5000),
  })

  const command = result ? (result.install_command || result.onboard_command) : ''
  const state = status ? connectorState(status) : 'waiting'
  const siteSlug = result?.site_slug || site || 'default'

  const copy = async () => {
    await navigator.clipboard?.writeText(command)
    setCopied(true)
  }

  const requirements = [
    t('pages.connectors.wizard.req1'),
    t('pages.connectors.wizard.req2'),
    t('pages.connectors.wizard.req3'),
  ]

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) reset(); onOpenChange(o) }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('pages.connectors.wizard.title')}</DialogTitle>
          <DialogDescription>
            {t('pages.connectors.wizard.stepLabel', { step, total: 3 })} — {t(`pages.connectors.wizard.step${step}Title`)}
          </DialogDescription>
        </DialogHeader>

        {step === 1 && (
          <div className="space-y-3" data-testid="wizard-step-1">
            <p className="text-sm">{t('pages.connectors.wizard.reqIntro')}</p>
            <ul className="space-y-2">
              {requirements.map((r) => (
                <li key={r} className="flex items-start gap-2 text-sm">
                  <CheckCircle2 className="h-4 w-4 mt-0.5 text-green-600 shrink-0" />
                  {r}
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">{t('pages.connectors.wizard.noInbound')}</p>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-3" data-testid="wizard-step-2">
            <div className="space-y-1">
              <Label htmlFor="connector-name">{t('pages.connectors.wizard.name')}</Label>
              <Input
                id="connector-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('pages.connectors.wizard.namePlaceholder')}
              />
            </div>
            <SiteSelect id="connector-site" value={site} onChange={setSite} />
            <div className="flex items-center justify-between gap-4 rounded-md border p-3">
              <div className="space-y-0.5">
                <Label htmlFor="connector-public">{t('pages.connectors.wizard.publicToggle')}</Label>
                <p className="text-xs text-muted-foreground">{t('pages.connectors.wizard.publicHint')}</p>
              </div>
              <Switch id="connector-public" checked={isPublic} onCheckedChange={setIsPublic} />
            </div>
            {isPublic && (
              <div className="space-y-1 rounded-md border border-dashed p-3">
                <p className="text-xs font-medium text-muted-foreground uppercase">{t('pages.connectors.wizard.advanced')}</p>
                <Label htmlFor="connector-address">{t('components.sites.router.address')}</Label>
                <Input
                  id="connector-address"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  placeholder="connector.example.org"
                />
                <p className="text-xs text-muted-foreground">{t('components.sites.router.addressHint')}</p>
              </div>
            )}
            {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          </div>
        )}

        {step === 3 && result && (
          <div className="space-y-3" data-testid="wizard-step-3">
            <p className="text-sm">{t('pages.connectors.wizard.runThis')}</p>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs" data-testid="install-command">
              {command}
            </pre>
            {result.warning && <p className="text-sm text-amber-600">{result.warning}</p>}
            <div className="flex items-center gap-2 text-sm">
              <Router className="h-4 w-4" />
              {t('components.sites.router.status')}
              <StateBadge state={state} />
            </div>
            {state === 'online' && (
              <Link
                to={`/app-publish?site=${encodeURIComponent(siteSlug)}`}
                className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
                data-testid="next-step-publish"
              >
                {t('pages.connectors.wizard.nextStep')}
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        )}

        <DialogFooter>
          {step === 2 && (
            <Button variant="outline" onClick={() => setStep(1)}>{t('pages.connectors.wizard.back')}</Button>
          )}
          {step === 1 && (
            <Button onClick={() => setStep(2)} data-testid="wizard-next">
              {t('pages.connectors.wizard.next')}
            </Button>
          )}
          {step === 2 && (
            <Button onClick={() => enroll.mutate()} disabled={enroll.isPending} data-testid="wizard-create">
              <Plus className="mr-2 h-4 w-4" />
              {t('pages.connectors.wizard.create')}
            </Button>
          )}
          {step === 3 && (
            <Button variant="outline" onClick={copy} data-testid="wizard-copy">
              {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
              {copied ? t('components.sites.router.copied') : t('components.sites.router.copy')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
