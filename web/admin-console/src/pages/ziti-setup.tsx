// Network Setup — guided, visual OpenZiti onboarding.
//
// One backend call (GET /api/v1/access/ziti/setup/status) powers the whole
// page: a live topology strip, an ordered setup checklist with remediation,
// an install advisor (what must be installed for THIS deployment), and
// per-route next-hop advice that mirrors exactly what the reconciler does.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRightCircle,
  MinusCircle,
  Lock,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  RefreshCw,
  Network,
  Globe,
  Laptop,
  Router as RouterIcon,
  ServerCog,
  AppWindow,
  Shield,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

// ─── API types (mirror internal/access/ziti_setup_handlers.go) ──────────────

interface SetupStep {
  id: string
  title: string
  description: string
  status: string
  detail?: string
  remediation?: string
  action_label?: string
  action_href?: string
}

interface SetupComponent {
  id: string
  name: string
  role: string
  required: 'required' | 'conditional' | 'optional'
  status: string
  detail?: string
  install?: string[]
}

interface RouteAdvice {
  route_name: string
  service_name: string
  to_url: string
  stored_mode: string
  effective_mode: string
  browzer_enabled: boolean
  route_enabled: boolean
  hop_port?: number
  next_hop: string
  client_side: string
  reconcile_state: string
  requirements?: string[]
  warnings?: string[]
}

interface RouterInfo {
  id: string
  name: string
  hostname: string
  isOnline: boolean
}

interface SetupSyncStatus {
  unsynced_users: number
  total_users: number
  total_identities: number
}

interface SetupStatus {
  ready: boolean
  summary: string
  console_url?: string
  steps: SetupStep[]
  components: SetupComponent[]
  routes: RouteAdvice[] | null
  routers: RouterInfo[] | null
  sync_status?: SetupSyncStatus
}

// ─── Status visuals ──────────────────────────────────────────────────────────

// Module-level, so it carries the catalog key rather than English; the key is
// the backend's own status enum.
const STATUS_META: Record<string, { icon: typeof CheckCircle2; className: string; labelKey: string }> = {
  complete: { icon: CheckCircle2, className: 'text-green-600', labelKey: 'complete' },
  warning: { icon: AlertTriangle, className: 'text-amber-500', labelKey: 'warning' },
  action_needed: { icon: ArrowRightCircle, className: 'text-blue-500', labelKey: 'action_needed' },
  error: { icon: XCircle, className: 'text-red-500', labelKey: 'error' },
  blocked: { icon: Lock, className: 'text-muted-foreground', labelKey: 'blocked' },
  optional: { icon: MinusCircle, className: 'text-muted-foreground', labelKey: 'optional' },
}

function StatusIcon({ status, className = 'h-5 w-5' }: { status: string; className?: string }) {
  const { t } = useTranslation()
  const meta = STATUS_META[status] ?? STATUS_META.optional
  const Icon = meta.icon
  return (
    <Icon
      className={`${className} ${meta.className}`}
      aria-label={t(`pages.zitiSetup.statuses.${meta.labelKey}`)}
    />
  )
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'complete':
      return 'bg-green-100 text-green-700'
    case 'warning':
      return 'bg-amber-100 text-amber-700'
    case 'action_needed':
      return 'bg-blue-100 text-blue-700'
    case 'error':
      return 'bg-red-100 text-red-700'
    default:
      return 'bg-muted text-muted-foreground'
  }
}

function modeBadgeClass(mode: string): string {
  switch (mode) {
    case 'identity':
      return 'bg-purple-100 text-purple-700'
    case 'direct':
      return 'bg-blue-100 text-blue-700'
    case 'hop':
      return 'bg-orange-100 text-orange-700'
    default:
      return 'bg-muted text-muted-foreground'
  }
}

// ─── Topology strip ──────────────────────────────────────────────────────────

interface TopoNode {
  label: string
  sub?: string
  ok: boolean | null // null = unknown/neutral
}

function TopoColumn({ title, icon: Icon, nodes }: { title: string; icon: typeof Globe; nodes: TopoNode[] }) {
  const { t } = useTranslation()
  return (
    <div className="flex min-w-[9.5rem] flex-1 flex-col gap-2">
      <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {nodes.map((n, i) => (
        <div key={i} className="rounded-lg border bg-card px-3 py-2 text-sm shadow-sm">
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 shrink-0 rounded-full ${
                n.ok === null ? 'bg-muted-foreground/40' : n.ok ? 'bg-green-500' : 'bg-red-500'
              }`}
            />
            <span className="truncate font-medium">{n.label}</span>
          </div>
          {n.sub && <div className="mt-0.5 truncate pl-4 text-xs text-muted-foreground">{n.sub}</div>}
        </div>
      ))}
      {nodes.length === 0 && (
        <div className="rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground">{t('pages.zitiSetup.topology.none')}</div>
      )}
    </div>
  )
}

function TopoArrow() {
  return (
    <div className="flex items-center self-stretch px-1 pt-6 text-muted-foreground/50">
      <ChevronRight className="h-5 w-5" />
    </div>
  )
}

// TopologyStrip draws the data path left→right: who connects, through what,
// governed by which control plane, to reach which applications.
function TopologyStrip({ data }: { data: SetupStatus }) {
  const { t } = useTranslation()
  const routes = data.routes ?? []
  const routers = data.routers ?? []
  const step = (id: string) => data.steps.find((s) => s.id === id)
  const comp = (id: string) => data.components.find((c) => c.id === id)

  const browzerRoutes = routes.filter((r) => r.browzer_enabled).length
  const identityRoutes = routes.filter((r) => r.effective_mode === 'identity').length

  const clients: TopoNode[] = []
  if (browzerRoutes > 0 || comp('browzer')?.status === 'complete') {
    clients.push({
      label: t('pages.zitiSetup.topology.browser'),
      sub: t('pages.zitiSetup.topology.browserSub', { n: browzerRoutes }),
      ok: comp('browzer')?.status === 'complete',
    })
  }
  clients.push({
    label: t('pages.zitiSetup.topology.tunneler'),
    sub:
      identityRoutes > 0
        ? t('pages.zitiSetup.topology.tunnelerNeeded', { n: identityRoutes })
        : t('pages.zitiSetup.topology.tunnelerIdle'),
    ok: null,
  })

  const routerNodes: TopoNode[] = routers.slice(0, 3).map((r) => ({
    label: r.name,
    sub: r.hostname || undefined,
    ok: r.isOnline,
  }))
  if (routers.length > 3) {
    routerNodes.push({ label: t('pages.zitiSetup.topology.andMore', { n: routers.length - 3 }), ok: null })
  }

  const controllerOK = step('controller')?.status === 'complete'
  const proxyOK = step('access_proxy')?.status === 'complete'
  const controlNodes: TopoNode[] = [
    { label: 'Ziti Controller', sub: t('pages.zitiSetup.topology.controllerSub'), ok: controllerOK },
    { label: 'OpenIDX access-proxy', sub: t('pages.zitiSetup.topology.proxySub'), ok: proxyOK },
  ]

  const appNodes: TopoNode[] = routes.slice(0, 3).map((r) => ({
    label: r.route_name,
    sub: `${r.effective_mode} → ${r.to_url}`,
    ok: r.reconcile_state === 'synced' ? true : r.reconcile_state.startsWith('error') ? false : null,
  }))
  if (routes.length > 3) {
    appNodes.push({ label: t('pages.zitiSetup.topology.andMore', { n: routes.length - 3 }), ok: null })
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4" />
          {t('pages.zitiSetup.topology.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <div className="flex min-w-[44rem] items-start gap-1">
            <TopoColumn title={t('pages.zitiSetup.topology.clients')} icon={Laptop} nodes={clients} />
            <TopoArrow />
            <TopoColumn title={t('pages.zitiSetup.topology.edgeRouters')} icon={RouterIcon} nodes={routerNodes} />
            <TopoArrow />
            <TopoColumn title={t('pages.zitiSetup.topology.controlPlane')} icon={ServerCog} nodes={controlNodes} />
            <TopoArrow />
            <TopoColumn title={t('pages.zitiSetup.topology.applications')} icon={AppWindow} nodes={appNodes} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Setup checklist ─────────────────────────────────────────────────────────

function SetupStepRow({ step, index }: { step: SetupStep; index: number }) {
  const { t } = useTranslation()
  return (
    <li className="relative flex gap-4 pb-8 last:pb-0">
      {/* vertical connector */}
      <div className="absolute left-[15px] top-8 h-full w-px bg-border last:hidden" aria-hidden />
      <div className="z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border bg-background">
        {step.status === 'complete' ? (
          <CheckCircle2 className="h-5 w-5 text-green-600" />
        ) : (
          <span className="text-sm font-semibold text-muted-foreground">{index + 1}</span>
        )}
      </div>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{step.title}</span>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusBadgeClass(step.status)}`}>
            {t(`pages.zitiSetup.statuses.${(STATUS_META[step.status] ?? STATUS_META.optional).labelKey}`)}
          </span>
        </div>
        <p className="text-sm text-muted-foreground">{step.description}</p>
        {step.detail && <p className="text-sm">{step.detail}</p>}
        {step.remediation && step.status !== 'complete' && (
          <div className="mt-1 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{step.remediation}</span>
          </div>
        )}
        {step.action_href && step.action_label && (
          <Button asChild variant="outline" size="sm" className="mt-1">
            <Link to={step.action_href}>{step.action_label}</Link>
          </Button>
        )}
      </div>
    </li>
  )
}

// ─── Install advisor ─────────────────────────────────────────────────────────

function RequiredBadge({ required }: { required: SetupComponent['required'] }) {
  const { t } = useTranslation()
  switch (required) {
    case 'required':
      return <Badge className="bg-red-100 text-red-700 hover:bg-red-100">{t('pages.zitiSetup.required.required')}</Badge>
    case 'conditional':
      return <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100">{t('pages.zitiSetup.required.conditional')}</Badge>
    default:
      return <Badge variant="outline">{t('pages.zitiSetup.required.optional')}</Badge>
  }
}

function ComponentCard({ comp }: { comp: SetupComponent }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <StatusIcon status={comp.status} className="h-4 w-4" />
            <span className="font-medium">{comp.name}</span>
          </div>
          <RequiredBadge required={comp.required} />
        </div>
        <p className="mt-2 text-sm text-muted-foreground">{comp.role}</p>
        {comp.detail && <p className="mt-1 text-xs text-muted-foreground">{comp.detail}</p>}
        {comp.install && comp.install.length > 0 && (
          <button
            type="button"
            className="mt-2 flex items-center gap-1 text-sm font-medium text-primary"
            onClick={() => setOpen(!open)}
          >
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            {t('pages.zitiSetup.howToInstall')}
          </button>
        )}
        {open && comp.install && (
          <ul className="mt-2 space-y-1.5">
            {comp.install.map((line, i) => (
              <li key={i} className="rounded bg-muted px-2.5 py-1.5 font-mono text-xs leading-relaxed">
                {line}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Route advice table ──────────────────────────────────────────────────────

// The `title` keeps the raw state so the exact backend string stays
// inspectable even when the badge shows a translated summary.
function ReconcileBadge({ state }: { state: string }) {
  const { t } = useTranslation()
  if (state === 'synced')
    return <Badge className="bg-green-100 text-green-700 hover:bg-green-100">{t('pages.zitiSetup.routes.synced')}</Badge>
  if (state.startsWith('error'))
    return (
      <Badge className="bg-red-100 text-red-700 hover:bg-red-100" title={state}>
        {t('pages.zitiSetup.routes.error')}
      </Badge>
    )
  if (state === 'route_disabled')
    return <Badge variant="outline">{t('pages.zitiSetup.routes.routeDisabled')}</Badge>
  return <Badge variant="outline">{state.split('_').join(' ')}</Badge>
}

function RouteRow({ route }: { route: RouteAdvice }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const autoCorrected = route.stored_mode !== route.effective_mode
  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setOpen(!open)}>
        <TableCell>
          <div className="flex items-center gap-1.5">
            {open ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <span className="font-medium">{route.route_name}</span>
            {route.browzer_enabled && (
              <Badge variant="outline" className="text-xs">
                BrowZer
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${modeBadgeClass(route.effective_mode)}`}>
            {route.effective_mode}
          </span>
          {autoCorrected && (
            <span
              className="ml-1.5 inline-flex items-center text-amber-500"
              title={t('pages.zitiSetup.routes.autoCorrected', {
                stored: route.stored_mode,
                effective: route.effective_mode,
              })}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
          )}
        </TableCell>
        <TableCell className="max-w-[16rem] truncate text-sm text-muted-foreground" title={route.to_url}>
          {route.to_url}
        </TableCell>
        <TableCell><ReconcileBadge state={route.route_enabled ? route.reconcile_state : 'route_disabled'} /></TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={4} className="space-y-3 py-4">
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('pages.zitiSetup.routes.dataPath')}</div>
              <p className="mt-1 font-mono text-xs">{route.next_hop}</p>
            </div>
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('pages.zitiSetup.routes.clientSide')}</div>
              <p className="mt-1 text-sm">{route.client_side}</p>
            </div>
            {route.requirements && route.requirements.length > 0 && (
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('pages.zitiSetup.routes.requires')}</div>
                <ul className="mt-1 list-inside list-disc space-y-0.5 text-sm">
                  {route.requirements.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
            {route.warnings && route.warnings.length > 0 && (
              <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="space-y-0.5">
                  {route.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                </div>
              </div>
            )}
            {route.reconcile_state.startsWith('error') && (
              <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{route.reconcile_state}</span>
              </div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function ZitiSetupPage() {
  const { t } = useTranslation()
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['ziti-setup-status'],
    queryFn: () => api.get<SetupStatus>('/api/v1/access/ziti/setup/status'),
    refetchInterval: 15000,
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.zitiSetup.title')}</h1>
          <p className="text-muted-foreground">
            {t('pages.zitiSetup.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <span
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium ${
                data.ready ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700'
              }`}
            >
              <Shield className="h-4 w-4" />
              {data.ready ? t('pages.zitiSetup.networkReady') : data.summary}
            </span>
          )}
          {data?.console_url && (
            <Button variant="outline" size="sm" asChild>
              <a href={data.console_url} target="_blank" rel="noreferrer">
                <ExternalLink className="mr-1.5 h-4 w-4" />
                {t('pages.zitiSetup.zitiConsole')}
              </a>
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-1.5 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            {t('pages.zitiSetup.refresh')}
          </Button>
        </div>
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">{t('pages.zitiSetup.loading')}</p>}

      {isError && <QueryError error={error} resource={t('pages.zitiSetup.resourceName')} />}

      {data && (
        <>
          <TopologyStrip data={data} />

          <div className="grid gap-6 lg:grid-cols-5">
            <Card className="lg:col-span-3">
              <CardHeader>
                <CardTitle className="text-base">{t('pages.zitiSetup.checklist')}</CardTitle>
              </CardHeader>
              <CardContent>
                <ol>
                  {data.steps.map((step, i) => (
                    <SetupStepRow key={step.id} step={step} index={i} />
                  ))}
                </ol>
              </CardContent>
            </Card>

            <div className="space-y-4 lg:col-span-2">
              <h2 className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
                {t('pages.zitiSetup.installHeading')}
              </h2>
              {data.components.map((comp) => (
                <ComponentCard key={comp.id} comp={comp} />
              ))}
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('pages.zitiSetup.routes.title')}</CardTitle>
              <p className="text-sm text-muted-foreground">
                {t('pages.zitiSetup.routes.subtitle')}
              </p>
            </CardHeader>
            <CardContent>
              {(data.routes ?? []).length === 0 ? (
                <div className="rounded-lg border border-dashed py-8 text-center text-sm text-muted-foreground">
                  {t('pages.zitiSetup.routes.emptyPrefix')}{' '}
                  <Link to="/proxy-routes" className="font-medium text-primary underline-offset-2 hover:underline">
                    {t('pages.zitiSetup.routes.emptyCta')}
                  </Link>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('pages.zitiSetup.routes.route')}</TableHead>
                      <TableHead>{t('pages.zitiSetup.routes.mode')}</TableHead>
                      <TableHead>{t('pages.zitiSetup.routes.upstream')}</TableHead>
                      <TableHead>{t('pages.zitiSetup.routes.state')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(data.routes ?? []).map((route) => (
                      <RouteRow key={route.service_name || route.route_name} route={route} />
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
