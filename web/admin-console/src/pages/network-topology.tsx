import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Search, Share2, ExternalLink } from 'lucide-react'
import { api } from '../lib/api'
import { QueryGate } from '../components/query-gate'
import { TableSkeleton } from '../components/ui/skeleton'
import { Input } from '../components/ui/input'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import { TopologyGraph } from '../components/topology-graph'
import { buildTopology, type BuildInput, type Topology, type TopoNode, type TopoKind } from '../lib/topology-model'

// ─── API response shapes (confirmed against ziti-network.tsx) ─────────────────

interface ZitiIdentityResp {
  id: string
  name: string
  attributes?: string[]
  enrolled?: boolean
  disabled?: boolean
}

interface ZitiServiceResp {
  id: string
  name: string
  roleAttributes?: string[]
}

interface FabricRouterResp {
  id: string
  name: string
  isOnline?: boolean
  roleAttributes?: string[]
}

interface ServicePolicyResp {
  id?: string
  name?: string
  type?: string
  identityRoles: string[]
  serviceRoles: string[]
}

// The sessions endpoint returns entries with nested identity/service refs
// (ZitiSessionEntry in ziti-network.tsx).
interface ZitiSessionResp {
  id: string
  identity?: { id: string; name: string }
  service?: { id: string; name: string }
}

type KindFilter = 'all' | TopoKind

// The filter values, resolved through the catalog at render so the buttons
// and the summary rows below cannot come to name different kinds.
const KIND_FILTERS: KindFilter[] = ['all', 'identity', 'router', 'service']

// ─── Filtering ────────────────────────────────────────────────────────────────

// filterTopology drops nodes that don't match the search text / kind filter, and
// then drops any edge referencing a removed node. Kept simple: a node survives if
// (kind matches) AND (search empty OR label contains search).
function filterTopology(topology: Topology, search: string, kind: KindFilter): Topology {
  const q = search.trim().toLowerCase()
  if (!q && kind === 'all') return topology

  const nodes = topology.nodes.filter((n) => {
    if (kind !== 'all' && n.kind !== kind) return false
    if (q && !n.label.toLowerCase().includes(q)) return false
    return true
  })
  const keep = new Set(nodes.map((n) => n.id))
  const edges = topology.edges.filter((e) => keep.has(e.source) && keep.has(e.target))
  return { nodes, edges }
}

// policiesFor derives the service-policies that involve a given identity/service
// node, by matching the node id against the resolved policy member refs. This is
// a light re-implementation of the ref matching in topology-model (@id / #attr /
// all) scoped to the single selected node so the detail panel can list them.
function refMatchesNode(refs: string[], node: TopoNode, roleAttributes: string[]): boolean {
  for (const ref of refs) {
    if (!ref) continue
    if (ref === 'all' || ref === '#all') return true
    if (ref.startsWith('@') && ref.slice(1) === node.id) return true
    if (ref.startsWith('#') && roleAttributes.includes(ref.slice(1))) return true
    if (!ref.startsWith('@') && !ref.startsWith('#') && ref === node.id) return true
  }
  return false
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function NetworkTopologyPage() {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<KindFilter>('all')
  const [showSessions, setShowSessions] = useState(false)
  const [selected, setSelected] = useState<TopoNode | null>(null)

  const identitiesQuery = useQuery({
    queryKey: ['topology-identities'],
    queryFn: () => api.get<{ identities: ZitiIdentityResp[] }>('/api/v1/access/ziti/identities'),
  })
  const servicesQuery = useQuery({
    queryKey: ['topology-services'],
    queryFn: () => api.get<{ services: ZitiServiceResp[] }>('/api/v1/access/ziti/services'),
  })
  const routersQuery = useQuery({
    queryKey: ['topology-routers'],
    queryFn: () => api.get<FabricRouterResp[]>('/api/v1/access/ziti/fabric/routers'),
  })
  const policiesQuery = useQuery({
    queryKey: ['topology-service-policies'],
    queryFn: () => api.get<ServicePolicyResp[]>('/api/v1/access/ziti/fabric/service-policies'),
  })
  const sessionsQuery = useQuery({
    queryKey: ['topology-sessions'],
    queryFn: () => api.get<ZitiSessionResp[]>('/api/v1/access/ziti/sessions'),
    enabled: showSessions,
  })

  const identities = identitiesQuery.data?.identities ?? []
  const services = servicesQuery.data?.services ?? []
  const routers = Array.isArray(routersQuery.data) ? routersQuery.data : []
  const policies = Array.isArray(policiesQuery.data) ? policiesQuery.data : []
  const sessions = Array.isArray(sessionsQuery.data) ? sessionsQuery.data : []

  const buildInput: BuildInput = useMemo(() => ({
    identities: identities.map((i) => ({
      id: i.id,
      name: i.name,
      roleAttributes: i.attributes,
      disabled: i.disabled ?? i.enrolled === false,
    })),
    services: services.map((s) => ({ id: s.id, name: s.name, roleAttributes: s.roleAttributes })),
    routers: routers.map((r) => ({ id: r.id, name: r.name, online: r.isOnline })),
    servicePolicies: policies.map((p, idx) => ({
      id: p.id ?? `policy-${idx}`,
      name: p.name,
      type: p.type,
      identityRoles: p.identityRoles ?? [],
      serviceRoles: p.serviceRoles ?? [],
    })),
    sessions: showSessions
      ? sessions.map((s) => ({ identityId: s.identity?.id, serviceId: s.service?.id }))
      : [],
  }), [identities, services, routers, policies, sessions, showSessions])

  const topology = useMemo(() => buildTopology(buildInput), [buildInput])
  const filtered = useMemo(() => filterTopology(topology, search, kind), [topology, search, kind])

  // role attributes for the selected node, so the detail panel can match policies.
  const selectedRoleAttrs = useMemo(() => {
    if (!selected) return [] as string[]
    if (selected.kind === 'identity') return identities.find((i) => i.id === selected.id)?.attributes ?? []
    if (selected.kind === 'service') return services.find((s) => s.id === selected.id)?.roleAttributes ?? []
    return []
  }, [selected, identities, services])

  const relatedPolicies = useMemo(() => {
    if (!selected || (selected.kind !== 'identity' && selected.kind !== 'service')) return []
    return policies.filter((p) => {
      const refs = selected.kind === 'identity' ? p.identityRoles ?? [] : p.serviceRoles ?? []
      return refMatchesNode(refs, selected, selectedRoleAttrs)
    })
  }, [selected, policies, selectedRoleAttrs])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Share2 className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            {t('nav.items.networkTopology')}
          </h1>
          <p className="text-muted-foreground">
            {t('pages.networkTopology.subtitle')}
          </p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t('pages.networkTopology.searchPlaceholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border p-0.5">
          {KIND_FILTERS.map((value) => (
            <Button
              key={value}
              variant={kind === value ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setKind(value)}
            >
              {t(`pages.networkTopology.kinds.${value}`)}
            </Button>
          ))}
        </div>
        <label className="ml-auto flex items-center gap-2 text-sm text-muted-foreground">
          <Switch checked={showSessions} onCheckedChange={setShowSessions} />
          {t('pages.networkTopology.showSessions')}
        </label>
      </div>

      {/* Main */}
      <QueryGate query={identitiesQuery} resource={t('pages.networkTopology.resource')}>
        {() => {
          const anyLoading =
            servicesQuery.isLoading || routersQuery.isLoading || policiesQuery.isLoading
          if (anyLoading) return <TableSkeleton rows={6} cols={3} />
          return (
            <div className="flex flex-col gap-4 lg:flex-row">
              <Card className="flex-1">
                <CardContent className="p-4">
                  <TopologyGraph
                    topology={filtered}
                    interactive
                    showSessions={showSessions}
                    onSelect={setSelected}
                  />
                </CardContent>
              </Card>

              <div className="w-full lg:w-80 shrink-0">
                {selected ? (
                  <DetailPanel node={selected} policies={relatedPolicies} />
                ) : (
                  <SummaryPanel topology={topology} />
                )}
              </div>
            </div>
          )
        }}
      </QueryGate>
    </div>
  )
}

// ─── Detail panel ─────────────────────────────────────────────────────────────

const STATUS_VARIANT: Record<string, 'default' | 'destructive' | 'secondary'> = {
  up: 'default',
  down: 'destructive',
  degraded: 'secondary',
  unknown: 'secondary',
}

function DetailPanel({ node, policies }: { node: TopoNode; policies: ServicePolicyResp[] }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-base">
          <span className="truncate text-foreground">{node.label}</span>
          <Badge variant="outline">
            {t(`pages.networkTopology.nodeKinds.${node.kind}`, { defaultValue: node.kind })}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">{t('pages.networkTopology.detail.status')}</span>
          <Badge variant={STATUS_VARIANT[node.status] ?? 'secondary'}>
            {t(`pages.networkTopology.statuses.${node.status}`, {
              defaultValue: node.status,
            })}
          </Badge>
        </div>

        {(node.kind === 'identity' || node.kind === 'service') && (
          <div className="space-y-2">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {t('pages.networkTopology.detail.policies', { n: policies.length })}
            </p>
            {policies.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                {t(`pages.networkTopology.detail.noPolicies.${node.kind}`)}
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.networkTopology.detail.colPolicy')}</TableHead>
                    <TableHead>{t('pages.networkTopology.detail.colType')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {policies.map((p, idx) => (
                    <TableRow key={p.id ?? `${p.name}-${idx}`}>
                      {/* Policy name and type come from the controller. */}
                      <TableCell className="font-medium">
                        {p.name ?? p.id ?? t('pages.networkTopology.detail.policyFallback')}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{p.type ?? '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        )}

        <div className="flex flex-col gap-2 border-t border-border pt-3">
          <Button variant="outline" size="sm" asChild>
            <Link to="/ziti-network">
              <ExternalLink className="mr-2 h-4 w-4" />{' '}
              {t('pages.networkTopology.detail.openZitiNetwork')}
            </Link>
          </Button>
          {node.kind === 'identity' && (
            <Button variant="outline" size="sm" asChild>
              <Link to="/devices">
                <ExternalLink className="mr-2 h-4 w-4" />{' '}
                {t('pages.networkTopology.detail.viewDevices')}
              </Link>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Summary panel (no selection) ─────────────────────────────────────────────

function SummaryPanel({ topology }: { topology: Topology }) {
  const { t } = useTranslation()
  const counts = useMemo(() => {
    let identities = 0
    let routers = 0
    let services = 0
    for (const n of topology.nodes) {
      if (n.kind === 'identity') identities++
      else if (n.kind === 'router') routers++
      else if (n.kind === 'service') services++
    }
    return { identities, routers, services }
  }, [topology.nodes])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base text-foreground">
          {t('pages.networkTopology.summary.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">
            {t('pages.networkTopology.kinds.identity')}
          </span>
          <span className="font-medium text-foreground">{counts.identities}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">
            {t('pages.networkTopology.kinds.router')}
          </span>
          <span className="font-medium text-foreground">{counts.routers}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">
            {t('pages.networkTopology.kinds.service')}
          </span>
          <span className="font-medium text-foreground">{counts.services}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground">
            {t('pages.networkTopology.summary.edges')}
          </span>
          <span className="font-medium text-foreground">{topology.edges.length}</span>
        </div>
        <p className="border-t border-border pt-3 text-xs text-muted-foreground">
          {t('pages.networkTopology.summary.hint')}
        </p>
      </CardContent>
    </Card>
  )
}

export default NetworkTopologyPage
