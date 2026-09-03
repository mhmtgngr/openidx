import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Network, Server, Users2, Copy, CheckCircle,
  Shield, Router, Fingerprint, RefreshCw, FileKey, AlertTriangle,
  Monitor, ExternalLink, MoreHorizontal, Search, ChevronDown, ChevronRight,
  LayoutDashboard, Clock, Link2, Key, Terminal, MonitorPlay, Lock, Pencil, ScrollText,
  Settings, Zap, Upload, Download,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Switch } from '../components/ui/switch'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ZitiService {
  id: string
  ziti_id: string
  name: string
  description?: string
  protocol: string
  host: string
  port: number
  route_id?: string
  enabled: boolean
  created_at: string
  browzer_path?: string
  browzer_domain?: string
}

interface ZitiIdentity {
  id: string
  ziti_id: string
  name: string
  display_name?: string
  identity_type: string
  user_id?: string
  enrolled: boolean
  attributes: string[]
  created_at: string
}

interface ZitiEndpointStatus {
  url: string
  active: boolean
  healthy: boolean
}

interface ZitiStatus {
  enabled: boolean
  sdk_ready: boolean
  controller_reachable?: boolean
  controller_error?: string
  controller_version?: Record<string, unknown>
  console_url?: string
  services_count: number
  identities_count: number
  // Present on the fabric/health-derived status; optional here so the overview
  // cards can fall back to it when the overview payload is unavailable.
  routers_online?: number
  routers_total?: number
  /** true when ZITI_CTRL_URLS configures >1 management endpoint (HA cluster) */
  ha?: boolean
  controller_endpoints?: ZitiEndpointStatus[]
}

interface ZitiSyncStatus {
  status: string
  last_full_sync_at?: string
  last_auto_sync_at?: string
  users_synced: number
  users_failed: number
  groups_synced: number
  unsynced_users: number
  total_users: number
  total_identities: number
}

interface FabricRouter {
  id: string
  name: string
  // The controller returns camelCase fields straight from the Ziti mgmt API
  // (isOnline/isVerified/versionInfo), and does NOT send fingerprint/created_at.
  // Matching the real shape here fixes the router showing as "Offline" and the
  // "Invalid Date" created cell.
  isOnline: boolean
  isVerified?: boolean
  hostname: string
  roleAttributes?: string[]
  versionInfo?: { os?: string; arch?: string; version?: string }
}

// The /ziti/fabric/overview endpoint returns { health: {...}, recent_metrics }.
// The FE previously expected a flat {controller_online, router_count,
// healthy_routers, ...} object whose keys never matched, so the overview cards
// all read 0 / Offline even though the fabric was healthy.
interface FabricHealth {
  controller_reachable: boolean
  controller_version?: string
  sdk_ready?: boolean
  routers_online: number
  routers_total: number
  services_count: number
  identities_count: number
  policies_count: number
  last_checked?: string
}
interface FabricOverview {
  health?: FabricHealth
}

interface PostureCheck {
  id: string
  name: string
  check_type: string
  parameters: Record<string, unknown>
  enabled: boolean
  severity: string
  platforms?: string[] | null
  created_at: string
}

interface PostureSummary {
  total_checks: number
  enabled_checks: number
  disabled_checks: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

interface PostureResult {
  id: string
  identity_id: string
  check_id: string
  passed: boolean
  details: Record<string, unknown>
  checked_at: string
  expires_at?: string
}

interface IdentityPostureReport {
  identity_id: string
  overall_passed: boolean
  results: PostureResult[]
  evaluated_at: string
}

interface PolicySync {
  id: string
  governance_policy_id: string
  ziti_policy_id: string
  sync_status: string
  last_synced_at: string
  error_message: string
}

interface ServicePolicy {
  id: string
  name: string
  type: string
  serviceRoles: string[]
  identityRoles: string[]
}

interface EdgeRouterPolicy {
  id: string
  name: string
  edgeRouterRoles: string[]
  identityRoles: string[]
}

interface Certificate {
  id: string
  name: string
  cert_type: string
  subject: string
  issuer: string
  fingerprint: string
  not_before: string
  not_after: string
  auto_renew: boolean
  status: string
  days_until_expiry: number
}

interface GuacConnection {
  id: string
  route_id: string
  guacamole_connection_id: string
  protocol: string
  hostname: string
  port: number
  parameters: Record<string, string>
  created_at: string
  updated_at: string
}

interface BrowZerStatus {
  enabled: boolean
  configured?: boolean
  external_jwt_signer_id?: string
  auth_policy_id?: string
  dial_policy_id?: string
  oidc_issuer?: string
  oidc_client_id?: string
  bootstrapper_url?: string
  reason?: string
}

interface TempAccessLink {
  id: string
  token: string
  name: string
  description?: string
  protocol: string
  target_host: string
  target_port: number
  username?: string
  created_by: string
  created_by_email: string
  expires_at: string
  max_uses: number
  current_uses: number
  allowed_ips?: string[]
  require_mfa: boolean
  notify_on_use: boolean
  notify_email?: string
  access_url: string
  status: 'active' | 'expired' | 'revoked' | 'used'
  last_used_at?: string
  last_used_ip?: string
  created_at: string
}

interface ZitiConfigType {
  id: string
  name: string
  schema?: Record<string, unknown>
}

interface ZitiConfig {
  id: string
  name: string
  configTypeId: string
  configType?: { id: string; name: string }
  data: Record<string, unknown>
}

interface ZitiAuthPolicy {
  id: string
  name: string
  primary: Record<string, Record<string, unknown>>
  secondary: Record<string, unknown>
}

interface ZitiJWTSigner {
  id: string
  name: string
  issuer: string
  audience: string
  jwksEndpoint: string
  claimsProperty: string
  useExternalId: boolean
  enabled: boolean
}

interface ZitiTerminator {
  id: string
  serviceId: string
  service?: { id: string; name: string }
  routerId: string
  router?: { id: string; name: string }
  binding: string
  address: string
  cost: number
  precedence: string
  createdAt: string
}

interface ZitiSessionEntry {
  id: string
  type: 'Dial' | 'Bind'
  identity?: { id: string; name: string }
  service?: { id: string; name: string }
  createdAt: string
}

interface AppZitiService {
  id: string
  ziti_id: string
  name: string
  protocol: string
  host: string
  port: number
  enabled: boolean
  linked_path: string
  classification: string
  route_name: string
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Render a possibly-missing/invalid timestamp without printing "Invalid Date"
// (some Ziti entities arrive with an empty or unparseable created_at).
function safeDate(v?: string | null): string {
  if (!v) return '—'
  const d = new Date(v)
  return isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

function TruncatedId({ value, label }: { value: string; label?: string }) {
  const { toast } = useToast()
  const { t } = useTranslation()
  if (!value) return <span className="text-xs text-muted-foreground">—</span>
  const short = value.length > 12 ? value.slice(0, 8) + '...' : value
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value)
        toast({
          title: t('pages.zitiNetwork.copied'),
          description: t('pages.zitiNetwork.copiedTo', { label: label || t('pages.zitiNetwork.idLabel') }),
        })
      }}
      className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
      title={value}
    >
      {short}
      <Copy className="h-3 w-3" />
    </button>
  )
}

function Spinner() {
  return (
    <div className="flex justify-center py-12">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
    </div>
  )
}

function EmptyState({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Icon className="h-12 w-12 text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium">{title}</h3>
        <p className="text-muted-foreground mt-1 text-center max-w-md">{description}</p>
      </CardContent>
    </Card>
  )
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative flex-1 max-w-sm">
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pl-9"
      />
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

const ZITI_TABS = ['connection', 'overview', 'services', 'identities', 'security', 'remote-access']

export function ZitiNetworkPage() {
  const { t } = useTranslation()
  // Deep-linkable tabs (e.g. /ziti-network?tab=connection from Network Setup).
  const [searchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab') ?? ''
  const [activeTab, setActiveTab] = useState(ZITI_TABS.includes(requestedTab) ? requestedTab : 'overview')

  const { data: status } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.zitiNetwork')}</h1>
          <p className="text-muted-foreground">{t('pages.zitiNetwork.subtitle')}</p>
        </div>
        <div className="flex items-center gap-3">
          {status && (
            <>
              <div className="flex items-center gap-1.5 text-sm">
                {status.controller_reachable ? (
                  <span className="flex items-center gap-1.5 text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                    {t('pages.zitiNetwork.connected')}
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-red-700 dark:text-red-400">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    {t('pages.zitiNetwork.disconnected')}
                  </span>
                )}
              </div>
              <Badge variant="outline">{t('pages.zitiNetwork.serviceCount', { count: status.services_count })}</Badge>
              <Badge variant="outline">{t('pages.zitiNetwork.identityCount', { count: status.identities_count })}</Badge>
              {status.console_url && (
                <Button variant="outline" size="sm" asChild>
                  <a href={status.console_url} target="_blank" rel="noreferrer">
                    <ExternalLink className="h-4 w-4 mr-1.5" />
                    {t('pages.zitiNetwork.console')}
                  </a>
                </Button>
              )}
            </>
          )}
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="connection" className="gap-1.5">
            <Settings className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.connection')}
          </TabsTrigger>
          <TabsTrigger value="overview" className="gap-1.5">
            <LayoutDashboard className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.overview')}
          </TabsTrigger>
          <TabsTrigger value="services" className="gap-1.5">
            <Server className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.services')}
          </TabsTrigger>
          <TabsTrigger value="identities" className="gap-1.5">
            <Users2 className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.identities')}
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5">
            <Shield className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.security')}
          </TabsTrigger>
          <TabsTrigger value="remote-access" className="gap-1.5">
            <Monitor className="h-4 w-4" />
            {t('pages.zitiNetwork.tabs.remoteAccess')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="connection">
          <ConnectionTab />
        </TabsContent>
        <TabsContent value="overview">
          <OverviewTab onNavigate={setActiveTab} />
        </TabsContent>
        <TabsContent value="services">
          <ServicesTab />
        </TabsContent>
        <TabsContent value="identities">
          <IdentitiesTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="remote-access">
          <RemoteAccessTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

interface ZitiConnSettings {
  enabled: boolean
  controller_url: string
  admin_user: string
  admin_password: string
  identity_dir: string
  insecure_skip_verify: boolean
}

// ConnectionTab manages the OpenZiti controller connection from the admin panel:
// view/edit the URL + admin creds, test reachability, and connect/disconnect the
// live manager at runtime (no service restart).
function ConnectionTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [form, setForm] = useState<ZitiConnSettings | null>(null)

  const { data: status } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })
  const { isLoading } = useQuery({
    queryKey: ['ziti-settings'],
    queryFn: async () => {
      const s = await api.get<ZitiConnSettings>('/api/v1/access/ziti/settings')
      setForm(s)
      return s
    },
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
    queryClient.invalidateQueries({ queryKey: ['ziti-fabric-overview'] })
    queryClient.invalidateQueries({ queryKey: ['access-overview'] })
  }

  const save = useMutation({
    mutationFn: (s: ZitiConnSettings) => api.put('/api/v1/access/ziti/settings', s),
    onSuccess: () => toast({ title: t('pages.zitiNetwork.connection.toast.saved'), description: t('pages.zitiNetwork.connection.toast.savedDesc') }),
    onError: (e: Error) => toast({ title: t('pages.zitiNetwork.connection.toast.saveFailed'), description: e.message, variant: 'destructive' }),
  })
  const test = useMutation({
    mutationFn: (s: ZitiConnSettings) =>
      api.post<{ reachable: boolean; authenticated: boolean; error?: string; controller_version?: { data?: { version?: string } } }>(
        '/api/v1/access/ziti/settings/test', s),
    onSuccess: (r) =>
      toast({
        title: r.reachable ? t('pages.zitiNetwork.connection.toast.testOk') : t('pages.zitiNetwork.connection.toast.testFailed'),
        description: r.reachable
          ? t('pages.zitiNetwork.connection.toast.controllerVersion', {
              version: r.controller_version?.data?.version || t('pages.zitiNetwork.connection.toast.reachable'),
            })
          : r.error || t('pages.zitiNetwork.connection.toast.unreachable'),
        variant: r.reachable ? undefined : 'destructive',
      }),
    onError: (e: Error) => toast({ title: t('pages.zitiNetwork.connection.toast.testError'), description: e.message, variant: 'destructive' }),
  })
  const connect = useMutation({
    mutationFn: async (s: ZitiConnSettings) => { await api.put('/api/v1/access/ziti/settings', s); return api.post('/api/v1/access/ziti/connect', {}) },
    onSuccess: () => { invalidate(); toast({ title: t('pages.zitiNetwork.connection.toast.connected'), description: t('pages.zitiNetwork.connection.toast.connectedDesc') }) },
    onError: (e: Error) => toast({ title: t('pages.zitiNetwork.connection.toast.connectFailed'), description: e.message, variant: 'destructive' }),
  })
  const disconnect = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/disconnect', {}),
    onSuccess: () => { invalidate(); toast({ title: t('pages.zitiNetwork.connection.toast.disconnected'), description: t('pages.zitiNetwork.connection.toast.disconnectedDesc') }) },
    onError: (e: Error) => toast({ title: t('pages.zitiNetwork.connection.toast.disconnectFailed'), description: e.message, variant: 'destructive' }),
  })

  if (isLoading || !form) return <div className="py-8 text-center text-muted-foreground">{t('pages.zitiNetwork.loading')}</div>

  const reachable = !!status?.controller_reachable
  const ctrlVer = (status?.controller_version as { data?: { version?: string } } | undefined)?.data?.version
  const set = (k: keyof ZitiConnSettings, v: string | boolean) => setForm({ ...form, [k]: v })

  return (
    <div className="space-y-4 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            {t('pages.zitiNetwork.connection.title')}
            <Badge className={`ml-auto ${reachable ? 'bg-green-100 text-green-700' : 'bg-muted text-muted-foreground'}`}>
              {!status?.enabled
                ? t('pages.zitiNetwork.connection.notConfigured')
                : reachable
                  ? t('pages.zitiNetwork.connection.connected')
                  : t('pages.zitiNetwork.connection.unreachable')}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="ctrl">{t('pages.zitiNetwork.connection.controllerUrl')}</Label>
            <Input id="ctrl" placeholder="https://ziti-controller.example.com:1280"
              value={form.controller_url} onChange={(e) => set('controller_url', e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="user">{t('pages.zitiNetwork.connection.adminUser')}</Label>
              <Input id="user" value={form.admin_user} onChange={(e) => set('admin_user', e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pw">{t('pages.zitiNetwork.connection.adminPassword')}</Label>
              <Input id="pw" type="password" placeholder="••••••••"
                value={form.admin_password} onChange={(e) => set('admin_password', e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dir">{t('pages.zitiNetwork.connection.identityDir')}</Label>
            <Input id="dir" value={form.identity_dir} onChange={(e) => set('identity_dir', e.target.value)} />
          </div>
          <div className="flex items-center gap-2">
            <Switch id="insecure" checked={form.insecure_skip_verify}
              onCheckedChange={(v) => set('insecure_skip_verify', v)} />
            <Label htmlFor="insecure" className="text-sm">{t('pages.zitiNetwork.connection.skipTls')}</Label>
          </div>
          {ctrlVer && (
            <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.connection.version', { version: ctrlVer })}</p>
          )}
          {status?.ha && status.controller_endpoints && (
            <div className="rounded-lg border p-3 space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                {t('pages.zitiNetwork.connection.haTitle')}
                <Badge className="bg-blue-100 text-blue-700">
                  {t('pages.zitiNetwork.connection.haHealthy', {
                    healthy: status.controller_endpoints.filter((e) => e.healthy).length,
                    total: status.controller_endpoints.length,
                  })}
                </Badge>
              </div>
              <div className="space-y-1">
                {status.controller_endpoints.map((ep) => (
                  <div key={ep.url} className="flex items-center gap-2 text-xs font-mono">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${ep.healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                    <span className="truncate">{ep.url}</span>
                    {ep.active && <Badge className="bg-green-100 text-green-700 ml-auto shrink-0">{t('pages.zitiNetwork.connection.haActive')}</Badge>}
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                {t('pages.zitiNetwork.connection.haNote')}
              </p>
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-2">
            <Button variant="outline" disabled={test.isPending} onClick={() => test.mutate(form)}>{t('pages.zitiNetwork.connection.test')}</Button>
            <Button variant="outline" disabled={save.isPending} onClick={() => save.mutate(form)}>{t('pages.zitiNetwork.connection.save')}</Button>
            <Button disabled={connect.isPending} onClick={() => connect.mutate(form)}>{t('pages.zitiNetwork.connection.saveConnect')}</Button>
            <Button variant="ghost" className="text-red-600" disabled={disconnect.isPending}
              onClick={() => disconnect.mutate()}>{t('pages.zitiNetwork.connection.disconnect')}</Button>
          </div>
        </CardContent>
      </Card>
      <p className="text-xs text-muted-foreground">
        {t('pages.zitiNetwork.connection.footnote')}
      </p>
    </div>
  )
}

function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { toast } = useToast()
  const { t } = useTranslation()

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  const { data: overview } = useQuery({
    queryKey: ['ziti-fabric-overview'],
    queryFn: () => api.get<FabricOverview>('/api/v1/access/ziti/fabric/overview'),
    refetchInterval: 15000,
  })

  const { data: routersData } = useQuery({
    queryKey: ['ziti-fabric-routers'],
    queryFn: () => api.get<FabricRouter[]>('/api/v1/access/ziti/fabric/routers'),
  })

  const reconnectMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/fabric/reconnect', {}),
    onSuccess: () => toast({ title: t('pages.zitiNetwork.overview.toast.reconnectStarted'), description: t('pages.zitiNetwork.overview.toast.reconnectStartedDesc') }),
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.overview.toast.reconnectFailed'), variant: 'destructive' }),
  })

  const healthCheckMutation = useMutation({
    mutationFn: () => api.get('/api/v1/access/ziti/fabric/health'),
    onSuccess: () => toast({ title: t('pages.zitiNetwork.overview.toast.healthOk'), description: t('pages.zitiNetwork.overview.toast.healthOkDesc') }),
    onError: () => toast({ title: t('pages.zitiNetwork.overview.toast.healthFailed'), description: t('pages.zitiNetwork.overview.toast.healthFailedDesc'), variant: 'destructive' }),
  })

  const routers = Array.isArray(routersData) ? routersData : []

  if (statusLoading) return <Spinner />

  // The overview endpoint nests everything under `health`. Fall back to the
  // separate `status` (fabric/health) source when present.
  const h = overview?.health
  const controllerUp = (h?.controller_reachable ?? status?.controller_reachable) ?? false
  const routersOnline = h?.routers_online ?? status?.routers_online ?? 0
  const routersTotal = h?.routers_total ?? status?.routers_total ?? routers.length
  const servicesCount = h?.services_count ?? status?.services_count ?? 0
  const identitiesCount = h?.identities_count ?? status?.identities_count ?? 0

  const statCards = [
    {
      title: t('pages.zitiNetwork.overview.controller'),
      value: controllerUp ? t('pages.zitiNetwork.overview.online') : t('pages.zitiNetwork.overview.offline'),
      description: (h?.sdk_ready ?? status?.sdk_ready) ? t('pages.zitiNetwork.overview.sdkReady') : t('pages.zitiNetwork.overview.sdkNotReady'),
      icon: Network,
      color: controllerUp ? 'text-green-600' : 'text-red-500',
      isStatus: true,
    },
    {
      title: t('pages.zitiNetwork.overview.routers'),
      value: routersTotal,
      description: t('pages.zitiNetwork.overview.routerSplit', {
        online: routersOnline,
        offline: Math.max(0, routersTotal - routersOnline),
      }),
      icon: Router,
      color: 'text-primary',
    },
    {
      title: t('pages.zitiNetwork.overview.services'),
      value: servicesCount,
      description: t('pages.zitiNetwork.overview.registeredServices'),
      icon: Server,
      color: 'text-purple-600',
      onClick: () => onNavigate('services'),
    },
    {
      title: t('pages.zitiNetwork.overview.identities'),
      value: identitiesCount,
      description: t('pages.zitiNetwork.overview.registeredIdentities'),
      icon: Users2,
      color: 'text-orange-600',
      onClick: () => onNavigate('identities'),
    },
  ]

  return (
    <div className="space-y-6 mt-4">
      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Card
            key={stat.title}
            className={stat.onClick ? 'cursor-pointer hover:shadow-md transition-all hover:scale-[1.02]' : ''}
            onClick={stat.onClick}
          >
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {stat.isStatus ? (
                  <span className={stat.color}>{stat.value}</span>
                ) : (
                  String(stat.value)
                )}
              </div>
              <p className="text-xs text-muted-foreground">{stat.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Routers section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">{t('pages.zitiNetwork.overview.edgeRouters')}</h3>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => healthCheckMutation.mutate()} disabled={healthCheckMutation.isPending}>
              <CheckCircle className="mr-2 h-4 w-4" />
              {healthCheckMutation.isPending ? t('pages.zitiNetwork.overview.checking') : t('pages.zitiNetwork.overview.healthCheck')}
            </Button>
            <Button variant="outline" size="sm" onClick={() => reconnectMutation.mutate()} disabled={reconnectMutation.isPending}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {reconnectMutation.isPending ? t('pages.zitiNetwork.overview.reconnecting') : t('pages.zitiNetwork.overview.reconnect')}
            </Button>
          </div>
        </div>

        {routers.length === 0 ? (
          <EmptyState icon={Router} title={t('pages.zitiNetwork.overview.emptyTitle')} description={t('pages.zitiNetwork.overview.emptyDesc')} />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.zitiNetwork.overview.colName')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.overview.colStatus')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.overview.colHostname')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.overview.colVerified')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.overview.colVersion')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {routers.map((router) => (
                  <TableRow key={router.id} className="hover:bg-muted/50">
                    <TableCell className="font-medium">{router.name}</TableCell>
                    <TableCell>
                      <Badge variant={router.isOnline ? 'default' : 'destructive'}>
                        {router.isOnline ? t('pages.zitiNetwork.overview.online') : t('pages.zitiNetwork.overview.offline')}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{router.hostname}</TableCell>
                    <TableCell>
                      <Badge variant={router.isVerified ? 'default' : 'secondary'}>
                        {router.isVerified ? t('pages.zitiNetwork.overview.verified') : t('pages.zitiNetwork.overview.unverified')}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {router.versionInfo?.version ?? '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>
    </div>
  )
}

// ─── Services Tab ────────────────────────────────────────────────────────────

interface ServiceTestResult {
  success: boolean
  service_name: string
  tests: Record<string, { success: boolean; latency_ms: number; error?: string }>
}

function ServicesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiService | null>(null)
  const [testingService, setTestingService] = useState<string | null>(null)
  // "How this works": the behind-the-scenes chain for one resource, so an
  // admin can see which link is broken without dropping to the CLI.
  const [explainName, setExplainName] = useState<string | null>(null)
  // intercept_address / dial_roles let the form provision a service that is
  // actually dialable, instead of a bare service object nobody can reach.
  const [form, setForm] = useState({ name: '', description: '', host: '', port: 8080, protocol: 'tcp', intercept_address: '', dial_roles: '' })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['ziti-services'],
    queryFn: () => api.get<{ services: ZitiService[] }>('/api/v1/access/ziti/services'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => {
      // dial_roles is a comma-separated UI field; send an array of role
      // attributes (each normalized to "#role"). Empty → backend defaults to
      // "#<name>-clients".
      const dial_roles = data.dial_roles
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean)
        .map((r) => (r.startsWith('#') ? r : `#${r}`))
      return api.post('/api/v1/access/ziti/services', {
        name: data.name,
        description: data.description,
        host: data.host,
        port: data.port,
        protocol: data.protocol,
        intercept_address: data.intercept_address.trim(),
        dial_roles,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', description: '', host: '', port: 8080, protocol: 'tcp', intercept_address: '', dial_roles: '' })
      toast({ title: t('pages.zitiNetwork.services.toast.created'), description: t('pages.zitiNetwork.services.toast.createdDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.services.toast.createFailed'), variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/services/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.services.toast.deleted'), description: t('pages.zitiNetwork.services.toast.deletedDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.services.toast.deleteFailed'), variant: 'destructive' }),
  })

  const testConnection = async (svc: ZitiService) => {
    setTestingService(svc.id)
    try {
      const result = await api.post<ServiceTestResult>(`/api/v1/access/ziti/services/${svc.id}/test`, {})
      if (result.success) {
        const latencies = Object.values(result.tests).map(t => t.latency_ms).filter(Boolean)
        const avgLatency = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0
        toast({
          title: t('pages.zitiNetwork.services.toast.testOk'),
          description: t('pages.zitiNetwork.services.toast.testOkDesc', { name: svc.name, ms: avgLatency }),
        })
      } else {
        // The per-probe names and their error text come from the controller.
        const failedTests = Object.entries(result.tests).filter(([, r]) => !r.success).map(([k, r]) => `${k}: ${r.error || 'failed'}`).join(', ')
        toast({ title: t('pages.zitiNetwork.services.toast.testFailed'), description: failedTests || t('pages.zitiNetwork.services.toast.testFailedDesc'), variant: 'destructive' })
      }
    } catch {
      toast({ title: t('common.error'), description: t('pages.zitiNetwork.services.toast.testError'), variant: 'destructive' })
    } finally {
      setTestingService(null)
    }
  }

  const services = (data?.services || []).filter((svc) =>
    !search || svc.name.toLowerCase().includes(search.toLowerCase()) ||
    svc.host.toLowerCase().includes(search.toLowerCase()) ||
    svc.description?.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />
  if (isError) return <QueryError error={error} resource={t('pages.zitiNetwork.services.resourceName')} />

  return (
    <div className="space-y-4 mt-4">
      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder={t('pages.zitiNetwork.services.searchPlaceholder')} />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.services.add')}
        </Button>
      </div>

      {services.length === 0 ? (
        <EmptyState
          icon={Server}
          title={search ? t('pages.zitiNetwork.services.emptySearchTitle') : t('pages.zitiNetwork.services.emptyTitle')}
          description={search ? t('pages.zitiNetwork.services.emptySearchDesc') : t('pages.zitiNetwork.services.emptyDesc')}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.services.colService')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.services.colProtocol')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.services.colTarget')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.services.colZitiId')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.services.colCreated')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((svc) => (
                <TableRow key={svc.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div>
                      <p className="font-medium">{svc.name}</p>
                      {svc.description && (
                        <p className="text-xs text-muted-foreground">{svc.description}</p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{svc.protocol.toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{svc.host}:{svc.port}</code>
                  </TableCell>
                  <TableCell><TruncatedId value={svc.ziti_id} label={t('pages.zitiNetwork.zitiIdLabel')} /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(svc.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => testConnection(svc)} disabled={testingService === svc.id}>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          {testingService === svc.id ? t('pages.zitiNetwork.services.testing') : t('pages.zitiNetwork.services.testConnection')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setExplainName(svc.name)}>
                          <ScrollText className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.services.howThisWorks')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(svc.ziti_id)
                          toast({ title: t('pages.zitiNetwork.copied'), description: t('pages.zitiNetwork.services.toast.idCopied') })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.services.copyId')}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(svc)}>
                          <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.zitiNetwork.services.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.services.name')}</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="internal-app" required />
              <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.services.nameHint')}</p>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.services.description')}</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder={t('pages.zitiNetwork.services.descriptionPlaceholder')} />
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.services.targetHost')}</Label>
                <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.5" required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ziti-network-port">{t('pages.zitiNetwork.services.port')}</Label>
                <Input id="ziti-network-port" type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Math.max(1, Math.min(65535, parseInt(e.target.value) || 1)) })} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ziti-network-protocol">{t('pages.zitiNetwork.services.protocol')}</Label>
                <select id="ziti-network-protocol"
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.services.interceptAddress')}</Label>
              <Input value={form.intercept_address} onChange={(e) => setForm({ ...form, intercept_address: e.target.value })} placeholder={form.name ? t('pages.zitiNetwork.services.interceptDefault', { name: form.name }) : 'internal-app.ziti'} />
              <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.services.interceptHint')} <code>&lt;name&gt;.ziti</code>.</p>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.services.dialRoles')}</Label>
              <Input value={form.dial_roles} onChange={(e) => setForm({ ...form, dial_roles: e.target.value })} placeholder={form.name ? t('pages.zitiNetwork.services.dialRolesDefault', { name: form.name }) : 'ci-clients, partner-x'} />
              <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.services.dialRolesHint')} <code>#&lt;name&gt;-clients</code>. {t('pages.zitiNetwork.services.dialRolesHintAfter')}</p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? t('pages.zitiNetwork.services.creating') : t('pages.zitiNetwork.services.create')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* "How this works" — the real chain, and which link is broken. */}
      <ExplainServiceDialog name={explainName} onClose={() => setExplainName(null)} />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.services.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.services.deleteDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <PublishedAppServicesSection />
    </div>
  )
}

// ─── F15: Published App Services Section ─────────────────────────────────────

function PublishedAppServicesSection() {
  const { t } = useTranslation()
  const [expandedApp, setExpandedApp] = useState<string | null>(null)

  const { data: appsResp } = useQuery({
    queryKey: ['published-apps'],
    queryFn: () => api.get<{ apps: Array<{ id: string; name: string; target_url: string; total_paths_published: number; status: string }> }>('/api/v1/access/apps'),
  })

  const { data: appServicesResp } = useQuery({
    queryKey: ['app-ziti-services', expandedApp],
    queryFn: () => api.get<{ services: AppZitiService[]; app_name: string }>(`/api/v1/access/apps/${expandedApp}/ziti-services`),
    enabled: !!expandedApp,
  })

  const publishedApps = appsResp?.apps?.filter((a) => a.total_paths_published > 0) ?? []

  if (publishedApps.length === 0) return null

  return (
    <div className="mt-6">
      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
        <Upload className="h-4 w-4" /> {t('pages.zitiNetwork.publishedApps.title')}
      </h3>
      <p className="text-xs text-muted-foreground mb-3">{t('pages.zitiNetwork.publishedApps.desc')}</p>
      <div className="space-y-2">
        {publishedApps.map((app) => (
          <div key={app.id} className="border rounded-lg">
            <button
              className="w-full flex items-center justify-between px-4 py-2 text-sm hover:bg-muted/50"
              onClick={() => setExpandedApp(expandedApp === app.id ? null : app.id)}
            >
              <div className="flex items-center gap-2">
                {expandedApp === app.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                <span className="font-medium">{app.name}</span>
                <span className="text-xs text-muted-foreground">{app.target_url}</span>
              </div>
              <Badge variant="outline">{t('pages.zitiNetwork.publishedApps.pathCount', { count: app.total_paths_published })}</Badge>
            </button>
            {expandedApp === app.id && (
              <div className="px-4 pb-3">
                {!appServicesResp?.services || appServicesResp.services.length === 0 ? (
                  <p className="text-xs text-muted-foreground py-2">{t('pages.zitiNetwork.publishedApps.empty')}</p>
                ) : (
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>{t('pages.zitiNetwork.publishedApps.colService')}</TableHead>
                      <TableHead>{t('pages.zitiNetwork.publishedApps.colPath')}</TableHead>
                      <TableHead>{t('pages.zitiNetwork.publishedApps.colClassification')}</TableHead>
                      <TableHead>{t('pages.zitiNetwork.publishedApps.colStatus')}</TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {appServicesResp.services.map((svc) => (
                        <TableRow key={svc.id}>
                          <TableCell className="font-medium text-xs">{svc.name}</TableCell>
                          <TableCell className="text-xs font-mono">{svc.linked_path}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${
                              svc.classification === 'critical' ? 'bg-red-50 text-red-700 border-red-200' :
                              svc.classification === 'sensitive' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                              svc.classification === 'public' ? 'bg-green-50 text-green-700 border-green-200' :
                              'bg-blue-50 text-blue-700 border-blue-200'
                            }`}>{svc.classification}</Badge>
                          </TableCell>
                          <TableCell>{svc.enabled ? <Badge className="bg-green-100 text-green-700 text-[10px]">{t('pages.zitiNetwork.publishedApps.active')}</Badge> : <Badge variant="secondary" className="text-[10px]">{t('pages.zitiNetwork.publishedApps.disabled')}</Badge>}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Identities Tab ──────────────────────────────────────────────────────────

interface UnsyncedUser {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
}

function IdentitiesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiIdentity | null>(null)
  const [jwtModal, setJwtModal] = useState<{ jwt: string; name: string } | null>(null)
  const [editAttrsTarget, setEditAttrsTarget] = useState<ZitiIdentity | null>(null)
  const [editAttrsValue, setEditAttrsValue] = useState('')
  const [form, setForm] = useState({ name: '', identity_type: 'Device', user_id: '', attributes: '' })
  const [showUnsynced, setShowUnsynced] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['ziti-identities'],
    queryFn: () => api.get<{ identities: ZitiIdentity[] }>('/api/v1/access/ziti/identities'),
  })

  const createMutation = useMutation({
    mutationFn: async (data: typeof form) => {
      const payload: Record<string, unknown> = {
        name: data.name,
        identity_type: data.identity_type,
        attributes: data.attributes ? data.attributes.split(',').map(s => s.trim()).filter(Boolean) : [],
      }
      if (data.user_id) payload.user_id = data.user_id
      return api.post<{ enrollment_jwt: string; name: string }>('/api/v1/access/ziti/identities', payload)
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', identity_type: 'Device', user_id: '', attributes: '' })
      const data = result as { enrollment_jwt?: string; name?: string }
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: data.name || form.name })
      }
      toast({ title: t('pages.zitiNetwork.identities.toast.created'), description: t('pages.zitiNetwork.identities.toast.createdDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.createFailed'), variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/identities/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.identities.toast.deleted'), description: t('pages.zitiNetwork.identities.toast.deletedDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.deleteFailed'), variant: 'destructive' }),
  })

  const updateAttrsMutation = useMutation({
    mutationFn: ({ id, attributes }: { id: string; attributes: string[] }) =>
      api.patch(`/api/v1/access/ziti/identities/${id}/attributes`, { attributes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      setEditAttrsTarget(null)
      toast({ title: t('pages.zitiNetwork.identities.toast.attrsUpdated'), description: t('pages.zitiNetwork.identities.toast.attrsUpdatedDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.attrsFailed'), variant: 'destructive' }),
  })

  const { data: syncStatus } = useQuery({
    queryKey: ['ziti-sync-status'],
    queryFn: () => api.get<ZitiSyncStatus>('/api/v1/access/ziti/sync/status'),
    refetchInterval: 5000,
  })

  const syncAllMutation = useMutation({
    mutationFn: () => api.post<{ users_synced: number; users_failed: number; groups_synced: number }>('/api/v1/access/ziti/sync/users'),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      toast({
        title: t('pages.zitiNetwork.identities.toast.syncDone'),
        description:
          t('pages.zitiNetwork.identities.toast.syncDoneDesc', { users: result.users_synced, groups: result.groups_synced }) +
          (result.users_failed > 0 ? t('pages.zitiNetwork.identities.toast.syncFailedSuffix', { failed: result.users_failed }) : ''),
      })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.syncFailed'), variant: 'destructive' }),
  })

  const syncGroupsMutation = useMutation({
    mutationFn: () => api.post<{ groups_synced: number }>('/api/v1/access/ziti/sync/groups'),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      toast({ title: t('pages.zitiNetwork.identities.toast.groupSyncDone'), description: t('pages.zitiNetwork.identities.toast.groupSyncDoneDesc', { n: result.groups_synced }) })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.groupSyncFailed'), variant: 'destructive' }),
  })

  const syncSingleMutation = useMutation({
    mutationFn: (userId: string) => api.post(`/api/v1/access/ziti/sync/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-unsynced-users'] })
      toast({ title: t('pages.zitiNetwork.identities.toast.userSynced'), description: t('pages.zitiNetwork.identities.toast.userSyncedDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.userSyncFailed'), variant: 'destructive' }),
  })

  const { data: unsyncedUsers } = useQuery({
    queryKey: ['ziti-unsynced-users'],
    queryFn: () => api.get<UnsyncedUser[]>('/api/v1/access/ziti/sync/unsynced'),
    enabled: showUnsynced,
  })

  const openEditAttrs = (ident: ZitiIdentity) => {
    setEditAttrsValue((ident.attributes || []).join(', '))
    setEditAttrsTarget(ident)
  }

  const fetchJWT = async (identity: ZitiIdentity) => {
    try {
      const data = await api.get<{ enrollment_jwt: string }>(`/api/v1/access/ziti/identities/${identity.id}/enrollment-jwt`)
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: identity.display_name || identity.name })
      } else {
        toast({ title: t('pages.zitiNetwork.identities.toast.noJwt'), description: t('pages.zitiNetwork.identities.toast.noJwtDesc'), variant: 'destructive' })
      }
    } catch {
      toast({ title: t('common.error'), description: t('pages.zitiNetwork.identities.toast.jwtFailed'), variant: 'destructive' })
    }
  }

  const identities = (data?.identities || []).filter((ident) =>
    !search ||
    (ident.display_name || '').toLowerCase().includes(search.toLowerCase()) ||
    ident.name.toLowerCase().includes(search.toLowerCase()) ||
    ident.identity_type.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4 mt-4">
      {/* Sync Status Card */}
      <Card className="border-blue-200 bg-blue-50/50">
        <CardContent className="py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <RefreshCw className={`h-4 w-4 ${syncAllMutation.isPending || syncGroupsMutation.isPending ? 'animate-spin' : ''} text-primary`} />
                <span className="text-sm font-medium">{t('pages.zitiNetwork.identities.syncTitle')}</span>
              </div>
              {syncStatus && (
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{t('pages.zitiNetwork.identities.syncCounts', { identities: syncStatus.total_identities, users: syncStatus.total_users })}</span>
                  {syncStatus.unsynced_users > 0 && (
                    <button
                      onClick={() => setShowUnsynced(!showUnsynced)}
                      className="inline-flex items-center gap-1"
                    >
                      <Badge variant="secondary" className="text-orange-700 bg-orange-100 cursor-pointer hover:bg-orange-200">
                        {t('pages.zitiNetwork.identities.unsynced', { n: syncStatus.unsynced_users })}
                        {showUnsynced ? <ChevronDown className="h-3 w-3 ml-0.5" /> : <ChevronRight className="h-3 w-3 ml-0.5" />}
                      </Badge>
                    </button>
                  )}
                  {syncStatus.last_auto_sync_at && (
                    <span>{t('pages.zitiNetwork.identities.autoSync', { time: new Date(syncStatus.last_auto_sync_at).toLocaleTimeString() })}</span>
                  )}
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => syncGroupsMutation.mutate()} disabled={syncGroupsMutation.isPending || syncAllMutation.isPending}>
                {syncGroupsMutation.isPending ? t('pages.zitiNetwork.identities.syncing') : t('pages.zitiNetwork.identities.syncGroups')}
              </Button>
              <Button size="sm" onClick={() => syncAllMutation.mutate()} disabled={syncAllMutation.isPending || syncGroupsMutation.isPending}>
                <RefreshCw className={`mr-2 h-3 w-3 ${syncAllMutation.isPending ? 'animate-spin' : ''}`} />
                {syncAllMutation.isPending ? t('pages.zitiNetwork.identities.syncing') : t('pages.zitiNetwork.identities.syncAll')}
              </Button>
            </div>
          </div>
          {/* Expandable unsynced users list */}
          {showUnsynced && unsyncedUsers && unsyncedUsers.length > 0 && (
            <div className="mt-3 border-t border-blue-200 pt-3">
              <p className="text-xs font-medium text-muted-foreground mb-2">{t('pages.zitiNetwork.identities.unsyncedTitle')}</p>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {unsyncedUsers.map((user) => (
                  <div key={user.id} className="flex items-center justify-between bg-background rounded px-3 py-1.5 text-sm">
                    <div className="flex items-center gap-2">
                      <Users2 className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="font-medium">{user.first_name || user.username} {user.last_name || ''}</span>
                      <span className="text-xs text-muted-foreground">@{user.username}</span>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={() => syncSingleMutation.mutate(user.id)}
                      disabled={syncSingleMutation.isPending}
                    >
                      {t('pages.zitiNetwork.identities.sync')}
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder={t('pages.zitiNetwork.identities.searchPlaceholder')} />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.identities.add')}
        </Button>
      </div>

      {identities.length === 0 ? (
        <EmptyState
          icon={Users2}
          title={search ? t('pages.zitiNetwork.identities.emptySearchTitle') : t('pages.zitiNetwork.identities.emptyTitle')}
          description={search ? t('pages.zitiNetwork.identities.emptySearchDesc') : t('pages.zitiNetwork.identities.emptyDesc')}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.identities.colIdentity')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.identities.colType')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.identities.colStatus')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.identities.colRoles')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.identities.colZitiId')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.identities.colCreated')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {identities.map((ident) => (
                <TableRow key={ident.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${ident.enrolled ? 'bg-green-100' : 'bg-yellow-100'}`}>
                        <Shield className={`h-4 w-4 ${ident.enrolled ? 'text-green-700' : 'text-yellow-700'}`} />
                      </div>
                      <div>
                        <p className="font-medium">{ident.display_name || ident.name}</p>
                        {ident.user_id && <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.identities.userRef', { id: ident.user_id.slice(0, 8) + '...' })}</p>}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell><Badge variant="outline">{ident.identity_type}</Badge></TableCell>
                  <TableCell>
                    <Badge variant={ident.enrolled ? 'default' : 'secondary'}>
                      {ident.enrolled ? t('pages.zitiNetwork.identities.enrolled') : t('pages.zitiNetwork.identities.pending')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(ident.attributes || []).map((attr) => (
                        <Badge key={attr} variant="outline" className="text-xs">{attr}</Badge>
                      ))}
                      {(!ident.attributes || ident.attributes.length === 0) && (
                        <span className="text-xs text-muted-foreground">{t('pages.zitiNetwork.identities.noRoles')}</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell><TruncatedId value={ident.ziti_id} label={t('pages.zitiNetwork.zitiIdLabel')} /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(ident.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(ident.ziti_id)
                          toast({ title: t('pages.zitiNetwork.copied'), description: t('pages.zitiNetwork.identities.toast.idCopied') })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.identities.copyId')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => openEditAttrs(ident)}>
                          <Pencil className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.identities.editAttrs')}
                        </DropdownMenuItem>
                        {!ident.enrolled && (
                          <DropdownMenuItem onClick={() => fetchJWT(ident)}>
                            <FileKey className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.identities.getJwt')}
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(ident)}>
                          <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.zitiNetwork.identities.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.identities.name')}</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="john-laptop" required />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ziti-network-type">{t('pages.zitiNetwork.identities.type')}</Label>
                <select id="ziti-network-type"
                  value={form.identity_type}
                  onChange={(e) => setForm({ ...form, identity_type: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="Device">{t('pages.zitiNetwork.identities.types.Device')}</option>
                  <option value="User">{t('pages.zitiNetwork.identities.types.User')}</option>
                  <option value="Service">{t('pages.zitiNetwork.identities.types.Service')}</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.identities.userId')}</Label>
                <Input value={form.user_id} onChange={(e) => setForm({ ...form, user_id: e.target.value })} placeholder={t('pages.zitiNetwork.identities.userIdPlaceholder')} />
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.identities.attributes')}</Label>
              <Input value={form.attributes} onChange={(e) => setForm({ ...form, attributes: e.target.value })} placeholder="developers, vpn-users" />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? t('pages.zitiNetwork.identities.creating') : t('pages.zitiNetwork.identities.create')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* JWT Modal */}
      <Dialog open={!!jwtModal} onOpenChange={() => setJwtModal(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.zitiNetwork.identities.jwtTitle', { name: jwtModal?.name ?? '' })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              {t('pages.zitiNetwork.identities.jwtIntro')} <code className="text-xs">ziti-edge-tunnel enroll --jwt &lt;file&gt;</code>{t('pages.zitiNetwork.identities.jwtIntroAfter')}
            </p>
            <div className="relative">
              <textarea
                readOnly
                value={jwtModal?.jwt || ''}
                className="w-full h-32 rounded-md border bg-muted p-3 text-xs font-mono"
              />
              <div className="absolute top-2 right-2 flex gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  title={t('pages.zitiNetwork.identities.jwtDownloadTitle')}
                  onClick={() => {
                    if (!jwtModal) return
                    const blob = new Blob([jwtModal.jwt], { type: 'application/jwt' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `${jwtModal.name.replace(/[^a-zA-Z0-9_.-]/g, '_')}.jwt`
                    a.click()
                    URL.revokeObjectURL(url)
                    toast({ title: t('pages.zitiNetwork.identities.toast.downloaded'), description: t('pages.zitiNetwork.identities.toast.downloadedDesc') })
                  }}
                >
                  <Download className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  title={t('pages.zitiNetwork.identities.jwtCopyTitle')}
                  onClick={() => {
                    if (jwtModal) {
                      navigator.clipboard.writeText(jwtModal.jwt)
                      toast({ title: t('pages.zitiNetwork.copied'), description: t('pages.zitiNetwork.identities.toast.jwtCopied') })
                    }
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Attributes Dialog */}
      <Dialog open={!!editAttrsTarget} onOpenChange={(v) => { if (!v) setEditAttrsTarget(null) }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('pages.zitiNetwork.identities.editAttrsTitle', { name: editAttrsTarget?.name ?? '' })}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (editAttrsTarget) {
              updateAttrsMutation.mutate({
                id: editAttrsTarget.id,
                attributes: editAttrsValue.split(',').map(s => s.trim()).filter(Boolean),
              })
            }
          }} className="space-y-4">
            <div className="space-y-2">
              <Label>{t('pages.zitiNetwork.identities.attributes')}</Label>
              <Input
                value={editAttrsValue}
                onChange={(e) => setEditAttrsValue(e.target.value)}
                placeholder="engineering, vpn-users, finance"
              />
              <p className="text-xs text-muted-foreground">
                {t('pages.zitiNetwork.identities.attrsHint')}
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setEditAttrsTarget(null)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={updateAttrsMutation.isPending}>
                {updateAttrsMutation.isPending ? t('pages.zitiNetwork.identities.saving') : t('pages.zitiNetwork.identities.saveAttrs')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.identities.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.identities.deleteDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ─── Security Tab ────────────────────────────────────────────────────────────

function CollapsibleSection({ title, count, icon: Icon, defaultOpen, children }: {
  title: string; count: number; icon: React.ElementType; defaultOpen?: boolean; children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen ?? true)
  return (
    <div className="border rounded-lg">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span className="font-semibold">{title}</span>
          <Badge variant="secondary" className="ml-1">{count}</Badge>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 pb-4 pt-1">{children}</div>}
    </div>
  )
}

function SecurityTab() {
  return (
    <div className="space-y-4 mt-4">
      <ActiveSessionsSection />
      <ServicePoliciesSection />
      <EdgeRouterPoliciesSection />
      <ConfigurationsSection />
      <AuthPoliciesSection />
      <TerminatorsSection />
      <PostureSection />
      <CertificatesSection />
      <PolicySyncSection />
    </div>
  )
}

// ─── F14: Active Sessions Section ────────────────────────────────────────────

function ActiveSessionsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [deleteTarget, setDeleteTarget] = useState<ZitiSessionEntry | null>(null)

  const { data: sessions } = useQuery({
    queryKey: ['ziti-sessions'],
    queryFn: () => api.get<ZitiSessionEntry[]>('/api/v1/access/ziti/sessions'),
    refetchInterval: 10000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/sessions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-sessions'] })
      toast({ title: t('pages.zitiNetwork.sessions.toast.terminated') })
      setDeleteTarget(null)
    },
  })

  const batchTerminateMutation = useMutation({
    mutationFn: (identityId: string) => api.post('/api/v1/access/ziti/sessions/batch-terminate', { identity_id: identityId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-sessions'] })
      toast({ title: t('pages.zitiNetwork.sessions.toast.batchTerminated') })
    },
  })

  // Get unique identities for batch terminate
  const uniqueIdentities = sessions ? [...new Map(sessions.filter(s => s.identity?.id).map(s => [s.identity!.id, s.identity!])).values()] : []

  return (
    <>
      <CollapsibleSection title={t('pages.zitiNetwork.sessions.title')} count={sessions?.length ?? 0} icon={Zap} defaultOpen>
        <p className="text-xs text-muted-foreground mb-3">{t('pages.zitiNetwork.sessions.desc')}</p>
        {uniqueIdentities.length > 1 && (
          <div className="flex flex-wrap gap-2 mb-3">
            {uniqueIdentities.map(ident => (
              <Button key={ident.id} variant="outline" size="sm" className="text-red-600 border-red-200 hover:bg-red-50" onClick={() => batchTerminateMutation.mutate(ident.id)} disabled={batchTerminateMutation.isPending}>
                {t('pages.zitiNetwork.sessions.terminateAll', { name: ident.name || ident.id })}
              </Button>
            ))}
          </div>
        )}
        {!sessions || sessions.length === 0 ? (
          <EmptyState icon={Clock} title={t('pages.zitiNetwork.sessions.emptyTitle')} description={t('pages.zitiNetwork.sessions.emptyDesc')} />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>{t('pages.zitiNetwork.sessions.colIdentity')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.sessions.colService')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.sessions.colType')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.sessions.colSince')}</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {sessions.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-medium">{s.identity?.name || s.identity?.id || '—'}</TableCell>
                  <TableCell>{s.service?.name || s.service?.id || '—'}</TableCell>
                  <TableCell>
                    <Badge variant={s.type === 'Dial' ? 'default' : 'secondary'}>{s.type}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.createdAt ? new Date(s.createdAt).toLocaleString() : '—'}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(s)} title={t('pages.zitiNetwork.sessions.forceDisconnect')}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.sessions.confirmTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.sessions.confirmDesc', {
                identity: deleteTarget?.identity?.name || t('pages.zitiNetwork.sessions.thisIdentity'),
                service: deleteTarget?.service?.name || t('pages.zitiNetwork.sessions.theService'),
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>{t('pages.zitiNetwork.sessions.disconnect')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F11: Configurations Section ─────────────────────────────────────────────

function ConfigurationsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiConfig | null>(null)
  const [form, setForm] = useState({ name: '', configTypeId: '', data: '{}' })

  const { data: configs } = useQuery({
    queryKey: ['ziti-configs'],
    queryFn: () => api.get<ZitiConfig[]>('/api/v1/access/ziti/configs'),
  })
  const { data: configTypes } = useQuery({
    queryKey: ['ziti-config-types'],
    queryFn: () => api.get<ZitiConfigType[]>('/api/v1/access/ziti/config-types'),
  })

  const createMutation = useMutation({
    mutationFn: (data: { name: string; configTypeId: string; data: string }) =>
      api.post('/api/v1/access/ziti/configs', { name: data.name, configTypeId: data.configTypeId, data: JSON.parse(data.data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-configs'] })
      toast({ title: t('pages.zitiNetwork.configs.toast.created') })
      setCreateModal(false)
      setForm({ name: '', configTypeId: '', data: '{}' })
    },
    onError: (e: Error) => toast({ title: t('common.error'), description: e.message, variant: 'destructive' }),
  })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/configs/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-configs'] })
      toast({ title: t('pages.zitiNetwork.configs.toast.deleted') })
      setDeleteTarget(null)
    },
  })

  const isSystem = (name: string) => name.startsWith('openidx-')

  return (
    <>
      <CollapsibleSection title={t('pages.zitiNetwork.configs.title')} count={configs?.length ?? 0} icon={Settings} defaultOpen={false}>
        <div className="flex justify-between items-center mb-3">
          <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.configs.desc')}</p>
          <Button size="sm" onClick={() => setCreateModal(true)}><Plus className="h-4 w-4 mr-1" /> {t('pages.zitiNetwork.configs.add')}</Button>
        </div>
        {!configs || configs.length === 0 ? (
          <EmptyState icon={Settings} title={t('pages.zitiNetwork.configs.emptyTitle')} description={t('pages.zitiNetwork.configs.emptyDesc')} />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>{t('pages.zitiNetwork.configs.colName')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.configs.colType')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.configs.colData')}</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {configs.map((cfg) => (
                <TableRow key={cfg.id}>
                  <TableCell className="font-medium">{cfg.name}</TableCell>
                  <TableCell><Badge variant="outline">{typeof cfg.configType === 'object' && cfg.configType?.name ? cfg.configType.name : cfg.configTypeId}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{JSON.stringify(cfg.data).slice(0, 80)}</TableCell>
                  <TableCell>
                    {!isSystem(cfg.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(cfg)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.zitiNetwork.configs.dialogTitle')}</DialogTitle></DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div><Label htmlFor="ziti-network-name">{t('pages.zitiNetwork.configs.name')}</Label><Input id="ziti-network-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
            <div><Label htmlFor="ziti-network-type-2">{t('pages.zitiNetwork.configs.type')}</Label>
              <select id="ziti-network-type-2" className="w-full border rounded-md p-2 text-sm" value={form.configTypeId} onChange={(e) => setForm({ ...form, configTypeId: e.target.value })} required>
                <option value="">{t('pages.zitiNetwork.configs.typePlaceholder')}</option>
                {configTypes?.map((ct) => <option key={ct.id} value={ct.id}>{ct.name}</option>)}
              </select>
            </div>
            <div><Label htmlFor="ziti-network-data">{t('pages.zitiNetwork.configs.data')}</Label><textarea id="ziti-network-data" className="w-full border rounded-md p-2 text-sm font-mono h-32" value={form.data} onChange={(e) => setForm({ ...form, data: e.target.value })} /></div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>{t('pages.zitiNetwork.configs.create')}</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.configs.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.zitiNetwork.configs.deleteDesc', { name: deleteTarget?.name ?? '' })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F12: Auth Policies & JWT Signers Section ────────────────────────────────

function AuthPoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [deleteAPTarget, setDeleteAPTarget] = useState<ZitiAuthPolicy | null>(null)
  const [deleteJSTarget, setDeleteJSTarget] = useState<ZitiJWTSigner | null>(null)

  const { data: authPolicies } = useQuery({
    queryKey: ['ziti-auth-policies'],
    queryFn: () => api.get<ZitiAuthPolicy[]>('/api/v1/access/ziti/auth-policies'),
  })
  const { data: jwtSigners } = useQuery({
    queryKey: ['ziti-jwt-signers'],
    queryFn: () => api.get<ZitiJWTSigner[]>('/api/v1/access/ziti/jwt-signers'),
  })

  const deleteAPMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/auth-policies/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-auth-policies'] }); toast({ title: t('pages.zitiNetwork.authPolicies.toast.policyDeleted') }); setDeleteAPTarget(null) },
  })
  const deleteJSMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/jwt-signers/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-jwt-signers'] }); toast({ title: t('pages.zitiNetwork.authPolicies.toast.signerDeleted') }); setDeleteJSTarget(null) },
  })

  const isSystem = (name: string) => name.startsWith('openidx-') || name === 'default'
  const totalCount = (authPolicies?.length ?? 0) + (jwtSigners?.length ?? 0)

  const authMethods = (p: ZitiAuthPolicy) => {
    const methods: string[] = []
    if (p.primary?.cert?.allowed) methods.push('Cert')
    if (p.primary?.updb?.allowed) methods.push('UPDB')
    if (p.primary?.extJwt?.allowed) methods.push('ExtJWT')
    return methods
  }

  return (
    <>
      <CollapsibleSection title={t('pages.zitiNetwork.authPolicies.title')} count={totalCount} icon={Key} defaultOpen={false}>
        <p className="text-xs text-muted-foreground mb-3">{t('pages.zitiNetwork.authPolicies.desc')}</p>

        <h4 className="text-sm font-semibold mb-2">{t('pages.zitiNetwork.authPolicies.policies')}</h4>
        {!authPolicies || authPolicies.length === 0 ? (
          <p className="text-xs text-muted-foreground mb-4">{t('pages.zitiNetwork.authPolicies.noPolicies')}</p>
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colName')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colPrimary')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colTotp')}</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {authPolicies.map((ap) => (
                <TableRow key={ap.id}>
                  <TableCell className="font-medium">{ap.name}{isSystem(ap.name) && <Badge variant="outline" className="ml-2 text-[10px]">{t('pages.zitiNetwork.authPolicies.system')}</Badge>}</TableCell>
                  <TableCell className="flex gap-1 flex-wrap">
                    {authMethods(ap).map((m) => (
                      <Badge key={m} variant="secondary" className="text-[10px]">{m}</Badge>
                    ))}
                    {authMethods(ap).length === 0 && <span className="text-xs text-muted-foreground">{t('pages.zitiNetwork.authPolicies.none')}</span>}
                  </TableCell>
                  <TableCell>{ap.secondary?.requireTotp ? <Badge className="text-[10px]">{t('pages.zitiNetwork.authPolicies.totpRequired')}</Badge> : <span className="text-xs text-muted-foreground">{t('pages.zitiNetwork.authPolicies.no')}</span>}</TableCell>
                  <TableCell>
                    {!isSystem(ap.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteAPTarget(ap)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <h4 className="text-sm font-semibold mt-4 mb-2">{t('pages.zitiNetwork.authPolicies.signers')}</h4>
        {!jwtSigners || jwtSigners.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.authPolicies.noSigners')}</p>
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colName')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colIssuer')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colAudience')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.authPolicies.colEnabled')}</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {jwtSigners.map((js) => (
                <TableRow key={js.id}>
                  <TableCell className="font-medium">{js.name}{isSystem(js.name) && <Badge variant="outline" className="ml-2 text-[10px]">{t('pages.zitiNetwork.authPolicies.system')}</Badge>}</TableCell>
                  <TableCell className="text-xs max-w-[150px] truncate">{js.issuer}</TableCell>
                  <TableCell className="text-xs">{js.audience}</TableCell>
                  <TableCell>{js.enabled ? <Badge className="bg-green-100 text-green-700 text-[10px]">{t('pages.zitiNetwork.authPolicies.yes')}</Badge> : <Badge variant="secondary" className="text-[10px]">{t('pages.zitiNetwork.authPolicies.no')}</Badge>}</TableCell>
                  <TableCell>
                    {!isSystem(js.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteJSTarget(js)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteAPTarget} onOpenChange={() => setDeleteAPTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>{t('pages.zitiNetwork.authPolicies.deletePolicyTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.zitiNetwork.authPolicies.deletePolicyDesc', { name: deleteAPTarget?.name ?? '' })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteAPTarget && deleteAPMutation.mutate(deleteAPTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog open={!!deleteJSTarget} onOpenChange={() => setDeleteJSTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>{t('pages.zitiNetwork.authPolicies.deleteSignerTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.zitiNetwork.authPolicies.deleteSignerDesc', { name: deleteJSTarget?.name ?? '' })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteJSTarget && deleteJSMutation.mutate(deleteJSTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F13: Terminators Section ────────────────────────────────────────────────

function TerminatorsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [deleteTarget, setDeleteTarget] = useState<ZitiTerminator | null>(null)

  const { data: terminators } = useQuery({
    queryKey: ['ziti-terminators'],
    queryFn: () => api.get<ZitiTerminator[]>('/api/v1/access/ziti/terminators'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/terminators/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-terminators'] })
      toast({ title: t('pages.zitiNetwork.terminators.toast.deleted') })
      setDeleteTarget(null)
    },
  })

  return (
    <>
      <CollapsibleSection title={t('pages.zitiNetwork.terminators.title')} count={terminators?.length ?? 0} icon={Link2} defaultOpen={false}>
        <p className="text-xs text-muted-foreground mb-3">{t('pages.zitiNetwork.terminators.desc')}</p>
        {!terminators || terminators.length === 0 ? (
          <EmptyState icon={Link2} title={t('pages.zitiNetwork.terminators.emptyTitle')} description={t('pages.zitiNetwork.terminators.emptyDesc')} />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>{t('pages.zitiNetwork.terminators.colService')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.terminators.colRouter')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.terminators.colBinding')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.terminators.colAddress')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.terminators.colCost')}</TableHead>
              <TableHead>{t('pages.zitiNetwork.terminators.colPrecedence')}</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {terminators.map((term) => (
                <TableRow key={term.id}>
                  <TableCell className="font-medium">{term.service?.name || term.serviceId}</TableCell>
                  <TableCell>{term.router?.name || term.routerId}</TableCell>
                  <TableCell><Badge variant="outline" className="text-[10px]">{term.binding}</Badge></TableCell>
                  <TableCell className="text-xs font-mono">{term.address}</TableCell>
                  <TableCell>{term.cost}</TableCell>
                  <TableCell><Badge variant="secondary" className="text-[10px]">{term.precedence}</Badge></TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(term)} title={t('pages.zitiNetwork.terminators.deleteTooltip')}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.terminators.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.terminators.deleteDesc', { name: deleteTarget?.service?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── Existing Security Sections ──────────────────────────────────────────────

function ServicePoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<ServicePolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ServicePolicy | null>(null)
  const [form, setForm] = useState({ name: '', type: 'Dial', service_roles: '', identity_roles: '' })

  const { data: policiesData, isLoading } = useQuery({
    queryKey: ['ziti-service-policies'],
    queryFn: () => api.get<ServicePolicy[]>('/api/v1/access/ziti/fabric/service-policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/service-policies', {
      name: data.name,
      type: data.type,
      service_roles: data.service_roles.split(',').map(s => s.trim()).filter(Boolean),
      identity_roles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setCreateModal(false)
      resetForm()
      toast({ title: t('pages.zitiNetwork.servicePolicies.toast.created') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.servicePolicies.toast.createFailed'), variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => api.put(`/api/v1/access/ziti/service-policies/${id}`, {
      name: data.name,
      type: data.type,
      service_roles: data.service_roles.split(',').map(s => s.trim()).filter(Boolean),
      identity_roles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setEditTarget(null)
      resetForm()
      toast({ title: t('pages.zitiNetwork.servicePolicies.toast.updated') })
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err?.response?.data?.error || t('pages.zitiNetwork.servicePolicies.toast.updateFailed')
      toast({ title: t('common.error'), description: msg, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/service-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.servicePolicies.toast.deleted') })
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err?.response?.data?.error || t('pages.zitiNetwork.servicePolicies.toast.deleteFailed')
      toast({ title: t('common.error'), description: msg, variant: 'destructive' })
    },
  })

  const resetForm = () => setForm({ name: '', type: 'Dial', service_roles: '', identity_roles: '' })

  const openEditModal = (policy: ServicePolicy) => {
    setForm({
      name: policy.name,
      type: policy.type,
      service_roles: (policy.serviceRoles || []).join(', '),
      identity_roles: (policy.identityRoles || []).join(', '),
    })
    setEditTarget(policy)
  }

  const isSystemPolicy = (name: string) => name.startsWith('openidx-')

  const policies = (Array.isArray(policiesData) ? policiesData : []).filter((p) =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.type.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <CollapsibleSection title={t('pages.zitiNetwork.servicePolicies.title')} count={policies.length} icon={ScrollText} defaultOpen>
      <p className="text-sm text-muted-foreground mb-3">
        {t('pages.zitiNetwork.servicePolicies.desc')} <code className="text-xs bg-muted px-1 py-0.5 rounded">#</code> {t('pages.zitiNetwork.servicePolicies.descAfter')}
      </p>

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder={t('pages.zitiNetwork.servicePolicies.searchPlaceholder')} />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.servicePolicies.add')}
        </Button>
      </div>

      {isLoading ? <Spinner /> : policies.length === 0 ? (
        <EmptyState icon={ScrollText} title={t('pages.zitiNetwork.servicePolicies.emptyTitle')} description={t('pages.zitiNetwork.servicePolicies.emptyDesc')} />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.servicePolicies.colName')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.servicePolicies.colType')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.servicePolicies.colServiceRoles')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.servicePolicies.colIdentityRoles')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow key={policy.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {isSystemPolicy(policy.name) && <span title={t('pages.zitiNetwork.servicePolicies.systemPolicy')}><Lock className="h-3.5 w-3.5 text-muted-foreground" /></span>}
                      <span className="font-medium">{policy.name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {/* Dial / Bind are the controller's own policy types. */}
                    <Badge variant={policy.type === 'Dial' ? 'default' : 'secondary'}>
                      {policy.type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.serviceRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const isId = role.startsWith('@')
                        const label = isAttr ? role.slice(1) : isId ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-purple-50 text-purple-700 border-purple-200' : isId ? 'bg-blue-50 text-blue-700 border-blue-200' : ''}`}
                            title={isAttr ? t('pages.zitiNetwork.servicePolicies.serviceAttrTitle', { label }) : isId ? t('pages.zitiNetwork.servicePolicies.serviceIdTitle', { label }) : role}
                          >
                            {isAttr && <span className="text-purple-400 mr-0.5">#</span>}
                            {isId && <span className="text-blue-400 mr-0.5">@</span>}
                            {label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.identityRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const isId = role.startsWith('@')
                        const label = isAttr ? role.slice(1) : isId ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-orange-50 text-orange-700 border-orange-200' : isId ? 'bg-blue-50 text-blue-700 border-blue-200' : ''}`}
                            title={isAttr ? t('pages.zitiNetwork.servicePolicies.identityAttrTitle', { label }) : isId ? t('pages.zitiNetwork.servicePolicies.identityIdTitle', { label }) : role}
                          >
                            {isAttr && <span className="text-orange-400 mr-0.5">#</span>}
                            {isId && <span className="text-blue-400 mr-0.5">@</span>}
                            {label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    {!isSystemPolicy(policy.name) && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEditModal(policy)}>
                            <Pencil className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.servicePolicies.edit')}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(policy)}>
                            <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: t('pages.zitiNetwork.servicePolicies.createTitle'), onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: t('pages.zitiNetwork.servicePolicies.createSubmit') },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: t('pages.zitiNetwork.servicePolicies.editTitle'), onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: t('pages.zitiNetwork.servicePolicies.editSubmit') },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.servicePolicies.policyName')}</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="allow-engineering-gitlab" required />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`ziti-service-policy-${i}-type`}>{t('pages.zitiNetwork.servicePolicies.type')}</Label>
                <select id={`ziti-service-policy-${i}-type`} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                  <option value="Dial">{t('pages.zitiNetwork.servicePolicies.typeDial')}</option>
                  <option value="Bind">{t('pages.zitiNetwork.servicePolicies.typeBind')}</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.servicePolicies.serviceRoles')}</Label>
                <Input value={form.service_roles} onChange={(e) => setForm({ ...form, service_roles: e.target.value })} placeholder="#gitlab, #internal-apps" required />
                <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.servicePolicies.commaSeparated')} <span className="text-purple-600 font-medium">#attribute</span> {t('pages.zitiNetwork.servicePolicies.serviceAttrHint')} <span className="text-primary font-medium">@id</span> {t('pages.zitiNetwork.servicePolicies.serviceIdHint')}</p>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.servicePolicies.identityRoles')}</Label>
                <Input value={form.identity_roles} onChange={(e) => setForm({ ...form, identity_roles: e.target.value })} placeholder="#engineering, #vpn-users" required />
                <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.servicePolicies.commaSeparated')} <span className="text-orange-600 font-medium">#attribute</span> {t('pages.zitiNetwork.servicePolicies.identityAttrHint')} <span className="text-primary font-medium">@id</span> {t('pages.zitiNetwork.servicePolicies.identityIdHint')}</p>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>{t('common.cancel')}</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? t('pages.zitiNetwork.servicePolicies.saving') : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.servicePolicies.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.servicePolicies.deleteDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function EdgeRouterPoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<EdgeRouterPolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<EdgeRouterPolicy | null>(null)
  const [form, setForm] = useState({ name: '', edge_router_roles: '', identity_roles: '' })

  const { data: policiesData, isLoading } = useQuery({
    queryKey: ['ziti-edge-router-policies'],
    queryFn: () => api.get<EdgeRouterPolicy[]>('/api/v1/access/ziti/edge-router-policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/edge-router-policies', {
      name: data.name,
      edgeRouterRoles: data.edge_router_roles.split(',').map(s => s.trim()).filter(Boolean),
      identityRoles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setCreateModal(false)
      resetForm()
      toast({ title: t('pages.zitiNetwork.edgeRouterPolicies.toast.created') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.edgeRouterPolicies.toast.createFailed'), variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => api.put(`/api/v1/access/ziti/edge-router-policies/${id}`, {
      name: data.name,
      edgeRouterRoles: data.edge_router_roles.split(',').map(s => s.trim()).filter(Boolean),
      identityRoles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setEditTarget(null)
      resetForm()
      toast({ title: t('pages.zitiNetwork.edgeRouterPolicies.toast.updated') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.edgeRouterPolicies.toast.updateFailed'), variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/edge-router-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.edgeRouterPolicies.toast.deleted') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.edgeRouterPolicies.toast.deleteFailed'), variant: 'destructive' }),
  })

  const resetForm = () => setForm({ name: '', edge_router_roles: '', identity_roles: '' })

  const openEditModal = (policy: EdgeRouterPolicy) => {
    setForm({
      name: policy.name,
      edge_router_roles: (policy.edgeRouterRoles || []).join(', '),
      identity_roles: (policy.identityRoles || []).join(', '),
    })
    setEditTarget(policy)
  }

  const isSystemPolicy = (name: string) => name.startsWith('allEdgeRouters') || name.startsWith('openidx-')

  const policies = (Array.isArray(policiesData) ? policiesData : []).filter((p) =>
    !search || p.name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <CollapsibleSection title={t('pages.zitiNetwork.edgeRouterPolicies.title')} count={policies.length} icon={Router} defaultOpen={false}>
      <p className="text-sm text-muted-foreground mb-3">
        {t('pages.zitiNetwork.edgeRouterPolicies.desc')}
      </p>

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder={t('pages.zitiNetwork.edgeRouterPolicies.searchPlaceholder')} />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.edgeRouterPolicies.add')}
        </Button>
      </div>

      {isLoading ? <Spinner /> : policies.length === 0 ? (
        <EmptyState icon={Router} title={t('pages.zitiNetwork.edgeRouterPolicies.emptyTitle')} description={t('pages.zitiNetwork.edgeRouterPolicies.emptyDesc')} />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.edgeRouterPolicies.colName')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.edgeRouterPolicies.colRouterRoles')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.edgeRouterPolicies.colIdentityRoles')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow key={policy.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {isSystemPolicy(policy.name) && <span title={t('pages.zitiNetwork.edgeRouterPolicies.systemPolicy')}><Lock className="h-3.5 w-3.5 text-muted-foreground" /></span>}
                      <span className="font-medium">{policy.name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.edgeRouterRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const label = isAttr ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-teal-50 text-teal-700 border-teal-200' : ''}`}
                            title={isAttr ? t('pages.zitiNetwork.edgeRouterPolicies.routerAttrTitle', { label }) : role}>
                            {isAttr && <span className="text-teal-400 mr-0.5">#</span>}{label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.identityRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const label = isAttr ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-orange-50 text-orange-700 border-orange-200' : ''}`}
                            title={isAttr ? t('pages.zitiNetwork.edgeRouterPolicies.identityAttrTitle', { label }) : role}>
                            {isAttr && <span className="text-orange-400 mr-0.5">#</span>}{label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    {!isSystemPolicy(policy.name) && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEditModal(policy)}>
                            <Pencil className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.servicePolicies.edit')}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(policy)}>
                            <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: t('pages.zitiNetwork.edgeRouterPolicies.createTitle'), onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: t('pages.zitiNetwork.edgeRouterPolicies.createSubmit') },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: t('pages.zitiNetwork.edgeRouterPolicies.editTitle'), onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: t('pages.zitiNetwork.edgeRouterPolicies.editSubmit') },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.edgeRouterPolicies.policyName')}</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="allow-all-routers" required />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.edgeRouterPolicies.routerRoles')}</Label>
                <Input value={form.edge_router_roles} onChange={(e) => setForm({ ...form, edge_router_roles: e.target.value })} placeholder="#public, #datacenter-us" required />
                <p className="text-xs text-muted-foreground"><span className="text-teal-600 font-medium">#attribute</span> {t('pages.zitiNetwork.edgeRouterPolicies.routerAttrHint')} <code className="text-xs bg-muted px-1 rounded">#all</code> {t('pages.zitiNetwork.edgeRouterPolicies.routerAllHint')}</p>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.edgeRouterPolicies.identityRoles')}</Label>
                <Input value={form.identity_roles} onChange={(e) => setForm({ ...form, identity_roles: e.target.value })} placeholder="#engineering, #vpn-users" required />
                <p className="text-xs text-muted-foreground"><span className="text-orange-600 font-medium">#attribute</span> {t('pages.zitiNetwork.edgeRouterPolicies.identityAttrHint')}</p>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>{t('common.cancel')}</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? t('pages.zitiNetwork.edgeRouterPolicies.saving') : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.edgeRouterPolicies.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.edgeRouterPolicies.deleteDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

const POSTURE_CHECK_TYPES = ['OS', 'Domain', 'MFA', 'Process', 'MAC'] as const

function PostureSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<PostureCheck | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<PostureCheck | null>(null)
  const [form, setForm] = useState({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true, platforms: [] as string[] })

  const { data: summary } = useQuery({
    queryKey: ['ziti-posture-summary'],
    queryFn: () => api.get<PostureSummary>('/api/v1/access/ziti/posture/summary'),
  })

  const { data: checksData, isLoading } = useQuery({
    queryKey: ['ziti-posture-checks'],
    queryFn: () => api.get<PostureCheck[]>('/api/v1/access/ziti/posture/checks'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/posture/checks', { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setCreateModal(false)
      resetForm()
      toast({ title: t('pages.zitiNetwork.posture.toast.created') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.posture.toast.createFailed'), variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) =>
      api.put(`/api/v1/access/ziti/posture/checks/${id}`, { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setEditTarget(null)
      resetForm()
      toast({ title: t('pages.zitiNetwork.posture.toast.updated') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.posture.toast.updateFailed'), variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/posture/checks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.posture.toast.deleted') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.posture.toast.deleteFailed'), variant: 'destructive' }),
  })

  const resetForm = () => setForm({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true, platforms: [] })

  const openEditModal = (check: PostureCheck) => {
    setForm({
      name: check.name,
      check_type: check.check_type,
      parameters: JSON.stringify(check.parameters, null, 2),
      severity: check.severity,
      enabled: check.enabled,
      platforms: Array.isArray(check.platforms) ? check.platforms : [],
    })
    setEditTarget(check)
  }

  const checks = (Array.isArray(checksData) ? checksData : []).filter((c) =>
    !search || c.name.toLowerCase().includes(search.toLowerCase()) || c.check_type.toLowerCase().includes(search.toLowerCase())
  )

  const severityColor = (severity: string): 'default' | 'destructive' | 'secondary' | 'outline' => {
    if (severity === 'critical' || severity === 'high') return 'destructive'
    if (severity === 'medium') return 'default'
    return 'secondary'
  }

  const totalChecks = summary?.total_checks || (Array.isArray(checksData) ? checksData.length : 0)

  return (
    <CollapsibleSection title={t('pages.zitiNetwork.posture.title')} count={totalChecks} icon={Fingerprint} defaultOpen>
      {/* Summary row */}
      {summary && (
        <div className="flex gap-4 mb-4 text-sm">
          <span className="text-green-600 font-medium">{t('pages.zitiNetwork.posture.enabledCount', { n: summary.enabled_checks })}</span>
          <span className="text-muted-foreground">{t('pages.zitiNetwork.posture.disabledCount', { n: summary.disabled_checks })}</span>
          {summary.by_type && Object.entries(summary.by_type).map(([type, count]) => (
            <Badge key={type} variant="outline" className="text-xs">{type}: {count}</Badge>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder={t('pages.zitiNetwork.posture.searchPlaceholder')} />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.posture.add')}
        </Button>
      </div>

      {isLoading ? <Spinner /> : checks.length === 0 ? (
        <EmptyState icon={Fingerprint} title={t('pages.zitiNetwork.posture.emptyTitle')} description={t('pages.zitiNetwork.posture.emptyDesc')} />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.posture.colName')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.posture.colType')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.posture.colSeverity')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.posture.colPlatforms')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.posture.colStatus')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.posture.colCreated')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {checks.map((check) => (
                <TableRow key={check.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{check.name}</TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {t(`pages.zitiNetwork.posture.checkTypes.${check.check_type}`, { defaultValue: check.check_type })}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {/* Severity is the controller's own value; unknown ones
                        still read as themselves. */}
                    <Badge variant={severityColor(check.severity)}>
                      {t(`pages.zitiNetwork.posture.severities.${check.severity}`, { defaultValue: check.severity })}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {Array.isArray(check.platforms) && check.platforms.length > 0
                      ? check.platforms.join(', ')
                      : t('pages.zitiNetwork.posture.allPlatforms')}
                  </TableCell>
                  <TableCell>
                    <Badge variant={check.enabled ? 'default' : 'secondary'}>
                      {check.enabled ? t('pages.zitiNetwork.posture.enabled') : t('pages.zitiNetwork.posture.disabled')}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(check.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => openEditModal(check)}>{t('pages.zitiNetwork.posture.edit')}</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(check)}>
                          <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Identity Posture Viewer */}
      <IdentityPostureViewer />

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: t('pages.zitiNetwork.posture.createTitle'), onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: t('pages.zitiNetwork.posture.createSubmit') },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: t('pages.zitiNetwork.posture.editTitle'), onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: t('pages.zitiNetwork.posture.editSubmit') },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.posture.name')}</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t('pages.zitiNetwork.posture.namePlaceholder')} required />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor={`ziti-posture-${i}-check-type`}>{t('pages.zitiNetwork.posture.checkType')}</Label>
                  <select id={`ziti-posture-${i}-check-type`} value={form.check_type} onChange={(e) => setForm({ ...form, check_type: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    {POSTURE_CHECK_TYPES.map((checkType) => (
                      <option key={checkType} value={checkType}>
                        {t(`pages.zitiNetwork.posture.checkTypes.${checkType}`)}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`ziti-posture-${i}-severity`}>{t('pages.zitiNetwork.posture.severity')}</Label>
                  <select id={`ziti-posture-${i}-severity`} value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    <option value="low">{t('pages.zitiNetwork.posture.severities.low')}</option>
                    <option value="medium">{t('pages.zitiNetwork.posture.severities.medium')}</option>
                    <option value="high">{t('pages.zitiNetwork.posture.severities.high')}</option>
                    <option value="critical">{t('pages.zitiNetwork.posture.severities.critical')}</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.posture.parameters')}</Label>
                <textarea
                  value={form.parameters}
                  onChange={(e) => setForm({ ...form, parameters: e.target.value })}
                  className="w-full h-24 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  placeholder='{"os_type": "Windows", "min_version": "10"}'
                />
              </div>
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.posture.platforms')}</Label>
                {/* Platform identifiers are shown as the controller names them. */}
                <div className="flex flex-wrap gap-3">
                  {['android', 'ios', 'windows', 'macos', 'linux'].map((p) => (
                    <label key={p} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={form.platforms.includes(p)}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            platforms: e.target.checked
                              ? [...form.platforms, p]
                              : form.platforms.filter((x) => x !== p),
                          })
                        }
                      />
                      {p}
                    </label>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  {t('pages.zitiNetwork.posture.platformsHint')}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Switch id={`ziti-posture-${i}-enabled`} checked={form.enabled} onCheckedChange={(checked) => setForm({ ...form, enabled: checked })} />
                <Label htmlFor={`ziti-posture-${i}-enabled`}>{t('pages.zitiNetwork.posture.enabledLabel')}</Label>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>{t('common.cancel')}</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? t('pages.zitiNetwork.posture.saving') : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.posture.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.zitiNetwork.posture.deleteDesc', { name: deleteTarget?.name ?? '' })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function IdentityPostureViewer() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [identityId, setIdentityId] = useState('')
  const [searchId, setSearchId] = useState('')

  const { data: postureData, isLoading, isFetching } = useQuery({
    queryKey: ['ziti-identity-posture', searchId],
    queryFn: () => api.get<IdentityPostureReport>(`/api/v1/access/ziti/posture/identities/${searchId}`),
    enabled: !!searchId,
  })

  const evaluateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/posture/identities/${id}/evaluate`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identity-posture', searchId] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      toast({ title: t('pages.zitiNetwork.identityPosture.toast.evaluated') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.identityPosture.toast.evaluateFailed'), variant: 'destructive' }),
  })

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault()
    if (identityId.trim()) setSearchId(identityId.trim())
  }

  return (
    <div className="mt-6 border-t pt-4">
      <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Search className="h-4 w-4" /> {t('pages.zitiNetwork.identityPosture.title')}
      </h4>
      <form onSubmit={handleLookup} className="flex gap-2 mb-3">
        <Input
          value={identityId}
          onChange={(e) => setIdentityId(e.target.value)}
          placeholder={t('pages.zitiNetwork.identityPosture.placeholder')}
          className="max-w-sm"
        />
        <Button type="submit" size="sm" variant="outline" disabled={!identityId.trim()}>
          {t('pages.zitiNetwork.identityPosture.lookup')}
        </Button>
        {searchId && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => evaluateMutation.mutate(searchId)}
            disabled={evaluateMutation.isPending}
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${evaluateMutation.isPending ? 'animate-spin' : ''}`} />
            {t('pages.zitiNetwork.identityPosture.evaluate')}
          </Button>
        )}
      </form>

      {isLoading || isFetching ? <Spinner /> : postureData && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 text-sm">
            <Badge variant={postureData.overall_passed ? 'default' : 'destructive'}>
              {postureData.overall_passed ? t('pages.zitiNetwork.identityPosture.passed') : t('pages.zitiNetwork.identityPosture.failed')}
            </Badge>
            <span className="text-muted-foreground">
              {t('pages.zitiNetwork.identityPosture.checksEvaluated', { n: postureData.results?.length || 0 })}
            </span>
            {postureData.evaluated_at && (
              <span className="text-muted-foreground">
                {t('pages.zitiNetwork.identityPosture.evaluatedAt', { time: new Date(postureData.evaluated_at).toLocaleString() })}
              </span>
            )}
          </div>

          {postureData.results && postureData.results.length > 0 && (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.zitiNetwork.identityPosture.colCheckId')}</TableHead>
                    <TableHead>{t('pages.zitiNetwork.identityPosture.colStatus')}</TableHead>
                    <TableHead>{t('pages.zitiNetwork.identityPosture.colDetails')}</TableHead>
                    <TableHead>{t('pages.zitiNetwork.identityPosture.colCheckedAt')}</TableHead>
                    <TableHead>{t('pages.zitiNetwork.identityPosture.colExpiresAt')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {postureData.results.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs">{r.check_id}</TableCell>
                      <TableCell>
                        <Badge variant={r.passed ? 'default' : 'destructive'}>
                          {r.passed ? t('pages.zitiNetwork.identityPosture.passed') : t('pages.zitiNetwork.identityPosture.failed')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs max-w-[300px] truncate">
                        {r.details ? JSON.stringify(r.details) : '-'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(r.checked_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {r.expires_at ? new Date(r.expires_at).toLocaleString() : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

function CertificatesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()

  const { data: certsData, isLoading } = useQuery({
    queryKey: ['ziti-certificates'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates'),
  })

  const { data: expiryAlerts } = useQuery({
    queryKey: ['ziti-certificates-expiry'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates/expiry-alerts?threshold_days=30'),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/certificates/${id}/rotate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates-expiry'] })
      toast({ title: t('pages.zitiNetwork.certificates.toast.rotated'), description: t('pages.zitiNetwork.certificates.toast.rotatedDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.certificates.toast.rotateFailed'), variant: 'destructive' }),
  })

  const certs = Array.isArray(certsData) ? certsData : []
  const alerts = Array.isArray(expiryAlerts) ? expiryAlerts : []

  const expiryBadge = (days: number) => {
    const variant: 'default' | 'destructive' | 'secondary' = days < 30 ? 'destructive' : days <= 60 ? 'secondary' : 'default'
    const label = days < 0
      ? t('pages.zitiNetwork.certificates.expired')
      : days === 0
        ? t('pages.zitiNetwork.certificates.expiresToday')
        : t('pages.zitiNetwork.certificates.daysRemaining', { n: days })
    return <Badge variant={variant}>{label}</Badge>
  }

  return (
    <CollapsibleSection title={t('pages.zitiNetwork.certificates.title')} count={certs.length} icon={FileKey}>
      {/* Expiry alerts */}
      {alerts.length > 0 && (
        <div className="mb-4 p-3 rounded-lg border border-yellow-300 bg-yellow-50">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-yellow-600" />
            <span className="text-sm font-medium text-yellow-800">{t('pages.zitiNetwork.certificates.expiringTitle', { n: alerts.length })}</span>
          </div>
          <div className="space-y-1">
            {alerts.map((cert) => (
              <div key={cert.id} className="flex items-center justify-between text-sm">
                <span className="font-medium text-yellow-900">{cert.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-yellow-700">
                    {cert.days_until_expiry < 0
                      ? t('pages.zitiNetwork.certificates.expiredAgo', { n: Math.abs(cert.days_until_expiry) })
                      : t('pages.zitiNetwork.certificates.daysLeft', { n: cert.days_until_expiry })}
                  </span>
                  <ConfirmAction
                    title={t('pages.zitiNetwork.certificates.rotateTitle')}
                    description={t('pages.zitiNetwork.certificates.rotateDesc')}
                    destructive
                    confirmLabel={t('pages.zitiNetwork.certificates.rotate')}
                    onConfirm={() => rotateMutation.mutate(cert.id)}
                  >
                    {(open) => (
                      <Button variant="outline" size="sm" onClick={open} disabled={rotateMutation.isPending}>
                        {t('pages.zitiNetwork.certificates.rotate')}
                      </Button>
                    )}
                  </ConfirmAction>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {isLoading ? <Spinner /> : certs.length === 0 ? (
        <EmptyState icon={FileKey} title={t('pages.zitiNetwork.certificates.emptyTitle')} description={t('pages.zitiNetwork.certificates.emptyDesc')} />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.certificates.colName')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.certificates.colType')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.certificates.colSubject')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.certificates.colExpiry')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.certificates.colAutoRenew')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {certs.map((cert) => (
                <TableRow key={cert.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{cert.name}</TableCell>
                  <TableCell><Badge variant="outline">{cert.cert_type}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate" title={cert.subject}>{cert.subject}</TableCell>
                  <TableCell>{expiryBadge(cert.days_until_expiry)}</TableCell>
                  <TableCell>
                    <Badge variant={cert.auto_renew ? 'default' : 'secondary'}>{cert.auto_renew ? t('pages.zitiNetwork.certificates.yes') : t('pages.zitiNetwork.certificates.no')}</Badge>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(cert.fingerprint)
                          toast({ title: t('pages.zitiNetwork.copied'), description: t('pages.zitiNetwork.certificates.toast.fingerprintCopied') })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.certificates.copyFingerprint')}
                        </DropdownMenuItem>
                        <ConfirmAction
                          title={t('pages.zitiNetwork.certificates.rotateTitle')}
                          description={t('pages.zitiNetwork.certificates.rotateDesc')}
                          destructive
                          confirmLabel={t('pages.zitiNetwork.certificates.rotate')}
                          onConfirm={() => rotateMutation.mutate(cert.id)}
                        >
                          {(open) => (
                            <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }}>
                              <RefreshCw className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.certificates.rotate')}
                            </DropdownMenuItem>
                          )}
                        </ConfirmAction>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </CollapsibleSection>
  )
}

function PolicySyncSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PolicySync | null>(null)
  const [form, setForm] = useState({ governance_policy_id: '', config: '{}', auto_fetch: true })

  const { data: syncsData, isLoading } = useQuery({
    queryKey: ['ziti-policy-sync'],
    queryFn: () => api.get<PolicySync[]>('/api/v1/access/ziti/policy-sync'),
  })

  // Fetch governance policies for dropdown and name lookup
  const { data: governancePolicies } = useQuery({
    queryKey: ['governance-policies-for-sync'],
    queryFn: () => api.get<{ id: string; name: string; description?: string }[]>('/api/v1/governance/policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/policy-sync', {
      governance_policy_id: data.governance_policy_id,
      auto_fetch: data.auto_fetch,
      ...(data.auto_fetch ? {} : { config: JSON.parse(data.config) }),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setCreateModal(false)
      setForm({ governance_policy_id: '', config: '{}', auto_fetch: true })
      toast({ title: t('pages.zitiNetwork.policySync.toast.created') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.policySync.toast.createFailed'), variant: 'destructive' }),
  })

  const triggerMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/policy-sync/${id}/trigger`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      toast({ title: t('pages.zitiNetwork.policySync.toast.resynced') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.policySync.toast.resyncFailed'), variant: 'destructive' }),
  })

  const syncAllMutation = useMutation({
    mutationFn: async () => {
      const results = []
      for (const sync of syncs) {
        try {
          await api.post(`/api/v1/access/ziti/policy-sync/${sync.id}/trigger`, {})
          results.push({ id: sync.id, success: true })
        } catch {
          results.push({ id: sync.id, success: false })
        }
      }
      return results
    },
    onSuccess: (results) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      const succeeded = results.filter(r => r.success).length
      const failed = results.filter(r => !r.success).length
      toast({
        title: t('pages.zitiNetwork.policySync.toast.syncAllDone'),
        description:
          t('pages.zitiNetwork.policySync.toast.syncAllDesc', { succeeded }) +
          (failed > 0 ? t('pages.zitiNetwork.policySync.toast.syncAllFailedSuffix', { failed }) : ''),
        variant: failed > 0 ? 'destructive' : undefined,
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/policy-sync/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.policySync.toast.deleted') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.policySync.toast.deleteFailed'), variant: 'destructive' }),
  })

  const syncs = Array.isArray(syncsData) ? syncsData : []

  const statusVariant = (status: string): 'default' | 'destructive' | 'secondary' => {
    if (status === 'synced') return 'default'
    if (status === 'error') return 'destructive'
    return 'secondary'
  }

  // Map governance policy IDs to names
  const govPolicyMap = new Map((Array.isArray(governancePolicies) ? governancePolicies : []).map(p => [p.id, p.name]))

  return (
    <CollapsibleSection title={t('pages.zitiNetwork.policySync.title')} count={syncs.length} icon={RefreshCw} defaultOpen={false}>
      <p className="text-sm text-muted-foreground mb-3">
        {t('pages.zitiNetwork.policySync.desc')}
      </p>
      <div className="flex items-center justify-between gap-4 mb-3">
        <div className="flex items-center gap-2">
          {syncs.length > 0 && (
            <Button variant="outline" size="sm" onClick={() => syncAllMutation.mutate()} disabled={syncAllMutation.isPending}>
              <RefreshCw className={`mr-2 h-3 w-3 ${syncAllMutation.isPending ? 'animate-spin' : ''}`} />
              {syncAllMutation.isPending ? t('pages.zitiNetwork.policySync.syncing') : t('pages.zitiNetwork.policySync.syncAll')}
            </Button>
          )}
        </div>
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.policySync.link')}
        </Button>
      </div>

      {isLoading ? <Spinner /> : syncs.length === 0 ? (
        <EmptyState icon={RefreshCw} title={t('pages.zitiNetwork.policySync.emptyTitle')} description={t('pages.zitiNetwork.policySync.emptyDesc')} />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.policySync.colGovernance')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.policySync.colZiti')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.policySync.colStatus')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.policySync.colLastSynced')}</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncs.map((sync) => (
                <TableRow key={sync.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div>
                      {govPolicyMap.get(sync.governance_policy_id) ? (
                        <span className="font-medium">{govPolicyMap.get(sync.governance_policy_id)}</span>
                      ) : (
                        <TruncatedId value={sync.governance_policy_id} label={t('pages.zitiNetwork.policySync.governanceIdLabel')} />
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    {sync.ziti_policy_id ? <TruncatedId value={sync.ziti_policy_id} label={t('pages.zitiNetwork.policySync.zitiIdLabel')} /> : <span className="text-muted-foreground">-</span>}
                  </TableCell>
                  <TableCell>
                    {/* Sync status and any error text come from the server. */}
                    <Badge variant={statusVariant(sync.sync_status)}>{sync.sync_status}</Badge>
                    {sync.error_message && (
                      <p className="text-xs text-red-500 mt-0.5 max-w-[200px] truncate" title={sync.error_message}>{sync.error_message}</p>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {sync.last_synced_at ? new Date(sync.last_synced_at).toLocaleString() : t('pages.zitiNetwork.policySync.never')}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => triggerMutation.mutate(sync.id)}>
                          <RefreshCw className="mr-2 h-4 w-4" /> {t('pages.zitiNetwork.policySync.resync')}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(sync)}>
                          <Trash2 className="mr-2 h-4 w-4" /> {t('common.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader><DialogTitle>{t('pages.zitiNetwork.policySync.dialogTitle')}</DialogTitle></DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ziti-network-governance-policy">{t('pages.zitiNetwork.policySync.governancePolicy')}</Label>
              {Array.isArray(governancePolicies) && governancePolicies.length > 0 ? (
                <select id="ziti-network-governance-policy"
                  value={form.governance_policy_id}
                  onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  required
                >
                  <option value="">{t('pages.zitiNetwork.policySync.selectPolicy')}</option>
                  {governancePolicies.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
                  ))}
                </select>
              ) : (
                <Input value={form.governance_policy_id} onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })} placeholder={t('pages.zitiNetwork.policySync.policyIdPlaceholder')} required />
              )}
              <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.policySync.policyHint')}</p>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="ziti-network-auto-detect" checked={form.auto_fetch} onCheckedChange={(checked) => setForm({ ...form, auto_fetch: checked })} />
              <Label htmlFor="ziti-network-auto-detect">{t('pages.zitiNetwork.policySync.autoDetect')}</Label>
            </div>
            <p className="text-xs text-muted-foreground -mt-2">
              {form.auto_fetch ? t('pages.zitiNetwork.policySync.autoHint') : t('pages.zitiNetwork.policySync.manualHint')}
            </p>
            {!form.auto_fetch && (
              <div className="space-y-2">
                <Label>{t('pages.zitiNetwork.policySync.mappingConfig')}</Label>
                <textarea
                  value={form.config}
                  onChange={(e) => setForm({ ...form, config: e.target.value })}
                  className="w-full h-32 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  placeholder='{"action": "allow", "service_roles": ["#web"], "identity_roles": ["#engineering"]}'
                />
                <p className="text-xs text-muted-foreground">{t('pages.zitiNetwork.policySync.mappingHint')}</p>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>{t('common.cancel')}</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? t('pages.zitiNetwork.policySync.linking') : t('pages.zitiNetwork.policySync.link')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.policySync.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.zitiNetwork.policySync.deleteDesc')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>{t('common.delete')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

// ─── Remote Access Tab ───────────────────────────────────────────────────────

function RemoteAccessTab() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { t } = useTranslation()

  // BrowZer status
  const { data: browzerStatus, isLoading: browzerLoading } = useQuery<BrowZerStatus>({
    queryKey: ['browzer-status'],
    queryFn: () => api.get<BrowZerStatus>('/api/v1/access/ziti/browzer/status'),
  })

  // Guacamole connections
  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ['guacamole-connections'],
    queryFn: () => api.get<{ connections: GuacConnection[] }>('/api/v1/access/guacamole/connections'),
  })

  // Services for per-service BrowZer toggle
  const { data: servicesData } = useQuery({
    queryKey: ['ziti-services-browzer'],
    queryFn: () => api.get<{ services: ZitiService[] }>('/api/v1/access/ziti/services'),
  })

  const enableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/enable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: t('pages.zitiNetwork.remoteAccess.toast.enabled') }) },
    onError: () => toast({ title: t('pages.zitiNetwork.remoteAccess.toast.enableFailed'), variant: 'destructive' }),
  })

  const disableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/disable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: t('pages.zitiNetwork.remoteAccess.toast.disabled') }) },
    onError: () => toast({ title: t('pages.zitiNetwork.remoteAccess.toast.disableFailed'), variant: 'destructive' }),
  })

  const connectMutation = useMutation({
    mutationFn: async (routeId: string) => api.post<{ connect_url: string }>(`/api/v1/access/guacamole/connections/${routeId}/connect`, {}),
    onSuccess: (resp) => {
      const connectUrl = (resp as Record<string, string>)?.connect_url
      if (connectUrl) window.open(connectUrl, '_blank', 'noopener,noreferrer')
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.remoteAccess.toast.connectFailed'), variant: 'destructive' }),
  })

  const enableOnServiceMutation = useMutation({
    mutationFn: ({ serviceId, path, domain }: { serviceId: string; path?: string; domain?: string }) => {
      const body: Record<string, string> = {}
      if (path) body.path = path
      if (domain) body.domain = domain
      return api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/enable`, Object.keys(body).length > 0 ? body : undefined)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-services-browzer'] })
      setInitialized(false)
      toast({ title: t('pages.zitiNetwork.remoteAccess.toast.serviceEnabled') })
    },
    onError: (err: Error) => toast({ title: t('pages.zitiNetwork.remoteAccess.toast.serviceEnableFailed'), description: err.message, variant: 'destructive' }),
  })

  const disableOnServiceMutation = useMutation({
    mutationFn: (serviceId: string) => api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/disable`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-services-browzer'] })
      setInitialized(false)
      toast({ title: t('pages.zitiNetwork.remoteAccess.toast.serviceDisabled') })
    },
    onError: (err: Error) => toast({ title: t('pages.zitiNetwork.remoteAccess.toast.serviceDisableFailed'), description: err.message, variant: 'destructive' }),
  })

  const connections = connData?.connections || []
  const services = servicesData?.services || []
  const [showHowItWorks, setShowHowItWorks] = useState(false)
  const [browzerPaths, setBrowzerPaths] = useState<Record<string, string>>({})
  const [browzerDomains, setBrowzerDomains] = useState<Record<string, string>>({})

  // Initialize paths/domains from API data when services load
  const [initialized, setInitialized] = useState(false)
  if (!initialized && services.length > 0) {
    const paths: Record<string, string> = {}
    const domains: Record<string, string> = {}
    for (const svc of services) {
      if (svc.browzer_path) paths[svc.id] = svc.browzer_path
      if (svc.browzer_domain) domains[svc.id] = svc.browzer_domain
    }
    if (Object.keys(paths).length > 0) setBrowzerPaths(prev => ({ ...prev, ...paths }))
    if (Object.keys(domains).length > 0) setBrowzerDomains(prev => ({ ...prev, ...domains }))
    setInitialized(true)
  }

  if (browzerLoading || connLoading) return <Spinner />

  const protocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-primary'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-6 mt-4">
      {/* BrowZer Status Banner */}
      <Card className={browzerStatus?.enabled ? 'border-green-200 bg-green-50/50' : ''}>
        <CardContent className="flex items-center justify-between py-4">
          <div className="flex items-center gap-4">
            <div className={`p-2.5 rounded-lg ${browzerStatus?.enabled ? 'bg-green-100' : 'bg-muted'}`}>
              <Monitor className={`h-5 w-5 ${browzerStatus?.enabled ? 'text-green-700' : 'text-muted-foreground'}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold">{t('pages.zitiNetwork.remoteAccess.browzer')}</h3>
                <Badge variant={browzerStatus?.enabled ? 'default' : 'secondary'}>
                  {browzerStatus?.enabled ? t('pages.zitiNetwork.remoteAccess.enabled') : t('pages.zitiNetwork.remoteAccess.disabled')}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                {t('pages.zitiNetwork.remoteAccess.browzerDesc')}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {browzerStatus?.enabled && browzerStatus.bootstrapper_url && (
              <a
                href={browzerStatus.bootstrapper_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-sm text-primary hover:underline"
              >
                {t('pages.zitiNetwork.remoteAccess.openBootstrapper')} <ExternalLink className="h-3 w-3" />
              </a>
            )}
            <Button
              variant={browzerStatus?.enabled ? 'destructive' : 'default'}
              size="sm"
              onClick={() => browzerStatus?.enabled ? disableMutation.mutate() : enableMutation.mutate()}
              disabled={enableMutation.isPending || disableMutation.isPending}
            >
              {browzerStatus?.enabled ? t('pages.zitiNetwork.remoteAccess.disable') : t('pages.zitiNetwork.remoteAccess.enable')}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* BrowZer Config Details (when enabled) */}
      {browzerStatus?.enabled && (browzerStatus.oidc_issuer || browzerStatus.external_jwt_signer_id) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {browzerStatus.bootstrapper_url && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">{t('pages.zitiNetwork.remoteAccess.bootstrapperUrl')}</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.bootstrapper_url}</code>
            </div>
          )}
          {browzerStatus.oidc_issuer && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">{t('pages.zitiNetwork.remoteAccess.oidcIssuer')}</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_issuer}</code>
            </div>
          )}
          {browzerStatus.oidc_client_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">{t('pages.zitiNetwork.remoteAccess.oidcClientId')}</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_client_id}</code>
            </div>
          )}
          {browzerStatus.external_jwt_signer_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">{t('pages.zitiNetwork.remoteAccess.jwtSigner')}</span>
              <TruncatedId value={browzerStatus.external_jwt_signer_id} label={t('pages.zitiNetwork.remoteAccess.jwtSignerIdLabel')} />
            </div>
          )}
        </div>
      )}

      {/* Guacamole Connections */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold">{t('pages.zitiNetwork.remoteAccess.connections')}</h3>
        {connections.length === 0 ? (
          <EmptyState
            icon={Monitor}
            title={t('pages.zitiNetwork.remoteAccess.emptyTitle')}
            description={t('pages.zitiNetwork.remoteAccess.emptyDesc')}
          />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colProtocol')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colTarget')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colGuacId')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colCreated')}</TableHead>
                  <TableHead className="text-right">{t('pages.zitiNetwork.remoteAccess.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {connections.map((conn) => (
                  <TableRow key={conn.id} className="hover:bg-muted/50">
                    <TableCell>
                      <Badge variant="default" className={protocolColor(conn.protocol)}>
                        {conn.protocol.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{conn.hostname}:{conn.port}</code>
                    </TableCell>
                    <TableCell><TruncatedId value={conn.guacamole_connection_id} label={t('pages.zitiNetwork.remoteAccess.guacIdLabel')} /></TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {safeDate(conn.created_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" onClick={() => connectMutation.mutate(conn.route_id)} disabled={connectMutation.isPending}>
                        <ExternalLink className="mr-1 h-3 w-3" /> {t('pages.zitiNetwork.remoteAccess.connect')}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>

      {/* Per-Service BrowZer Toggle */}
      {browzerStatus?.enabled && services.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold">{t('pages.zitiNetwork.remoteAccess.servicesTitle')}</h3>
          <p className="text-sm text-muted-foreground">
            {t('pages.zitiNetwork.remoteAccess.servicesDesc')}
          </p>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colService')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colTarget')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colPath')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colDomain')}</TableHead>
                  <TableHead>{t('pages.zitiNetwork.remoteAccess.colBrowzer')}</TableHead>
                  <TableHead className="text-right">{t('pages.zitiNetwork.remoteAccess.colAction')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {services.map((svc) => {
                  const isBrowzerEnabled = !!(svc.browzer_path || svc.browzer_domain)
                  return (
                    <TableRow key={svc.id} className="hover:bg-muted/50">
                      <TableCell className="font-medium">{svc.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{svc.host}:{svc.port}</TableCell>
                      <TableCell>
                        <Input
                          placeholder={`/${svc.name}`}
                          value={browzerPaths[svc.id] ?? ''}
                          onChange={(e) => setBrowzerPaths(prev => ({ ...prev, [svc.id]: e.target.value }))}
                          className="h-8 w-32 text-sm"
                          disabled={isBrowzerEnabled}
                        />
                      </TableCell>
                      <TableCell>
                        <Input
                          placeholder={`${svc.name}.localtest.me`}
                          value={browzerDomains[svc.id] ?? ''}
                          onChange={(e) => setBrowzerDomains(prev => ({ ...prev, [svc.id]: e.target.value }))}
                          className="h-8 w-44 text-sm"
                          disabled={isBrowzerEnabled}
                        />
                      </TableCell>
                      <TableCell>
                        <Badge variant={isBrowzerEnabled ? 'default' : 'secondary'}>
                          {isBrowzerEnabled ? t('pages.zitiNetwork.remoteAccess.enabled') : t('pages.zitiNetwork.remoteAccess.disabled')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant={isBrowzerEnabled ? 'destructive' : 'outline'}
                          onClick={() => {
                            if (isBrowzerEnabled) {
                              disableOnServiceMutation.mutate(svc.ziti_id)
                            } else {
                              const path = browzerPaths[svc.id] || `/${svc.name}`
                              const domain = browzerDomains[svc.id] || undefined
                              enableOnServiceMutation.mutate({ serviceId: svc.ziti_id, path, domain })
                            }
                          }}
                        >
                          {isBrowzerEnabled ? t('pages.zitiNetwork.remoteAccess.disable') : t('pages.zitiNetwork.remoteAccess.enable')}
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* Temporary Access Links Section */}
      <TempAccessLinksSection />

      {/* How it works - collapsible */}
      <button
        onClick={() => setShowHowItWorks(!showHowItWorks)}
        className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        {showHowItWorks ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        {t('pages.zitiNetwork.remoteAccess.howItWorks')}
      </button>
      {showHowItWorks && (
        <Card>
          <CardContent className="pt-4 space-y-3">
            <ol className="text-sm space-y-1.5 list-decimal list-inside text-muted-foreground">
              <li>{t('pages.zitiNetwork.remoteAccess.step1')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step2')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step3')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step4')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step5')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step6')}</li>
              <li>{t('pages.zitiNetwork.remoteAccess.step7Before')} <kbd className="bg-muted px-1 py-0.5 rounded text-xs">Alt+F12</kbd> {t('pages.zitiNetwork.remoteAccess.step7After')}</li>
            </ol>
            <div className="p-3 bg-muted rounded-lg">
              <p className="text-xs font-medium mb-1">{t('pages.zitiNetwork.remoteAccess.flowTitle')}</p>
              {/* Component names in the data path, shown as-is. */}
              <code className="text-xs text-muted-foreground">
                Browser (ZBR + SW) &rarr; WSS &rarr; Edge Router &rarr; Ziti Circuit &rarr; Access Service &rarr; Upstream
              </code>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Temporary Access Links Section ──────────────────────────────────────────

function TempAccessLinksSection() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const [createModal, setCreateModal] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<TempAccessLink | null>(null)

  const [form, setForm] = useState({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  // Fetch temp access links
  const { data: linksData, isLoading } = useQuery({
    queryKey: ['temp-access-links'],
    queryFn: () => api.get<{ links: TempAccessLink[] }>('/api/v1/access/temp-access'),
  })

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post<TempAccessLink>('/api/v1/access/temp-access', {
      ...data,
      target_port: Number(data.target_port),
      duration_mins: Number(data.duration_mins),
      max_uses: Number(data.max_uses),
      allowed_ips: data.allowed_ips ? data.allowed_ips.split(',').map(ip => ip.trim()).filter(Boolean) : [],
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setCreateModal(false)
      resetForm()
      toast({ title: t('pages.zitiNetwork.tempAccess.toast.created'), description: t('pages.zitiNetwork.tempAccess.toast.createdDesc') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.tempAccess.toast.createFailed'), variant: 'destructive' }),
  })

  // Revoke mutation
  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/temp-access/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setDeleteTarget(null)
      toast({ title: t('pages.zitiNetwork.tempAccess.toast.revoked') })
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.zitiNetwork.tempAccess.toast.revokeFailed'), variant: 'destructive' }),
  })

  const resetForm = () => setForm({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast({ title: t('pages.zitiNetwork.tempAccess.toast.copied') })
    setTimeout(() => setCopiedId(null), 2000)
  }

  const links = linksData?.links || []

  const getStatusBadge = (link: TempAccessLink) => {
    const now = new Date()
    const expires = new Date(link.expires_at)
    if (link.status === 'revoked') return <Badge variant="destructive">{t('pages.zitiNetwork.tempAccess.revoked')}</Badge>
    if (link.status === 'expired' || expires < now) return <Badge variant="secondary">{t('pages.zitiNetwork.tempAccess.expired')}</Badge>
    if (link.max_uses > 0 && link.current_uses >= link.max_uses) return <Badge variant="secondary">{t('pages.zitiNetwork.tempAccess.used')}</Badge>
    return <Badge className="bg-green-600">{t('pages.zitiNetwork.tempAccess.active')}</Badge>
  }

  const getTimeRemaining = (expiresAt: string) => {
    const now = new Date()
    const expires = new Date(expiresAt)
    const diff = expires.getTime() - now.getTime()
    if (diff <= 0) return t('pages.zitiNetwork.tempAccess.expired')
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    if (hours > 24) return t('pages.zitiNetwork.tempAccess.remainingDays', { d: Math.floor(hours / 24), h: hours % 24 })
    if (hours > 0) return t('pages.zitiNetwork.tempAccess.remainingHours', { h: hours, m: mins })
    return t('pages.zitiNetwork.tempAccess.remainingMinutes', { m: mins })
  }

  const protocolIcon = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return <Terminal className="h-4 w-4" />
      case 'rdp': return <MonitorPlay className="h-4 w-4" />
      case 'vnc': return <Monitor className="h-4 w-4" />
      default: return <Server className="h-4 w-4" />
    }
  }

  const protocolColor = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-primary'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-4" data-testid="temp-access-section">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-lg font-semibold">{t('pages.zitiNetwork.tempAccess.title')}</h3>
          <Badge variant="outline" className="ml-2">{links.length}</Badge>
        </div>
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="h-4 w-4 mr-1" />
          {t('pages.zitiNetwork.tempAccess.create')}
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        {t('pages.zitiNetwork.tempAccess.desc')}
      </p>

      {isLoading ? (
        <Spinner />
      ) : links.length === 0 ? (
        <EmptyState
          icon={Link2}
          title={t('pages.zitiNetwork.tempAccess.emptyTitle')}
          description={t('pages.zitiNetwork.tempAccess.emptyDesc')}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colName')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colTarget')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colStatus')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colUsage')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colExpires')}</TableHead>
                <TableHead>{t('pages.zitiNetwork.tempAccess.colUrl')}</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {links.map((link) => (
                <TableRow key={link.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded ${protocolColor(link.protocol)}`}>
                        {protocolIcon(link.protocol)}
                      </div>
                      <div>
                        <p className="font-medium">{link.name}</p>
                        {link.description && (
                          <p className="text-xs text-muted-foreground">{link.description}</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">
                      {link.target_host}:{link.target_port}
                    </code>
                  </TableCell>
                  <TableCell>{getStatusBadge(link)}</TableCell>
                  <TableCell>
                    <span className="text-sm">
                      {link.max_uses > 0
                        ? t('pages.zitiNetwork.tempAccess.usesOfMax', { used: link.current_uses, max: link.max_uses })
                        : t('pages.zitiNetwork.tempAccess.uses', { used: link.current_uses })}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-sm">{getTimeRemaining(link.expires_at)}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded max-w-[200px] truncate">
                        {link.access_url}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => copyToClipboard(link.access_url, link.id)}
                      >
                        {copiedId === link.id ? (
                          <CheckCircle className="h-3.5 w-3.5 text-green-600" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => copyToClipboard(link.access_url, link.id)}>
                          <Copy className="h-4 w-4 mr-2" />
                          {t('pages.zitiNetwork.tempAccess.copyUrl')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => window.open(link.access_url, '_blank')}>
                          <ExternalLink className="h-4 w-4 mr-2" />
                          {t('pages.zitiNetwork.tempAccess.openLink')}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => setDeleteTarget(link)}
                          disabled={link.status !== 'active'}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          {t('pages.zitiNetwork.tempAccess.revokeAccess')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('pages.zitiNetwork.tempAccess.dialogTitle')}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <Label>{t('pages.zitiNetwork.tempAccess.name')}</Label>
                <Input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t('pages.zitiNetwork.tempAccess.namePlaceholder')}
                  required
                />
              </div>
              <div className="col-span-2">
                <Label>{t('pages.zitiNetwork.tempAccess.description')}</Label>
                <Input
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder={t('pages.zitiNetwork.tempAccess.descriptionPlaceholder')}
                />
              </div>
              <div>
                <Label htmlFor="ziti-network-protocol-2">{t('pages.zitiNetwork.tempAccess.protocol')}</Label>
                <select id="ziti-network-protocol-2"
                  value={form.protocol}
                  onChange={(e) => {
                    const proto = e.target.value
                    const port = proto === 'ssh' ? 22 : proto === 'rdp' ? 3389 : proto === 'vnc' ? 5900 : 22
                    setForm({ ...form, protocol: proto, target_port: port })
                  }}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="ssh">SSH</option>
                  <option value="rdp">RDP</option>
                  <option value="vnc">VNC</option>
                </select>
              </div>
              <div>
                <Label>{t('pages.zitiNetwork.tempAccess.targetHost')}</Label>
                <Input
                  value={form.target_host}
                  onChange={(e) => setForm({ ...form, target_host: e.target.value })}
                  placeholder="10.0.0.10"
                  required
                />
              </div>
              <div>
                <Label htmlFor="ziti-network-port-2">{t('pages.zitiNetwork.tempAccess.port')}</Label>
                <Input id="ziti-network-port-2"
                  type="number"
                  value={form.target_port}
                  onChange={(e) => setForm({ ...form, target_port: parseInt(e.target.value) || 22 })}
                  required
                />
              </div>
              <div>
                <Label>{t('pages.zitiNetwork.tempAccess.username')}</Label>
                <Input
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="support"
                />
              </div>
              <div>
                <Label htmlFor="ziti-network-duration">{t('pages.zitiNetwork.tempAccess.duration')}</Label>
                <Input id="ziti-network-duration"
                  type="number"
                  value={form.duration_mins}
                  onChange={(e) => setForm({ ...form, duration_mins: parseInt(e.target.value) || 120 })}
                  min={5}
                  max={10080}
                  required
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {form.duration_mins >= 60
                    ? t('pages.zitiNetwork.tempAccess.remainingHours', { h: Math.floor(form.duration_mins / 60), m: form.duration_mins % 60 })
                    : t('pages.zitiNetwork.tempAccess.remainingMinutes', { m: form.duration_mins })}
                </p>
              </div>
              <div>
                <Label htmlFor="ziti-network-max-uses">{t('pages.zitiNetwork.tempAccess.maxUses')}</Label>
                <Input id="ziti-network-max-uses"
                  type="number"
                  value={form.max_uses}
                  onChange={(e) => setForm({ ...form, max_uses: parseInt(e.target.value) || 0 })}
                  min={0}
                />
              </div>
              <div className="col-span-2">
                <Label htmlFor="ziti-network-allowed-ips">{t('pages.zitiNetwork.tempAccess.allowedIps')}</Label>
                <Input
                  id="ziti-network-allowed-ips"
                  value={form.allowed_ips}
                  onChange={(e) => setForm({ ...form, allowed_ips: e.target.value })}
                  placeholder="1.2.3.4, 5.6.7.8"
                />
              </div>
              <div className="col-span-2 flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Switch id="ziti-network-notify-on-use"
                    checked={form.notify_on_use}
                    onCheckedChange={(v) => setForm({ ...form, notify_on_use: v })}
                  />
                  <Label htmlFor="ziti-network-notify-on-use" className="text-sm">{t('pages.zitiNetwork.tempAccess.notifyOnUse')}</Label>
                </div>
                {form.notify_on_use && (
                  <Input
                    value={form.notify_email}
                    onChange={(e) => setForm({ ...form, notify_email: e.target.value })}
                    placeholder="admin@company.com"
                    className="flex-1"
                  />
                )}
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => { setCreateModal(false); resetForm() }}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? t('pages.zitiNetwork.tempAccess.creating') : t('pages.zitiNetwork.tempAccess.submit')}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.zitiNetwork.tempAccess.revokeTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.zitiNetwork.tempAccess.revokeDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && revokeMutation.mutate(deleteTarget.id)}
            >
              {t('pages.zitiNetwork.tempAccess.revokeAccess')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ---------------------------------------------------------------------------
// "How this works" — behind the scenes for one resource.
//
// End users get a single Open/Connect button and never see the overlay. Admins
// need the opposite: the actual chain a connection traverses, which hop is
// missing, and what to do about it — without opening a terminal.
// ---------------------------------------------------------------------------

interface ChainHop {
  step: number
  title: string
  detail: string
  technical?: string
  status: 'ok' | 'missing' | 'unknown'
  fix?: string
}

interface ResourceDiagnosis {
  name: string
  reachable: boolean
  summary: string
  chain: ChainHop[]
}

function ExplainServiceDialog({ name, onClose }: { name: string | null; onClose: () => void }) {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ['ziti-explain', name],
    queryFn: () =>
      api.get<ResourceDiagnosis>(
        `/api/v1/access/ziti/services/by-name/${encodeURIComponent(name!)}/explain`
      ),
    enabled: !!name,
  })

  return (
    <Dialog open={!!name} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('pages.zitiNetwork.explain.title', { name: name ?? '' })}</DialogTitle>
        </DialogHeader>

        {/* Everything below is composed by the backend's explain endpoint —
            the summary, and each hop's title, detail, fix and technical line —
            so it is rendered as sent rather than translated in the client. */}
        {isLoading || !data ? (
          <p className="py-8 text-center text-muted-foreground">{t('pages.zitiNetwork.explain.checking')}</p>
        ) : (
          <div className="space-y-4">
            <div
              className={`rounded-md p-3 text-sm ${
                data.reachable
                  ? 'bg-green-50 text-green-900 border border-green-200'
                  : 'bg-amber-50 text-amber-900 border border-amber-200'
              }`}
            >
              {data.summary}
            </div>

            <ol className="space-y-2">
              {data.chain.map((hop) => (
                <li key={hop.step} className="flex gap-3 rounded-md border p-3">
                  <div className="mt-0.5 shrink-0">
                    {hop.status === 'ok' ? (
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-amber-600" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{hop.title}</p>
                    <p className="text-sm text-muted-foreground">{hop.detail}</p>
                    {hop.fix && (
                      <p className="mt-1 text-xs font-medium text-amber-700">→ {hop.fix}</p>
                    )}
                    {hop.technical && (
                      <code className="mt-1 inline-block rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                        {hop.technical}
                      </code>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
