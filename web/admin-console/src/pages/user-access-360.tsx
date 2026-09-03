import { useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { complianceTooltip, formatCompliancePercent } from '../lib/compliance'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Shield, Key, Network, Server, Laptop, Clock,
  Zap, AlertTriangle, Activity, Lock, Fingerprint, RefreshCw,
  ShieldCheck, ShieldX, ShieldAlert, Link2, MonitorSmartphone, Ban,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Textarea } from '../components/ui/textarea'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { api } from '../lib/api'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

interface NamedRef { id: string; name: string }

interface VaultGrant {
  secret_id: string
  secret_name: string
  secret_type: string
  actions: string[]
  via: string
  expires_at?: string
}

interface Checkout { id: string; secret_name: string; mode: string; leased_at: string; expires_at?: string }
interface JITGrant { id: string; role_name: string; expires_at: string }
interface PrivSession { id: string; route_name: string; protocol: string; started_at: string; over_ziti: boolean }
interface Device {
  agent_id: string
  platform: string
  status: string
  compliance_status: string
  ziti_identity_id?: string
  last_seen_at?: string
}
interface DialPolicy { name: string; services: string[] }
interface AuditEvent { source: string; event_type: string; actor_ip?: string; created_at: string }

interface AccessMap {
  user: {
    id: string
    username: string
    email: string
    enabled: boolean
    created_at: string
    last_login_at?: string
  }
  iam: {
    roles: NamedRef[]
    groups: NamedRef[]
    active_sessions: number
    active_api_keys: number
    pending_access_requests: number
  }
  pam: {
    vault_grants: VaultGrant[]
    active_checkouts: Checkout[]
    active_jit_grants: JITGrant[]
    active_sessions: PrivSession[]
    sessions_30d: number
    pending_session_requests: number
    pending_credential_requests: number
  }
  ziti: {
    identity: { ziti_id: string; name: string; enrolled: boolean; attributes: string[] } | null
    devices: Device[]
    dial_policies: DialPolicy[]
    reachable_services: string[]
    trusted_device: boolean
  }
  activity: AuditEvent[]
  generated_at: string
}

interface DevicePostureSummary {
  check_type: string
  status: string
  severity: string
  reported_at?: string
}

interface DeviceIAM {
  known_device_id: string
  fingerprint: string
  name: string
  device_type: string
  ip_address?: string
  trusted: boolean
  last_seen_at?: string
}

interface DeviceZiti {
  agent_id: string
  ziti_identity_id?: string
  status: string
  platform?: string
  management_mode?: string
  compliance_status: string
  compliance_score: number
  posture: DevicePostureSummary[]
  last_seen_at?: string
}

interface UserDeviceEntry {
  source: 'linked' | 'iam' | 'ziti'
  iam?: DeviceIAM
  ziti?: DeviceZiti
}

interface UserDevicesResponse {
  user_id: string
  username: string
  devices: UserDeviceEntry[]
  generated_at: string
}

interface DeviceRevokeResult {
  agent_id: string
  agent_revoked: boolean
  ziti_identity_deleted: boolean
  ziti_edge_sessions_terminated: number
  ziti_api_sessions_terminated: number
  known_device_untrusted: boolean
  warnings?: string[]
}

interface KillSwitchResult {
  user_id: string
  username: string
  user_disabled: boolean
  iam_sessions_revoked: number
  iam_api_keys_revoked: number
  pam_checkouts_revoked: number
  pam_vault_grants_expired: number
  pam_jit_grants_revoked: number
  pam_privileged_sessions_terminated: number
  ziti_edge_sessions_terminated: number
  ziti_api_sessions_terminated: number
  ziti_identity_deleted: boolean
  ziti_controller_online: boolean
  warnings?: string[]
}

const sourceBadgeClass: Record<string, string> = {
  openidx: 'bg-blue-50 text-blue-700 border-blue-200',
  ziti: 'bg-green-50 text-green-700 border-green-200',
  guacamole: 'bg-purple-50 text-purple-700 border-purple-200',
}

function complianceBadge(status: string) {
  switch (status) {
    case 'compliant':
      return { cls: 'bg-green-50 text-green-700 border-green-200', Icon: ShieldCheck }
    case 'non_compliant':
      return { cls: 'bg-red-50 text-red-700 border-red-200', Icon: ShieldX }
    case 'grace_period':
      return { cls: 'bg-yellow-50 text-yellow-700 border-yellow-200', Icon: ShieldAlert }
    default:
      return { cls: 'bg-slate-50 text-slate-600 border-slate-200', Icon: Shield }
  }
}

// Module level, so the label is a catalog key resolved at render rather than
// a string frozen at import time.
function deviceSourceLabel(source: string): { labelKey: string; cls: string } {
  switch (source) {
    case 'linked':
      return { labelKey: 'pages.userAccess360.devices.sources.linked', cls: 'bg-blue-50 text-blue-700 border-blue-200' }
    case 'iam':
      return { labelKey: 'pages.userAccess360.devices.sources.iam', cls: 'bg-slate-50 text-slate-600 border-slate-200' }
    default:
      return { labelKey: 'pages.userAccess360.devices.sources.ziti', cls: 'bg-green-50 text-green-700 border-green-200' }
  }
}

export function UserAccess360Page() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [killOpen, setKillOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [disableUser, setDisableUser] = useState(false)

  const { data: map, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['user-access-map', id],
    queryFn: () => api.get<AccessMap>(`/api/v1/access/users/${id}/access-map`),
    enabled: !!id,
  })

  const { data: devicesData } = useQuery({
    queryKey: ['user-devices', id],
    queryFn: () => api.get<UserDevicesResponse>(`/api/v1/access/users/${id}/devices`),
    enabled: !!id,
  })

  const revokeDeviceMutation = useMutation({
    mutationFn: ({ agentId, reason }: { agentId: string; reason: string }) =>
      api.post<DeviceRevokeResult>(`/api/v1/access/users/${id}/devices/${agentId}/revoke`, { reason }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['user-devices', id] })
      queryClient.invalidateQueries({ queryKey: ['user-access-map', id] })
      const net = res.ziti_edge_sessions_terminated + res.ziti_api_sessions_terminated
      // One sentence per outcome, so each locale controls its own punctuation.
      const outcomes = [t('pages.userAccess360.devices.revokedSessions', { count: net })]
      if (res.ziti_identity_deleted) outcomes.push(t('pages.userAccess360.devices.revokedIdentity'))
      if (res.known_device_untrusted) outcomes.push(t('pages.userAccess360.devices.revokedUntrusted'))
      toast({
        title: t('pages.userAccess360.devices.revoked'),
        description: outcomes.join(' '),
      })
    },
    onError: () => toast({ title: t('pages.userAccess360.devices.revokeFailed'), variant: 'destructive' }),
  })

  const killMutation = useMutation({
    mutationFn: (body: { reason: string; disable_user: boolean }) =>
      api.post<KillSwitchResult>(`/api/v1/access/users/${id}/kill-switch`, body),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['user-access-map', id] })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      const parts = [
        t('pages.userAccess360.kill.partSessions', { n: res.iam_sessions_revoked }),
        t('pages.userAccess360.kill.partCheckouts', { n: res.pam_checkouts_revoked }),
        t('pages.userAccess360.kill.partJit', { n: res.pam_jit_grants_revoked }),
        t('pages.userAccess360.kill.partPrivSessions', { n: res.pam_privileged_sessions_terminated }),
        t('pages.userAccess360.kill.partNetwork', {
          n: res.ziti_edge_sessions_terminated + res.ziti_api_sessions_terminated,
        }),
      ]
      const detail = parts.join(', ')
      toast({
        title: res.user_disabled
          ? t('pages.userAccess360.kill.executedDisabled')
          : t('pages.userAccess360.kill.executed'),
        description: res.warnings?.length
          ? t('pages.userAccess360.kill.descWithWarnings', { detail, n: res.warnings.length })
          : t('pages.userAccess360.kill.desc', { detail }),
      })
      setKillOpen(false)
      setReason('')
      setDisableUser(false)
    },
    onError: () => toast({ title: t('pages.userAccess360.kill.failed'), variant: 'destructive' }),
  })

  if (isError) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.userAccess360.title')}</h1>
        </div>
        <QueryError error={error} resource={t('pages.userAccess360.resource')} />
      </div>
    )
  }

  if (isLoading || !map) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.userAccess360.title')}</h1>
        </div>
        <p className="text-muted-foreground">
          {isLoading ? t('pages.userAccess360.correlating') : t('pages.userAccess360.notFound')}
        </p>
      </div>
    )
  }

  const { user, iam, pam, ziti, activity } = map
  const liveTotal =
    iam.active_sessions + pam.active_checkouts.length + pam.active_jit_grants.length + pam.active_sessions.length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold tracking-tight">{user.username}</h1>
              <Badge className={user.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                {user.enabled ? t('pages.userAccess360.active') : t('pages.userAccess360.disabled')}
              </Badge>
            </div>
            <p className="text-muted-foreground">
              {t('pages.userAccess360.subtitle', { email: user.email })}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />{t('common.refresh')}
          </Button>
          <Button variant="destructive" onClick={() => setKillOpen(true)}>
            <Zap className="mr-2 h-4 w-4" />{t('pages.userAccess360.killSwitch')}
          </Button>
        </div>
      </div>

      {/* Live access summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg"><Shield className="h-6 w-6 text-primary" /></div>
              <div>
                <p className="text-2xl font-bold">{iam.active_sessions}</p>
                <p className="text-sm text-muted-foreground">{t('pages.userAccess360.summary.iamSessions')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-100 rounded-lg"><Key className="h-6 w-6 text-amber-600" /></div>
              <div>
                <p className="text-2xl font-bold">{pam.active_checkouts.length}</p>
                <p className="text-sm text-muted-foreground">{t('pages.userAccess360.summary.checkouts')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 rounded-lg"><Lock className="h-6 w-6 text-purple-600" /></div>
              <div>
                <p className="text-2xl font-bold">{pam.active_sessions.length}</p>
                <p className="text-sm text-muted-foreground">{t('pages.userAccess360.summary.privSessions')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg"><Network className="h-6 w-6 text-green-600" /></div>
              <div>
                <p className="text-2xl font-bold">{ziti.reachable_services.length}</p>
                <p className="text-sm text-muted-foreground">{t('pages.userAccess360.summary.networkServices')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-100 rounded-lg"><Laptop className="h-6 w-6 text-slate-600" /></div>
              <div>
                <p className="text-2xl font-bold">{ziti.devices.length}</p>
                <p className="text-sm text-muted-foreground">{t('pages.userAccess360.summary.devices')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Three pillars */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* IAM */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5 text-primary" />{t('pages.userAccess360.iam.heading')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.iam.roles', { n: iam.roles.length })}</p>
              <div className="flex flex-wrap gap-1.5">
                {iam.roles.length > 0
                  ? iam.roles.map(r => <Badge key={r.id} variant="outline" className="bg-blue-50">{r.name}</Badge>)
                  : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.iam.none')}</span>}
              </div>
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.iam.groups', { n: iam.groups.length })}</p>
              <div className="flex flex-wrap gap-1.5">
                {iam.groups.length > 0
                  ? iam.groups.map(g => <Badge key={g.id} variant="outline" className="bg-green-50">{g.name}</Badge>)
                  : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.iam.none')}</span>}
              </div>
              <p className="text-xs text-muted-foreground mt-1.5">
                {t('pages.userAccess360.iam.groupsHint')}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center border rounded-lg p-2">
              <div>
                <p className="text-lg font-semibold">{iam.active_sessions}</p>
                <p className="text-xs text-muted-foreground">{t('pages.userAccess360.iam.sessions')}</p>
              </div>
              <div>
                <p className="text-lg font-semibold">{iam.active_api_keys}</p>
                <p className="text-xs text-muted-foreground">{t('pages.userAccess360.iam.apiKeys')}</p>
              </div>
              <div>
                <p className="text-lg font-semibold">{iam.pending_access_requests}</p>
                <p className="text-xs text-muted-foreground">{t('pages.userAccess360.iam.pendingRequests')}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* PAM */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Key className="h-5 w-5 text-amber-600" />{t('pages.userAccess360.pam.heading')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.pam.vaultAccess', { n: pam.vault_grants.length })}</p>
              {pam.vault_grants.length > 0 ? (
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {pam.vault_grants.map((g, i) => (
                    <div key={`${g.secret_id}-${g.via}-${i}`} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="font-medium truncate">{g.secret_name}</span>
                      <span className="flex gap-1 shrink-0">
                        <Badge variant="secondary" className="text-xs">{g.via}</Badge>
                        {g.actions.includes('reveal') && <Badge variant="outline" className="text-xs text-amber-700">{t('pages.userAccess360.pam.reveal')}</Badge>}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.pam.noVaultGrants')}</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.pam.checkouts', { n: pam.active_checkouts.length })}</p>
              {pam.active_checkouts.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_checkouts.map(co => (
                    <div key={co.id} className="flex items-center justify-between p-2 rounded bg-amber-50 text-sm">
                      <span className="font-medium">{co.secret_name}</span>
                      <span className="text-xs text-muted-foreground">
                        {co.expires_at
                          ? t('pages.userAccess360.pam.expiresAt', {
                              time: new Date(co.expires_at).toLocaleTimeString(),
                            })
                          : co.mode}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.pam.none')}</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.pam.jit', { n: pam.active_jit_grants.length })}</p>
              {pam.active_jit_grants.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_jit_grants.map(j => (
                    <div key={j.id} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="font-medium">{j.role_name}</span>
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" />{new Date(j.expires_at).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.pam.none')}</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.pam.liveSessions', { n: pam.active_sessions.length })}</p>
              {pam.active_sessions.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_sessions.map(ps => (
                    <div key={ps.id} className="flex items-center justify-between p-2 rounded bg-purple-50 text-sm">
                      <span className="font-medium truncate">{ps.route_name || ps.protocol || t('pages.userAccess360.pam.sessionFallback')}</span>
                      {ps.over_ziti && (
                        <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                          <Network className="mr-1 h-3 w-3" />{t('pages.userAccess360.pam.overZiti')}
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.pam.none')}</span>}
              <p className="text-xs text-muted-foreground mt-1.5">{t('pages.userAccess360.pam.sessions30d', { count: pam.sessions_30d })}</p>
            </div>
          </CardContent>
        </Card>

        {/* Ziti */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Network className="h-5 w-5 text-green-600" />{t('pages.userAccess360.ziti.heading')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.ziti.identity')}</p>
              {ziti.identity ? (
                <div className="p-2 rounded bg-muted/50 space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium truncate">{ziti.identity.name}</span>
                    <Badge variant="outline" className={ziti.identity.enrolled
                      ? 'bg-green-50 text-green-700 border-green-200'
                      : 'bg-yellow-50 text-yellow-700 border-yellow-200'}>
                      {ziti.identity.enrolled
                        ? t('pages.userAccess360.ziti.enrolled')
                        : t('pages.userAccess360.ziti.awaitingEnrollment')}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {ziti.identity.attributes.map(a => (
                      <Badge key={a} variant="secondary" className="text-xs">#{a}</Badge>
                    ))}
                    {ziti.trusted_device && (
                      <Badge variant="outline" className="text-xs bg-blue-50 text-blue-700 border-blue-200">
                        <Fingerprint className="mr-1 h-3 w-3" />{t('pages.userAccess360.ziti.trustedDevice')}
                      </Badge>
                    )}
                  </div>
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">{t('pages.userAccess360.ziti.notSynced')}</span>
              )}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.ziti.reachableServices', { n: ziti.reachable_services.length })}</p>
              {ziti.reachable_services.length > 0 ? (
                <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                  {ziti.reachable_services.map(svc => (
                    <Badge key={svc} variant="outline" className="bg-green-50 text-green-800">
                      <Server className="mr-1 h-3 w-3" />{svc}
                    </Badge>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.ziti.noDialPolicies')}</span>}
              {ziti.dial_policies.length > 0 && (
                <p className="text-xs text-muted-foreground mt-1.5">
                  {t('pages.userAccess360.ziti.via', {
                    count: ziti.dial_policies.length,
                    names: ziti.dial_policies.map(p => p.name).join(', '),
                  })}
                </p>
              )}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">{t('pages.userAccess360.ziti.devices', { n: ziti.devices.length })}</p>
              {ziti.devices.length > 0 ? (
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {ziti.devices.map(d => (
                    <div key={d.agent_id} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="flex items-center gap-2 min-w-0">
                        <Laptop className="h-3.5 w-3.5 shrink-0" />
                        <span className="font-medium truncate">{d.agent_id}</span>
                      </span>
                      <span className="flex gap-1 shrink-0">
                        {d.platform && <Badge variant="secondary" className="text-xs">{d.platform}</Badge>}
                        <Badge variant="outline" className={`text-xs ${d.compliance_status === 'compliant'
                          ? 'bg-green-50 text-green-700' : 'bg-yellow-50 text-yellow-700'}`}>
                          {t(`pages.userAccess360.devices.complianceStatuses.${d.compliance_status}`, {
                            defaultValue: d.compliance_status.replace('_', ' '),
                          })}
                        </Badge>
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">{t('pages.userAccess360.ziti.noAgents')}</span>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Cross-pillar devices */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <MonitorSmartphone className="h-5 w-5" />{t('pages.userAccess360.devices.heading')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!devicesData?.devices?.length ? (
            <p className="text-center py-6 text-muted-foreground">{t('pages.userAccess360.devices.empty')}</p>
          ) : (
            <div className="space-y-3">
              {devicesData.devices.map((d, i) => {
                const comp = d.ziti ? complianceBadge(d.ziti.compliance_status) : null
                const src = deviceSourceLabel(d.source)
                const failing = (d.ziti?.posture || []).filter(p => p.status !== 'pass')
                return (
                  <div key={i} className="flex items-start justify-between gap-3 p-3 border rounded-lg">
                    <div className="min-w-0 space-y-1.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Laptop className="h-4 w-4 shrink-0" />
                        <span className="font-medium truncate">
                          {d.iam?.name || d.ziti?.agent_id || t('pages.userAccess360.devices.deviceFallback')}
                        </span>
                        <Badge variant="outline" className={`text-xs ${src.cls}`}>
                          {d.source === 'linked' && <Link2 className="mr-1 h-3 w-3" />}{t(src.labelKey)}
                        </Badge>
                        {d.iam && (
                          <Badge variant="outline" className={`text-xs ${d.iam.trusted
                            ? 'bg-green-50 text-green-700 border-green-200'
                            : 'bg-slate-50 text-slate-600 border-slate-200'}`}>
                            {d.iam.trusted ? <ShieldCheck className="mr-1 h-3 w-3" /> : <Shield className="mr-1 h-3 w-3" />}
                            {d.iam.trusted
                              ? t('pages.userAccess360.devices.trusted')
                              : t('pages.userAccess360.devices.untrusted')}
                          </Badge>
                        )}
                        {comp && d.ziti && (
                          <Badge variant="outline" className={`text-xs ${comp.cls}`}>
                            <comp.Icon className="mr-1 h-3 w-3" />
                            {t(`pages.userAccess360.devices.complianceStatuses.${d.ziti.compliance_status}`, {
                              defaultValue: d.ziti.compliance_status.replace('_', ' '),
                            })}
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground flex flex-wrap gap-x-3 gap-y-0.5">
                        {d.ziti?.platform && <span>{d.ziti.platform}</span>}
                        {d.ziti?.management_mode && <span>{d.ziti.management_mode}</span>}
                        {d.iam?.ip_address && <span>{d.iam.ip_address}</span>}
                        {d.ziti && (
                          <span title={complianceTooltip(d.ziti.compliance_status)}>
                            {t('pages.userAccess360.devices.score', {
                              score: formatCompliancePercent(d.ziti.compliance_status, d.ziti.compliance_score),
                            })}
                          </span>
                        )}
                        {d.ziti?.status && d.ziti.status !== 'active' && (
                          <span className="text-red-600">
                            {t('pages.userAccess360.devices.agentStatus', { status: d.ziti.status })}
                          </span>
                        )}
                      </div>
                      {failing.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {failing.map((p, j) => (
                            <Badge key={j} variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200">
                              {p.check_type}: {p.status}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    {d.ziti && d.ziti.status !== 'revoked' && (
                      <ConfirmAction
                        title={t('pages.userAccess360.devices.revokeTitle')}
                        description={t('pages.userAccess360.devices.revokeDesc')}
                        destructive
                        requireReason
                        confirmLabel={t('pages.userAccess360.devices.revoke')}
                        onConfirm={(reason) => revokeDeviceMutation.mutateAsync({ agentId: d.ziti!.agent_id, reason: reason || '' })}
                      >
                        {(open) => (
                          <Button variant="outline" size="sm" className="shrink-0 text-red-600 hover:text-red-700"
                            disabled={revokeDeviceMutation.isPending}
                            onClick={open}>
                            <Ban className="mr-1 h-3.5 w-3.5" />{t('pages.userAccess360.devices.revoke')}
                          </Button>
                        )}
                      </ConfirmAction>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <p className="text-xs text-muted-foreground mt-3">
            <Trans
              i18nKey="pages.userAccess360.devices.footnote"
              components={[<span key="0" className="font-medium" />]}
            />
          </p>
        </CardContent>
      </Card>

      {/* Cross-pillar activity */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Activity className="h-5 w-5" />{t('pages.userAccess360.activity.heading')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {activity.length === 0 ? (
            <p className="text-center py-6 text-muted-foreground">{t('pages.userAccess360.activity.empty')}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.userAccess360.activity.colSource')}</TableHead>
                  <TableHead>{t('pages.userAccess360.activity.colEvent')}</TableHead>
                  <TableHead>{t('pages.userAccess360.activity.colIp')}</TableHead>
                  <TableHead>{t('pages.userAccess360.activity.colWhen')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activity.map((e, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Badge variant="outline" className={sourceBadgeClass[e.source] || ''}>{e.source}</Badge>
                    </TableCell>
                    <TableCell className="font-medium">{e.event_type}</TableCell>
                    <TableCell className="text-muted-foreground">{e.actor_ip || '—'}</TableCell>
                    <TableCell>{new Date(e.created_at).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Kill switch dialog */}
      <Dialog open={killOpen} onOpenChange={setKillOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />
              {t('pages.userAccess360.kill.dialogTitle', { username: user.username })}
            </DialogTitle>
            <DialogDescription>{t('pages.userAccess360.kill.dialogDesc')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-red-50 text-sm text-red-800">
              {ziti.identity
                ? t('pages.userAccess360.kill.willSeverWithZiti', {
                    iamSessions: iam.active_sessions,
                    checkouts: pam.active_checkouts.length,
                    jit: pam.active_jit_grants.length,
                    privSessions: pam.active_sessions.length,
                    identity: ziti.identity.name,
                  })
                : t('pages.userAccess360.kill.willSever', {
                    iamSessions: iam.active_sessions,
                    checkouts: pam.active_checkouts.length,
                    jit: pam.active_jit_grants.length,
                    privSessions: pam.active_sessions.length,
                  })}
              {liveTotal === 0 && t('pages.userAccess360.kill.nothingLive')}
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.userAccess360.kill.reason')}</label>
              <Textarea value={reason} onChange={e => setReason(e.target.value)} rows={2}
                placeholder={t('pages.userAccess360.kill.reasonPlaceholder')} className="mt-1" />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={disableUser} onCheckedChange={v => setDisableUser(v === true)} />
              <span>
                <Trans
                  i18nKey="pages.userAccess360.kill.disableAccount"
                  components={[<span key="0" className="font-medium" />]}
                />
              </span>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setKillOpen(false)}>{t('common.cancel')}</Button>
            <Button variant="destructive" disabled={killMutation.isPending}
              onClick={() => killMutation.mutate({ reason, disable_user: disableUser })}>
              <Zap className="mr-2 h-4 w-4" />
              {killMutation.isPending
                ? t('pages.userAccess360.kill.severing')
                : t('pages.userAccess360.kill.severAll')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
