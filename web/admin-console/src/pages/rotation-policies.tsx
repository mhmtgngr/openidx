import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  api,
  VaultSecretMeta,
  VaultRotationPolicy,
  VaultRotationPolicyInput,
  VaultGenerationPolicy,
} from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Input } from '../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { RefreshCw, Plus, Trash2, Pencil } from 'lucide-react'
import i18n from '../i18n'
import { useToast } from '../hooks/use-toast'

function formatInterval(seconds: number): string {
  if (seconds === 0) return i18n.t('pages.rotationPolicies.manual')
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

const CONNECTOR_TYPES = [
  'directory', 'generate_only', 'ssh', 'ssh_key', 'postgres', 'mysql', 'aws_iam', 'gcp_sa',
] as const

function connectorLabel(type: string): string {
  return (CONNECTOR_TYPES as readonly string[]).includes(type)
    ? i18n.t(`pages.rotationPolicies.connectors.${type}`)
    : type
}

const connectorColors: Record<string, string> = {
  directory: 'bg-blue-100 text-blue-800',
  generate_only: 'bg-green-100 text-green-800',
  ssh: 'bg-purple-100 text-purple-800',
  ssh_key: 'bg-purple-100 text-purple-800',
  postgres: 'bg-sky-100 text-sky-800',
  mysql: 'bg-orange-100 text-orange-800',
  aws_iam: 'bg-yellow-100 text-yellow-800',
  gcp_sa: 'bg-red-100 text-red-800',
}

// ── Connector config schema ──────────────────────────────────────────────────
// One declarative table drives both the dynamic form fields and validation.
// Keys/required-ness mirror the backend validators (sshConfigFromMap /
// pgConfigFromMap / mysqlConfigFromMap in internal/credentials/).
type ConnectorFieldType = 'text' | 'number' | 'secret' | 'textarea' | 'select' | 'checkbox'
interface ConnectorField {
  key: string
  /** Catalog key under pages.rotationPolicies.fields — never raw English. */
  labelKey: string
  required: boolean
  type: ConnectorFieldType
  placeholder?: string
  /** Options carry a labelKey for prose and a raw label for protocol values. */
  options?: { value: string; label?: string; labelKey?: string }[]
  default?: string
}

// ssh and ssh_key share the exact same config (sshConfigFromMap).
const SSH_FIELDS: ConnectorField[] = [
  { key: 'host', labelKey: 'host', required: true, type: 'text', placeholder: 'ssh.example.com' },
  { key: 'port', labelKey: 'port', required: false, type: 'number', placeholder: '22', default: '22' },
  { key: 'username', labelKey: 'username', required: true, type: 'text', placeholder: 'svc-account' },
  { key: 'admin_secret_id', labelKey: 'adminSecret', required: true, type: 'secret' },
  { key: 'admin_username', labelKey: 'adminUsername', required: true, type: 'text', placeholder: 'root' },
  {
    key: 'admin_auth', labelKey: 'adminAuth', required: false, type: 'select', default: 'password',
    options: [
      { value: 'password', labelKey: 'adminAuthPassword' },
      { value: 'private_key', labelKey: 'adminAuthPrivateKey' },
    ],
  },
  { key: 'host_key', labelKey: 'hostKey', required: true, type: 'textarea', placeholder: 'ssh-ed25519 AAAA...' },
]

const CONNECTOR_FIELDS: Record<string, ConnectorField[]> = {
  ssh: SSH_FIELDS,
  ssh_key: SSH_FIELDS,
  aws_iam: [
    { key: 'target_user', labelKey: 'iamUser', required: true, type: 'text', placeholder: 'svc-rotated' },
    { key: 'admin_secret_id', labelKey: 'adminSecretAws', required: true, type: 'secret' },
    { key: 'region', labelKey: 'region', required: false, type: 'text', placeholder: 'us-east-1', default: 'us-east-1' },
  ],
  postgres: [
    { key: 'host', labelKey: 'host', required: true, type: 'text', placeholder: 'db.example.com' },
    { key: 'port', labelKey: 'port', required: false, type: 'number', placeholder: '5432', default: '5432' },
    { key: 'dbname', labelKey: 'dbname', required: true, type: 'text', placeholder: 'appdb' },
    {
      key: 'sslmode', labelKey: 'sslmode', required: false, type: 'select', default: 'require',
      options: ['disable', 'require', 'verify-ca', 'verify-full'].map((v) => ({ value: v, label: v })),
    },
    { key: 'admin_secret_id', labelKey: 'adminSecret', required: true, type: 'secret' },
    { key: 'admin_username', labelKey: 'adminUsername', required: true, type: 'text', placeholder: 'postgres' },
    { key: 'target_role', labelKey: 'targetRole', required: true, type: 'text', placeholder: 'app_role' },
  ],
  mysql: [
    { key: 'host', labelKey: 'host', required: true, type: 'text', placeholder: 'db.example.com' },
    { key: 'port', labelKey: 'port', required: false, type: 'number', placeholder: '3306', default: '3306' },
    { key: 'dbname', labelKey: 'dbnameOptional', required: false, type: 'text', placeholder: 'appdb' },
    { key: 'tls', labelKey: 'tls', required: false, type: 'checkbox' },
    { key: 'admin_secret_id', labelKey: 'adminSecret', required: true, type: 'secret' },
    { key: 'admin_username', labelKey: 'adminUsername', required: true, type: 'text', placeholder: 'root' },
    { key: 'target_user', labelKey: 'targetUser', required: true, type: 'text', placeholder: 'app_user' },
    { key: 'target_host', labelKey: 'targetHost', required: false, type: 'text', placeholder: '%', default: '%' },
  ],
  gcp_sa: [
    { key: 'service_account_email', labelKey: 'serviceAccountEmail', required: true, type: 'text', placeholder: 'rotated@proj.iam.gserviceaccount.com' },
    { key: 'admin_secret_id', labelKey: 'adminSecretGcp', required: true, type: 'secret' },
  ],
}

// Connector types whose config is driven by CONNECTOR_FIELDS (vs the bespoke
// directory branch and the config-less generate_only).
const SCHEMA_CONNECTORS = ['ssh', 'ssh_key', 'aws_iam', 'postgres', 'mysql', 'gcp_sa']

// Seed a config bag with the schema's default values when a connector is chosen.
function seedConnectorConfig(type: string): Record<string, string> {
  const fields = CONNECTOR_FIELDS[type]
  if (!fields) return {}
  const bag: Record<string, string> = {}
  for (const f of fields) if (f.default !== undefined) bag[f.key] = f.default
  return bag
}

// Assemble the backend connector_config from the string bag: coerce port to a
// number, tls to a boolean, and drop empty optional values.
function buildConnectorConfig(type: string, bag: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const field of CONNECTOR_FIELDS[type] ?? []) {
    const raw = bag[field.key]
    if (field.type === 'checkbox') {
      if (raw === 'true') out[field.key] = true
      else if (raw === 'false') out[field.key] = false
      continue
    }
    if (raw === undefined || raw === '') continue
    if (field.type === 'number') {
      const n = parseInt(raw, 10)
      out[field.key] = Number.isNaN(n) ? raw : n
    } else {
      out[field.key] = raw
    }
  }
  return out
}

// Load a saved policy's connector_config back into the string bag for editing.
function configToBag(cfg: Record<string, unknown>): Record<string, string> {
  const bag: Record<string, string> = {}
  for (const [k, v] of Object.entries(cfg ?? {})) {
    bag[k] = typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v)
  }
  return bag
}

function connectorConfigValid(f: PolicyFormState): boolean {
  if (f.connectorType === 'directory') return !!f.directoryId && !!f.username
  if (SCHEMA_CONNECTORS.includes(f.connectorType)) {
    return (CONNECTOR_FIELDS[f.connectorType] ?? []).every(
      (field) => !field.required || !!f.connectorConfig[field.key],
    )
  }
  return true // generate_only needs no config
}

const defaultGenPolicy: VaultGenerationPolicy = {
  length: 24,
  upper: true,
  lower: true,
  digits: true,
  symbols: false,
}

type IntervalUnit = 'seconds' | 'minutes' | 'hours' | 'days'

function toSeconds(value: number, unit: IntervalUnit): number {
  if (value === 0) return 0
  const multipliers: Record<IntervalUnit, number> = {
    seconds: 1,
    minutes: 60,
    hours: 3600,
    days: 86400,
  }
  return value * multipliers[unit]
}

function fromSeconds(s: number): { value: number; unit: IntervalUnit } {
  if (s === 0) return { value: 0, unit: 'days' }
  if (s % 86400 === 0) return { value: s / 86400, unit: 'days' }
  if (s % 3600 === 0) return { value: s / 3600, unit: 'hours' }
  if (s % 60 === 0) return { value: s / 60, unit: 'minutes' }
  return { value: s, unit: 'seconds' }
}

interface PolicyFormState {
  secretId: string
  connectorType: string
  directoryId: string
  username: string
  connectorConfig: Record<string, string>
  intervalValue: number
  intervalUnit: IntervalUnit
  rotateOnCheckout: boolean
  genLength: number
  genUpper: boolean
  genLower: boolean
  genDigits: boolean
  genSymbols: boolean
  enabled: boolean
}

function blankForm(): PolicyFormState {
  return {
    secretId: '',
    connectorType: 'generate_only',
    directoryId: '',
    username: '',
    connectorConfig: {},
    intervalValue: 7,
    intervalUnit: 'days',
    rotateOnCheckout: false,
    genLength: defaultGenPolicy.length,
    genUpper: defaultGenPolicy.upper,
    genLower: defaultGenPolicy.lower,
    genDigits: defaultGenPolicy.digits,
    genSymbols: defaultGenPolicy.symbols,
    enabled: true,
  }
}

function policyToForm(p: VaultRotationPolicy): PolicyFormState {
  const { value, unit } = fromSeconds(p.interval_seconds)
  const cfg = p.connector_config as Record<string, unknown>
  return {
    secretId: p.secret_id,
    connectorType: p.connector_type,
    directoryId: (cfg.directory_id as string) ?? '',
    username: (cfg.username as string) ?? '',
    connectorConfig: SCHEMA_CONNECTORS.includes(p.connector_type)
      ? configToBag(p.connector_config as Record<string, unknown>)
      : {},
    intervalValue: value,
    intervalUnit: unit,
    rotateOnCheckout: p.rotate_on_checkout,
    genLength: p.generation_policy.length,
    genUpper: p.generation_policy.upper,
    genLower: p.generation_policy.lower,
    genDigits: p.generation_policy.digits,
    genSymbols: p.generation_policy.symbols,
    enabled: p.enabled,
  }
}

function formToInput(f: PolicyFormState): VaultRotationPolicyInput {
  const connectorConfig: Record<string, unknown> =
    f.connectorType === 'directory'
      ? { directory_id: f.directoryId, username: f.username }
      : SCHEMA_CONNECTORS.includes(f.connectorType)
        ? buildConnectorConfig(f.connectorType, f.connectorConfig)
        : {}
  return {
    secret_id: f.secretId,
    connector_type: f.connectorType,
    connector_config: connectorConfig,
    generation_policy: {
      length: f.genLength,
      upper: f.genUpper,
      lower: f.genLower,
      digits: f.genDigits,
      symbols: f.genSymbols,
    },
    interval_seconds: toSeconds(f.intervalValue, f.intervalUnit),
    rotate_on_checkout: f.rotateOnCheckout,
    enabled: f.enabled,
  }
}

export function RotationPoliciesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [showDialog, setShowDialog] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<VaultRotationPolicy | null>(null)
  const [form, setForm] = useState<PolicyFormState>(blankForm())

  // Queries
  const { data: policiesData, isLoading, isError, error } = useQuery({
    queryKey: ['rotation-policies'],
    queryFn: () => api.vault.listPolicies(),
  })

  const { data: secretsData } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
  })

  const policies: VaultRotationPolicy[] = policiesData?.policies || []
  const secrets: VaultSecretMeta[] = secretsData?.secrets || []

  function secretName(secretId: string): string {
    return secrets.find((s) => s.id === secretId)?.name ?? secretId
  }

  // Mutations
  const createMutation = useMutation({
    mutationFn: (body: VaultRotationPolicyInput) => api.vault.createPolicy(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rotation-policies'] })
      setShowDialog(false)
      toast({ title: t('pages.rotationPolicies.toasts.created') })
    },
    onError: () => {
      toast({ title: t('pages.rotationPolicies.toasts.createFailed'), variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: VaultRotationPolicyInput }) =>
      api.vault.updatePolicy(id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rotation-policies'] })
      setShowDialog(false)
      toast({ title: t('pages.rotationPolicies.toasts.updated') })
    },
    onError: () => {
      toast({ title: t('pages.rotationPolicies.toasts.updateFailed'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.vault.deletePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rotation-policies'] })
      toast({ title: t('pages.rotationPolicies.toasts.deleted') })
    },
  })

  function openCreate() {
    setEditingPolicy(null)
    setForm(blankForm())
    setShowDialog(true)
  }

  function openEdit(p: VaultRotationPolicy) {
    setEditingPolicy(p)
    setForm(policyToForm(p))
    setShowDialog(true)
  }

  function handleSubmit() {
    const body = formToInput(form)
    if (editingPolicy) {
      updateMutation.mutate({ id: editingPolicy.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  const isFormValid = !!form.secretId && !!form.connectorType && connectorConfigValid(form)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('nav.items.rotationPolicies')}</h1>
          <p className="text-muted-foreground">{t('pages.rotationPolicies.subtitle')}</p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="h-4 w-4 mr-2" />
          {t('pages.rotationPolicies.newPolicy')}
        </Button>
      </div>

      {/* List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RefreshCw className="h-5 w-5" />
            {t('pages.rotationPolicies.list.title', { count: policies.length })}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.rotationPolicies.resourceName')} />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.rotationPolicies.list.table.secret')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.connector')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.interval')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.onCheckout')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.enabled')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.lastStatus')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.lastRun')}</TableHead>
                  <TableHead>{t('pages.rotationPolicies.list.table.nextRun')}</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{secretName(p.secret_id)}</TableCell>
                    <TableCell>
                      <Badge className={connectorColors[p.connector_type] || 'bg-muted text-foreground'}>
                        {connectorLabel(p.connector_type)}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatInterval(p.interval_seconds)}</TableCell>
                    <TableCell>
                      {p.rotate_on_checkout ? (
                        <Badge className="bg-purple-100 text-purple-800">
                          {t('pages.rotationPolicies.list.yes')}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-sm">
                          {t('pages.rotationPolicies.list.no')}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          p.enabled ? 'bg-green-100 text-green-800' : 'bg-muted text-foreground'
                        }
                      >
                        {p.enabled
                          ? t('pages.rotationPolicies.list.enabled')
                          : t('pages.rotationPolicies.list.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {p.last_status ? (
                        <Badge
                          className={
                            p.last_status === 'success'
                              ? 'bg-green-100 text-green-800'
                              : p.last_status === 'failed'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-yellow-100 text-yellow-800'
                          }
                        >
                          {p.last_status}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground text-sm">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {p.last_run_at ? new Date(p.last_run_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {p.next_run_at ? new Date(p.next_run_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEdit(p)}
                          data-testid={`edit-${p.id}`}
                        >
                          <Pencil className="h-3 w-3" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-600 hover:bg-red-50"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>{t('pages.rotationPolicies.confirmDelete.title')}</AlertDialogTitle>
                              <AlertDialogDescription>
                                {t('pages.rotationPolicies.confirmDelete.descriptionBefore')}
                                <strong>{secretName(p.secret_id)}</strong>
                                {t('pages.rotationPolicies.confirmDelete.descriptionAfter')}
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteMutation.mutate(p.id)}
                                className="bg-red-600 hover:bg-red-700"
                              >
                                {t('common.delete')}
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {policies.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center text-muted-foreground py-8">
                      {t('pages.rotationPolicies.list.empty')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit dialog */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editingPolicy
                ? t('pages.rotationPolicies.dialog.editTitle')
                : t('pages.rotationPolicies.dialog.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {/* Secret */}
            <div>
              <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.secret')}</label>
              <Select
                value={form.secretId}
                onValueChange={(v) => setForm((f) => ({ ...f, secretId: v }))}
              >
                <SelectTrigger className="mt-1" data-testid="secret-select">
                  <SelectValue placeholder={t('pages.rotationPolicies.dialog.secretPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {secrets.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Connector type */}
            <div>
              <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.connectorType')}</label>
              <Select
                value={form.connectorType}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, connectorType: v, connectorConfig: seedConnectorConfig(v) }))
                }
              >
                <SelectTrigger className="mt-1" data-testid="connector-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONNECTOR_TYPES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {t(`pages.rotationPolicies.connectors.${c}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Directory-specific fields */}
            {form.connectorType === 'directory' && (
              <>
                <div>
                  <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.directoryId')}</label>
                  <Input
                    className="mt-1"
                    placeholder={t('pages.rotationPolicies.dialog.directoryIdPlaceholder')}
                    value={form.directoryId}
                    onChange={(e) => setForm((f) => ({ ...f, directoryId: e.target.value }))}
                    data-testid="directory-id-input"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.username')}</label>
                  <Input
                    className="mt-1"
                    placeholder={t('pages.rotationPolicies.dialog.usernamePlaceholder')}
                    value={form.username}
                    onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
                    data-testid="username-input"
                  />
                </div>
              </>
            )}

            {/* Schema-driven connector fields (ssh / ssh_key / postgres / mysql) */}
            {SCHEMA_CONNECTORS.includes(form.connectorType) && (
              <div className="space-y-3">
                {CONNECTOR_FIELDS[form.connectorType].map((field) => (
                  <ConnectorFieldInput
                    key={field.key}
                    field={field}
                    value={form.connectorConfig[field.key] ?? ''}
                    secrets={secrets}
                    onChange={(val) =>
                      setForm((f) => ({
                        ...f,
                        connectorConfig: { ...f.connectorConfig, [field.key]: val },
                      }))
                    }
                  />
                ))}
              </div>
            )}

            {/* Interval */}
            <div>
              <label className="text-sm font-medium">{t('pages.rotationPolicies.dialog.interval')}</label>
              <div className="flex gap-2 mt-1">
                <Input
                  type="number"
                  min={0}
                  className="flex-1"
                  value={form.intervalValue}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, intervalValue: parseInt(e.target.value, 10) || 0 }))
                  }
                />
                <Select
                  value={form.intervalUnit}
                  onValueChange={(v) => setForm((f) => ({ ...f, intervalUnit: v as IntervalUnit }))}
                >
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="seconds">{t('pages.rotationPolicies.dialog.units.seconds')}</SelectItem>
                    <SelectItem value="minutes">{t('pages.rotationPolicies.dialog.units.minutes')}</SelectItem>
                    <SelectItem value="hours">{t('pages.rotationPolicies.dialog.units.hours')}</SelectItem>
                    <SelectItem value="days">{t('pages.rotationPolicies.dialog.units.days')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Rotate on checkout */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="rotateOnCheckout"
                checked={form.rotateOnCheckout}
                onChange={(e) => setForm((f) => ({ ...f, rotateOnCheckout: e.target.checked }))}
                className="h-4 w-4"
              />
              <label htmlFor="rotateOnCheckout" className="text-sm font-medium">
                {t('pages.rotationPolicies.dialog.rotateOnCheckout')}
              </label>
            </div>

            {/* Generation policy */}
            <div className="space-y-2 border rounded-lg p-3">
              <p className="text-sm font-medium">{t('pages.rotationPolicies.dialog.generation')}</p>
              <div>
                <label className="text-xs text-muted-foreground">{t('pages.rotationPolicies.dialog.length')}</label>
                <Input
                  type="number"
                  min={8}
                  max={256}
                  className="mt-1"
                  value={form.genLength}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, genLength: parseInt(e.target.value, 10) || 24 }))
                  }
                />
              </div>
              <div className="flex gap-4">
                {(
                  [
                    ['genUpper', 'upper'],
                    ['genLower', 'lower'],
                    ['genDigits', 'digits'],
                    ['genSymbols', 'symbols'],
                  ] as const
                ).map(([key, labelKey]) => (
                  <label key={key} className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={form[key]}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, [key]: e.target.checked }))
                      }
                      className="h-4 w-4"
                    />
                    {t(`pages.rotationPolicies.dialog.charsets.${labelKey}`)}
                  </label>
                ))}
              </div>
            </div>

            {/* Enabled toggle */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="enabled"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <label htmlFor="enabled" className="text-sm font-medium">
                {t('pages.rotationPolicies.dialog.enabled')}
              </label>
            </div>

            <Button
              onClick={handleSubmit}
              disabled={!isFormValid || isPending}
              className="w-full"
            >
              {isPending
                ? editingPolicy
                  ? t('pages.rotationPolicies.dialog.saving')
                  : t('pages.rotationPolicies.dialog.creating')
                : editingPolicy
                ? t('pages.rotationPolicies.dialog.save')
                : t('pages.rotationPolicies.dialog.create')}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function ConnectorFieldInput({
  field,
  value,
  secrets,
  onChange,
}: {
  field: ConnectorField
  value: string
  secrets: VaultSecretMeta[]
  onChange: (val: string) => void
}) {
  const { t } = useTranslation()
  const fieldLabel = t(`pages.rotationPolicies.fields.${field.labelKey}`)
  const label = `${fieldLabel}${field.required ? ' *' : ''}`
  const testId = `cc-${field.key}`

  if (field.type === 'secret') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id={testId} className="mt-1" data-testid={testId}>
            <SelectValue placeholder={t('pages.rotationPolicies.fields.selectSecret')} />
          </SelectTrigger>
          <SelectContent>
            {secrets.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'select') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id={testId} className="mt-1" data-testid={testId}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(field.options ?? []).map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.labelKey ? t(`pages.rotationPolicies.fields.${o.labelKey}`) : o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'textarea') {
    return (
      <div>
        <label htmlFor={testId} className="text-sm font-medium">{label}</label>
        <textarea
          id={testId}
          className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
          rows={2}
          placeholder={field.placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          data-testid={testId}
        />
      </div>
    )
  }

  if (field.type === 'checkbox') {
    return (
      <div className="flex items-center gap-3">
        <input
          type="checkbox"
          id={testId}
          checked={value === 'true'}
          onChange={(e) => onChange(e.target.checked ? 'true' : '')}
          data-testid={testId}
        />
        <label htmlFor={testId} className="text-sm font-medium">
          {fieldLabel}
        </label>
      </div>
    )
  }

  // 'text' | 'number'
  return (
    <div>
      <label htmlFor={testId} className="text-sm font-medium">{label}</label>
      <Input
        id={testId}
        className="mt-1"
        type={field.type === 'number' ? 'number' : 'text'}
        placeholder={field.placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid={testId}
      />
    </div>
  )
}
