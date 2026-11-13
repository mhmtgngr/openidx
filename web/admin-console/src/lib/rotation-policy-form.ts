import i18n from '../i18n'
import type { VaultRotationPolicy, VaultRotationPolicyInput, VaultGenerationPolicy } from './api'

// Rotation-policy form model shared by the Rotation Policies page, the vault
// secret detail and PAM connections.

export function formatInterval(seconds: number): string {
  if (seconds === 0) return i18n.t('pages.rotationPolicies.manual')
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

export const CONNECTOR_TYPES = [
  'directory', 'generate_only', 'ssh', 'ssh_key', 'postgres', 'mysql', 'aws_iam', 'gcp_sa',
] as const

export function connectorLabel(type: string): string {
  return (CONNECTOR_TYPES as readonly string[]).includes(type)
    ? i18n.t(`pages.rotationPolicies.connectors.${type}`)
    : type
}

export const connectorColors: Record<string, string> = {
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
export type ConnectorFieldType = 'text' | 'number' | 'secret' | 'textarea' | 'select' | 'checkbox'
export interface ConnectorField {
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
export const SSH_FIELDS: ConnectorField[] = [
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

export const CONNECTOR_FIELDS: Record<string, ConnectorField[]> = {
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
export const SCHEMA_CONNECTORS = ['ssh', 'ssh_key', 'aws_iam', 'postgres', 'mysql', 'gcp_sa']

// Seed a config bag with the schema's default values when a connector is chosen.
export function seedConnectorConfig(type: string): Record<string, string> {
  const fields = CONNECTOR_FIELDS[type]
  if (!fields) return {}
  const bag: Record<string, string> = {}
  for (const f of fields) if (f.default !== undefined) bag[f.key] = f.default
  return bag
}

// Assemble the backend connector_config from the string bag: coerce port to a
// number, tls to a boolean, and drop empty optional values.
export function buildConnectorConfig(type: string, bag: Record<string, string>): Record<string, unknown> {
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
export function configToBag(cfg: Record<string, unknown>): Record<string, string> {
  const bag: Record<string, string> = {}
  for (const [k, v] of Object.entries(cfg ?? {})) {
    bag[k] = typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v)
  }
  return bag
}

export function connectorConfigValid(f: PolicyFormState): boolean {
  if (f.connectorType === 'directory') return !!f.directoryId && !!f.username
  if (SCHEMA_CONNECTORS.includes(f.connectorType)) {
    return (CONNECTOR_FIELDS[f.connectorType] ?? []).every(
      (field) => !field.required || !!f.connectorConfig[field.key],
    )
  }
  return true // generate_only needs no config
}

export const defaultGenPolicy: VaultGenerationPolicy = {
  length: 24,
  upper: true,
  lower: true,
  digits: true,
  symbols: false,
}

export type IntervalUnit = 'seconds' | 'minutes' | 'hours' | 'days'

export function toSeconds(value: number, unit: IntervalUnit): number {
  if (value === 0) return 0
  const multipliers: Record<IntervalUnit, number> = {
    seconds: 1,
    minutes: 60,
    hours: 3600,
    days: 86400,
  }
  return value * multipliers[unit]
}

export function fromSeconds(s: number): { value: number; unit: IntervalUnit } {
  if (s === 0) return { value: 0, unit: 'days' }
  if (s % 86400 === 0) return { value: s / 86400, unit: 'days' }
  if (s % 3600 === 0) return { value: s / 3600, unit: 'hours' }
  if (s % 60 === 0) return { value: s / 60, unit: 'minutes' }
  return { value: s, unit: 'seconds' }
}

export interface PolicyFormState {
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

export function blankForm(): PolicyFormState {
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

export function policyToForm(p: VaultRotationPolicy): PolicyFormState {
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

export function formToInput(f: PolicyFormState): VaultRotationPolicyInput {
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

/**
 * Prefill a rotation-policy form from a PAM entry: ssh entries rotate over SSH
 * (host, port, username from the entry; the admin credential and host key are
 * left for the administrator), port 5432 is Postgres, 3306 is MySQL, anything
 * else is generate-only.
 */
export function rotationPrefillFromEntry(entry: {
  entry_type: string
  hostname?: string
  port?: number
  username?: string
  vault_secret_id?: string
}): Partial<PolicyFormState> {
  const base = { secretId: entry.vault_secret_id ?? '' }
  const host = entry.hostname ?? ''
  const user = entry.username ?? ''
  if (entry.entry_type === 'ssh') {
    return {
      ...base,
      connectorType: 'ssh',
      connectorConfig: { ...seedConnectorConfig('ssh'), host, port: String(entry.port || 22), username: user },
    }
  }
  if (entry.port === 5432) {
    return {
      ...base,
      connectorType: 'postgres',
      connectorConfig: { ...seedConnectorConfig('postgres'), host, port: '5432', target_role: user },
    }
  }
  if (entry.port === 3306) {
    return {
      ...base,
      connectorType: 'mysql',
      connectorConfig: { ...seedConnectorConfig('mysql'), host, port: '3306', target_user: user },
    }
  }
  return { ...base, connectorType: 'generate_only', connectorConfig: {} }
}
